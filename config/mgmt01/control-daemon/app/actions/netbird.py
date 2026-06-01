"""NetBird-quarantaine via deny-by-default groepsverwijdering.

Correcties t.o.v. Addendum J §J.6.5:
- STRIP GESCOPT tot NETBIRD_POLICY_GROUPS (persona-groepen). Addendum J streepte
  alle groepen behalve 'All' -> dat zou een infra-peer uit Core-Services halen.
  Hier blijft infra structureel onaantastbaar (V34-veiligheidseigenschap).
- ENFORCE poort ALLE schrijfacties (NetBird-PUT + Redis-restore). Dry-run berekent
  en logt de beslissing maar raakt niets aan.
- Fail-loud (beslispunt 4): onresolvebaar IP -> CRITICAL-log + result {ok:false};
  geen drop-unknown. Eén bounded retry (V34-poll-convergentie / re-enrollment-churn).

NetBird-quirk: een groep ZONDER peers geeft "peers": null terug (niet [] en niet
afwezig). dict.get("peers", []) levert dan None. Daarom overal _peer_ids() met
(... or []) coercie. Bug uit V35-test: docent1 was enige in Docenten -> na strip
peers=null -> restore + Quarantine-remove crashten.

Bekende beperking (GitHub #5399): PUT /api/groups/{id} vervangt de volledige
peers-lijst, niet atomair. Single daemon-instance -> acceptabel voor de PoC.
"""
import asyncio
import json
import logging

import httpx
import redis.asyncio as redis

from app.config import (
    ACTION_RETRY,
    ACTION_RETRY_DELAY,
    ENFORCE,
    NETBIRD_API_TOKEN,
    NETBIRD_API_URL,
    NETBIRD_POLICY_GROUPS,
    NETBIRD_QUARANTINE_GROUP,
    REDIS_URL,
)

logger = logging.getLogger("control-daemon.netbird")
_redis = redis.from_url(REDIS_URL, decode_responses=True)
_POLICY_SET = set(NETBIRD_POLICY_GROUPS)


def _peer_ids(group: dict) -> list[str]:
    """Peer-id's uit een groep-object. NetBird geeft peers=null voor lege groepen."""
    return [p["id"] for p in (group.get("peers") or [])]


async def _get(path: str):
    headers = {"Authorization": f"Token {NETBIRD_API_TOKEN}", "Accept": "application/json"}
    async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
        r = await c.get(f"{NETBIRD_API_URL}{path}", headers=headers)
        r.raise_for_status()
        return r.json()


async def _put(path: str, data: dict):
    headers = {
        "Authorization": f"Token {NETBIRD_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
        r = await c.put(f"{NETBIRD_API_URL}{path}", headers=headers, json=data)
        r.raise_for_status()
        return r.json()


async def list_peers() -> list[dict]:
    """Publieke helper: voor de identity-map-bootstrap in main."""
    return await _get("/peers")


async def _find_peer_by_ip(peer_ip: str) -> dict | None:
    for p in await _get("/peers"):
        if str(p.get("ip", "")).split("/")[0] == peer_ip:
            return p
    return None


async def _resolve_with_retry(peer_ip: str) -> dict | None:
    peer = await _find_peer_by_ip(peer_ip)
    attempts = 0
    while peer is None and attempts < ACTION_RETRY:
        attempts += 1
        logger.warning("peer %s niet gevonden, retry %d/%d over %.1fs",
                       peer_ip, attempts, ACTION_RETRY, ACTION_RETRY_DELAY)
        await asyncio.sleep(ACTION_RETRY_DELAY)
        peer = await _find_peer_by_ip(peer_ip)
    return peer


async def _find_group_by_name(name: str) -> dict | None:
    for g in await _get("/groups"):
        if g.get("name") == name:
            return g
    return None


async def _add_to_quarantine_group(peer_id: str) -> None:
    """Administratieve markering; mag de hoofdactie nooit laten falen."""
    try:
        q = await _find_group_by_name(NETBIRD_QUARANTINE_GROUP)
        if not q:
            logger.warning("Quarantine-groep '%s' bestaat niet -- gestript maar niet gemarkeerd",
                           NETBIRD_QUARANTINE_GROUP)
            return
        members = _peer_ids(q)
        if peer_id not in members:
            members.append(peer_id)
            await _put(f"/groups/{q['id']}", {"name": NETBIRD_QUARANTINE_GROUP, "peers": members})
    except Exception as e:
        logger.error("kon peer niet aan Quarantine-groep toevoegen (marker): %s", e)


async def _remove_from_quarantine_group(peer_id: str) -> None:
    try:
        q = await _find_group_by_name(NETBIRD_QUARANTINE_GROUP)
        if not q:
            return
        members = [pid for pid in _peer_ids(q) if pid != peer_id]
        await _put(f"/groups/{q['id']}", {"name": NETBIRD_QUARANTINE_GROUP, "peers": members})
    except Exception as e:
        logger.error("kon peer niet uit Quarantine-groep verwijderen (marker): %s", e)


async def quarantine_peer(peer_ip: str, attribution: str = "") -> dict:
    """Quarantaine: verwijder peer uit de policy-dragende persona-groepen.

    Retourneert een result-dict zodat main fail-loud kan escaleren/emitten.
    """
    peer = await _resolve_with_retry(peer_ip)
    if not peer:
        logger.critical(
            "ACTIE ONUITVOERBAAR: quarantaine-doel %s niet resolvebaar naar een peer "
            "(%s) -- geen actie, geescaleerd", peer_ip, attribution or "geen attributie")
        return {"ok": False, "action": "quarantine", "peer_ip": peer_ip,
                "peer_name": None, "reason": "peer_unresolved", "stripped": [], "mode": "n/a"}

    peer_id = peer["id"]
    peer_name = peer.get("name", "unknown")

    # Strip GESCOPT tot de policy-groepen -> infra (Core-Services) blijft onaangeroerd.
    strip = [g for g in (peer.get("groups") or []) if g.get("name") in _POLICY_SET]
    strip_names = [g.get("name") for g in strip]

    if not strip:
        logger.info("peer %s (%s) zit in geen policy-groep (infra of al kaal) -- no-op",
                    peer_name, peer_ip)
        return {"ok": True, "action": "quarantine", "peer_ip": peer_ip,
                "peer_name": peer_name, "reason": "no_policy_groups", "stripped": [], "mode": "noop"}

    mode = "ENFORCE" if ENFORCE else "DRY-RUN"

    if not ENFORCE:
        logger.warning(
            "[DRY-RUN] ZOU quarantainen: %s (%s) uit %s -> deny-by-default. "
            "Geen NetBird-/Redis-schrijfactie.", attribution or peer_name, peer_ip, strip_names)
        return {"ok": True, "action": "quarantine", "peer_ip": peer_ip,
                "peer_name": peer_name, "reason": "dry_run", "stripped": strip_names, "mode": mode}

    # --- ENFORCE: schrijfacties ---
    await _redis.set(f"quarantine:original_groups:{peer_id}",
                     json.dumps([g["id"] for g in strip]), ex=86400)

    for g in strip:
        gid = g["id"]
        try:
            full = await _get(f"/groups/{gid}")
            remaining = [pid for pid in _peer_ids(full) if pid != peer_id]
            await _put(f"/groups/{gid}", {"name": full["name"], "peers": remaining})
            logger.info("peer %s verwijderd uit groep %s", peer_name, full["name"])
        except Exception as e:
            logger.error("fout bij verwijderen uit groep %s: %s", gid, e)

    await _add_to_quarantine_group(peer_id)

    logger.warning("QUARANTAINE: %s (%s) uit %s -- deny-by-default actief",
                   attribution or peer_name, peer_ip, strip_names)
    return {"ok": True, "action": "quarantine", "peer_ip": peer_ip,
            "peer_name": peer_name, "reason": "enforced", "stripped": strip_names, "mode": mode}


async def unquarantine_peer(peer_ip: str) -> dict:
    """Herstel peer naar de originele groepen uit Redis (enforce-only)."""
    if not ENFORCE:
        logger.warning("[DRY-RUN] unquarantine %s genegeerd (geen schrijfactie)", peer_ip)
        return {"ok": True, "action": "unquarantine", "peer_ip": peer_ip, "reason": "dry_run"}

    peer = await _resolve_with_retry(peer_ip)
    if not peer:
        logger.critical("unquarantine: peer %s niet resolvebaar", peer_ip)
        return {"ok": False, "action": "unquarantine", "peer_ip": peer_ip, "reason": "peer_unresolved"}

    peer_id = peer["id"]
    peer_name = peer.get("name", "unknown")
    stored = await _redis.get(f"quarantine:original_groups:{peer_id}")
    if not stored:
        logger.error("geen restore-data voor %s -- handmatige restore nodig", peer_id)
        return {"ok": False, "action": "unquarantine", "peer_ip": peer_ip, "reason": "no_restore_data"}

    for gid in json.loads(stored):
        try:
            full = await _get(f"/groups/{gid}")
            members = _peer_ids(full)
            if peer_id not in members:
                members.append(peer_id)
                await _put(f"/groups/{gid}", {"name": full["name"], "peers": members})
                logger.info("peer %s hersteld naar groep %s", peer_name, full["name"])
        except Exception as e:
            logger.error("fout bij herstellen naar groep %s: %s", gid, e)

    await _remove_from_quarantine_group(peer_id)
    await _redis.delete(f"quarantine:original_groups:{peer_id}")
    logger.warning("UNQUARANTINE: %s (%s) hersteld", peer_name, peer_ip)
    return {"ok": True, "action": "unquarantine", "peer_ip": peer_ip, "reason": "restored"}
