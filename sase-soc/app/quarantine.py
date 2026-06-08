"""
Handmatige quarantaine/herstel via de NetBird API.
Repliceert de exacte logica van control-daemon (Verslag 35, netbird.py):
  - strip peer uit persona-groepen (Studenten/Docenten/Admins)
  - voeg toe aan Quarantine-groep
  - schrijf quarantine:original_groups:{peer_id} in Redis
zodat de daemon de staat correct herkent en kan herstellen.

Break-glass accounts worden geblokkeerd.
Alle acties worden gelogd via de store + WS broadcast.
"""
import json
import logging
from typing import Optional

import httpx
import redis.asyncio as aioredis

from app import config

log = logging.getLogger("soc.quarantine")


def _netbird_client() -> httpx.AsyncClient:
    import os
    ca = config.NETBIRD_CA_CERT
    verify = ca if (ca and os.path.exists(ca)) else False
    if not verify:
        log.warning("CA cert niet gevonden op %s — TLS-verificatie uitgeschakeld", ca)
    return httpx.AsyncClient(
        base_url=config.NETBIRD_API_URL,
        headers={"Authorization": f"Token {config.NETBIRD_API_TOKEN}",
                 "Content-Type": "application/json"},
        verify=verify,
        timeout=10.0,
    )


async def _find_peer(client: httpx.AsyncClient, overlay_ip: str) -> Optional[dict]:
    r = await client.get("/api/peers")
    r.raise_for_status()
    clean = overlay_ip.split("/")[0]
    for p in r.json():
        if str(p.get("ip", "")).split("/")[0] == clean:
            return p
    return None


async def _peer_ids_in_group(client: httpx.AsyncClient, group_id: str) -> list[str]:
    r = await client.get(f"/api/groups/{group_id}")
    r.raise_for_status()
    return [p["id"] for p in (r.json().get("peers") or [])]


async def _set_group_peers(client: httpx.AsyncClient, group_id: str, peer_ids: list[str]):
    r = await client.put(f"/api/groups/{group_id}", json={"peers": peer_ids})
    r.raise_for_status()


async def get_all_peers() -> list[dict]:
    """Alle ingeschreven NetBird peers ophalen voor de peer-tabel in de UI."""
    try:
        async with _netbird_client() as client:
            r = await client.get("/api/peers")
            r.raise_for_status()
            return r.json()
    except Exception as e:  # noqa: BLE001
        log.warning("get_all_peers faalde: %s", e)
        return []


async def quarantine_peer(overlay_ip: str) -> dict:
    """
    Strip peer uit persona-groepen → Quarantine-groep → Redis-sleutel schrijven.
    Exact zelfde patroon als daemon zodat de daemon de staat herkent.
    """
    if not config.NETBIRD_API_TOKEN:
        return {"ok": False, "reason": "NETBIRD_API_TOKEN niet geconfigureerd in .env"}

    try:
        async with _netbird_client() as client:
            peer = await _find_peer(client, overlay_ip)
            if not peer:
                return {"ok": False, "reason": f"peer {overlay_ip} niet gevonden in NetBird"}

            peer_id   = peer["id"]
            peer_name = peer.get("name", "unknown")

            # Break-glass blokkering
            for bg in config.NETBIRD_BREAK_GLASS:
                if bg.lower() in peer_name.lower():
                    return {"ok": False,
                            "reason": f"break-glass account '{peer_name}' kan niet in quarantaine"}

            # Bepaal welke persona-groepen de peer heeft
            policy_set    = set(config.NETBIRD_POLICY_GROUPS)
            current_groups = peer.get("groups") or []
            strip = [g for g in current_groups if g.get("name") in policy_set]

            if not strip:
                return {"ok": False,
                        "reason": f"{peer_name} heeft geen persona-groepen — al in quarantaine?"}

            # Strip uit elke persona-groep
            for g in strip:
                ids = await _peer_ids_in_group(client, g["id"])
                await _set_group_peers(client, g["id"],
                                        [pid for pid in ids if pid != peer_id])
                log.info("Verwijderd uit groep %s: %s", g["name"], peer_name)

            # Voeg toe aan Quarantine-groep
            q_ids = await _peer_ids_in_group(client, config.NETBIRD_QUARANTINE_GROUP_ID)
            if peer_id not in q_ids:
                await _set_group_peers(client, config.NETBIRD_QUARANTINE_GROUP_ID,
                                        q_ids + [peer_id])

            # Schrijf restore-data in Redis (zelfde sleutel als daemon)
            r_client = aioredis.from_url(config.REDIS_URL, decode_responses=True)
            async with r_client:
                await r_client.set(
                    f"quarantine:original_groups:{peer_id}",
                    json.dumps([{"id": g["id"], "name": g["name"]} for g in strip])
                )

            stripped = [g["name"] for g in strip]
            log.warning("MANUELE QUARANTAINE: %s (%s) uit %s → deny-by-default",
                        peer_name, overlay_ip, stripped)
            return {"ok": True, "peer_name": peer_name, "peer_id": peer_id,
                    "stripped": stripped}

    except Exception as e:  # noqa: BLE001
        log.error("quarantine_peer fout: %s", e)
        return {"ok": False, "reason": str(e)}


async def unquarantine_peer(overlay_ip: str) -> dict:
    """Herstel peer: originele groepen uit Redis → NetBird → Redis-sleutel verwijderen."""
    if not config.NETBIRD_API_TOKEN:
        return {"ok": False, "reason": "NETBIRD_API_TOKEN niet geconfigureerd in .env"}

    try:
        async with _netbird_client() as client:
            peer = await _find_peer(client, overlay_ip)
            if not peer:
                return {"ok": False, "reason": f"peer {overlay_ip} niet gevonden"}

            peer_id   = peer["id"]
            peer_name = peer.get("name", "unknown")

            # Hersteldata ophalen uit Redis
            r_client = aioredis.from_url(config.REDIS_URL, decode_responses=True)
            async with r_client:
                stored = await r_client.get(f"quarantine:original_groups:{peer_id}")

            if not stored:
                return {"ok": False,
                        "reason": "geen hersteldata in Redis — peer niet via daemon/dashboard in quarantaine gezet"}

            original = json.loads(stored)

            # Herstel in elke originele groep
            for g in original:
                ids = await _peer_ids_in_group(client, g["id"])
                if peer_id not in ids:
                    await _set_group_peers(client, g["id"], ids + [peer_id])
                log.info("Hersteld in groep %s: %s", g["name"], peer_name)

            # Verwijder uit Quarantine-groep
            q_ids = await _peer_ids_in_group(client, config.NETBIRD_QUARANTINE_GROUP_ID)
            await _set_group_peers(client, config.NETBIRD_QUARANTINE_GROUP_ID,
                                    [pid for pid in q_ids if pid != peer_id])

            # Verwijder Redis-sleutel
            async with r_client:
                await r_client.delete(f"quarantine:original_groups:{peer_id}")

            restored = [g["name"] for g in original]
            log.warning("MANUEEL HERSTEL: %s (%s) hersteld in %s",
                        peer_name, overlay_ip, restored)
            return {"ok": True, "peer_name": peer_name, "peer_id": peer_id,
                    "restored": restored}

    except Exception as e:  # noqa: BLE001
        log.error("unquarantine_peer fout: %s", e)
        return {"ok": False, "reason": str(e)}
