"""
Identiteits-resolver: overlay-IP -> {user, name, persona, groups}.

Bron: de bestaande identity-bridge op :8088, endpoint GET /lookup?ip=<ip>.
We weten zeker dat dit endpoint bestaat (recon D: 422 'ip field required').
De exacte JSON-veldnamen kennen we nog niet 100% -> daarom DEFENSIEF: we proberen
meerdere gangbare sleutels en loggen de ruwe respons 1x zodat we kunnen finetunen.

Read-only HTTP GET. Cache met korte TTL (= de eigen refresh-interval van de bridge).
Faalt nooit hard: bij error/onbekend valt het terug op het IP zelf.
"""
import logging
import time
from typing import Any, Optional

import httpx

from app import config

log = logging.getLogger("soc.identity")

# Kandidaat-veldnamen (defensief; we finetunen na de eerste echte lookup).
_USER_KEYS = ("user", "email", "upn", "user_id", "username", "userId")
_NAME_KEYS = ("name", "peer_name", "hostname", "peer", "host")
_PERSONA_KEYS = ("persona", "personas")
_GROUP_KEYS = ("groups", "group")
_PEERID_KEYS = ("peer_id", "id", "peerId")


def _first(d: dict, keys) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return None


def _as_persona(raw_persona, raw_groups) -> Optional[str]:
    """Persona is bij voorkeur de expliciete persona; anders de policy-groep."""
    def pick(val):
        if isinstance(val, list):
            # eerste persona-groep die een policy-groep is, anders de eerste
            for g in val:
                gn = g.get("name") if isinstance(g, dict) else g
                if gn in config.NETBIRD_POLICY_GROUPS:
                    return gn
            if val:
                g0 = val[0]
                return g0.get("name") if isinstance(g0, dict) else g0
            return None
        return val
    return pick(raw_persona) or pick(raw_groups)


class IdentityResolver:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, dict]] = {}
        self._client: Optional[httpx.AsyncClient] = None
        self._logged_shape = False

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=4.0)

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()

    async def health(self) -> dict:
        try:
            r = await self._client.get(f"{config.IDENTITY_BRIDGE_URL}/health")
            return {"ok": r.status_code == 200, "body": r.json()}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    async def resolve(self, ip: Optional[str]) -> dict:
        """Geef {ip, user, name, persona, groups, peer_id, display} terug."""
        if not ip:
            return self._blank(ip)
        now = time.time()
        hit = self._cache.get(ip)
        if hit and (now - hit[0]) < config.IDENTITY_CACHE_TTL:
            return hit[1]

        rec = self._blank(ip)
        try:
            r = await self._client.get(
                f"{config.IDENTITY_BRIDGE_URL}/lookup", params={"ip": ip}
            )
            if r.status_code == 200:
                data = r.json()
                if not self._logged_shape:
                    log.info("identity-bridge /lookup vorm (1x): %s", data)
                    self._logged_shape = True
                # de respons kan {..} of {"result": {..}} / {"identity": {..}} zijn
                body = data
                if isinstance(data, dict):
                    for wrap in ("result", "identity", "peer", "data"):
                        if isinstance(data.get(wrap), dict):
                            body = data[wrap]
                            break
                if isinstance(body, dict):
                    groups = _first(body, _GROUP_KEYS)
                    personas = _first(body, _PERSONA_KEYS)
                    rec = {
                        "ip": ip,
                        "user": _first(body, _USER_KEYS),
                        "name": _first(body, _NAME_KEYS),
                        "persona": _as_persona(personas, groups),
                        "groups": groups,
                        "peer_id": _first(body, _PEERID_KEYS),
                    }
            # 404 = onbekend IP -> blijft blank (kort cachen om hammeren te vermijden)
        except Exception as e:  # noqa: BLE001
            log.debug("lookup faalde voor %s: %s", ip, e)

        rec["display"] = self._display(rec)
        self._cache[ip] = (now, rec)
        return rec

    def _blank(self, ip: Optional[str]) -> dict:
        return {"ip": ip, "user": None, "name": None, "persona": None,
                "groups": None, "peer_id": None, "display": ip or "?"}

    @staticmethod
    def _display(rec: dict) -> str:
        """Naam-boven-IP: 'Docent_1 · Docenten' > naam > user > IP."""
        user = rec.get("user")
        name = rec.get("name")
        persona = rec.get("persona")
        label = None
        if user:
            # toon korte vorm vóór de @ als het een email is
            label = user.split("@")[0] if isinstance(user, str) and "@" in user else user
        elif name:
            label = name
        if label and persona:
            return f"{label} · {persona}"
        return label or rec.get("ip") or "?"

    def peer_id_index(self) -> dict[str, str]:
        """peer_id -> display, opgebouwd uit de cache (voor quarantaine-join)."""
        out = {}
        for _, rec in self._cache.values():
            if rec.get("peer_id"):
                out[rec["peer_id"]] = rec.get("display", rec.get("ip"))
        return out
