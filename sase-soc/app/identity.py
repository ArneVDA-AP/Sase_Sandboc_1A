"""
Identiteitsresolver: overlay-IP -> {user, name, persona, groups}.

Bron: identity-bridge /lookup?ip=<ip> met header X-Bridge-Secret.
Exacte responsstructuur (uit identity-bridge/app/main.py):
  {"status":"OK","user":"email@domain","groups":["Docenten","Core-Services"],"os":"linux"}

Persona = de eerste groep uit de config NETBIRD_POLICY_GROUPS die in de groepen zit.
"""
import logging
import time
from typing import Optional

import httpx

from app import config

log = logging.getLogger("soc.identity")


class IdentityResolver:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, dict]] = {}
        self._client: Optional[httpx.AsyncClient] = None
        self._logged_shape = False

    async def start(self) -> None:
        headers = {}
        if config.IDENTITY_BRIDGE_SECRET:
            headers["X-Bridge-Secret"] = config.IDENTITY_BRIDGE_SECRET
        else:
            log.warning("IDENTITY_BRIDGE_SECRET niet ingesteld — /lookup geeft 401")
        self._client = httpx.AsyncClient(
            timeout=4.0,
            headers=headers,
        )

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
        """Geeft {ip, user, name, persona, groups, display} terug."""
        if not ip:
            return self._blank(ip)
        now = time.time()
        hit = self._cache.get(ip)
        if hit and (now - hit[0]) < config.IDENTITY_CACHE_TTL:
            return hit[1]

        rec = self._blank(ip)
        if not config.IDENTITY_BRIDGE_SECRET:
            # Geen secret → sla lookup over, cache kort
            self._cache[ip] = (now, rec)
            return rec

        try:
            r = await self._client.get(
                f"{config.IDENTITY_BRIDGE_URL}/lookup",
                params={"ip": ip},
            )
            if r.status_code == 200:
                data = r.json()
                if not self._logged_shape:
                    log.info("identity-bridge /lookup (1x): %s", data)
                    self._logged_shape = True
                if data.get("status") == "OK":
                    groups = data.get("groups") or []   # list van strings
                    persona = self._pick_persona(groups)
                    user = data.get("user") or ip
                    rec = {
                        "ip":      ip,
                        "user":    user,
                        "name":    data.get("name"),
                        "os":      data.get("os"),
                        "groups":  groups,
                        "persona": persona,
                        "peer_id": None,
                    }
            elif r.status_code == 401:
                log.warning("identity-bridge 401 voor %s — X-Bridge-Secret fout?", ip)
        except Exception as e:  # noqa: BLE001
            log.debug("lookup fout voor %s: %s", ip, e)

        rec["display"] = self._display(rec)
        self._cache[ip] = (now, rec)
        return rec

    @staticmethod
    def _pick_persona(groups: list) -> Optional[str]:
        """Eerste persona-groep (Studenten/Docenten/Admins) die in de groepen zit."""
        policy_set = set(config.NETBIRD_POLICY_GROUPS)
        for g in groups:
            name = g.get("name") if isinstance(g, dict) else g
            if name in policy_set:
                return name
        return None

    @staticmethod
    def _display(rec: dict) -> str:
        """Naam-boven-IP: 'Docent_1 · Docenten' > user > IP."""
        user    = rec.get("user")
        persona = rec.get("persona")
        if user and "@" in str(user):
            label = user.split("@")[0]
        elif user:
            label = str(user)
        else:
            label = rec.get("name")
        if label and persona:
            return f"{label} · {persona}"
        return label or rec.get("ip") or "?"

    def _blank(self, ip: Optional[str]) -> dict:
        return {"ip": ip, "user": None, "name": None, "os": None,
                "groups": None, "persona": None, "peer_id": None,
                "display": ip or "?"}

    def peer_id_index(self) -> dict[str, str]:
        return {rec.get("peer_id"): rec.get("display", rec.get("ip"))
                for _, rec in self._cache.values() if rec.get("peer_id")}
