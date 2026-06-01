"""In-memory identiteit-map: overlay-IP -> {user, name, groups, os, personas}.

Decision 1 (optie A): de daemon abonneert op identity.> en houdt deze map vers
uit de bridge-events (peer.connected / peer.disconnected / identity.multi_persona).
Bootstrap eenmalig via NetBird /api/peers bij opstart (cold-start gat dichten voor
peers wiens connect-event uit de retentie viel).

BELANGRIJK: deze map is voor attributie in de log/demo ("we weten wie dit is").
De quarantaine-ACTIE resolveert het IP autoritatief live tegen NetBird /api/peers
(actions/netbird.py). Een stale/ontbrekende map-entry beschadigt de actie dus niet.
"""
import logging

logger = logging.getLogger("control-daemon.identity")


class IdentityMap:
    def __init__(self) -> None:
        self._m: dict[str, dict] = {}

    def bootstrap(self, peers: list[dict]) -> None:
        """Vul de map uit een NetBird /api/peers-respons (alleen connected peers).

        Fallback-laag: identity.>-events (DeliverPolicy.ALL) overschrijven dit met de
        rijkere data (email i.p.v. user_id) zodra ze binnenkomen.
        """
        n = 0
        for p in peers:
            if not p.get("connected"):
                continue
            ip = str(p.get("ip", "")).split("/")[0]
            if not ip:
                continue
            self._m[ip] = {
                "user": p.get("user_id"),   # email pas via identity.>-events
                "name": p.get("name"),
                "groups": [g.get("name") for g in p.get("groups", []) if g.get("name")],
                "os": p.get("os"),
                "personas": [],
            }
            n += 1
        logger.info("identity-map bootstrap: %d connected peers", n)

    def apply_event(self, evt: dict) -> None:
        """Verwerk een identity.>-event van de bridge."""
        et = evt.get("event_type", "")
        ip = evt.get("ip")
        if not ip:
            return
        if et == "peer.connected":
            self._m[ip] = {
                "user": evt.get("user"),
                "name": evt.get("name"),
                "groups": evt.get("groups", []),
                "os": evt.get("os"),
                "personas": self._m.get(ip, {}).get("personas", []),
            }
        elif et == "peer.disconnected":
            self._m.pop(ip, None)
        elif et in ("identity.multi_persona", "multi_persona"):
            if ip in self._m:
                self._m[ip]["personas"] = evt.get("personas", [])
        # bridge.degraded / health: genegeerd

    def get(self, ip: str) -> dict | None:
        return self._m.get(ip)

    def describe(self, ip: str) -> str:
        e = self._m.get(ip)
        if not e:
            return f"{ip} (unattributed)"
        who = e.get("user") or e.get("name") or "?"
        groups = ",".join(g for g in e.get("groups", []) if g) or "-"
        return f"{ip} -> {who} [{groups}]"
