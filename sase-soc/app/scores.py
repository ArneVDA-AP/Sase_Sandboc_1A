"""
Read-only toegang tot de Redis-store van de control-daemon.

WE SCHRIJVEN NOOIT. Alleen scan/zrange/get/exists.

Score-schema (Verslag 35 + scoring.py):
  key   = threat:<overlay_ip>         (ZSET)
  member= "<ts>|<nonce>|<event_type>" met score = epoch
  huidige score = som van SCORE_WEIGHTS[event_type] over members binnen SCORE_WINDOW
Quarantaine-state (netbird.py):
  key   = quarantine:original_groups:<peer_id>   (string; bestaat = peer in quarantaine)
"""
import logging
import time
from typing import Optional

import redis.asyncio as redis

from app import config

log = logging.getLogger("soc.scores")


class ScoreReader:
    def __init__(self) -> None:
        self._r: Optional[redis.Redis] = None

    async def start(self) -> None:
        # decode_responses=True -> strings i.p.v. bytes (zoals de daemon)
        self._r = redis.from_url(config.REDIS_URL, decode_responses=True)

    async def stop(self) -> None:
        if self._r:
            await self._r.aclose()

    async def ping(self) -> bool:
        try:
            return await self._r.ping()
        except Exception:  # noqa: BLE001
            return False

    async def current_scores(self) -> list[dict]:
        """Lijst van {ip, score, breakdown:{event_type:count}} voor actieve peers."""
        out: list[dict] = []
        now = time.time()
        try:
            async for key in self._r.scan_iter(match="threat:*", count=100):
                ip = key.split("threat:", 1)[1]
                # alleen members binnen het venster (read-only; we decayen niet)
                members = await self._r.zrangebyscore(
                    key, min=now - config.SCORE_WINDOW, max="+inf"
                )
                score = 0
                breakdown: dict[str, int] = {}
                for m in members:
                    parts = m.split("|")
                    etype = parts[2] if len(parts) >= 3 else (parts[-1] if parts else "")
                    score += config.SCORE_WEIGHTS.get(etype, 0)
                    breakdown[etype] = breakdown.get(etype, 0) + 1
                if score > 0 or members:
                    out.append({
                        "ip": ip,
                        "score": score,
                        "breakdown": breakdown,
                        "over_threshold": score >= config.SCORE_QUARANTINE,
                    })
        except Exception as e:  # noqa: BLE001
            log.warning("current_scores faalde: %s", e)
        return out

    async def active_quarantines(self) -> list[str]:
        """peer_id's die nu in quarantaine zitten (ENFORCE-modus)."""
        out: list[str] = []
        try:
            prefix = "quarantine:original_groups:"
            async for key in self._r.scan_iter(match=f"{prefix}*", count=100):
                out.append(key.split(prefix, 1)[1])
        except Exception as e:  # noqa: BLE001
            log.warning("active_quarantines faalde: %s", e)
        return out
