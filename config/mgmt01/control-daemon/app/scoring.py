"""Per-peer threat score met sliding-window decay (Redis sorted set).

Sleutel: threat:<client_ip>  (ZSET, member = "<ts>|<nonce>|<event_type>", score = ts)
Huidige score = som van SCORE_WEIGHTS over alle members binnen het venster.
Decay is impliciet: oude members vallen uit het venster via ZREMRANGEBYSCORE.
Auditabel: ZRANGE toont exact welke events de score dragen ("3 hits in 5 min").

ids-events worden hier NOOIT toegevoegd (niet in SCORE_WEIGHTS); add_event op een
ongewogen type is een no-op-guard.
"""
import logging
import time
import uuid

import redis.asyncio as redis

from app.config import REDIS_URL, SCORE_QUARANTINE, SCORE_WEIGHTS, SCORE_WINDOW

logger = logging.getLogger("control-daemon.scoring")


def _sum_weights(members: list[str]) -> int:
    total = 0
    for m in members:
        parts = m.split("|")
        if len(parts) == 3:
            total += SCORE_WEIGHTS.get(parts[2], 0)
    return total


class ThreatScorer:
    def __init__(self) -> None:
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)

    async def add_event(self, client_ip: str, event_type: str) -> dict:
        """Voeg een gewogen event toe; retourneer huidige venster-score + quarantaine-vlag."""
        weight = SCORE_WEIGHTS.get(event_type)
        if weight is None:
            # Niet-gewogen type (bv. ids) -> niet scoren. Defensieve guard.
            return {"score": await self.current_score(client_ip), "quarantine": False, "weight": 0}

        now = time.time()
        key = f"threat:{client_ip}"
        member = f"{now:.3f}|{uuid.uuid4().hex[:8]}|{event_type}"

        pipe = self.redis.pipeline()
        pipe.zadd(key, {member: now})
        pipe.zremrangebyscore(key, 0, now - SCORE_WINDOW)   # decay: drop verlopen events
        pipe.expire(key, SCORE_WINDOW * 2)                  # opruimen lege keys
        pipe.zrange(key, 0, -1)
        results = await pipe.execute()

        members = results[-1]
        score = _sum_weights(members)
        quarantine = score >= SCORE_QUARANTINE

        logger.info(
            "score %s += %d (%s) = %d/%d%s",
            client_ip, weight, event_type, score, SCORE_QUARANTINE,
            "  >> DREMPEL OVERSCHREDEN" if quarantine else "",
        )
        return {"score": score, "quarantine": quarantine, "weight": weight}

    async def current_score(self, client_ip: str) -> int:
        now = time.time()
        key = f"threat:{client_ip}"
        await self.redis.zremrangebyscore(key, 0, now - SCORE_WINDOW)
        members = await self.redis.zrange(key, 0, -1)
        return _sum_weights(members)

    async def reset(self, client_ip: str) -> None:
        await self.redis.delete(f"threat:{client_ip}")
