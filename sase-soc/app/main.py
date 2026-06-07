"""
SOC-dashboard backend — FastAPI + uvicorn.
Read-only observer; schrijft nooit naar NATS, Redis of NetBird.
"""
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import config
from app.bus import Bus
from app.identity import IdentityResolver
from app.normalize import normalize
from app.scores import ScoreReader
from app.store import Store
from app.ws import WSManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("soc.main")

# singletons
identity = IdentityResolver()
store = Store()
scores = ScoreReader()
bus = Bus()
ws_mgr = WSManager()

# score-poller: bijhouden van vorige staat om drempeloverschrijdingen te detecteren
_prev_scores: dict[str, int] = {}
_prev_quarantines: set[str] = set()


async def _on_event(subject: str, raw: bytes) -> None:
    """Verwerkt elk inkomend bus-bericht: normaliseer, resolve, opslaan, broadcasten."""
    ev = normalize(subject, raw)

    # Identiteits-resolutie voor peer-events (overlay-IP -> naam/persona)
    if ev["actor_type"] == "peer" and ev.get("actor_ip"):
        rec = await identity.resolve(ev["actor_ip"])
        ev["actor_user"] = ev.get("actor_user") or rec.get("user")
        ev["actor_persona"] = rec.get("persona")
        ev["actor_display"] = rec.get("display")
    elif ev["actor_type"] == "user":
        ev["actor_display"] = ev.get("actor_user") or "?"

    await store.insert_event(ev)
    await ws_mgr.broadcast("event", _ev_wire(ev))


def _ev_wire(ev: dict) -> dict:
    """Lichte subset voor de wire (niet de volledige raw blob tenzij gevraagd)."""
    return {k: ev.get(k) for k in (
        "ts_epoch", "subject", "category", "producer",
        "actor_type", "actor_ip", "actor_user", "actor_persona", "actor_display",
        "severity", "summary", "scored", "weight", "notable",
    )}


async def _score_poller() -> None:
    """Poll Redis threat:* elke SCORE_POLL_INTERVAL seconden.
    Detecteert drempeloverschrijdingen en quarantainewijzigingen -> timeline + WS."""
    global _prev_scores, _prev_quarantines
    while True:
        await asyncio.sleep(config.SCORE_POLL_INTERVAL)
        try:
            peer_scores = await scores.current_scores()
            # resolve identiteit per IP
            resolved = []
            for s in peer_scores:
                rec = await identity.resolve(s["ip"])
                s["actor_user"] = rec.get("user")
                s["actor_persona"] = rec.get("persona")
                s["actor_display"] = rec.get("display")
                resolved.append(s)

            await ws_mgr.broadcast("scores", resolved)

            # Drempeloverschrijding detectie
            for s in resolved:
                ip, score = s["ip"], s["score"]
                was = _prev_scores.get(ip, 0)
                if score >= config.SCORE_QUARANTINE and was < config.SCORE_QUARANTINE:
                    item = {
                        "kind": "threshold_crossed",
                        "actor_ip": ip,
                        "actor_display": s.get("actor_display"),
                        "score": score,
                        "detail": f"score {score}>={config.SCORE_QUARANTINE}; breakdown={s['breakdown']}",
                        "raw": s,
                    }
                    await store.insert_timeline(item)
                    await ws_mgr.broadcast("timeline", item)
                    log.warning("DREMPEL OVERSCHREDEN: %s score=%d", s.get("actor_display"), score)
                _prev_scores[ip] = score
            # verwijder IPs die niet meer actief zijn uit de prev-map
            active_ips = {s["ip"] for s in resolved}
            _prev_scores = {ip: v for ip, v in _prev_scores.items() if ip in active_ips}

            # Quarantaine-wijziging detectie (ENFORCE-modus; DRY-RUN: geen keys)
            active_q = set(await scores.active_quarantines())
            peerid_map = identity.peer_id_index()
            for pid in active_q - _prev_quarantines:
                item = {"kind": "quarantine_active", "actor_id": pid,
                        "actor_display": peerid_map.get(pid, pid), "raw": {}}
                await store.insert_timeline(item)
                await ws_mgr.broadcast("timeline", item)
            for pid in _prev_quarantines - active_q:
                item = {"kind": "quarantine_cleared", "actor_id": pid,
                        "actor_display": peerid_map.get(pid, pid), "raw": {}}
                await store.insert_timeline(item)
                await ws_mgr.broadcast("timeline", item)
            _prev_quarantines = active_q
        except Exception as exc:  # noqa: BLE001
            log.warning("score-poller fout: %s", exc)


async def _prune_task() -> None:
    while True:
        await asyncio.sleep(config.PRUNE_INTERVAL_SEC)
        await store.prune()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    log.info("=== SOC-dashboard start (Fase 1) ===")
    await store.start()
    await scores.start()
    await identity.start()
    ib_health = await identity.health()
    log.info("identity-bridge: %s", ib_health)
    await bus.start(on_event=_on_event)
    asyncio.create_task(_score_poller(), name="score-poller")
    asyncio.create_task(_prune_task(), name="prune")
    log.info("=== alle subsystemen gestart ===")
    yield
    log.info("=== SOC-dashboard afsluiten ===")
    await bus.stop()
    await scores.stop()
    await identity.stop()
    await store.stop()


app = FastAPI(title="SASE SOC Dashboard", lifespan=_lifespan)

# ── statische bestanden ──
_WEB = Path(__file__).parent.parent / "web"
if _WEB.exists():
    app.mount("/static", StaticFiles(directory=str(_WEB)), name="static")


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(str(_WEB / "index.html"))


# ── REST endpoints ──

@app.get("/health")
async def health():
    redis_ok = await scores.ping()
    ib = await identity.health()
    db_counts = await store.counts()
    return {
        "status": "ok" if (bus.connected and redis_ok) else "degraded",
        "nats": {"connected": bus.connected},
        "redis": {"ok": redis_ok},
        "identity_bridge": ib,
        "ws_clients": ws_mgr.count,
        "db": db_counts,
        "config": {
            "score_window": config.SCORE_WINDOW,
            "score_quarantine": config.SCORE_QUARANTINE,
            "score_weights": config.SCORE_WEIGHTS,
            "retention_days": config.RETENTION_DAYS,
        },
    }


@app.get("/api/events")
async def api_events(
    since: Optional[float] = Query(None),
    category: Optional[str] = Query(None),
    producer: Optional[str] = Query(None),
    persona: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    rows = await store.query_events(since=since, category=category, producer=producer,
                                    persona=persona, user=user, q=q, limit=limit)
    return {"events": rows, "count": len(rows)}


@app.get("/api/scores")
async def api_scores():
    peer_scores = await scores.current_scores()
    resolved = []
    for s in peer_scores:
        rec = await identity.resolve(s["ip"])
        s.update({"actor_user": rec.get("user"), "actor_persona": rec.get("persona"),
                   "actor_display": rec.get("display")})
        resolved.append(s)
    quarantines = await scores.active_quarantines()
    return {"scores": resolved, "active_quarantines": quarantines,
            "threshold": config.SCORE_QUARANTINE}


@app.get("/api/timeline")
async def api_timeline(
    since: Optional[float] = Query(None),
    kind: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    rows = await store.query_timeline(since=since, kind=kind, limit=limit)
    return {"timeline": rows, "count": len(rows)}


@app.get("/api/peers")
async def api_peers():
    """Alle bekende peers uit de identity-resolver cache."""
    cache = {}
    for ip, (_, rec) in identity._cache.items():
        cache[ip] = rec
    return {"peers": cache, "count": len(cache)}


# ── WebSocket ──

@app.websocket("/ws")
async def websocket(ws: WebSocket):
    await ws_mgr.connect(ws)
    try:
        # snapshot on connect: recente events + huidige scores
        rows = await store.query_events(
            since=time.time() - 300,  # laatste 5 min
            limit=50,
        )
        await ws.send_json({"type": "snapshot_events",
                            "data": [_ev_wire(r) for r in rows]})
        peer_scores = await scores.current_scores()
        await ws.send_json({"type": "scores", "data": peer_scores})
        # blijf verbonden tot de client weg is
        while True:
            await ws.receive_text()  # ping/pong of browser keepalive
    except WebSocketDisconnect:
        pass
    finally:
        await ws_mgr.disconnect(ws)
