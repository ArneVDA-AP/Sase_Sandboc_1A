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

identity = IdentityResolver()
store    = Store()
scores   = ScoreReader()
bus      = Bus()
ws_mgr   = WSManager()

_prev_scores: dict[str, int] = {}
_prev_quarantines: set[str] = set()


async def _on_event(subject: str, raw: bytes, is_replay: bool = False) -> None:
    ev = normalize(subject, raw)

    if ev["actor_type"] == "peer" and ev.get("actor_ip"):
        rec = await identity.resolve(ev["actor_ip"])
        ev["actor_user"]    = ev.get("actor_user") or rec.get("user")
        ev["actor_persona"] = rec.get("persona")
        ev["actor_display"] = rec.get("display")
    elif ev["actor_type"] == "user":
        ev["actor_display"] = ev.get("actor_user") or "?"

    await store.insert_event(ev)

    # Tijdens replay: alleen opslaan, NIET broadcasten (voorkomt WS-flood)
    if not is_replay:
        await ws_mgr.broadcast("event", _ev_wire(ev))


async def _on_replay_done() -> None:
    """Zodra replay klaar is: stuur een GEBALANCEERDE snapshot (laatste N per
    categorie) zodat álle categorieën zichtbaar zijn, niet alleen proxy."""
    log.info("Replay compleet — gebalanceerde snapshot pushen naar browsers")
    rows = await store.query_events_balanced()
    await ws_mgr.broadcast("snapshot_events", [_ev_wire(r) for r in rows])
    await ws_mgr.broadcast("replay_done", {"count": len(rows)})


def _ev_wire(ev: dict) -> dict:
    return {k: ev.get(k) for k in (
        "ts_epoch", "ts_ingest", "subject", "category", "producer",
        "actor_type", "actor_ip", "actor_user", "actor_persona", "actor_display",
        "severity", "summary", "scored", "weight", "notable",
    )}


async def _score_poller() -> None:
    global _prev_scores, _prev_quarantines
    while True:
        await asyncio.sleep(config.SCORE_POLL_INTERVAL)
        try:
            peer_scores = await scores.current_scores()
            resolved = []
            for s in peer_scores:
                rec = await identity.resolve(s["ip"])
                s["actor_user"]    = rec.get("user")
                s["actor_persona"] = rec.get("persona")
                s["actor_display"] = rec.get("display")
                resolved.append(s)

            quarantines = set(await scores.active_quarantines())
            await ws_mgr.broadcast("scores", {
                "peers": resolved,
                "active_quarantines": list(quarantines),
                "threshold": config.SCORE_QUARANTINE,
                "mode": "ENFORCE" if quarantines else "DRY-RUN",
            })

            for s in resolved:
                ip, score = s["ip"], s["score"]
                was = _prev_scores.get(ip, 0)
                if score >= config.SCORE_QUARANTINE and was < config.SCORE_QUARANTINE:
                    item = {"kind": "threshold_crossed", "actor_ip": ip,
                            "actor_display": s.get("actor_display"),
                            "score": score,
                            "detail": f"score {score}>={config.SCORE_QUARANTINE} | {s['breakdown']}",
                            "raw": s}
                    await store.insert_timeline(item)
                    await ws_mgr.broadcast("timeline", item)
                _prev_scores[ip] = score

            active_ips = {s["ip"] for s in resolved}
            _prev_scores = {ip: v for ip, v in _prev_scores.items() if ip in active_ips}

            peerid_map = identity.peer_id_index()
            for pid in quarantines - _prev_quarantines:
                item = {"kind": "quarantine_active", "actor_id": pid,
                        "actor_display": peerid_map.get(pid, pid), "raw": {}}
                await store.insert_timeline(item)
                await ws_mgr.broadcast("timeline", item)
            for pid in _prev_quarantines - quarantines:
                item = {"kind": "quarantine_cleared", "actor_id": pid,
                        "actor_display": peerid_map.get(pid, pid), "raw": {}}
                await store.insert_timeline(item)
                await ws_mgr.broadcast("timeline", item)
            _prev_quarantines = quarantines
        except Exception as exc:  # noqa: BLE001
            log.warning("score-poller fout: %s", exc)


async def _prune_task() -> None:
    while True:
        await asyncio.sleep(config.PRUNE_INTERVAL_SEC)
        await store.prune()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    log.info("=== SOC-dashboard start ===")
    await store.start()
    await scores.start()
    await identity.start()
    ib = await identity.health()
    log.info("identity-bridge: %s", ib)
    await bus.start(on_event=_on_event, on_replay_done=_on_replay_done)
    asyncio.create_task(_score_poller(), name="score-poller")
    asyncio.create_task(_prune_task(), name="prune")
    log.info("=== alle subsystemen gestart ===")
    yield
    await bus.stop()
    await scores.stop()
    await identity.stop()
    await store.stop()


app = FastAPI(title="SASE SOC Dashboard", lifespan=_lifespan)

_WEB = Path(__file__).parent.parent / "web"
if _WEB.exists():
    app.mount("/static", StaticFiles(directory=str(_WEB)), name="static")


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(str(_WEB / "index.html"))


@app.get("/health")
async def health():
    redis_ok = await scores.ping()
    ib = await identity.health()
    db_counts = await store.counts()
    return {
        "status": "ok" if (bus.connected and redis_ok) else "degraded",
        "nats": {"connected": bus.connected, "live": bus.live},
        "redis": {"ok": redis_ok},
        "identity_bridge": ib,
        "ws_clients": ws_mgr.count,
        "db": db_counts,
        "config": {
            "score_window": config.SCORE_WINDOW,
            "score_quarantine": config.SCORE_QUARANTINE,
            "score_weights": config.SCORE_WEIGHTS,
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
    rows = await store.query_events(since=since, category=category,
                                    producer=producer, persona=persona,
                                    user=user, q=q, limit=limit)
    return {"events": rows, "count": len(rows)}


@app.get("/api/events/snapshot")
async def api_events_snapshot(per_category: int = Query(60, ge=10, le=300)):
    """Gebalanceerde snapshot: laatste N events per categorie, nieuwste eerst.
    Garandeert dat élke categorie zichtbaar is ongeacht volume-verschillen."""
    rows = await store.query_events_balanced(per_category=per_category)
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
    q = await scores.active_quarantines()
    return {"scores": resolved, "active_quarantines": q,
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
    return {"peers": {ip: rec for ip, (_, rec) in identity._cache.items()},
            "count": len(identity._cache)}


@app.websocket("/ws")
async def websocket(ws: WebSocket):
    await ws_mgr.connect(ws)
    try:
        # Gebalanceerde snapshot: laatste N per categorie (álle categorieën zichtbaar)
        rows = await store.query_events_balanced()
        await ws.send_json({"type": "snapshot_events",
                            "data": [_ev_wire(r) for r in rows]})
        ps = await scores.current_scores()
        await ws.send_json({"type": "scores", "data": {"peers": ps,
                            "active_quarantines": await scores.active_quarantines(),
                            "threshold": config.SCORE_QUARANTINE}})
        await ws.send_json({"type": "replay_status",
                            "data": {"replay_done": bus.live}})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await ws_mgr.disconnect(ws)


# ── Fase 4b: Quarantaine endpoints ──────────────────────────────────────────

@app.get("/api/netbird/peers")
async def api_netbird_peers():
    """Alle ingeschreven NetBird peers + huidige groepen (voor de peer-tabel)."""
    from app.quarantine import get_all_peers
    peers = await get_all_peers()
    quarantines = set(await scores.active_quarantines())
    q_group_id = config.NETBIRD_QUARANTINE_GROUP_ID
    result = []
    for p in peers:
        group_names = [g.get("name") for g in (p.get("groups") or [])]
        in_quarantine = any(g.get("id") == q_group_id for g in (p.get("groups") or []))
        # overlay IP zonder prefix
        ip = str(p.get("ip", "")).split("/")[0]
        rec = await identity.resolve(ip) if ip else {}

        # Identiteit alleen gebruiken als de bridge écht resolvde (user != None).
        # Anders (offline peer) valt de bridge terug op het IP -> dan liever de
        # NetBird-peernaam tonen. Persona uit NetBird-groepen als fallback.
        if rec.get("user"):
            display = rec.get("display")
            persona = rec.get("persona")
        else:
            display = p.get("name") or ip
            persona = next((g for g in group_names
                            if g in config.NETBIRD_POLICY_GROUPS), None)

        result.append({
            "id":           p.get("id"),
            "name":         p.get("name"),
            "ip":           ip,
            "os":           p.get("os"),
            "connected":    p.get("connected"),
            "groups":       group_names,
            "quarantined":  in_quarantine,
            "display":      display,
            "persona":      persona,
        })
    result.sort(key=lambda x: (not x["connected"], x["display"] or ""))
    return {"peers": result, "quarantines": list(quarantines)}


@app.post("/api/quarantine/{overlay_ip:path}")
async def api_quarantine(overlay_ip: str):
    from app.quarantine import quarantine_peer
    result = await quarantine_peer(overlay_ip)
    if result["ok"]:
        item = {
            "kind":         "quarantine_active",
            "actor_ip":     overlay_ip,
            "actor_display": result.get("peer_name"),
            "detail":       f"Manueel dashboard | uit: {result.get('stripped', [])}",
            "raw":          result,
        }
        await store.insert_timeline(item)
        await ws_mgr.broadcast("timeline", item)
        await ws_mgr.broadcast("quarantine_change",
                               {"ip": overlay_ip, "state": "quarantined",
                                "peer_name": result.get("peer_name")})
    return result


@app.post("/api/unquarantine/{overlay_ip:path}")
async def api_unquarantine(overlay_ip: str):
    from app.quarantine import unquarantine_peer
    result = await unquarantine_peer(overlay_ip)
    if result["ok"]:
        item = {
            "kind":         "quarantine_cleared",
            "actor_ip":     overlay_ip,
            "actor_display": result.get("peer_name"),
            "detail":       f"Manueel hersteld via dashboard | in: {result.get('restored', [])}",
            "raw":          result,
        }
        await store.insert_timeline(item)
        await ws_mgr.broadcast("timeline", item)
        await ws_mgr.broadcast("quarantine_change",
                               {"ip": overlay_ip, "state": "restored",
                                "peer_name": result.get("peer_name")})
    return result
