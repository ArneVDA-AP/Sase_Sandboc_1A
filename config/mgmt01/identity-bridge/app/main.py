"""
SASE PoC — Identity Bridge
Vertaalt NetBird overlay IPs naar Entra ID identiteiten.

Architectuur: pollt NetBird Management API (REST /api, plain HTTP via
              Docker-intern netwerk) -> bouwt in-memory cache
              -> exposeert lookup endpoint voor de Squid external_acl helper.

Afwijkingen t.o.v. Addendum H v1 (sessie-beslissingen):
  - /lookup vereist een shared secret (X-Bridge-Secret) -> 401 zonder/fout.
    /health blijft open voor monitoring.
  - lifespan-context i.p.v. de deprecated @app.on_event("startup").
  - cache wordt alleen vervangen bij een geslaagde poll; bij failure blijft
    de oude cache staan (fail-open degradatie, Addendum H S.H.7.5).
"""

import asyncio
import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, Query, Header
from fastapi.responses import JSONResponse

# --- Configuratie uit environment ---
NETBIRD_API_URL = os.environ.get("NETBIRD_API_URL", "http://management:80/api")
NETBIRD_API_TOKEN = os.environ.get("NETBIRD_API_TOKEN", "")
REFRESH_INTERVAL = int(os.environ.get("REFRESH_INTERVAL", "30"))
# TLS-verificatie: false bij intern Docker-netwerk (plain HTTP), true bij extern HTTPS
VERIFY_TLS = os.environ.get("VERIFY_TLS", "false").lower() == "true"
# Shared secret tussen de Squid-helper en deze bridge. Leeg = auth uitgeschakeld
# (alleen voor lokale tests; in de container ALTIJD gezet via .env).
LOOKUP_SECRET = os.environ.get("LOOKUP_SECRET", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("identity-bridge")

# De drie persona-groepen (single source of truth, Sessie 1 / Pad B).
# Gebruikt voor multi-persona-anomaliedetectie — NIET voor filtering
# (filteren doet Squid via de http_access-volgorde).
PERSONA_GROUPS = {"Studenten", "Docenten", "Admins"}

# --- In-memory cache ---
CACHE: dict[str, dict] = {}
LAST_REFRESH: Optional[datetime] = None
LAST_REFRESH_SUCCESS: bool = False


def emit_event(event_type: str, payload: dict):
    """NATS-ready event-abstractie. v1: logt naar stdout.
    v2 (na NATS-sessie): publiceert ook naar subject 'identity.<event_type>'."""
    logger.info(f"EVENT {event_type}: {payload}")


async def refresh_cache():
    """Poll NetBird Management API, herbouw IP -> identity mapping."""
    global CACHE, LAST_REFRESH, LAST_REFRESH_SUCCESS

    headers = {"Authorization": f"Token {NETBIRD_API_TOKEN}"}
    old_keys = set(CACHE.keys())
    was_healthy = LAST_REFRESH_SUCCESS

    try:
        async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=10.0) as client:
            peers_resp = await client.get(f"{NETBIRD_API_URL}/peers", headers=headers)
            peers_resp.raise_for_status()
            peers = peers_resp.json()

            users_resp = await client.get(f"{NETBIRD_API_URL}/users", headers=headers)
            users_resp.raise_for_status()
            users = users_resp.json()

        # user_id -> user data (voor email; groepen komen uit de peer)
        user_map = {u["id"]: u for u in users}

        new_cache: dict[str, dict] = {}
        for peer in peers:
            if not peer.get("connected"):
                continue

            raw_ip = peer.get("ip", "")
            ip = raw_ip.split("/")[0] if raw_ip else ""  # strip CIDR (/32)
            if not ip:
                continue

            user = user_map.get(peer.get("user_id", ""), {})
            # Groepen uit de PEER (gematerialiseerd via propagation), niet uit
            # user.auto_groups (dat zijn group-IDs, geen namen).
            groups = [g["name"] for g in peer.get("groups", []) if "name" in g]

            new_cache[ip] = {
                "user": user.get("email", "unknown"),
                "name": user.get("name", "unknown"),
                "groups": groups,
                "os": peer.get("os", "unknown"),
            }

            # Zero-trust observability: een identiteit die naar meerdere
            # privilege-tiers resolvet is zelf een signaal. Niet stil oplossen
            # — loggen zodat de SIEM (Fase 4) het ziet. Squid's http_access
            # past de most-restrictive policy cumulatief toe.
            personas = PERSONA_GROUPS & set(groups)
            if len(personas) > 1:
                emit_event("identity.multi_persona", {
                    "ip": ip,
                    "user": new_cache[ip]["user"],
                    "personas": sorted(personas),
                })

        CACHE = new_cache
        LAST_REFRESH = datetime.now(timezone.utc)
        LAST_REFRESH_SUCCESS = True
        logger.info(f"Cache refreshed: {len(CACHE)} connected peers")

        # NATS-ready: cache-delta detectie
        for ip in set(new_cache) - old_keys:
            emit_event("peer.connected", {"ip": ip, **new_cache[ip]})
        for ip in old_keys - set(new_cache):
            emit_event("peer.disconnected", {"ip": ip})

    except Exception as e:
        # Cache NIET legen: oude cache blijft staan = fail-open degradatie.
        LAST_REFRESH = datetime.now(timezone.utc)
        LAST_REFRESH_SUCCESS = False
        logger.error(f"Cache refresh failed (oude cache behouden): {e}")
        if was_healthy:
            emit_event("bridge.degraded", {"error": str(e)})


async def periodic_refresh():
    while True:
        await asyncio.sleep(REFRESH_INTERVAL)
        await refresh_cache()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Eerste refresh synchroon -> cache gevuld vóór de eerste request.
    await refresh_cache()
    task = asyncio.create_task(periodic_refresh())
    yield
    task.cancel()


app = FastAPI(title="SASE PoC Identity Bridge", lifespan=lifespan)


@app.get("/lookup")
async def lookup(
    ip: str = Query(..., description="NetBird overlay IP"),
    x_bridge_secret: str = Header(default=""),
):
    """Squid external_acl-compatibele lookup. Vereist de shared secret."""
    if not LOOKUP_SECRET or x_bridge_secret != LOOKUP_SECRET:
        return JSONResponse(status_code=401, content={"status": "ERR", "reason": "unauthorized"})

    identity = CACHE.get(ip)
    if not identity:
        return JSONResponse(content={"status": "ERR", "reason": "ip_not_found"})
    return {
        "status": "OK",
        "user": identity["user"],
        "groups": identity["groups"],
        "os": identity["os"],
    }


@app.get("/health")
async def health():
    """Open monitoring-endpoint (geen secret) — bewust geen identity-data."""
    return {
        "status": "healthy" if LAST_REFRESH_SUCCESS else "degraded",
        "cache_size": len(CACHE),
        "last_refresh": LAST_REFRESH.isoformat() if LAST_REFRESH else None,
        "last_refresh_success": LAST_REFRESH_SUCCESS,
        "refresh_interval_seconds": REFRESH_INTERVAL,
    }
