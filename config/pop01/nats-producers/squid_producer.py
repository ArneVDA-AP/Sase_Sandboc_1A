"""
SASE PoC — Squid access.log -> NATS JetStream producer.
Draait op pop01 (OPNsense/FreeBSD), in dezelfde venv als de Suricata-producer.

Tailt /var/log/squid/access.log (10-velden default logformat), publiceert
policy-block-events naar security.alert.proxy op NATS JetStream (mgmt01).

Filter   : result_code begint met "TCP_DENIED" — de access-control-beslissingsregel.
           Dedupet de TCP_DENIED-CONNECT / NONE_NONE-403-GET dubbeling (we nemen de
           CONNECT, want die draagt ook de persona-user=). Vangt ook plain-HTTP
           TCP_DENIED/403. De TCP_MISS/403 DLP-block valt bewust buiten scope
           (hoort bij de c-icap-producer).
Identiteit: persona-denies dragen user= (via de identity-helper); URL-categorie-
           denies niet (user="-"). "-" wordt genormaliseerd naar null.
Auth/robuust: identiek aan de Suricata-producer (user/pass, js.publish+timeout,
           oneindige reconnect, rotation-aware tail, fail-safe parse).
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone

import nats
from nats.errors import TimeoutError as NatsTimeoutError

from nats_tail import tail_file

NATS_URL = os.environ.get("NATS_URL", "nats://192.168.122.23:4222")
NATS_USER = os.environ.get("NATS_USER", "pop01-pub")
NATS_PASS = os.environ.get("NATS_PASS", "")
SQUID_LOG = os.environ.get("SQUID_LOG", "/var/log/squid/access.log")
SUBJECT = "security.alert.proxy"
PUBLISH_TIMEOUT = float(os.environ.get("NATS_PUBLISH_TIMEOUT", "5"))
MAX_PAYLOAD = 60 * 1024  # soft guard < 64 KiB SECURITY_ALERTS-cap (V32 32.11)


def log(msg):
    print(msg, flush=True)


async def _err_cb(e):
    log(f"[nats] error: {e}")


async def _disconnected_cb():
    log("[nats] disconnected")


async def _reconnected_cb():
    log("[nats] reconnected")


async def _closed_cb():
    log("[nats] connection closed")


def parse_line(line):
    """Parse een default-format access.log-regel. Return dict of None (skip)."""
    fields = line.split()
    if len(fields) < 10:
        return None  # fail-safe: ongewone/onvolledige regel
    ts_epoch, _elapsed, client_ip, code, _bytes, method, url, user, _hier, _ctype = fields[:10]

    if not code.startswith("TCP_DENIED"):
        return None  # enkel access-control-denies

    try:
        iso_ts = datetime.fromtimestamp(float(ts_epoch), tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        iso_ts = None

    return {
        "timestamp": iso_ts,                       # ISO8601 UTC, consistent met Suricata
        "ts_epoch": float(ts_epoch),               # precieze correlatie-sleutel voor 3c
        "client_ip": client_ip,                    # overlay-IP -> peer-attribueerbaar
        "result_code": code,
        "method": method,
        "url": url,
        "user": None if user == "-" else user,     # persona-identiteit of null (categorie-deny)
        "producer": "squid",
    }


async def main():
    if not NATS_PASS:
        log("FATAAL: NATS_PASS niet gezet — heb je nats.env gesourcet?")
        sys.exit(1)

    nc = await nats.connect(
        NATS_URL,
        user=NATS_USER,
        password=NATS_PASS,
        name="squid-producer",
        reconnect_time_wait=2,
        max_reconnect_attempts=-1,
        error_cb=_err_cb,
        disconnected_cb=_disconnected_cb,
        reconnected_cb=_reconnected_cb,
        closed_cb=_closed_cb,
    )
    js = nc.jetstream()
    log(f"Verbonden met NATS: {NATS_URL} als {NATS_USER}")
    log(f"Tail op: {SQUID_LOG} -> {SUBJECT}")

    published = skipped = parse_err = pub_err = 0

    async for line in tail_file(SQUID_LOG):
        if not line:
            continue
        payload = parse_line(line)
        if payload is None:
            skipped += 1
            continue

        msg = json.dumps(payload).encode()
        if len(msg) > MAX_PAYLOAD:
            pub_err += 1
            log(f"WAARSCHUWING: payload {len(msg)}B > {MAX_PAYLOAD}B, overgeslagen (url={payload.get('url')})")
            continue

        try:
            await js.publish(SUBJECT, msg, timeout=PUBLISH_TIMEOUT)
            published += 1
            if published % 50 == 0:
                log(f"gepubliceerd={published} skip={skipped} parse_err={parse_err} pub_err={pub_err}")
        except NatsTimeoutError:
            pub_err += 1
            log(f"PubAck timeout (NATS traag of permissie-deny?) url={payload.get('url')}")
        except Exception as e:
            pub_err += 1
            log(f"publish-fout: {e}")

    await nc.drain()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log("producer gestopt")
        sys.exit(0)
