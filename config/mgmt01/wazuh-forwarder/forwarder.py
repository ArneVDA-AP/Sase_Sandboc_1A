#!/usr/bin/env python3
"""NATS -> Wazuh forwarder (transport C: localfile NDJSON tail).

Leest security.alert.> van de NATS JetStream-bus en schrijft elke message als
NDJSON-regel naar een shared-volume-bestand dat de Wazuh-manager tailt via
<localfile><log_format>json>. De manager mount dat volume read-only; alleen
deze forwarder schrijft.

Ontwerpkeuzes (Verslag 36/37):
  - Durable PULL-consumer op SECURITY_ALERTS, DeliverPolicy.NEW: geen replay van
    de ~1374 historische events; een forwarder-RESTART hervat vanaf de opgeslagen
    cursor (events staan 7d in de stream -> geen gat).
  - AckPolicy.EXPLICIT, ack PAS NA een geslaagde write -> at-least-once in het
    bestand. Crash tussen receive en write => redelivery na ack_wait.
  - Reconnect-resilient (V36 36.18): max_reconnect_attempts=-1 + hostname-URL
    (nats://nats:4222) zodat nats-py DNS HER-resolvet bij elke reconnect; een
    bus-recreate met nieuw container-IP legt de forwarder dus niet plat.
  - write_event(): het transport-swap-punt. C = NDJSON append (deze file).
    A (analysisd-socket) blijft een ~5-regel-fallback achter de hand.

Env (via .env / compose):
  NATS_URL (default nats://nats:4222), NATS_USER, NATS_PASS,
  STREAM (SECURITY_ALERTS), SUBJECT (security.alert.>),
  DURABLE (wazuh-forwarder), OUT_PATH (/ingest/security_alerts.json),
  BATCH (50), FETCH_TIMEOUT (5), ACK_WAIT (30), MAX_ACK_PENDING (1000)
"""
import asyncio
import os
import signal
from datetime import datetime, timezone

import nats
from nats.errors import TimeoutError as NatsTimeout
from nats.js.api import ConsumerConfig, DeliverPolicy, AckPolicy

NATS_URL = os.environ.get("NATS_URL", "nats://nats:4222")  # hostnaam -> re-resolve
NATS_USER = os.environ["NATS_USER"]
NATS_PASS = os.environ["NATS_PASS"]
STREAM = os.environ.get("STREAM", "SECURITY_ALERTS")
SUBJECT = os.environ.get("SUBJECT", "security.alert.>")
DURABLE = os.environ.get("DURABLE", "wazuh-forwarder")
OUT_PATH = os.environ.get("OUT_PATH", "/ingest/security_alerts.json")
BATCH = int(os.environ.get("BATCH", "50"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "5"))
ACK_WAIT = float(os.environ.get("ACK_WAIT", "30"))
MAX_ACK_PENDING = int(os.environ.get("MAX_ACK_PENDING", "1000"))

_stop = asyncio.Event()


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc).isoformat()} {msg}", flush=True)


def write_events(raws) -> None:
    """Transport C: append elke (al-geldige, compacte) JSON-message als NDJSON-regel.
    De manager tailt dezelfde page-cache; flush() volstaat (geen fsync -> throughput;
    verliesvenster = host-crash in het sub-seconde-venster voor flush-naar-disk)."""
    with open(OUT_PATH, "ab") as f:
        for raw in raws:
            f.write(raw.rstrip(b"\n") + b"\n")
        f.flush()


async def run() -> None:
    async def on_disconnected() -> None:
        log("[nats] disconnected")

    async def on_reconnected() -> None:
        log(f"[nats] reconnected -> {nc.connected_url.netloc if nc.connected_url else '?'}")

    async def on_error(e) -> None:
        log(f"[nats] error: {e}")

    nc = await nats.connect(
        NATS_URL,
        user=NATS_USER,
        password=NATS_PASS,
        max_reconnect_attempts=-1,
        reconnect_time_wait=2,
        disconnected_cb=on_disconnected,
        reconnected_cb=on_reconnected,
        error_cb=on_error,
    )
    log(f"[nats] connected as {NATS_USER} -> {NATS_URL}")

    js = nc.jetstream()
    psub = await js.pull_subscribe(
        SUBJECT,
        durable=DURABLE,
        stream=STREAM,
        config=ConsumerConfig(
            durable_name=DURABLE,
            deliver_policy=DeliverPolicy.NEW,  # enkel bij EERSTE creatie gehonoreerd
            ack_policy=AckPolicy.EXPLICIT,
            ack_wait=ACK_WAIT,
            max_ack_pending=MAX_ACK_PENDING,
        ),
    )
    log(f"[js] '{DURABLE}' bound op {STREAM}/{SUBJECT} -> {OUT_PATH}")

    while not _stop.is_set():
        try:
            msgs = await psub.fetch(BATCH, timeout=FETCH_TIMEOUT)
        except (NatsTimeout, asyncio.TimeoutError):
            continue  # leeg venster, geen events; gewoon opnieuw fetchen
        if not msgs:
            continue
        try:
            write_events([m.data for m in msgs])
        except Exception as e:
            # geen ack -> JetStream herlevert na ack_wait (at-least-once)
            log(f"[write] faalde, geen ack (redeliver na ack_wait): {e}")
            continue
        for m in msgs:
            await m.ack()  # ack PAS na geslaagde write
        log(f"[fwd] {len(msgs)} event(s) -> {OUT_PATH}")

    log("[nats] draining")
    await nc.drain()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for s in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(s, _stop.set)
    loop.run_until_complete(run())
