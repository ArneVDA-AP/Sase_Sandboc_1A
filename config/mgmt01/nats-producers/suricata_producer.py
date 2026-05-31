"""
SASE PoC — Suricata eve.json -> NATS JetStream producer.
Draait op pop01 (OPNsense/FreeBSD).

Tailt /var/log/suricata/eve.json, filtert event_type=="alert",
publiceert een compacte payload naar security.alert.ips op NATS JetStream (mgmt01).

Auth     : user/pass via env (NATS_USER/NATS_PASS uit nats.env, 600 root).
Publish  : js.publish met PubAck (leverbewijs) + expliciete timeout-afhandeling
           (een PubAck-timeout kan NATS-traagheid OF een permissie-deny zijn — V32 32.14).
Robuust  : oneindige NATS-reconnect; rotation-aware tail; fail-safe parse;
           payload-guard onder de 64 KiB stream-cap.
"""

import asyncio
import json
import os
import sys

import nats
from nats.errors import TimeoutError as NatsTimeoutError

from nats_tail import tail_file

NATS_URL = os.environ.get("NATS_URL", "nats://192.168.122.23:4222")
NATS_USER = os.environ.get("NATS_USER", "pop01-pub")
NATS_PASS = os.environ.get("NATS_PASS", "")
EVE_LOG = os.environ.get("EVE_LOG", "/var/log/suricata/eve.json")
SUBJECT = "security.alert.ips"
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


async def main():
    if not NATS_PASS:
        log("FATAAL: NATS_PASS niet gezet — heb je nats.env gesourcet?")
        sys.exit(1)

    nc = await nats.connect(
        NATS_URL,
        user=NATS_USER,
        password=NATS_PASS,
        name="suricata-producer",
        reconnect_time_wait=2,
        max_reconnect_attempts=-1,  # security-producer geeft niet op
        error_cb=_err_cb,
        disconnected_cb=_disconnected_cb,
        reconnected_cb=_reconnected_cb,
        closed_cb=_closed_cb,
    )
    js = nc.jetstream()
    log(f"Verbonden met NATS: {NATS_URL} als {NATS_USER}")
    log(f"Tail op: {EVE_LOG} -> {SUBJECT}")

    published = skipped = parse_err = pub_err = 0

    async for line in tail_file(EVE_LOG):
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            parse_err += 1
            continue  # fail-safe: onparsebare regel skipt, crasht niet

        if event.get("event_type") != "alert":
            skipped += 1
            continue

        a = event.get("alert", {})
        payload = {
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "src_port": event.get("src_port"),
            "dest_port": event.get("dest_port"),
            "proto": event.get("proto"),
            "alert": {
                "signature_id": a.get("signature_id"),
                "signature": a.get("signature"),
                "category": a.get("category"),
                "severity": a.get("severity"),
            },
            "flow_id": event.get("flow_id"),
            "in_iface": event.get("in_iface"),  # vtnet0=WAN / vtnet1=LAN (Doc3) — detectie-domein
            "producer": "suricata",
        }
        msg = json.dumps(payload).encode()

        if len(msg) > MAX_PAYLOAD:
            pub_err += 1
            log(f"WAARSCHUWING: payload {len(msg)}B > {MAX_PAYLOAD}B, overgeslagen "
                f"(sig_id={a.get('signature_id')})")
            continue

        try:
            await js.publish(SUBJECT, msg, timeout=PUBLISH_TIMEOUT)
            published += 1
            if published % 50 == 0:
                log(f"gepubliceerd={published} skip={skipped} "
                    f"parse_err={parse_err} pub_err={pub_err}")
        except NatsTimeoutError:
            pub_err += 1
            log(f"PubAck timeout (NATS traag of permissie-deny?) sig_id={a.get('signature_id')}")
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
