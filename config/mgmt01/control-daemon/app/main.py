"""SASE PoC — Control Daemon (Laag 3).

Twee consumers:
- SECURITY_ALERTS / security.alert.>  -> durable + DeliverPolicy.NEW
  (geen 1100+ historische proxy-events herafspelen; positie onthouden over restarts).
  Dispatch op het `producer`-veld (.ips naast dode .ids maakt subject onbetrouwbaar).
- IDENTITY_EVENTS / identity.>  -> ephemeral + DeliverPolicy.ALL
  De identity-map is in-memory en MOET bij elke start herbouwd worden, dus de
  consumer speelt de volledige (laag-volume) identity-historie opnieuw af. Een
  durable consumer zou hervatten-vanaf-ack en de map leeg laten na restart.

Attributie-tiering (beslispunt 2, empirisch bevestigd V33/V34):
- direct attribueerbaar (client_ip = overlay): squid, dlp, c-icap -> scoren/quarantaine
- correlatie-only (src_ip = remote, geen overlay): suricata -> LOG-ONLY
  (C2-beacon-respons loopt via Zeek/RITA -> ioc2rpz -> RPZ, Sessie 7)
"""
import asyncio
import json
import logging
import signal

import nats
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

from app import config
from app.actions.netbird import list_peers, quarantine_peer
from app.identity import IdentityMap
from app.scoring import ThreatScorer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("control-daemon")

idmap = IdentityMap()
scorer = ThreatScorer()
_js = None  # JetStream-context, gezet in main()


async def _emit_action_failed(result: dict) -> None:
    if not config.EMIT_ACTION_FAILED or _js is None:
        return
    try:
        await _js.publish(config.ACTION_FAILED_SUBJECT,
                          json.dumps({"producer": "control-daemon", **result}).encode())
    except Exception as e:
        logger.error("kon control.action.failed niet publiceren (grant?): %s", e)


async def _maybe_quarantine(client_ip: str, result: dict) -> None:
    if not result.get("quarantine"):
        return
    who = idmap.describe(client_ip)
    logger.warning("DREMPEL -> quarantaine-trigger voor %s (score=%d)", who, result["score"])
    res = await quarantine_peer(client_ip, attribution=who)
    if not res.get("ok"):
        await _emit_action_failed(res)


# --- Handlers per producer ---

async def handle_malware(data: dict) -> None:
    ip = data.get("client_ip", "")
    logger.info("malware: %s sig=%s url=%s", idmap.describe(ip),
                data.get("signature", "?"), data.get("url", ""))
    result = await scorer.add_event(ip, "malware")   # gewicht 80 -> kruist alleen
    await _maybe_quarantine(ip, result)


async def handle_dlp(data: dict) -> None:
    ip = data.get("client_ip", "")
    logger.info("dlp: %s violations=%s", idmap.describe(ip), data.get("violations", []))
    result = await scorer.add_event(ip, "dlp_match")
    await _maybe_quarantine(ip, result)


async def handle_proxy(data: dict) -> None:
    ip = data.get("client_ip", "")
    logger.info("proxy: %s %s %s", idmap.describe(ip),
                data.get("result_code", ""), data.get("url", ""))
    result = await scorer.add_event(ip, "proxy_block")
    await _maybe_quarantine(ip, result)


async def handle_ids(data: dict) -> None:
    # Correlatie-only: src_ip is de remote host, NIET een overlay-peer. Geen score/quarantaine.
    alert = data.get("alert", {})
    logger.info("ids (log-only): src=%s sev=%s sig=%s",
                data.get("src_ip", "?"), alert.get("severity"), alert.get("signature", ""))


_DISPATCH = {
    "c-icap": handle_malware,
    "dlp": handle_dlp,
    "squid": handle_proxy,
    "suricata": handle_ids,
}


async def on_security(msg) -> None:
    try:
        data = json.loads(msg.data.decode())
        handler = _DISPATCH.get(data.get("producer"))
        if handler:
            await handler(data)
        else:
            logger.info("onbekende producer op %s: %s", msg.subject, data.get("producer"))
    except Exception as e:
        logger.error("fout bij verwerken security-event: %s", e)
    finally:
        await msg.ack()


async def on_identity(msg) -> None:
    try:
        idmap.apply_event(json.loads(msg.data.decode()))
    except Exception as e:
        logger.error("fout bij verwerken identity-event: %s", e)
    finally:
        await msg.ack()


async def main() -> None:
    global _js

    opts = {"name": "control-daemon"}
    if config.NATS_USER:
        opts.update(user=config.NATS_USER, password=config.NATS_PASS)
    elif config.NATS_TOKEN:
        opts.update(token=config.NATS_TOKEN)
    nc = await nats.connect(config.NATS_URL, **opts)
    _js = nc.jetstream()

    mode = "ENFORCE (schrijft naar NetBird!)" if config.ENFORCE else "DRY-RUN (geen schrijfacties)"
    logger.warning("=== Control daemon gestart -- MODE: %s ===", mode)
    logger.info("policy-groepen (strip-scope): %s | quarantaine-drempel: %d",
                config.NETBIRD_POLICY_GROUPS, config.SCORE_QUARANTINE)

    # Bootstrap identity-map (cold-start fallback); identity.>-replay verrijkt 'm daarna.
    try:
        idmap.bootstrap(await list_peers())
    except Exception as e:
        logger.error("identity-map bootstrap faalde (ga door, events vullen 'm): %s", e)

    await _js.subscribe(
        config.SECURITY_SUBJECT, stream=config.SECURITY_STREAM, cb=on_security, manual_ack=True,
        config=ConsumerConfig(durable_name="control-daemon-security",
                              deliver_policy=DeliverPolicy.NEW, ack_policy=AckPolicy.EXPLICIT),
    )
    # Ephemeral (geen durable_name) + ALL: herbouwt de in-memory map bij elke start.
    await _js.subscribe(
        config.IDENTITY_SUBJECT, stream=config.IDENTITY_STREAM, cb=on_identity, manual_ack=True,
        config=ConsumerConfig(deliver_policy=DeliverPolicy.ALL, ack_policy=AckPolicy.EXPLICIT),
    )
    logger.info("subscribed: %s (%s, durable/new) + %s (%s, ephemeral/all)",
                config.SECURITY_SUBJECT, config.SECURITY_STREAM,
                config.IDENTITY_SUBJECT, config.IDENTITY_STREAM)

    stop = asyncio.Event()
    loop = asyncio.get_event_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop.set)
    await stop.wait()
    logger.info("control daemon stopt...")
    await nc.drain()


if __name__ == "__main__":
    asyncio.run(main())
