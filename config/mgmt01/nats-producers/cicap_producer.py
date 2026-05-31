#!/usr/local/bin/python3
"""
SASE PoC — c-icap RESPMOD-log -> NATS JetStream producer.
Draait op pop01 (OPNsense/FreeBSD), in dezelfde venv als de Suricata- en
Squid-producers. De vierde en laatste detectie-bron op de event-bus.

Tailt /var/log/cicap/latest.log (symlink -> cicap_YYYYMMDD.log, door c-icap
onderhouden; dagrotatie wijzigt de inode -> nats_tail.tail_file handelt dat af).
Publiceert virus/malware-treffers naar security.alert.malware op NATS JetStream
(mgmt01).

Filter   : enkel regels met "VIRUS DETECTED" (de uitzondering tussen de <30>-
           access-ruis; treffers dragen syslog-priority <26> = crit). De honderden
           "204"/"200"-access-regels zijn schone scans en worden overgeslagen.
Voorbeeld-treffer (empirisch, V-deze-sessie):
  <26>1 2026-05-31T21:51:48+00:00 OPNsense.internal c-icap 9240 - [meta sequenceId="10"] \
      9240/30482222233608, VIRUS DETECTED: Eicar-Test-Signature , \
      http client ip: 100.70.247.142, http user: -, http url: https://secure.eicar.org/eicar.com.txt
Identiteit: bij RESPMOD draagt "http client ip" het overlay-IP van de client-peer
           (bewezen met docent1 = 100.70.247.142) -> peer/user-attribueerbaar in 3c,
           net als de squid/dlp-bron (en in tegenstelling tot de ids-bron, V33 33.16).
Routing  : ClamAV-signatures -> security.alert.malware. Latente safeguard: een
           "YARA.DLP_*"-signature zou naar security.alert.dlp gaan (deze pijplijn
           draagt nu geen YARA-DLP-sigs — grep bevestigd leeg — dus dat pad is
           latent, niet actief; voorkomt dat malware ooit stil als dlp gelabeld wordt).
Auth/robuust: identiek aan de Squid-/Suricata-producer (user/pass, js.publish+
           timeout, oneindige reconnect, rotation-aware tail, fail-safe parse).
"""

import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone

import nats
from nats.errors import TimeoutError as NatsTimeoutError

from nats_tail import tail_file

NATS_URL = os.environ.get("NATS_URL", "nats://192.168.122.23:4222")
NATS_USER = os.environ.get("NATS_USER", "pop01-pub")
NATS_PASS = os.environ.get("NATS_PASS", "")
CICAP_LOG = os.environ.get("CICAP_LOG", "/var/log/cicap/latest.log")
SUBJECT_MALWARE = "security.alert.malware"
SUBJECT_DLP = "security.alert.dlp"
PUBLISH_TIMEOUT = float(os.environ.get("NATS_PUBLISH_TIMEOUT", "5"))
MAX_PAYLOAD = 60 * 1024  # soft guard < 64 KiB SECURITY_ALERTS-cap (V32 32.11)

# Treffer-regel parsen. Voorbeeld (na de syslog-header):
#   ..., VIRUS DETECTED: Eicar-Test-Signature , http client ip: 100.70.247.142,
#       http user: - , http url: https://secure.eicar.org/eicar.com.txt
# We ankeren op de self-labelende velden, niet op veld-posities (de syslog-header
# en het "<pid>/<id>"-prefix variëren). re.search i.p.v. match: header vóór de treffer.
RE_VIRUS = re.compile(r"VIRUS DETECTED:\s*(?P<sig>.+?)\s*,")
RE_CLIENT = re.compile(r"http client ip:\s*(?P<ip>[^\s,]+)")
RE_USER = re.compile(r"http user:\s*(?P<user>[^\s,]+)")
RE_URL = re.compile(r"http url:\s*(?P<url>\S+)")

# Syslog-timestamp uit de header (RFC5424): "<pri>1 2026-05-31T21:51:48+00:00 host ..."
RE_TS = re.compile(r"^<\d+>\d+\s+(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2})")


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
    """Parse een c-icap-logregel. Return (subject, payload-dict) of None (skip).

    Skip-strategie (fail-safe): geen 'VIRUS DETECTED' -> None (de access-ruis).
    Een treffer zonder signature -> None (kan niet attribueren/labelen).
    """
    m_virus = RE_VIRUS.search(line)
    if not m_virus:
        return None  # schone scan / access-ruis / OPTIONS — overslaan

    signature = m_virus.group("sig").strip()
    if not signature:
        return None  # treffer zonder bruikbare signature — fail-safe skip

    m_client = RE_CLIENT.search(line)
    m_user = RE_USER.search(line)
    m_url = RE_URL.search(line)
    m_ts = RE_TS.search(line)

    client_ip = m_client.group("ip") if m_client else None
    user = m_user.group("user") if m_user else None
    url = m_url.group("url") if m_url else None

    # syslog-timestamp -> ISO8601 UTC (consistent met de andere producers)
    iso_ts = None
    ts_epoch = None
    if m_ts:
        try:
            dt = datetime.fromisoformat(m_ts.group("ts")).astimezone(timezone.utc)
            iso_ts = dt.isoformat()
            ts_epoch = dt.timestamp()
        except ValueError:
            pass

    # Routing: latente DLP-safeguard. Deze pijplijn draagt nu enkel ClamAV-sigs
    # (-> malware); een toekomstige YARA.DLP_*-sig zou semantisch naar dlp gaan.
    subject = SUBJECT_DLP if signature.upper().startswith("YARA.DLP") else SUBJECT_MALWARE

    payload = {
        "timestamp": iso_ts,                                # ISO8601 UTC
        "ts_epoch": ts_epoch,                               # precieze correlatie-sleutel voor 3c
        "client_ip": client_ip,                             # overlay-IP -> peer-attribueerbaar (squid-conventie)
        "signature": signature,                             # ClamAV/YARA detectie-naam
        "url": url,                                          # de gescande/geweigerde resource
        "user": None if user in (None, "-") else user,      # c-icap levert hier doorgaans "-" -> null
        "producer": "c-icap",
    }
    return subject, payload


async def main():
    if not NATS_PASS:
        log("FATAAL: NATS_PASS niet gezet — heb je nats.env gesourcet?")
        sys.exit(1)

    nc = await nats.connect(
        NATS_URL,
        user=NATS_USER,
        password=NATS_PASS,
        name="cicap-producer",
        reconnect_time_wait=2,
        max_reconnect_attempts=-1,
        error_cb=_err_cb,
        disconnected_cb=_disconnected_cb,
        reconnected_cb=_reconnected_cb,
        closed_cb=_closed_cb,
    )
    js = nc.jetstream()
    log(f"Verbonden met NATS: {NATS_URL} als {NATS_USER}")
    log(f"Tail op: {CICAP_LOG} -> {SUBJECT_MALWARE} (DLP-safeguard -> {SUBJECT_DLP})")

    published = skipped = pub_err = 0

    async for line in tail_file(CICAP_LOG):
        if not line:
            continue
        result = parse_line(line)
        if result is None:
            skipped += 1
            continue
        subject, payload = result

        msg = json.dumps(payload).encode()
        if len(msg) > MAX_PAYLOAD:
            pub_err += 1
            log(f"WAARSCHUWING: payload {len(msg)}B > {MAX_PAYLOAD}B, overgeslagen (url={payload.get('url')})")
            continue

        try:
            await js.publish(subject, msg, timeout=PUBLISH_TIMEOUT)
            published += 1
            log(f"[{subject}] sig={payload['signature']} ip={payload['client_ip']} url={payload['url']}")
        except NatsTimeoutError:
            pub_err += 1
            log(f"PubAck timeout (NATS traag of permissie-deny?) sig={payload.get('signature')}")
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
