"""Control daemon configuratie uit environment-variabelen.

Ontwerpbeslissingen die hier zichtbaar zijn (zie Verslag 35 / beslispunten 1-4):
- ENFORCE poort ALLE schrijfacties. Default false = dry-run (puur loggen,
  geen NetBird-PUT, geen Redis-restore). Pas op true zetten na de
  dry-run-validatie op een testpeer.
- NETBIRD_POLICY_GROUPS = de persona-groepen. De quarantaine-strip wordt
  STRIKT hiertoe beperkt -> infra (Core-Services) kan structureel niet
  gequarantained worden (V34-veiligheidseigenschap).
- ids (suricata) staat NIET in SCORE_WEIGHTS: niet peer-attribueerbaar
  (src_ip = remote, geen overlay), dus log-only. C2-beacon-respons loopt via
  Zeek/RITA -> ioc2rpz -> RPZ (Sessie 7), niet via deze daemon.
"""
import os


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# --- NATS ---
NATS_URL = os.environ.get("NATS_URL", "nats://nats-jetstream:4222")
# Live NATS gebruikt accounts {} (Gerben-correctie), niet authorization { token }.
# Daarom user/pass als primair, token als fallback. Bevestig het juiste
# consumer-account + de subscribe/consume-rechten tegen /opt/nats-jetstream/nats.conf
# VOOR de eerste run -- dit is de enige niet-gevalideerde aanname in dit skelet.
NATS_USER = os.environ.get("NATS_USER", "")
NATS_PASS = os.environ.get("NATS_PASS", "")
NATS_TOKEN = os.environ.get("NATS_TOKEN", "")

SECURITY_STREAM = os.environ.get("SECURITY_STREAM", "SECURITY_ALERTS")
SECURITY_SUBJECT = os.environ.get("SECURITY_SUBJECT", "security.alert.>")
IDENTITY_STREAM = os.environ.get("IDENTITY_STREAM", "IDENTITY_EVENTS")
IDENTITY_SUBJECT = os.environ.get("IDENTITY_SUBJECT", "identity.>")

# Fail-loud (beslispunt 4): emit een marker-event op actie-falen zodat een
# latere SIEM-consumer (Wazuh, Sessie 4) erop kan alarmeren. Goedkoop, optioneel.
EMIT_ACTION_FAILED = _bool("EMIT_ACTION_FAILED", True)
ACTION_FAILED_SUBJECT = os.environ.get("ACTION_FAILED_SUBJECT", "control.action.failed")

# --- Redis ---
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis-session:6379/0")

# --- NetBird ---
NETBIRD_API_URL = os.environ.get("NETBIRD_API_URL", "https://netbird.sandbox.local/api")
NETBIRD_API_TOKEN = os.environ.get("NETBIRD_API_TOKEN", "")
NETBIRD_QUARANTINE_GROUP = os.environ.get("NETBIRD_QUARANTINE_GROUP", "Quarantine")
NETBIRD_POLICY_GROUPS = _list("NETBIRD_POLICY_GROUPS", "Studenten,Docenten,Admins")

# --- Enforcement ---
ENFORCE = _bool("ENFORCE", False)
ACTION_RETRY = int(os.environ.get("ACTION_RETRY", "1"))         # 1 bounded retry op IP->peer
ACTION_RETRY_DELAY = float(os.environ.get("ACTION_RETRY_DELAY", "2.0"))

# --- Scoring (sliding window, beslispunt 3) ---
# Per-peer score = gewogen som van events binnen SCORE_WINDOW seconden.
# Decay = events vallen uit het venster (ZREMRANGEBYSCORE), geen flat TTL-reset.
SCORE_WINDOW = int(os.environ.get("SCORE_WINDOW", "600"))       # 10 min
SCORE_QUARANTINE = int(os.environ.get("SCORE_QUARANTINE", "80"))
SCORE_WEIGHTS = {
    "malware": int(os.environ.get("W_MALWARE", "80")),    # single-event: kruist alleen (headline)
    "dlp_match": int(os.environ.get("W_DLP", "30")),      # accruing, betekenisvol
    # proxy_block: bewust GEEN gewicht -> log-only. Ambient OS-ruis (NCSI, msn/ad-telemetrie,
    #              UT1-categorieblocks) accrueerde anders naar quarantaine = vals positief (V35).
    # ids: bewust afwezig -> log-only, niet peer-attribueerbaar (src_ip = remote).
}
