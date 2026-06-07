"""
Centrale configuratie voor het SOC-dashboard (read-only observer).

Alle waarden komen uit environment-variabelen (.env). De scoring-constanten
SPIEGELEN bewust de control-daemon (Verslag 35): zelfde gewichten, venster en
drempel. Zo blijft de score die het dashboard TOONT identiek aan wat de daemon
INTERN berekent. Wijzigt het team de daemon-waarden, pas ze hier ook aan
(zelfde env-namen als de daemon gebruikt).

Belangrijk: dit proces SCHRIJFT NOOIT naar NATS, Redis of NetBird. Puur lezen.
"""
import os


def _bool(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# ── NATS (hergebruikt het bestaande control-daemon-account; subscribe-only) ──
NATS_URL = os.environ.get("NATS_URL", "nats://nats:4222")
NATS_USER = os.environ.get("NATS_USER", "control-daemon")
NATS_PASS = os.environ.get("NATS_DAEMON_PASS", "")  # zelfde var-naam als daemon-.env

SECURITY_SUBJECT = os.environ.get("SECURITY_SUBJECT", "security.alert.>")
IDENTITY_SUBJECT = os.environ.get("IDENTITY_SUBJECT", "identity.>")
ACTION_FAILED_SUBJECT = os.environ.get("ACTION_FAILED_SUBJECT", "control.action.failed")

# ── Redis (de threat-score store van de daemon; read-only) ──
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis-session:6379/0")

# ── Identity-bridge resolver (IP -> identiteit) ──
IDENTITY_BRIDGE_URL = os.environ.get("IDENTITY_BRIDGE_URL", "http://identity-bridge:8088")
IDENTITY_CACHE_TTL = float(os.environ.get("IDENTITY_CACHE_TTL", "30"))  # s, = bridge-refresh

# ── Scoring-spiegel (identiek aan control-daemon/app/config.py) ──
SCORE_WINDOW = int(os.environ.get("SCORE_WINDOW", "600"))          # 10 min sliding window
SCORE_QUARANTINE = int(os.environ.get("SCORE_QUARANTINE", "80"))   # drempel
# event_type -> gewicht. Spiegelt SCORE_WEIGHTS van de daemon (Verslag 35).
SCORE_WEIGHTS: dict[str, int] = {
    "malware": int(os.environ.get("WEIGHT_MALWARE", "80")),
    "dlp_match": int(os.environ.get("WEIGHT_DLP", "30")),
}
NETBIRD_POLICY_GROUPS = _list("NETBIRD_POLICY_GROUPS", "Studenten,Docenten,Admins")

# ── Opslag / retentie ──
DB_PATH = os.environ.get("DB_PATH", "/data/soc.db")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
PRUNE_INTERVAL_SEC = int(os.environ.get("PRUNE_INTERVAL_SEC", str(6 * 3600)))

# ── Pollers / server ──
SCORE_POLL_INTERVAL = float(os.environ.get("SCORE_POLL_INTERVAL", "2.0"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8090"))
DISPLAY_TZ = os.environ.get("DISPLAY_TZ", "Europe/Brussels")

# ── Subject -> event_type map (welke security-events tellen mee voor de score) ──
# De daemon dispatcht op het `producer`-veld; voor de UI-hint mappen we de
# subject-categorie naar het score-event_type. Niet-gescoorde categorieen
# (proxy/dns/ids/casb) zijn log-only, exact zoals de daemon.
CATEGORY_TO_EVENT_TYPE = {
    "malware": "malware",
    "dlp": "dlp_match",
}
