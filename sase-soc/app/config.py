"""
Centrale configuratie — alle waarden uit environment (.env).
Scoring-constanten spiegelen de control-daemon (Verslag 35).
"""
import os


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# ── NATS ──
NATS_URL              = os.environ.get("NATS_URL", "nats://nats:4222")
NATS_USER             = os.environ.get("NATS_USER", "control-daemon")
NATS_PASS             = os.environ.get("NATS_DAEMON_PASS", "")
SECURITY_SUBJECT      = os.environ.get("SECURITY_SUBJECT", "security.alert.>")
IDENTITY_SUBJECT      = os.environ.get("IDENTITY_SUBJECT", "identity.>")
ACTION_FAILED_SUBJECT = os.environ.get("ACTION_FAILED_SUBJECT", "control.action.failed")

# ── Redis ──
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis-session:6379/0")

# ── Identity-bridge ──
IDENTITY_BRIDGE_URL = os.environ.get("IDENTITY_BRIDGE_URL", "http://identity-bridge:8088")
IDENTITY_CACHE_TTL  = float(os.environ.get("IDENTITY_CACHE_TTL", "30"))

# ── Scoring (identiek aan daemon) ──
SCORE_WINDOW     = int(os.environ.get("SCORE_WINDOW", "600"))
SCORE_QUARANTINE = int(os.environ.get("SCORE_QUARANTINE", "80"))
SCORE_WEIGHTS: dict[str, int] = {
    "malware":   int(os.environ.get("WEIGHT_MALWARE", "80")),
    "dlp_match": int(os.environ.get("WEIGHT_DLP", "30")),
}
NETBIRD_POLICY_GROUPS = _list("NETBIRD_POLICY_GROUPS", "Studenten,Docenten,Admins")
CATEGORY_TO_EVENT_TYPE = {"malware": "malware", "dlp": "dlp_match"}

# ── NetBird API (Fase 4b — handmatige quarantaine) ──
# Normaliseer: strip trailing slash én een eventueel reeds aanwezige /api,
# zodat de client altijd zelf /api/... toevoegt (voorkomt dubbele /api/api/).
_nb_url = os.environ.get("NETBIRD_API_URL", "https://netbird.sandbox.local").rstrip("/")
if _nb_url.endswith("/api"):
    _nb_url = _nb_url[:-4]
NETBIRD_API_URL            = _nb_url
NETBIRD_API_TOKEN          = os.environ.get("NETBIRD_API_TOKEN", "")
NETBIRD_QUARANTINE_GROUP_ID = os.environ.get("NETBIRD_QUARANTINE_GROUP_ID", "d8ecpedv0c4s73aaq6s0")
NETBIRD_CA_CERT            = os.environ.get("NETBIRD_CA_CERT", "/certs/caddy-root.crt")
NETBIRD_BREAK_GLASS        = set(_list("NETBIRD_BREAK_GLASS", "admin.1a,arne.vda,mgmt01"))

# ── Opslag / retentie ──
DB_PATH            = os.environ.get("DB_PATH", "/data/soc.db")
RETENTION_DAYS     = int(os.environ.get("RETENTION_DAYS", "30"))
PRUNE_INTERVAL_SEC = int(os.environ.get("PRUNE_INTERVAL_SEC", str(6 * 3600)))

# ── Pollers / server ──
SCORE_POLL_INTERVAL = float(os.environ.get("SCORE_POLL_INTERVAL", "2.0"))
HTTP_PORT           = int(os.environ.get("HTTP_PORT", "8090"))
DISPLAY_TZ          = os.environ.get("DISPLAY_TZ", "Europe/Brussels")

# ── Identity-bridge secret (Fase fix — X-Bridge-Secret header) ──
# Waarde ophalen: sudo grep LOOKUP_SECRET /opt/identity-bridge/.env (of docker inspect)
IDENTITY_BRIDGE_SECRET = os.environ.get("IDENTITY_BRIDGE_SECRET", "")
