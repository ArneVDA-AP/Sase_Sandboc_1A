"""
Normaliseert de twee verschillende bus-schema's naar één gemeenschappelijk model.

Twee echte schema's (recon B):
  native (malware/dlp/proxy/dns):
    {timestamp, ts_epoch, client_ip(overlay), signature, url, user, producer}
  casb/o365:
    {CreationTime, Operation, Workload, UserId(email), ClientIP(public),
     SourceFileName, ObjectId, SharingLinkScope, TargetUserOrGroupName, producer:"o365", ts_epoch}
  ids/suricata (Verslag 35):
    {src_ip(remote), alert:{severity,signature}, producer:"suricata"}  -> niet peer-attribueerbaar

Output: één dict. Identiteits-resolutie (IP->naam) gebeurt NIET hier maar in main
(want dat is async); hier zetten we wel actor_type + actor_ip/actor_user klaar.
"""
import json
from typing import Any

from app import config


def _epoch(data: dict) -> float:
    for k in ("ts_epoch", "epoch"):
        if isinstance(data.get(k), (int, float)):
            return float(data[k])
    return 0.0


def _category(subject: str) -> str:
    # security.alert.malware -> malware ; identity.peer.connected -> identity
    parts = subject.split(".")
    if subject.startswith("security.alert."):
        return parts[-1]
    if subject.startswith("identity."):
        return "identity"
    if subject.startswith("control."):
        return "control"
    return parts[-1] if parts else subject


def normalize(subject: str, raw_bytes: bytes) -> dict:
    try:
        data = json.loads(raw_bytes.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        data = {"_unparsed": raw_bytes.decode("utf-8", "replace")[:500]}

    cat = _category(subject)
    producer = (data.get("producer") or "").lower()
    ev: dict[str, Any] = {
        "ts_epoch": _epoch(data) or None,
        "subject": subject,
        "category": cat,
        "producer": producer or None,
        "actor_type": "unknown",   # peer | user | external | system
        "actor_ip": None,
        "actor_user": None,
        "severity": None,
        "summary": "",
        "scored": False,
        "weight": 0,
        "notable": False,          # bv. anonieme/org-brede share
        "raw": data,
    }

    if subject.startswith("identity."):
        ev["actor_type"] = "system"
        ip = data.get("ip") or data.get("client_ip")
        ev["actor_ip"] = ip
        if cat == "identity" and "." in subject:
            kind = subject.split(".", 1)[1]  # peer.connected / multi_persona / bridge.degraded
        else:
            kind = subject
        ev["summary"] = f"identity: {kind}"
        if "degraded" in subject:
            ev["severity"] = "warning"
        return ev

    if subject.startswith("control."):
        ev["actor_type"] = "system"
        ev["actor_ip"] = data.get("peer_ip")
        ev["severity"] = "warning"
        ev["summary"] = f"control: {data.get('reason') or data.get('action') or subject}"
        return ev

    # ── security.alert.* ──
    if producer == "o365" or cat == "casb":
        ev["actor_type"] = "user"
        ev["actor_user"] = data.get("UserId") or data.get("user")
        ev["raw_public_ip"] = data.get("ClientIP")
        op = data.get("Operation", "")
        wl = data.get("Workload", "")
        fname = data.get("SourceFileName") or data.get("ObjectId") or ""
        ev["summary"] = " ".join(x for x in (op, wl, fname) if x).strip() or "CASB-event"
        # anonieme / organisatiebrede deel-link = noemenswaardig CASB-signaal
        scope = str(data.get("SharingLinkScope", "")).lower()
        tgt = str(data.get("TargetUserOrGroupName", "")).lower()
        if op in ("AnonymousLinkCreated", "AddedToSecureLink") or "anonymous" in scope \
                or "organizationview" in tgt or "anonymous" in tgt:
            ev["notable"] = True
            ev["severity"] = "warning"
        return ev

    if producer == "suricata" or cat == "ids":
        ev["actor_type"] = "external"
        ev["actor_ip"] = data.get("src_ip")  # remote scanner, niet onze peer
        alert = data.get("alert") or {}
        ev["severity"] = str(alert.get("severity") or data.get("severity") or "")
        sig = alert.get("signature") or data.get("signature") or ""
        ev["summary"] = f"IDS: {sig}".strip() or "IDS-alert"
        return ev

    # native peer-attribueerbaar (malware/dlp/proxy/dns)
    ev["actor_type"] = "peer"
    ev["actor_ip"] = data.get("client_ip")
    ev["actor_user"] = data.get("user")  # vaak null -> resolven in main
    sig = data.get("signature") or ""
    url = data.get("url") or data.get("domain") or data.get("category") or ""
    ev["summary"] = " ".join(x for x in (sig, url) if x).strip() or f"{cat}-event"
    # score-hint (spiegelt de daemon: alleen malware + dlp tellen mee)
    etype = config.CATEGORY_TO_EVENT_TYPE.get(cat)
    if etype and etype in config.SCORE_WEIGHTS:
        ev["scored"] = True
        ev["weight"] = config.SCORE_WEIGHTS[etype]
    return ev
