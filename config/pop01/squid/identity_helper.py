"""
SASE PoC — Squid external_acl membership-oracle.

Squid-protocol (concurrency=0): leest per regel '<ip> <group>' van stdin,
antwoordt 'OK [user=...]' of 'ERR' op stdout, één regel per request.

De helper is een DOMME oracle: hij beantwoordt enkel "zit <ip> in <group>?".
De multi-persona-resolutie (most-restrictive) leeft in de http_access-volgorde
op Squid, NIET hier.

Fail-open (vastgelegde SWG-beslissing): bridge onbereikbaar, IP onbekend, of
elke andere fout -> 'ERR'. ERR betekent "geen persona-match", waardoor de
persona-deny's niet vuren en het verkeer terugvalt op de generieke
http_access-keten (URL-filtering/ClamAV/DLP blijven actief). De helper laat
nooit verkeer hard vallen op een identity-probleem.

Argumenten (vast, op de external_acl_type-regel):
    argv[1] = bridge base URL   (bv. http://192.168.122.23:8088)
    argv[2] = pad naar secret-file (één regel: de LOOKUP_SECRET, mode 0640)

Geen externe dependencies (stdlib urllib) — OPNsense/FreeBSD heeft geen pip-flow.
"""

import sys
import json
import urllib.request
import urllib.parse

TIMEOUT = 3.0  # seconden; bridge is lokaal op het mgmt-LAN, kort houden


def log_err(msg: str):
    """Naar stderr -> Squid cache.log. Spaarzaam, geen per-request spam."""
    sys.stderr.write(f"[identity-helper] {msg}\n")
    sys.stderr.flush()


def load_secret(path: str) -> str:
    with open(path, "r") as f:
        return f.read().strip()


def lookup(bridge_url: str, secret: str, ip: str) -> tuple[set, str]:
    """Geeft (groepen-set, user) terug. Bij elk probleem: (lege set, "")."""
    url = f"{bridge_url.rstrip('/')}/lookup?ip={urllib.parse.quote(ip)}"
    req = urllib.request.Request(url, headers={"X-Bridge-Secret": secret})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        # Fail-open: bridge down / timeout / 401 -> behandel als "geen groepen"
        log_err(f"lookup failed for {ip}: {e}")
        return set(), ""
    if data.get("status") != "OK":
        return set(), ""
    return set(data.get("groups", [])), data.get("user", "")


def main():
    if len(sys.argv) < 3:
        log_err("usage: helper.py <bridge_url> <secret_file>")
        sys.exit(1)

    bridge_url = sys.argv[1]
    try:
        secret = load_secret(sys.argv[2])
    except Exception as e:
        log_err(f"kan secret niet lezen ({sys.argv[2]}): {e}")
        sys.exit(1)

    # Per-request lus. EOF (Squid sluit de helper) -> nette exit.
    for line in sys.stdin:
        line = line.strip()
        if not line:
            sys.stdout.write("ERR\n")
            sys.stdout.flush()
            continue

        parts = line.split()
        ip = parts[0]
        # groepsnaam kan in theorie spaties bevatten; onze persona's niet,
        # maar defensief samenvoegen
        group = " ".join(parts[1:]) if len(parts) > 1 else ""

        groups, user = lookup(bridge_url, secret, ip)

        if group and group in groups:
            if user:
                sys.stdout.write(f"OK user={user}\n")
            else:
                sys.stdout.write("OK\n")
        else:
            sys.stdout.write("ERR\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
