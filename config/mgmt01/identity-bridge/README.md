# Identity Bridge — SASE PoC

SWG identity-based access control: vertaalt NetBird overlay-IP's naar Entra ID-identiteit/persona-groepen en levert die aan Squid, zodat de Secure Web Gateway op persona kan filteren i.p.v. op netwerkpositie.

## Architectuur

```
NetBird Mgmt API ──poll(30s)──> Identity Bridge (mgmt01, FastAPI) ──cache──> /lookup
                                                                                │ X-Bridge-Secret
Squid (pop01) ──%SRC (overlay-IP)──> external_acl helper ──HTTP──────────────────┘
                                          │ OK user=… / ERR
                                          v
                                   http_access deny <ai_chat> <persona_studenten>
```

Twee deploy-targets, één logische component:
- **Bridge** (`app/`, mgmt01 Docker) — pollt `/api/peers` + `/api/users`, bouwt een IP→identity→groups-cache, exposeert `/lookup` (shared-secret) + `/health` (open).
- **Squid-helper** (`squid/`, pop01) — `external_acl`-membership-oracle: beantwoordt "zit `<ip>` in `<groep>`?" tegen de bridge.

## ⚠️ Kritiek: NetBird service-user (issue #3127)

De bridge MOET authenticeren met een **NetBird service-user + PAT** (role `admin`), nooit een menselijk user-token. Een user-token van een user wiens auto-groups via JWT group sync naar peers zijn gepropageerd, **verwijdert die groepen van alle peers** bij elke API-call (NetBird #3127). Een service-user heeft geen gepropageerde groepen en geen peers → strip-veilig.

## Configuratie (`.env`, niet in git)

Kopieer `.env.example` → `.env` en vul in:

| Var | Waarde |
|---|---|
| `NETBIRD_API_URL` | `http://management:80/api` (Docker-intern) |
| `NETBIRD_API_TOKEN` | service-user PAT (`nbp_…`) |
| `LOOKUP_SECRET` | `openssl rand -hex 32` — identiek in de helper-secret-file |
| `REFRESH_INTERVAL` | `30` |
| `VERIFY_TLS` | `false` (intern, plain HTTP) |

## Deploy

**Bridge (mgmt01):**
```bash
cp .env.example .env && nano .env      # PAT + secret invullen
docker compose up -d --build
curl -s http://192.168.122.23:8088/health | python3 -m json.tool
```

**Helper (pop01):**
```bash
cp squid/squid_identity_helper.py /usr/local/etc/squid/identity_helper.py
chown root:squid /usr/local/etc/squid/identity_helper.py && chmod 750 ...
echo '<zelfde hex als LOOKUP_SECRET>' > /usr/local/etc/squid/identity_bridge.secret
chown root:squid ... && chmod 640 ...
cp squid/netbird-identity.conf /usr/local/etc/squid/pre-auth/   # NIET post-auth (laadt ná deny all)
configctl proxy reload
```

## Ontwerp-eigenschappen

- **Fail-open op de SWG-laag:** bridge onbereikbaar / IP onbekend → helper `ERR` → verkeer valt terug op de generieke `http_access`-keten (URL-filtering/ClamAV/DLP blijven). Bewuste keuze (false-positives op 4000 users niet het hele net laten raken). Fail-closed zit op de NetBird policy-laag.
- **Most-restrictive multi-persona:** de helper is een domme membership-oracle; de persona-resolutie zit in de `http_access`-volgorde (cumulatieve deny's = doorsnede van het toegestane). Multi-persona membership wordt als anomalie gelogd (`identity.multi_persona`, NATS-ready).
- **Identity-anker:** het overlay-IP is via WireGuard cryptokey-routing onspoofbaar gebonden aan de peer — dezelfde trust-root als de ZTNA-laag.

## Status / open

- 2a (deze component) operationeel; Studenten→ChatGPT-deny live bewezen.
- Open: docent-spiegel + volledige persona-matrix (Sessie 11), overlay-listener bind-race hardening, PAT 365d-rotatie, bridge max-staleness-eviction. Zie Verslag 31.
