# SASE PoC

Open-source Secure Access Service Edge proof-of-concept gebouwd op GNS3/Proxmox. Configuratie, code en documentatie van de volledige SASE-stack.

**Doelklant:** Atlascollege — grote Belgische scholengroep met managed Windows devices.

---

## Architectuur

```
                          NetBird WireGuard Overlay (100.64.0.0/10)
                    ┌──────────────────┬──────────────────────────┐
                    │                  │                          │
              ┌─────┴─────┐     ┌──────┴──────┐          ┌───────┴───────┐
              │  mobile01  │     │    pop01    │          │    mgmt01    │
              │  (Windows) │     │ (OPNsense) │          │   (Docker)   │
              │  ZTNA client │     │  SWG + IDS  │          │ NetBird+WPAD │
              └───────────┘     └──────┬──────┘          └──────┬──────┘
                                       │                        │
                              ┌────────┴────────┐               │
                              │   DC-LAN        │        ioc2rpz, DLP ICAP,
                              │   10.0.0.0/24   │        Zitadel, Caddy
                              │   dc01          │
                              └─────────────────┘

              site01 (VyOS) — SASE Gateway / ZT-SDWAN
```

## Nodes

| VM | OS | IP (WAN) | Rol |
|---|---|---|---|
| pop01 | OPNsense/FreeBSD | 192.168.122.13 | SWG (Squid, SSL Bump), IDS (Suricata), DNS (BIND+Unbound RPZ), ClamAV/DLP |
| mgmt01 | Ubuntu + Docker | 192.168.122.23 | NetBird (Zitadel+Caddy), ioc2rpz, Python DLP ICAP, WPAD |
| site01 | VyOS | 192.168.122.33 | SASE Gateway, QoS, PBR |
| dc01 | Ubuntu | 10.0.0.100 | Gesimuleerde domain controller |
| mobile01 | Windows 11 | DHCP (VMware) | Managed client, NetBird enrolled |

## Repostructuur

```
config/
├── pop01/
│   ├── squid-pre-auth/      # Squid pre-auth includes (listeners, DLP ICAP, SNMP)
│   ├── suricata/            # Suricata IDS configuratie
│   ├── unbound/             # Unbound RPZ config
│   ├── bind/                # BIND 9.20 (TSIG secondary voor ioc2rpz)
│   └── config.xml           # OPNsense config (secrets geredacteerd)
├── mgmt01/
│   ├── netbird/             # Docker compose + Caddyfile (NetBird stack)
│   ├── dlp-icap/            # Docker compose (Python DLP ICAP server)
│   └── ioc2rpz/             # Docker compose (DNS threat intel feeds)
├── netbird/
│   └── wpad.dat             # PAC bestand voor proxy auto-discovery
└── site01/
    └── vyos-commands.txt    # VyOS configuratie export

code/
└── dlp-icap/
    └── dlp_icap_server.py   # Python DLP ICAP server (CC Luhn, IBAN mod-97, BSN 11-proof)

docs/
├── verslagen/               # Gespreksverslagen (audit trail)
└── addenda/                 # Architectuur- en implementatiedocumenten
```

## Wat zit hier NIET in

- **Secrets** — wachtwoorden, TSIG keys, setup keys, certificaten (`.gitignore`)
- **OPNsense GUI-configuratie** — de meeste Squid/Suricata/Unbound instellingen zitten in `config.xml`, niet in losse bestanden. De losse bestanden in deze repo zijn de configuratie die *buiten* de GUI valt
- **NetBird Dashboard configuratie** — ACL policies, groepen, DNS zones, Network Routes. Deze zijn alleen via de web UI configureerbaar
- **Entra ID configuratie** — app registrations, Conditional Access policies, tenant settings

## Operationele componenten (Fase 1-3)

| Component | Locatie | Status |
|---|---|---|
| Squid (expliciete proxy, SSL Bump) | pop01 :3128 | Operationeel via WPAD/PAC |
| ClamAV + c-icap (YARA, SDD) | pop01 | Operationeel |
| Python DLP ICAP (CC, IBAN, BSN) | mgmt01 :1345 | Operationeel |
| Suricata IDS (vtnet0 + vtnet1) | pop01 | Operationeel, ET Open rules |
| BIND 9.20 (TSIG secondary) | pop01 :53530 | Operationeel |
| ioc2rpz (URLhaus + ThreatFox) | mgmt01 | Operationeel, ~71.767 RPZ records |
| Unbound RPZ | pop01 | Operationeel |
| NetBird ZTNA (WireGuard mesh) | mgmt01 | Operationeel |
| WPAD/PAC discovery | mgmt01 (Caddy) | Operationeel |

## Commit-conventies

```
<type>(<scope>): <korte beschrijving>
```

Types: `feat`, `fix`, `config`, `docs`, `refactor`, `test`
Scopes: `pop01`, `mgmt01`, `site01`, `netbird`, `sitepc01`, `docs`, `dlp-icap`

## Documentatie

- **Wiki:** [arnevda-ap.github.io/sase-poc-wiki](https://arnevda-ap.github.io/sase-poc-wiki) — runbooks, component docs, beslissingsverantwoordingen, bevindingen
- **Verslagen:** chronologische audit trail van alle implementatie- en troubleshootingsessies
- **Addenda:** architectuurdocumenten per component/feature (A t/m J)
