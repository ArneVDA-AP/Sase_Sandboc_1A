# RECOVERY — SASE PoC Sandbox

**Waarom dit document bestaat:** de GroupSync-keten (en delen van de bredere stack) spant systemen waarvan de staat **niet in deze git-repo zit**. De repo is daardoor géén volledige source of truth. Dit document mapt waar elke staat leeft en hoe je 'm herstelt.

Suggestie voor de README — voeg één pointer-regel toe:
> **Recovery & backups:** zie [`RECOVERY.md`](./RECOVERY.md). De repo bevat config-bron + docs; Entra/Zitadel/NetBird-state vereist aparte backup.

---

## Waar leeft welke staat

| Systeem | Staat | In de repo? | Hersteldekking |
|---|---|---|---|
| **Git-repo** | Zitadel Action-scripts (`config/zitadel/actions/*.js`), docs/verslagen | ✅ ja | volledig |
| **Entra ID** | App Registration, token-config, Enterprise-App-toewijzingen, persona-groepen | ⚠️ alleen gedocumenteerd | `config/entra/2ITCSC1A-Netbird-Sandbox.entra-config.md` |
| **Zitadel-DB** (postgres `netbird-deploy-zdb-1`) | external-IdP-config, **action↔flow-bindings**, users/orgs | ❌ nee | DB-backup vereist (zie onder) |
| **NetBird-DB** (SQLite) | JWT-sync-instelling, claim-naam, propagation, peers, groepen, policies, setup-keys | ❌ nee | DB-backup vereist (zie onder) |

**Let op de Zitadel-DB-regel:** de `.js`-scripts staan in de repo, maar de **koppeling** van die actions aan de flows (External Authentication → Post Authentication; Complement Token → beide triggers) zit in de DB. Herstel vanuit de repo = scripts opnieuw plakken **én** opnieuw koppelen aan de flows. De koppelstap staat in de header van elk `.js`-bestand.

---

## Herstel per systeem

### Entra ID
Handmatig herbouwen vanuit `config/entra/2ITCSC1A-Netbird-Sandbox.entra-config.md`. Bevat alle ID's, de manifest-velden, de toewijzingen en de cloud-only-eis. Secret-waarde staat daar bewust niet in (secret store) — bij herbouw genereer een nieuw secret en voer het in de Zitadel-IdP-config in.

### Zitadel Actions (code)
Uit `config/zitadel/actions/`: beide scripts in de console plakken (Action-naam = functienaam), dan koppelen aan de flows per de header-instructies.

### Zitadel-DB (postgres) — ⚠️ TODO: backup-script maken
```bash
# Verifieer eerst DB-naam en user (uit de container-env of de compose):
docker exec netbird-deploy-zdb-1 env | grep -i postgres

# Dump (vervang user/db door de werkelijke waarden):
docker exec -t netbird-deploy-zdb-1 pg_dump -U <pg_user> <pg_db> \
  > backups/zitadel-$(date +%F).sql
```

### NetBird-DB (SQLite) — ⚠️ TODO: backup-script maken
NetBird-management gebruikt in deze stack een SQLite-store (bevestigd door #5399: herstel vereist "direct SQLite database intervention"). Locatie staat niet vast — verifieer de volume-mount:
```bash
# Vind het store-pad en management.json via de mounts:
docker inspect netbird-deploy-management-1 \
  --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'

# Hot-backup van de SQLite-store (pas pad aan naar de gevonden mount):
sqlite3 <pad>/store.db ".backup backups/netbird-store-$(date +%F).db"

# En management.json mee-backuppen (config + IdP-issuer/clientID):
cp <pad>/management.json backups/management-$(date +%F).json
```

> Verifieer of de store werkelijk `store.db` heet en waar 'ie gemount staat — niet aannemen. De `.backup`-methode is veilig tijdens runtime; een kale `cp` van een live SQLite-bestand kan corrupt zijn.

---

## TODO (los van de implementatiesessies)
- [ ] Backup-script (Zitadel pg_dump + NetBird SQLite `.backup` + management.json) + cron op mgmt01.
- [ ] `backups/` toevoegen aan `.gitignore` (dumps horen niet in git — wel offsite/secure opslaan).
- [ ] Secret-rotatie Zitadel-federation vóór **29/05/2028** (Verslag 30 open punt 2).
- [ ] Entra-config-doc bijwerken bij elke wijziging aan de app.
