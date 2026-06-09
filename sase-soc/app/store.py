"""
SQLite-opslag voor 30 dagen geschiedenis met geïndexeerde filters.

Twee tabellen:
  events   : elk genormaliseerd bus-event (voor de live feed + historische filter)
  timeline : afgeleide enforcement-gebeurtenissen (drempel overschreden,
             quarantaine actief/opgeheven, actie mislukt) -> de audit-tijdlijn

Retentie: nachtelijke prune verwijdert alles ouder dan RETENTION_DAYS.
Tijd: we sorteren/prunen op ts_ingest (server-ingestietijd) — Verslag-les
('time.time() als timestamp') vermijdt tijdzone-vergiftiging. ts_epoch (bron)
bewaren we apart voor weergave.
"""
import json
import logging
import time
from typing import Any, Optional

import aiosqlite

from app import config

log = logging.getLogger("soc.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ingest   REAL NOT NULL,
    ts_epoch    REAL,
    subject     TEXT,
    producer    TEXT,
    category    TEXT,
    actor_type  TEXT,
    actor_ip    TEXT,
    actor_user  TEXT,
    actor_persona TEXT,
    actor_display TEXT,
    severity    TEXT,
    summary     TEXT,
    scored      INTEGER DEFAULT 0,
    weight      INTEGER DEFAULT 0,
    notable     INTEGER DEFAULT 0,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts       ON events(ts_ingest);
CREATE INDEX IF NOT EXISTS ix_events_cat      ON events(category);
CREATE INDEX IF NOT EXISTS ix_events_producer ON events(producer);
CREATE INDEX IF NOT EXISTS ix_events_persona  ON events(actor_persona);
CREATE INDEX IF NOT EXISTS ix_events_user     ON events(actor_user);

CREATE TABLE IF NOT EXISTS timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ingest   REAL NOT NULL,
    kind        TEXT,           -- threshold_crossed | quarantine_active | quarantine_cleared | action_failed
    actor_ip    TEXT,
    actor_id    TEXT,           -- peer_id (voor quarantaine)
    actor_display TEXT,
    score       INTEGER,
    detail      TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS ix_timeline_ts   ON timeline(ts_ingest);
CREATE INDEX IF NOT EXISTS ix_timeline_kind ON timeline(kind);
"""


class Store:
    def __init__(self) -> None:
        self._db: Optional[aiosqlite.Connection] = None

    async def start(self) -> None:
        self._db = await aiosqlite.connect(config.DB_PATH)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        await self.prune()

    async def stop(self) -> None:
        if self._db:
            await self._db.close()

    async def insert_event(self, ev: dict) -> None:
        await self._db.execute(
            """INSERT INTO events
               (ts_ingest, ts_epoch, subject, producer, category, actor_type,
                actor_ip, actor_user, actor_persona, actor_display, severity,
                summary, scored, weight, notable, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (time.time(), ev.get("ts_epoch"), ev.get("subject"), ev.get("producer"),
             ev.get("category"), ev.get("actor_type"), ev.get("actor_ip"),
             ev.get("actor_user"), ev.get("actor_persona"), ev.get("actor_display"),
             ev.get("severity"), ev.get("summary"), int(bool(ev.get("scored"))),
             int(ev.get("weight") or 0), int(bool(ev.get("notable"))),
             json.dumps(ev.get("raw"), default=str)),
        )
        await self._db.commit()

    async def insert_timeline(self, item: dict) -> None:
        await self._db.execute(
            """INSERT INTO timeline
               (ts_ingest, kind, actor_ip, actor_id, actor_display, score, detail, raw)
               VALUES (?,?,?,?,?,?,?,?)""",
            (time.time(), item.get("kind"), item.get("actor_ip"), item.get("actor_id"),
             item.get("actor_display"), item.get("score"), item.get("detail"),
             json.dumps(item.get("raw"), default=str)),
        )
        await self._db.commit()

    async def query_events(self, *, since: Optional[float] = None, category: Optional[str] = None,
                           producer: Optional[str] = None, persona: Optional[str] = None,
                           user: Optional[str] = None, q: Optional[str] = None,
                           limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM events WHERE 1=1"
        args: list[Any] = []
        if since:
            sql += " AND ts_ingest >= ?"; args.append(since)
        if category:
            sql += " AND category = ?"; args.append(category)
        if producer:
            sql += " AND producer = ?"; args.append(producer)
        if persona:
            sql += " AND actor_persona = ?"; args.append(persona)
        if user:
            sql += " AND actor_user = ?"; args.append(user)
        if q:
            sql += " AND (summary LIKE ? OR actor_display LIKE ? OR actor_ip LIKE ?)"
            like = f"%{q}%"; args += [like, like, like]
        sql += " ORDER BY id DESC LIMIT ?"; args.append(max(1, min(limit, 1000)))
        cur = await self._db.execute(sql, args)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def query_events_balanced(self, per_category: int = 60,
                                     total_cap: int = 500) -> list[dict]:
        """Laatste N events van ELKE categorie, samengevoegd en gesorteerd op tijd.
        Voorkomt dat hoogfrequente categorieen (proxy) de zeldzame verdringen."""
        cur = await self._db.execute("SELECT DISTINCT category FROM events")
        cats = [r["category"] for r in await cur.fetchall()]
        out: list[dict] = []
        for cat in cats:
            cur = await self._db.execute(
                "SELECT * FROM events WHERE category = ? ORDER BY id DESC LIMIT ?",
                (cat, per_category),
            )
            out.extend([dict(r) for r in await cur.fetchall()])
        # nieuwste eerst op BRON-tijd (ts_epoch); val terug op ingest-tijd
        # voor events zonder bron-timestamp (identity/ids). Tijdens replay
        # hebben alle rijen ~dezelfde ts_ingest, dus ts_epoch is leidend.
        out.sort(key=lambda r: (r.get("ts_epoch") or r.get("ts_ingest") or 0),
                 reverse=True)
        return out[:total_cap]

    async def query_timeline(self, *, since: Optional[float] = None,
                             kind: Optional[str] = None, limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM timeline WHERE 1=1"
        args: list[Any] = []
        if since:
            sql += " AND ts_ingest >= ?"; args.append(since)
        if kind:
            sql += " AND kind = ?"; args.append(kind)
        sql += " ORDER BY id DESC LIMIT ?"; args.append(max(1, min(limit, 1000)))
        cur = await self._db.execute(sql, args)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def prune(self) -> int:
        cutoff = time.time() - config.RETENTION_DAYS * 86400
        c1 = await self._db.execute("DELETE FROM events WHERE ts_ingest < ?", (cutoff,))
        c2 = await self._db.execute("DELETE FROM timeline WHERE ts_ingest < ?", (cutoff,))
        await self._db.commit()
        n = (c1.rowcount or 0) + (c2.rowcount or 0)
        if n:
            log.info("prune: %d rijen ouder dan %dd verwijderd", n, config.RETENTION_DAYS)
        return n

    async def counts(self) -> dict:
        cur = await self._db.execute("SELECT COUNT(*) AS n FROM events")
        e = (await cur.fetchone())["n"]
        cur = await self._db.execute("SELECT COUNT(*) AS n FROM timeline")
        t = (await cur.fetchone())["n"]
        return {"events": e, "timeline": t}
