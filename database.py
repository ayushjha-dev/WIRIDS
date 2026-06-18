"""WIDIRS async SQLite persistence layer (aiosqlite)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import aiosqlite
import structlog

logger = structlog.get_logger(__name__)

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sites (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL DEFAULT '',
    scan_interval   INTEGER NOT NULL DEFAULT 300,
    alert_threshold TEXT NOT NULL DEFAULT 'medium',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    html_hash       TEXT NOT NULL,
    screenshot_path TEXT NOT NULL DEFAULT '',
    html_path       TEXT NOT NULL DEFAULT '',
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    report_id   TEXT NOT NULL DEFAULT '',
    risk_score  REAL NOT NULL DEFAULT 0,
    threat_type TEXT NOT NULL DEFAULT 'unknown',
    severity    TEXT NOT NULL DEFAULT 'low',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    value       TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    confidence  REAL NOT NULL DEFAULT 0.5,
    context     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS ti_cache (
    key        TEXT PRIMARY KEY,
    data_json  TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    html_path   TEXT NOT NULL DEFAULT '',
    pdf_path    TEXT NOT NULL DEFAULT '',
    sha256      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    channel     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    sent_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_snapshots_site   ON snapshots(site_id, created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_site   ON incidents(site_id, created_at);
CREATE INDEX IF NOT EXISTS idx_iocs_incident    ON iocs(incident_id);
CREATE INDEX IF NOT EXISTS idx_reports_incident ON reports(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident  ON alerts(incident_id);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Async SQLite wrapper. Use as an async context manager or call
    connect()/close() explicitly."""

    def __init__(self, db_path: Union[str, Path]) -> None:
        self.db_path = Path(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def connect(self) -> "Database":
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()
        logger.info("database_initialized", path=str(self.db_path))
        return self

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> "Database":
        return await self.connect()

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    # ------------------------------------------------------------------
    # Sites
    # ------------------------------------------------------------------
    async def upsert_site(
        self,
        url: str,
        name: str = "",
        scan_interval: int = 300,
        alert_threshold: str = "medium",
    ) -> int:
        cur = await self.conn.execute(
            """INSERT INTO sites (url, name, scan_interval, alert_threshold)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(url) DO UPDATE SET
                 name = excluded.name,
                 scan_interval = excluded.scan_interval,
                 alert_threshold = excluded.alert_threshold
               RETURNING id""",
            (url, name, scan_interval, alert_threshold),
        )
        row = await cur.fetchone()
        await self.conn.commit()
        return int(row["id"])

    async def get_site_by_url(self, url: str) -> Optional[Dict[str, Any]]:
        cur = await self.conn.execute("SELECT * FROM sites WHERE url = ?", (url,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def list_sites(self) -> List[Dict[str, Any]]:
        cur = await self.conn.execute("SELECT * FROM sites ORDER BY id")
        return [dict(r) for r in await cur.fetchall()]

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------
    async def insert_snapshot(
        self,
        site_id: int,
        html_hash: str,
        screenshot_path: str = "",
        html_path: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        cur = await self.conn.execute(
            """INSERT INTO snapshots
               (site_id, html_hash, screenshot_path, html_path, metadata_json)
               VALUES (?, ?, ?, ?, ?)""",
            (site_id, html_hash, screenshot_path, html_path,
             json.dumps(metadata or {})),
        )
        await self.conn.commit()
        return int(cur.lastrowid)

    async def get_latest_snapshot(self, site_id: int) -> Optional[Dict[str, Any]]:
        cur = await self.conn.execute(
            """SELECT * FROM snapshots WHERE site_id = ?
               ORDER BY created_at DESC, id DESC LIMIT 1""",
            (site_id,),
        )
        row = await cur.fetchone()
        return dict(row) if row else None

    async def get_baseline_snapshot(self, site_id: int) -> Optional[Dict[str, Any]]:
        cur = await self.conn.execute(
            """SELECT * FROM snapshots WHERE site_id = ?
               ORDER BY created_at ASC, id ASC LIMIT 1""",
            (site_id,),
        )
        row = await cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------
    async def insert_incident(
        self,
        site_id: int,
        report_id: str,
        risk_score: float,
        threat_type: str,
        severity: str,
    ) -> int:
        cur = await self.conn.execute(
            """INSERT INTO incidents
               (site_id, report_id, risk_score, threat_type, severity)
               VALUES (?, ?, ?, ?, ?)""",
            (site_id, report_id, risk_score, threat_type, severity),
        )
        await self.conn.commit()
        return int(cur.lastrowid)

    async def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        )
        row = await cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------
    async def insert_iocs(
        self, incident_id: int, iocs: List[Dict[str, Any]]
    ) -> int:
        await self.conn.executemany(
            """INSERT INTO iocs (incident_id, value, ioc_type, confidence, context)
               VALUES (?, ?, ?, ?, ?)""",
            [
                (
                    incident_id,
                    i["value"],
                    i.get("ioc_type", "url"),
                    float(i.get("confidence", 0.5)),
                    i.get("context", ""),
                )
                for i in iocs
            ],
        )
        await self.conn.commit()
        return len(iocs)

    async def get_iocs_for_incident(self, incident_id: int) -> List[Dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM iocs WHERE incident_id = ?", (incident_id,)
        )
        return [dict(r) for r in await cur.fetchall()]

    # ------------------------------------------------------------------
    # Threat-intel cache
    # ------------------------------------------------------------------
    async def ti_cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT data_json, expires_at FROM ti_cache WHERE key = ?", (key,)
        )
        row = await cur.fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            await self.conn.execute("DELETE FROM ti_cache WHERE key = ?", (key,))
            await self.conn.commit()
            return None
        return json.loads(row["data_json"])

    async def ti_cache_set(
        self, key: str, data: Dict[str, Any], ttl_hours: int = 24
    ) -> None:
        expires = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        await self.conn.execute(
            """INSERT INTO ti_cache (key, data_json, expires_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                 data_json = excluded.data_json,
                 expires_at = excluded.expires_at""",
            (key, json.dumps(data), expires.isoformat()),
        )
        await self.conn.commit()

    async def ti_cache_purge_expired(self) -> int:
        cur = await self.conn.execute(
            "DELETE FROM ti_cache WHERE expires_at < ?", (_now_iso(),)
        )
        await self.conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    async def insert_report(
        self, incident_id: int, html_path: str, pdf_path: str, sha256: str
    ) -> int:
        cur = await self.conn.execute(
            """INSERT INTO reports (incident_id, html_path, pdf_path, sha256)
               VALUES (?, ?, ?, ?)""",
            (incident_id, html_path, pdf_path, sha256),
        )
        await self.conn.commit()
        return int(cur.lastrowid)

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    async def insert_alert(
        self, incident_id: int, channel: str, status: str = "pending"
    ) -> int:
        cur = await self.conn.execute(
            "INSERT INTO alerts (incident_id, channel, status, sent_at) "
            "VALUES (?, ?, ?, ?)",
            (incident_id, channel, status,
             _now_iso() if status == "sent" else None),
        )
        await self.conn.commit()
        return int(cur.lastrowid)

    async def mark_alert_sent(self, alert_id: int, status: str = "sent") -> None:
        await self.conn.execute(
            "UPDATE alerts SET status = ?, sent_at = ? WHERE id = ?",
            (status, _now_iso(), alert_id),
        )
        await self.conn.commit()
