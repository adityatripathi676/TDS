from __future__ import annotations

import json
import sqlite3
from threading import Lock
from typing import Any

from app.config import DATA_DIR, DB_PATH, DEFAULT_STORE, SAMPLE_EVENTS_PATH


from contextlib import contextmanager


class SqliteStore:
    def __init__(self, db_path=DB_PATH) -> None:
        self.db_path = db_path
        self._lock = Lock()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    host TEXT,
                    user TEXT,
                    event_type TEXT,
                    process_name TEXT,
                    source_ip TEXT,
                    command_line TEXT,
                    metadata_json TEXT,
                    created_at TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    event_id TEXT,
                    host TEXT,
                    score REAL,
                    severity TEXT,
                    summary TEXT,
                    reasons_json TEXT,
                    recommendations_json TEXT,
                    mitre_tags_json TEXT,
                    anomaly_score REAL,
                    rule_score REAL,
                    event_json TEXT,
                    created_at TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);")

    def append_event(self, event: dict[str, Any]) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO events (
                    id, timestamp, host, user, event_type, process_name, source_ip, command_line, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.get("id"),
                    event.get("timestamp"),
                    event.get("host"),
                    event.get("user"),
                    event.get("event_type"),
                    event.get("process_name"),
                    event.get("source_ip"),
                    event.get("command_line", ""),
                    json.dumps(event.get("metadata", {})),
                    event.get("created_at"),
                ),
            )

    def append_alert(self, alert: dict[str, Any]) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    id, event_id, host, score, severity, summary, reasons_json, recommendations_json, mitre_tags_json, anomaly_score, rule_score, event_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    alert.get("id"),
                    alert.get("event_id"),
                    alert.get("host"),
                    float(alert.get("score", 0.0)),
                    alert.get("severity"),
                    alert.get("summary"),
                    json.dumps(alert.get("reasons", [])),
                    json.dumps(alert.get("recommendations", [])),
                    json.dumps(alert.get("mitre_tags", [])),
                    float(alert.get("anomaly_score", 0.0)),
                    float(alert.get("rule_score", 0.0)),
                    json.dumps(alert.get("event", {})),
                    alert.get("created_at"),
                ),
            )

    def _row_to_event(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        return item

    def _row_to_alert(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["reasons"] = json.loads(item.pop("reasons_json") or "[]")
        item["recommendations"] = json.loads(item.pop("recommendations_json") or "[]")
        item["mitre_tags"] = json.loads(item.pop("mitre_tags_json") or "[]")
        item["event"] = json.loads(item.pop("event_json") or "{}")
        return item

    def get_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT ?;", (limit,))
            return [self._row_to_event(row) for row in cursor.fetchall()]

    def get_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM alerts ORDER BY rowid DESC LIMIT ?;", (limit,))
            return [self._row_to_alert(row) for row in cursor.fetchall()]

    def read(self) -> dict[str, list[dict[str, Any]]]:
        # Return dict with full historical records for backwards compatibility
        return {
            "events": self.get_events(limit=500),
            "alerts": self.get_alerts(limit=500),
        }

    def reset(self) -> None:
        with self._lock, self._connection() as conn:
            conn.execute("DELETE FROM events;")
            conn.execute("DELETE FROM alerts;")

    def load_sample_events(self) -> list[dict[str, Any]]:
        if not SAMPLE_EVENTS_PATH.exists():
            return []
        with SAMPLE_EVENTS_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)


# Alias JsonStore to SqliteStore for seamless drop-in compatibility across codebase
JsonStore = SqliteStore
