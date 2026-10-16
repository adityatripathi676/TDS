from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from app.core.storage import SqliteStore


class SqliteStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_tds.db"
        self.store = SqliteStore(db_path=self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_database_initialization(self) -> None:
        self.assertTrue(self.db_path.exists())

    def test_append_and_get_events(self) -> None:
        event = {
            "id": "evt-1001",
            "timestamp": "2026-09-17T11:55:00Z",
            "host": "test-host",
            "user": "test-user",
            "event_type": "process_start",
            "process_name": "cmd.exe",
            "source_ip": "127.0.0.1",
            "command_line": "cmd.exe /c dir",
            "metadata": {"failed_login_count": 0},
            "created_at": "2026-09-17T11:55:00Z",
        }
        self.store.append_event(event)

        events = self.store.get_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], "evt-1001")
        self.assertEqual(events[0]["host"], "test-host")
        self.assertEqual(events[0]["metadata"]["failed_login_count"], 0)

    def test_append_and_get_alerts(self) -> None:
        alert = {
            "id": "alt-2001",
            "event_id": "evt-1001",
            "host": "test-host",
            "score": 85.5,
            "severity": "critical",
            "summary": "Critical Threat Detected",
            "reasons": ["suspicious process: mimikatz.exe"],
            "recommendations": ["isolate host"],
            "mitre_tags": ["T1003 OS Credential Dumping"],
            "anomaly_score": 35.0,
            "rule_score": 60.0,
            "event": {"id": "evt-1001"},
            "created_at": "2026-09-17T11:55:00Z",
        }
        self.store.append_alert(alert)

        alerts = self.store.get_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], "alt-2001")
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertIn("T1003 OS Credential Dumping", alerts[0]["mitre_tags"])

    def test_reset_clears_tables(self) -> None:
        event = {"id": "evt-99", "host": "h1", "user": "u1", "event_type": "test", "metadata": {}}
        self.store.append_event(event)
        self.assertEqual(len(self.store.get_events()), 1)

        self.store.reset()
        self.assertEqual(len(self.store.get_events()), 0)


if __name__ == "__main__":
    unittest.main()
