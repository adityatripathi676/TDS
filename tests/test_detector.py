from __future__ import annotations

import unittest

from app.core.detector import ThreatDetector
from app.models.schemas import EventIn


class ThreatDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        baseline = [
            {
                "metadata": {
                    "failed_login_count": 0,
                    "file_modifications": 1,
                    "outbound_connections": 3,
                    "data_transfer_mb": 10,
                    "new_services_installed": 0,
                }
            },
            {
                "metadata": {
                    "failed_login_count": 1,
                    "file_modifications": 2,
                    "outbound_connections": 4,
                    "data_transfer_mb": 12,
                    "new_services_installed": 0,
                }
            },
        ]
        self.detector = ThreatDetector(baseline)

    def test_benign_event_stays_below_alert_threshold(self) -> None:
        event = EventIn(
            host="finance-ws-02",
            user="analyst1",
            event_type="process_start",
            process_name="chrome.exe",
            metadata={
                "failed_login_count": 1,
                "file_modifications": 2,
                "outbound_connections": 4,
                "data_transfer_mb": 9,
            },
        )
        result = self.detector.analyze(event)
        self.assertIsNone(result.alert)

    def test_attack_event_creates_alert(self) -> None:
        event = EventIn(
            host="dc-01",
            user="admin",
            event_type="data_exfiltration",
            process_name="rclone.exe",
            metadata={
                "failed_login_count": 14,
                "file_modifications": 40,
                "outbound_connections": 21,
                "data_transfer_mb": 1200,
                "new_services_installed": 1,
            },
        )
        result = self.detector.analyze(event)
        self.assertIsNotNone(result.alert)
        self.assertIn(result.alert.severity, {"high", "critical"})


if __name__ == "__main__":
    unittest.main()
