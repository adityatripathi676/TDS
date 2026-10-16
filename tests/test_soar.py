from __future__ import annotations

import unittest
from app.core.soar import SOAREngine


class SOARPlaybookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.soar = SOAREngine()
        self.soar.enabled = True
        self.soar.threshold = 85.0

    def test_soar_initialization_and_status(self) -> None:
        status = self.soar.get_status()
        self.assertTrue(status["enabled"])
        self.assertEqual(status["threshold"], 85.0)
        self.assertIn("auto_kill_process", status["playbooks"])

    def test_evaluate_alert_below_threshold_takes_no_action(self) -> None:
        alert = {"id": "alt-101", "score": 40.0, "severity": "medium", "summary": "Low severity event"}
        actions = self.soar.evaluate_alert(alert)
        self.assertEqual(len(actions), 0)

    def test_evaluate_alert_above_threshold_triggers_auto_kill(self) -> None:
        alert = {"id": "alt-102", "score": 90.0, "severity": "critical", "summary": "Mimikatz detected on PID 4412"}
        event = {"metadata": {"observed_pid": 999999}}
        actions = self.soar.evaluate_alert(alert, event)
        self.assertGreaterEqual(len(actions), 1)
        self.assertEqual(actions[0]["playbook"], "auto_kill_process")
        self.assertIn("PID 999999", actions[0]["target"])

        history = self.soar.get_history()
        self.assertTrue(len(history) >= 1)

    def test_evaluate_alert_above_threshold_triggers_auto_block(self) -> None:
        alert = {"id": "alt-103", "score": 88.0, "severity": "high", "summary": "C2 traffic to 198.51.100.55"}
        event = {"metadata": {"c2_ip": "198.51.100.55"}}
        actions = self.soar.evaluate_alert(alert, event)
        self.assertGreaterEqual(len(actions), 1)
        self.assertEqual(actions[0]["playbook"], "auto_block_ip")
        self.assertIn("198.51.100.55", actions[0]["target"])

    def test_soar_toggle(self) -> None:
        self.soar.toggle_soar(False)
        alert = {"id": "alt-104", "score": 95.0, "severity": "critical", "summary": "Critical outbreak"}
        actions = self.soar.evaluate_alert(alert, {"metadata": {"observed_pid": 1234}})
        self.assertEqual(len(actions), 0)


if __name__ == "__main__":
    unittest.main()
