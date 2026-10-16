from __future__ import annotations

import unittest
from app.core.ai_classifier import LocalMLClassifier, ProcessIntelligence


class AIClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ml_classifier = LocalMLClassifier()
        self.pi = ProcessIntelligence()

    def test_local_ml_classifier_initialization(self) -> None:
        self.assertIsNotNone(self.ml_classifier.model)

    def test_local_ml_detects_mimikatz(self) -> None:
        process = {
            "pid": 4321,
            "name": "mimikatz.exe",
            "username": "SYSTEM",
            "cpu_percent": 12.5,
            "memory_percent": 8.0,
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        }
        res = self.ml_classifier.assess(process)
        self.assertIsNotNone(res)
        self.assertTrue(res["suspicious"])
        self.assertEqual(res["category"], "IsolationForest Anomaly")

    def test_local_ml_detects_encoded_powershell(self) -> None:
        process = {
            "pid": 5678,
            "name": "powershell.exe",
            "username": "analyst1",
            "cpu_percent": 2.0,
            "memory_percent": 3.0,
            "command_line": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
        }
        res = self.ml_classifier.assess(process)
        self.assertIsNotNone(res)
        self.assertTrue(res["suspicious"])
        self.assertGreaterEqual(res["confidence"], 70)

    def test_process_intelligence_classification(self) -> None:
        processes = [
            {
                "pid": 111,
                "name": "chrome.exe",
                "username": "user",
                "cpu_percent": 1.0,
                "memory_percent": 2.0,
                "command_line": "chrome.exe",
            },
            {
                "pid": 999,
                "name": "psexec.exe",
                "username": "admin",
                "cpu_percent": 5.0,
                "memory_percent": 4.0,
                "command_line": "psexec.exe \\\\dc-01 -s cmd.exe",
            },
        ]
        classified = self.pi.classify_processes(processes, {})
        self.assertTrue(len(classified) >= 1)
        self.assertEqual(classified[0]["name"], "psexec.exe")
        self.assertIn(classified[0]["detection_source"], {"gemini", "local_ml_isolation_forest", "fallback"})


if __name__ == "__main__":
    unittest.main()
