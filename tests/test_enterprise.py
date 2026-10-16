from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.core.agent_manager import MultiHostAgentManager
from app.core.broadcaster import TelemetryBroadcaster
from app.core.response import ThreatContainmentEngine
from app.core.yara_scanner import YARASignatureScanner


class EnterpriseSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.containment = ThreatContainmentEngine()
        self.yara = YARASignatureScanner()
        self.agent_manager = MultiHostAgentManager()
        self.broadcaster = TelemetryBroadcaster()

    def test_kill_non_existent_process_returns_error(self) -> None:
        res = self.containment.kill_process(999999)
        self.assertEqual(res["status"], "error")

    def test_block_invalid_ip_format(self) -> None:
        res = self.containment.block_ip("invalid-ip")
        self.assertEqual(res["status"], "error")

    def test_yara_detects_mimikatz_pattern(self) -> None:
        text = "Executing sekurlsa::logonpasswords against lsass memory"
        matches = self.yara.scan_text(text)
        self.assertTrue(len(matches) >= 1)
        self.assertEqual(matches[0]["rule_name"], "Mimikatz_Credential_Dumping")

    def test_yara_scan_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            tmp.write("WARNING: HOW_TO_DECRYPT files vssadmin.exe delete shadows")
            tmp_path = tmp.name

        try:
            res = self.yara.scan_file(tmp_path)
            self.assertEqual(res["status"], "scanned")
            self.assertTrue(res["is_malicious"])
            self.assertGreaterEqual(res["match_count"], 1)
        finally:
            if Path(tmp_path).exists():
                Path(tmp_path).unlink()

    def test_agent_registration_and_heartbeat(self) -> None:
        agent = self.agent_manager.register_agent("test-server-01", "Linux", "10.0.0.50")
        self.assertIsNotNone(agent["id"])
        self.assertEqual(agent["hostname"], "test-server-01")

        updated = self.agent_manager.heartbeat(agent["id"], events_count=5)
        self.assertEqual(updated["status"], "online")
        self.assertEqual(updated["events_ingested"], 5)

        agents = self.agent_manager.get_agents()
        self.assertTrue(len(agents) >= 2)  # Local + registered test agent


if __name__ == "__main__":
    unittest.main()
