from __future__ import annotations

import unittest
from app.core.fim import CrossPlatformFIM
from app.core.os_event_log import CrossOSEventIngestor


class CrossOSEventIngestorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ingestor = CrossOSEventIngestor()
        self.fim = CrossPlatformFIM()

    def test_ingestor_instantiation(self) -> None:
        self.assertIsNotNone(self.ingestor.platform)
        self.assertIsNotNone(self.ingestor.hostname)

    def test_windows_event_data_parsing_4625(self) -> None:
        data = {
            "TargetUserName": "attacker",
            "IpAddress": "192.168.1.100",
            "Status": "0xC000006D",
        }
        event = self.ingestor._parse_windows_event_data(4625, data)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "login_failure")
        self.assertEqual(event.user, "attacker")
        self.assertEqual(event.source_ip, "192.168.1.100")

    def test_windows_event_data_parsing_4688(self) -> None:
        data = {
            "SubjectUserName": "admin",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        }
        event = self.ingestor._parse_windows_event_data(4688, data)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "process_start")
        self.assertEqual(event.process_name, "cmd.exe")
        self.assertEqual(event.command_line, "cmd.exe /c whoami")

    def test_linux_log_line_parsing(self) -> None:
        line = "Sep 17 10:00:00 server sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2"
        event = self.ingestor._parse_linux_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "login_failure")
        self.assertEqual(event.user, "root")
        self.assertEqual(event.source_ip, "203.0.113.5")

    def test_fim_buffering(self) -> None:
        self.fim.start()
        self.assertTrue(self.fim.enabled)
        self.fim.stop()
        self.assertFalse(self.fim.enabled)


if __name__ == "__main__":
    unittest.main()
