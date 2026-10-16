from __future__ import annotations

import unittest
from pathlib import Path

from scripts.service_manager import check_service_status, get_project_root


class ServiceManagerTests(unittest.TestCase):
    def test_project_root_contains_scripts(self) -> None:
        root = get_project_root()
        self.assertTrue((root / "scripts" / "install_windows_service.ps1").exists())
        self.assertTrue((root / "scripts" / "uninstall_windows_service.ps1").exists())
        self.assertTrue((root / "scripts" / "ai-hids.service").exists())
        self.assertTrue((root / "scripts" / "install_linux_service.sh").exists())
        self.assertTrue((root / "scripts" / "uninstall_linux_service.sh").exists())

    def test_check_service_status_returns_dict(self) -> None:
        status = check_service_status()
        self.assertIn("os", status)
        self.assertIn("service_name", status)
        self.assertIn("installed", status)
        self.assertIn("running", status)


if __name__ == "__main__":
    unittest.main()
