from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Any

import psutil


class ThreatContainmentEngine:
    def __init__(self) -> None:
        self.platform = sys.platform

    def kill_process(self, pid: int) -> dict[str, Any]:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            username = proc.username() if hasattr(proc, "username") else "unknown"
            proc.kill()
            return {
                "status": "success",
                "message": f"Successfully terminated process '{name}' (PID {pid}).",
                "pid": pid,
                "name": name,
                "username": username,
            }
        except psutil.NoSuchProcess:
            return {"status": "error", "message": f"Process PID {pid} is no longer running.", "pid": pid}
        except psutil.AccessDenied:
            return {"status": "error", "message": f"Access denied terminating PID {pid}. Run with elevated privileges.", "pid": pid}
        except Exception as err:
            return {"status": "error", "message": f"Failed to kill PID {pid}: {err}", "pid": pid}

    def block_ip(self, ip_address: str) -> dict[str, Any]:
        ip_clean = ip_address.strip()
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_clean):
            return {"status": "error", "message": f"Invalid IPv4 address format: '{ip_address}'", "ip": ip_clean}

        cmd: list[str] = []
        rule_name = f"TDS_Block_{ip_clean.replace('.', '_')}"

        if self.platform == "win32":
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip_clean}",
            ]
        elif self.platform.startswith("linux"):
            cmd = ["iptables", "-A", "OUTPUT", "-d", ip_clean, "-j", "DROP"]
        elif self.platform == "darwin":
            cmd = ["route", "add", "-host", ip_clean, "127.0.0.1", "-blackhole"]
        else:
            return {"status": "error", "message": f"Firewall blocking not supported on platform '{self.platform}'", "ip": ip_clean}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return {
                    "status": "success",
                    "message": f"Successfully added firewall block rule for IP {ip_clean}.",
                    "ip": ip_clean,
                    "rule_name": rule_name,
                }
            else:
                return {
                    "status": "error",
                    "message": f"Firewall command failed: {res.stderr.strip() or res.stdout.strip() or 'Requires Administrator privileges'}",
                    "ip": ip_clean,
                }
        except Exception as err:
            return {"status": "error", "message": f"Failed to execute firewall rule: {err}", "ip": ip_clean}

    def unblock_ip(self, ip_address: str) -> dict[str, Any]:
        ip_clean = ip_address.strip()
        rule_name = f"TDS_Block_{ip_clean.replace('.', '_')}"
        cmd: list[str] = []

        if self.platform == "win32":
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        elif self.platform.startswith("linux"):
            cmd = ["iptables", "-D", "OUTPUT", "-d", ip_clean, "-j", "DROP"]
        elif self.platform == "darwin":
            cmd = ["route", "delete", "-host", ip_clean]
        else:
            return {"status": "error", "message": "Unsupported platform", "ip": ip_clean}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {
                "status": "success" if res.returncode == 0 else "error",
                "message": f"Unblock action completed for IP {ip_clean}.",
                "ip": ip_clean,
            }
        except Exception as err:
            return {"status": "error", "message": str(err), "ip": ip_clean}
