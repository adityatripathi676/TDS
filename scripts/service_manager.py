from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path


def get_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def check_service_status() -> dict:
    os_type = platform.system().lower()
    res = {
        "os": os_type,
        "service_name": "AIHIDSSentinel" if os_type == "windows" else "ai-hids.service",
        "installed": False,
        "running": False,
        "detail": "",
    }

    if os_type == "windows":
        try:
            out = subprocess.check_output(
                ["sc.exe", "query", "AIHIDSSentinel"],
                stderr=subprocess.STDOUT,
                text=True,
            )
            res["installed"] = True
            res["detail"] = out
            if "RUNNING" in out:
                res["running"] = True
        except subprocess.CalledProcessError as e:
            res["detail"] = f"Service not found or error: {e.output}"
        except Exception as e:
            res["detail"] = str(e)

    elif os_type == "linux":
        try:
            out = subprocess.check_output(
                ["systemctl", "status", "ai-hids.service"],
                stderr=subprocess.STDOUT,
                text=True,
            )
            res["installed"] = True
            res["detail"] = out
            if "active (running)" in out:
                res["running"] = True
        except subprocess.CalledProcessError as e:
            res["detail"] = f"Service status output: {e.output}"
        except Exception as e:
            res["detail"] = str(e)

    else:
        res["detail"] = f"Platform '{os_type}' requires custom service configuration."

    return res


def print_service_instructions() -> None:
    os_type = platform.system().lower()
    root = get_project_root()
    print("======================================================================")
    print(" AI-HIDS Sentinel - Background Service Deployment Helper")
    print("======================================================================")
    status = check_service_status()
    print(f"OS Platform     : {platform.system()} ({platform.release()})")
    print(f"Service Name    : {status['service_name']}")
    print(f"Installed       : {'Yes' if status['installed'] else 'No'}")
    print(f"Running         : {'Yes' if status['running'] else 'No'}")
    print("----------------------------------------------------------------------")

    if os_type == "windows":
        print("To install AI-HIDS as a Windows Background Service (Run as Administrator):")
        print(f"  powershell -ExecutionPolicy Bypass -File \"{root}\\scripts\\install_windows_service.ps1\"")
        print("\nTo remove the Windows Background Service:")
        print(f"  powershell -ExecutionPolicy Bypass -File \"{root}\\scripts\\uninstall_windows_service.ps1\"")

    elif os_type == "linux":
        print("To install AI-HIDS as a Linux Systemd Service (Run with sudo):")
        print(f"  sudo bash \"{root}/scripts/install_linux_service.sh\"")
        print("\nTo remove the Linux Systemd Service:")
        print(f"  sudo bash \"{root}/scripts/uninstall_linux_service.sh\"")

    print("======================================================================")


if __name__ == "__main__":
    print_service_instructions()
