"""
system_scanner.py – Robust deep real-system scanner for Windows.

Collects actual hardware, firmware/BIOS, security-posture, and threat-indicator
data from the host using:
  • winreg       — fast registry reads (CPU name, BIOS, OS info)
  • psutil       — CPU / memory / disk / network / processes
  • subprocess   — wmic / powershell ONLY where no registry alternative exists
  • platform/sys — OS detection without any subprocess

Design principles:
  - Every _ps() and _wmic() call has a hard timeout (default 8 s).
  - Every section is wrapped in try/except so one slow query can't hang the scan.
  - Registry is preferred over wmic wherever possible (10–100× faster).
"""
from __future__ import annotations

import json
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

import psutil

# winreg is Windows-only; graceful no-op on other platforms
try:
    import winreg  # type: ignore
    _HAVE_WINREG = True
except ImportError:
    _HAVE_WINREG = False


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: list[str], timeout: int = 8) -> str:
    """Run a command and return stdout as text; empty string on any failure."""
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _ps(script: str, timeout: int = 10) -> str:
    """Run a PowerShell one-liner and return stdout."""
    try:
        return subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        ).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _wmic(query: str, timeout: int = 8) -> str:
    """Run a wmic command — may be slow or unavailable on Windows 11."""
    return _run(["wmic"] + query.split(), timeout)


def _reg_read(hive, path: str, name: str, default: str = "Unknown") -> str:
    """Read a single registry value; return default on any error."""
    if not _HAVE_WINREG:
        return default
    try:
        key = winreg.OpenKey(hive, path)
        val, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return str(val).strip() or default
    except Exception:
        return default


def _reg_key_count(hive, path: str) -> int:
    """Count subkeys under a registry path."""
    if not _HAVE_WINREG:
        return 0
    try:
        key = winreg.OpenKey(hive, path)
        count = winreg.QueryInfoKey(key)[0]
        winreg.CloseKey(key)
        return count
    except Exception:
        return 0


# ──────────────────────────────────────────────────────────────────────────────
# BIOS / Firmware  (registry-first, wmic fallback)
# ──────────────────────────────────────────────────────────────────────────────

def _get_bios_info() -> dict[str, Any]:
    bios_path = r"HARDWARE\DESCRIPTION\System\BIOS"
    mfr     = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "BIOSVendor", "")
    version = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "BIOSVersion", "")
    date    = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "BIOSReleaseDate", "")
    sys_mfr = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "SystemManufacturer", "")
    sys_prd = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "SystemProductName", "")

    if not mfr or mfr == "Unknown":
        # Fallback: wmic
        raw = _wmic("bios get Manufacturer,Name,Version,ReleaseDate,SerialNumber /format:list")
        data: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip()
        mfr     = data.get("Manufacturer", "Unknown")
        version = data.get("Version", version or "Unknown")
        date    = data.get("ReleaseDate", date or "")[:8]
        serial  = data.get("SerialNumber", "Unknown")
        name    = data.get("Name", "Unknown")
    else:
        serial = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "BIOSSerialNumber", "Unknown")
        name = version  # use version string as name when coming from registry
        date = date[:8] if date else "Unknown"

    return {
        "manufacturer": mfr or "Unknown",
        "name":         name or "Unknown",
        "version":      version or "Unknown",
        "release_date": date or "Unknown",
        "serial":       serial or "Unknown",
        "system_manufacturer": sys_mfr or "Unknown",
        "system_model":        sys_prd or "Unknown",
    }


def _get_firmware_type() -> str:
    r"""Detect UEFI vs Legacy BIOS.

    Uses registry keys readable without admin rights:
    - HKLM\HARDWARE\ACPI\DSDT  (only exists on UEFI/ACPI systems)
    - HKLM\SYSTEM\..\SecureBoot\State  (Secure Boot key = UEFI)
    - FirmwareBootDevice value in HKLM\SYSTEM\..\Control
    No PowerShell needed.
    """
    if not _HAVE_WINREG:
        return "Unknown"

    # Method 1: Secure Boot exists → must be UEFI
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        )
        winreg.CloseKey(key)
        return "UEFI"   # SecureBoot key only exists on UEFI machines
    except Exception:
        pass

    # Method 2: ACPI/DSDT presence → UEFI
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT")
        winreg.CloseKey(key)
        return "UEFI"
    except Exception:
        pass

    # Method 3: FirmwareBootDevice
    try:
        val = _reg_read(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control",
            "FirmwareBootDevice", ""
        )
        if val and ("uefi" in val.lower() or "efi" in val.lower()):
            return "UEFI"
    except Exception:
        pass

    return "Legacy BIOS"


def _get_secure_boot() -> dict[str, Any]:
    r"""Read Secure Boot status from registry - no admin rights needed.

    HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
      UEFISecureBootEnabled = 1  -> Enabled
      UEFISecureBootEnabled = 0  -> Disabled
      Key absent               -> Not supported / Legacy BIOS
    """
    if _HAVE_WINREG:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
            )
            val, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
            winreg.CloseKey(key)
            if val == 1:
                return {"enabled": True,  "status": "Enabled",    "source": "registry"}
            else:
                return {"enabled": False, "status": "Disabled ⚠", "source": "registry"}
        except Exception:
            pass
    # Key not present = not UEFI or Secure Boot not supported
    return {"enabled": False, "status": "Not supported / Legacy BIOS", "source": "registry"}


def _get_tpm() -> dict[str, Any]:
    r"""Detect TPM without admin rights.

    Strategy (no elevation needed):
    1. Get-PnpDevice -Class SecurityDevices -- lists TPM hardware devices
       Works without admin. Returns name, status, instance ID.
    2. Registry HKLM\SOFTWARE\Microsoft\TPM for version hints.
    3. If TPM 2.0 found in PnP, mark present=True, spec_version='2.0'.
    """
    tpm_name      = None
    tpm_present   = False
    tpm_ready     = False
    spec_version  = "Unknown"
    tpm_status    = "Unknown"
    source        = "pnp"

    # ── Method 1: Get-PnpDevice (no admin needed) ────────────────────────────
    try:
        raw = _ps(
            "Get-PnpDevice -Class SecurityDevices -ErrorAction SilentlyContinue "
            "| Select-Object Name,Status,InstanceId | ConvertTo-Json",
            timeout=12
        )
        if raw:
            import json as _json
            devices = _json.loads(raw)
            if isinstance(devices, dict):
                devices = [devices]
            for dev in devices:
                name = dev.get("Name", "") or ""
                status = dev.get("Status", "") or ""
                inst   = dev.get("InstanceId", "") or ""
                if "trusted platform module" in name.lower() or "tpm" in name.lower():
                    tpm_present = True
                    tpm_ready   = status.strip().lower() == "ok"
                    tpm_name    = name
                    tpm_status  = status
                    # Guess version from name
                    if "2.0" in name:
                        spec_version = "2.0"
                    elif "1.2" in name:
                        spec_version = "1.2"
                    # Instance ID ACPI\MSFT0101 = TPM 2.0 spec
                    if "MSFT0101" in inst:
                        spec_version = "2.0"
                    elif "MSFT0100" in inst:
                        spec_version = "1.2"
    except Exception:
        pass

    # ── Method 2: Registry HKLM\SOFTWARE\Microsoft\TPM for extra data ────────
    if _HAVE_WINREG:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\TPM")
            vals: dict[str, Any] = {}
            i = 0
            while True:
                try:
                    n, v, _ = winreg.EnumValue(key, i)
                    vals[n] = v
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            # If TPM key exists, TPM is present
            if vals:
                tpm_present = True
                if not tpm_ready:
                    tpm_ready = True  # key exists = service initialized
                source = "registry+pnp"
        except Exception:
            pass

    return {
        "present":      tpm_present,
        "ready":        tpm_ready,
        "spec_version": spec_version,
        "name":         tpm_name or ("TPM" if tpm_present else "Not detected"),
        "status":       tpm_status,
        "source":       source,
        "note":         "Detected via Windows PnP device manager (no admin needed)",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Motherboard  (registry-first)
# ──────────────────────────────────────────────────────────────────────────────

def _get_motherboard_info() -> dict[str, Any]:
    bios_path = r"HARDWARE\DESCRIPTION\System\BIOS"
    mfr  = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "BaseBoardManufacturer", "")
    prod = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "BaseBoardProduct",      "")
    ver  = _reg_read(winreg.HKEY_LOCAL_MACHINE, bios_path, "BaseBoardVersion",      "")

    if not mfr or mfr == "Unknown":
        raw = _wmic("baseboard get Manufacturer,Product,SerialNumber,Version /format:list")
        data: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip()
        mfr  = data.get("Manufacturer", "Unknown")
        prod = data.get("Product",      "Unknown")
        ver  = data.get("Version",      "Unknown")

    return {
        "manufacturer": mfr  or "Unknown",
        "product":      prod or "Unknown",
        "version":      ver  or "Unknown",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Hardware: CPU  (registry-first — fastest, no subprocess)
# ──────────────────────────────────────────────────────────────────────────────

def _get_cpu_info() -> dict[str, Any]:
    # Registry path: HARDWARE\DESCRIPTION\System\CentralProcessor\0
    cpu_path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
    cpu_name = _reg_read(winreg.HKEY_LOCAL_MACHINE, cpu_path, "ProcessorNameString", "")
    vendor   = _reg_read(winreg.HKEY_LOCAL_MACHINE, cpu_path, "VendorIdentifier",   "")
    mhz_str  = _reg_read(winreg.HKEY_LOCAL_MACHINE, cpu_path, "~MHz", "0")

    try:
        max_mhz = int(mhz_str)
    except Exception:
        max_mhz = 0

    if not cpu_name or cpu_name == "Unknown":
        # wmic fallback
        raw = _wmic("cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,Manufacturer /format:list")
        data: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip()
        cpu_name = data.get("Name", platform.processor() or "Unknown")
        vendor   = data.get("Manufacturer", vendor or "Unknown")
        try:
            max_mhz = int(data.get("MaxClockSpeed", max_mhz))
        except Exception:
            pass

    return {
        "name":          cpu_name.strip(),
        "cores":         psutil.cpu_count(logical=False) or 0,
        "logical":       psutil.cpu_count(logical=True) or 0,
        "max_mhz":       max_mhz,
        "manufacturer":  vendor,
        "current_usage": round(psutil.cpu_percent(interval=0.3), 1),
        "per_core":      psutil.cpu_percent(interval=0.2, percpu=True),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Hardware: Memory, Disks, GPU
# ──────────────────────────────────────────────────────────────────────────────

def _get_memory_info() -> dict[str, Any]:
    vm  = psutil.virtual_memory()
    sw  = psutil.swap_memory()

    sticks: list[dict] = []
    try:
        raw = _wmic("memorychip get Speed,Manufacturer,MemoryType,Capacity /format:list", timeout=8)
        stick: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                stick[k.strip()] = v.strip()
            elif not line.strip() and stick:
                if stick.get("Capacity"):
                    sticks.append({
                        "manufacturer": stick.get("Manufacturer", "Unknown"),
                        "speed_mhz":    int(stick.get("Speed", 0) or 0),
                        "capacity_gb":  round(int(stick.get("Capacity", 0) or 0) / 1024**3, 1),
                    })
                stick = {}
    except Exception:
        pass

    return {
        "total_gb":      round(vm.total  / 1024**3, 2),
        "used_gb":       round(vm.used   / 1024**3, 2),
        "available_gb":  round(vm.available / 1024**3, 2),
        "percent":       vm.percent,
        "swap_total_gb": round(sw.total  / 1024**3, 2),
        "swap_used_gb":  round(sw.used   / 1024**3, 2),
        "sticks":        sticks,
    }


def _get_disks() -> list[dict[str, Any]]:
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device":     part.device,
                "mountpoint": part.mountpoint,
                "fstype":     part.fstype,
                "total_gb":   round(usage.total / 1024**3, 2),
                "used_gb":    round(usage.used  / 1024**3, 2),
                "percent":    usage.percent,
            })
        except PermissionError:
            pass
    return disks


def _get_gpu_info() -> list[dict[str, Any]]:
    gpus: list[dict] = []
    try:
        raw = _wmic("path Win32_VideoController get Name,AdapterRAM,DriverVersion /format:list", timeout=8)
        card: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                card[k.strip()] = v.strip()
            elif not line.strip() and card:
                if card.get("Name"):
                    ram_bytes = int(card.get("AdapterRAM", 0) or 0)
                    gpus.append({
                        "name":           card.get("Name", "Unknown"),
                        "vram_mb":        round(ram_bytes / 1024**2) if ram_bytes else None,
                        "driver_version": card.get("DriverVersion", "Unknown"),
                    })
                card = {}
    except Exception:
        pass
    return gpus


# ──────────────────────────────────────────────────────────────────────────────
# OS  (platform + registry — no subprocess needed)
# ──────────────────────────────────────────────────────────────────────────────

def _get_os_info() -> dict[str, Any]:
    """Collect OS information using stdlib + registry (no wmic)."""
    sys_name = platform.system()
    caption  = "Unknown"
    version  = platform.version()
    build    = ""
    arch     = platform.machine()

    if sys_name == "Windows":
        try:
            wv = sys.getwindowsversion()
            build = str(wv.build)
            major, minor = wv.major, wv.minor
            if major == 10 and wv.build >= 22000:
                caption = "Microsoft Windows 11"
            elif major == 10:
                caption = "Microsoft Windows 10"
            else:
                caption = f"Microsoft Windows {major}.{minor}"
            # Try to get edition from registry
            edition = _reg_read(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "EditionID",
                ""
            )
            if edition:
                caption = f"{caption} {edition}"
            # Friendly version
            display_ver = _reg_read(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "DisplayVersion",
                ""
            )
            version = display_ver or version
        except Exception:
            caption = f"Windows {platform.release()}"

    elif sys_name == "Linux":
        try:
            import distro  # type: ignore
            caption = distro.name(pretty=True)
        except ImportError:
            # Read /etc/os-release
            try:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            caption = line.split("=", 1)[1].strip().strip('"')
                            break
            except Exception:
                caption = f"Linux {platform.release()}"

    elif sys_name == "Darwin":
        caption = f"macOS {platform.mac_ver()[0]}"
        version = platform.mac_ver()[0]

    return {
        "caption":        caption,
        "version":        version,
        "build":          build,
        "architecture":   arch,
        "hostname":       socket.gethostname(),
        "platform":       sys_name,
        "python_version": platform.python_version(),
        "boot_time_epoch": psutil.boot_time(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Security: Windows Defender, Firewall, Updates
# ──────────────────────────────────────────────────────────────────────────────

def _get_windows_defender() -> dict[str, Any]:
    status = _ps(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | "
        "Select-Object AMServiceEnabled,RealTimeProtectionEnabled,"
        "AntivirusSignatureLastUpdated,AntivirusSignatureVersion | ConvertTo-Json",
        timeout=12
    )
    if not status:
        return {"available": False, "note": "Could not query Windows Defender status"}
    try:
        d = json.loads(status)
        sig_date = d.get("AntivirusSignatureLastUpdated", "")
        return {
            "available":              True,
            "service_enabled":        bool(d.get("AMServiceEnabled",       False)),
            "realtime_protection":    bool(d.get("RealTimeProtectionEnabled", False)),
            "signature_version":      d.get("AntivirusSignatureVersion",   "Unknown"),
            "signature_last_updated": sig_date[:10] if sig_date else "Unknown",
        }
    except Exception:
        return {"available": False, "raw": status[:200]}


def _get_firewall_status() -> dict[str, Any]:
    profiles: dict[str, bool] = {}
    for profile in ("Domain", "Private", "Public"):
        result = _ps(
            f"(Get-NetFirewallProfile -Name {profile} -ErrorAction SilentlyContinue).Enabled",
            timeout=8
        )
        profiles[profile.lower()] = result.lower() == "true"
    return profiles


def _get_windows_updates() -> dict[str, Any]:
    raw = _ps(
        "(New-Object -ComObject Microsoft.Update.Session)"
        ".CreateUpdateSearcher().Search('IsInstalled=0 and Type=Software').Updates.Count",
        timeout=20
    )
    try:
        count = int(raw.strip())
        return {"pending_count": count, "status": "ok" if count == 0 else f"{count} updates pending ⚠"}
    except Exception:
        return {"pending_count": None, "status": "Could not query Windows Update"}


# ──────────────────────────────────────────────────────────────────────────────
# Services
# ──────────────────────────────────────────────────────────────────────────────

def _get_services() -> list[dict[str, Any]]:
    services = []
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                if info.get("status") in ("running",) or info.get("start_type") == "automatic":
                    services.append({
                        "name":       info.get("name"),
                        "display":    info.get("display_name"),
                        "status":     info.get("status"),
                        "start_type": info.get("start_type"),
                        "pid":        info.get("pid"),
                        "binpath":    info.get("binpath", ""),
                    })
            except Exception:
                pass
    except Exception:
        pass
    return services[:80]


# ──────────────────────────────────────────────────────────────────────────────
# Startup / Persistence IOC
# ──────────────────────────────────────────────────────────────────────────────

def _read_registry_run_key(hive: Any, path: str) -> list[dict[str, str]]:
    entries = []
    if not _HAVE_WINREG:
        return entries
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(key, i)
                entries.append({"name": name, "command": val})
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass
    return entries


def _get_startup_items() -> list[dict[str, Any]]:
    if not _HAVE_WINREG:
        return []
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    SUSPICIOUS = {"temp", "tmp", "%appdata%", "roaming", "powershell -e", "cmd /c", "wscript", "mshta"}
    items = []
    for hive, path in run_keys:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        for entry in _read_registry_run_key(hive, path):
            cmd_lower = entry["command"].lower()
            items.append({
                "source":    f"{hive_name}\\{path.split(chr(92))[-1]}",
                "name":      entry["name"],
                "command":   entry["command"],
                "suspicious": any(s in cmd_lower for s in SUSPICIOUS),
            })
    return items


def _get_scheduled_tasks_suspicious() -> list[dict[str, Any]]:
    raw = _ps(
        "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | "
        "Select-Object TaskName,TaskPath,State | ConvertTo-Json -Depth 2",
        timeout=15
    )
    tasks = []
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            for t in (data or []):
                name = t.get("TaskName", "")
                path = t.get("TaskPath", "")
                tasks.append({
                    "name":  name,
                    "path":  path,
                    "state": t.get("State", ""),
                    "suspicious": any(s in (name + path).lower() for s in [
                        "update", "telemetry", "microsoftedge", "googlechrome",
                    ]),
                })
        except Exception:
            pass
    return tasks[:40]


# ──────────────────────────────────────────────────────────────────────────────
# Network
# ──────────────────────────────────────────────────────────────────────────────

def _get_network_adapters() -> list[dict[str, Any]]:
    adapters = []
    for name, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        ipv4  = next((a.address for a in addrs if a.family.name == "AF_INET"),  None)
        mac   = next((a.address for a in addrs if a.family.name == "AF_LINK"),  None)
        ipv6  = next((a.address for a in addrs if a.family.name == "AF_INET6"), None)
        adapters.append({
            "name":     name,
            "ipv4":     ipv4,
            "ipv6":     ipv6,
            "mac":      mac,
            "is_up":    stats.isup  if stats else False,
            "speed_mb": stats.speed if stats else 0,
        })
    return adapters


def _get_open_ports() -> list[dict[str, Any]]:
    ports = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "System"
                except Exception:
                    proc_name = "Unknown"
                ports.append({
                    "port":    conn.laddr.port,
                    "addr":    conn.laddr.ip,
                    "pid":     conn.pid,
                    "process": proc_name,
                })
    except Exception:
        pass
    return sorted(ports, key=lambda x: x["port"])


def _get_installed_software_count() -> int:
    if not _HAVE_WINREG:
        return 0
    count = 0
    for hive, path in [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]:
        count += _reg_key_count(hive, path)
    return count


# ──────────────────────────────────────────────────────────────────────────────
# USB / PnP Devices
# ──────────────────────────────────────────────────────────────────────────────

def _get_usb_devices() -> list[dict[str, Any]]:
    devices: list[dict] = []
    try:
        raw = _wmic("path Win32_USBControllerDevice get Dependent /format:list", timeout=8)
        ids = re.findall(r'Win32_PnPEntity\.DeviceID="([^"]+)"', raw)
        for dev_id in ids[:20]:
            raw2 = _wmic(
                f'path Win32_PnPEntity where DeviceID="{dev_id.replace(chr(92), chr(92)*2)}" '
                f'get Name,Manufacturer /format:list',
                timeout=4
            )
            data: dict[str, str] = {}
            for line in raw2.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip()
            name = data.get("Name", dev_id.split("\\")[-1])
            mfr  = data.get("Manufacturer", "")
            if name and name not in ("", "Unknown"):
                devices.append({"name": name, "manufacturer": mfr, "device_id": dev_id})
    except Exception:
        pass
    return devices


# ──────────────────────────────────────────────────────────────────────────────
# Process IOC scan
# ──────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_PROC_NAMES = {
    "mimikatz.exe", "procdump.exe", "dumpert.exe", "pwdump.exe",
    "cobalt strike", "meterpreter", "nmap.exe", "masscan.exe",
    "wce.exe", "htran.exe", "psexec.exe", "netcat.exe", "nc.exe",
    "powersploit", "empire.exe", "cobaltstrike",
    "certutil.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
}

SUSPICIOUS_CMD_PATTERNS = [
    "invoke-expression", "invoke-mimikatz", "-encodedcommand",
    "downloadstring", "frombase64string", "-nop -w hidden",
    "iex (", "bypass", "webclient", "downloadfile",
]


def _scan_running_processes() -> dict[str, Any]:
    suspicious = []
    total = 0
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            total += 1
            name_lower = (info.get("name") or "").lower()
            cmd = " ".join(info.get("cmdline") or []).lower()
            if name_lower in SUSPICIOUS_PROC_NAMES or any(s in cmd for s in SUSPICIOUS_CMD_PATTERNS):
                suspicious.append({
                    "pid":       info.get("pid"),
                    "name":      info.get("name"),
                    "exe":       info.get("exe", ""),
                    "cmdline":   cmd[:200],
                    "user":      info.get("username", ""),
                    "cpu":       round(info.get("cpu_percent") or 0, 1),
                    "mem":       round(info.get("memory_percent") or 0, 2),
                    "ioc_match": "process_name" if name_lower in SUSPICIOUS_PROC_NAMES else "command_line",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return {"total_processes": total, "suspicious": suspicious}


# ──────────────────────────────────────────────────────────────────────────────
# Security posture scoring
# ──────────────────────────────────────────────────────────────────────────────

def _score_posture(scan: dict) -> dict[str, Any]:
    score = 100
    findings: list[dict] = []

    def deduct(pts: int, issue: str, severity: str, fix: str) -> None:
        nonlocal score
        score -= pts
        findings.append({"issue": issue, "severity": severity, "fix": fix, "deduction": pts})

    # Secure Boot
    if not scan.get("firmware", {}).get("secure_boot", {}).get("enabled"):
        deduct(15, "Secure Boot is disabled or unavailable", "high",
               "Enable Secure Boot in UEFI/BIOS settings → Security tab")

    # TPM
    tpm = scan.get("firmware", {}).get("tpm", {})
    if not tpm.get("present"):
        deduct(10, "TPM chip not detected", "medium", "Verify TPM in Device Manager or BIOS")
    elif not tpm.get("ready"):
        deduct(5, "TPM present but not ready/initialized", "low", "Initialize TPM in tpm.msc")

    # Windows Defender
    wd = scan.get("security", {}).get("windows_defender", {})
    if not wd.get("realtime_protection"):
        deduct(20, "Windows Defender real-time protection is OFF", "critical",
               "Enable via Windows Security → Virus & threat protection")
    elif not wd.get("service_enabled"):
        deduct(15, "Windows Defender service is disabled", "high",
               "Start Windows Defender via services.msc or Windows Security")

    # Firewall
    fw = scan.get("security", {}).get("firewall", {})
    for profile, enabled in fw.items():
        if not enabled:
            deduct(8, f"Windows Firewall disabled for {profile} profile", "high",
                   f"Re-enable via: netsh advfirewall set {profile}profile state on")

    # Pending updates
    upd = scan.get("security", {}).get("windows_updates", {})
    pending = upd.get("pending_count")
    if pending and pending > 0:
        deduct(min(15, pending), f"{pending} pending Windows updates", "medium",
               "Run Windows Update immediately")

    # Suspicious startup items
    susp_startup = [s for s in scan.get("persistence", {}).get("startup_items", []) if s.get("suspicious")]
    if susp_startup:
        deduct(min(30, 10 * len(susp_startup)),
               f"{len(susp_startup)} suspicious startup entry/entries", "critical",
               "Review via msconfig or Autoruns (Sysinternals) and remove unknown entries")

    # Suspicious processes
    susp_procs = scan.get("processes", {}).get("suspicious", [])
    if susp_procs:
        deduct(20, f"{len(susp_procs)} suspicious process(es) detected by IOC scan", "critical",
               "Investigate these processes immediately in Process Explorer")

    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    return {"score": score, "grade": grade, "findings": findings}


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_deep_scan() -> dict[str, Any]:
    """
    Full deep scan of the local machine.
    Registry-first design: most data collected in <1 s without wmic.
    Takes 15–40 s total due to PowerShell calls (Defender, TPM, firewall).
    """
    scan: dict[str, Any] = {
        "scan_time": _utcnow(),
        "hostname":  socket.gethostname(),
        "platform":  platform.system(),
    }

    # ── OS (pure Python, instant) ─────────────────────────────────────────────
    scan["os"] = _get_os_info()

    # ── Firmware / Boot integrity ─────────────────────────────────────────────
    scan["firmware"] = {
        "bios":          _get_bios_info(),
        "firmware_type": _get_firmware_type(),
        "secure_boot":   _get_secure_boot(),
        "tpm":           _get_tpm(),
        "motherboard":   _get_motherboard_info(),
    }

    # ── Hardware ─────────────────────────────────────────────────────────────
    scan["hardware"] = {
        "cpu":    _get_cpu_info(),
        "memory": _get_memory_info(),
        "disks":  _get_disks(),
        "gpu":    _get_gpu_info(),
    }

    # ── Security posture (PowerShell queries) ─────────────────────────────────
    scan["security"] = {
        "windows_defender": _get_windows_defender(),
        "firewall":         _get_firewall_status(),
        "windows_updates":  _get_windows_updates(),
    }

    # ── Services ─────────────────────────────────────────────────────────────
    scan["services"] = _get_services()

    # ── Persistence / Startup IOC (registry, fast) ───────────────────────────
    scan["persistence"] = {
        "startup_items":   _get_startup_items(),
        "scheduled_tasks": _get_scheduled_tasks_suspicious(),
    }

    # ── Network ──────────────────────────────────────────────────────────────
    scan["network"] = {
        "adapters":                  _get_network_adapters(),
        "listening_ports":           _get_open_ports(),
        "installed_software_count":  _get_installed_software_count(),
    }

    # ── USB / PnP devices ────────────────────────────────────────────────────
    scan["devices"] = _get_usb_devices()

    # ── Process IOC scan ─────────────────────────────────────────────────────
    scan["processes"] = _scan_running_processes()

    # ── Posture score (computed last, uses all sections above) ───────────────
    scan["posture"] = _score_posture(scan)

    global _LAST_DEEP_SCAN_RESULT
    _LAST_DEEP_SCAN_RESULT = scan

    return scan


_LAST_DEEP_SCAN_RESULT: dict[str, Any] | None = None


def get_last_deep_scan() -> dict[str, Any] | None:
    """Return the cached result of the most recent deep scan, or None if not run yet."""
    return _LAST_DEEP_SCAN_RESULT


def get_or_run_deep_scan() -> dict[str, Any]:
    """Return cached deep scan or run a fresh one if missing."""
    global _LAST_DEEP_SCAN_RESULT
    if _LAST_DEEP_SCAN_RESULT is not None:
        return _LAST_DEEP_SCAN_RESULT
    return run_deep_scan()

