"""
elevated_scanner.py – Privileged firmware/TPM queries via Windows UAC elevation.

Flow:
  1. Backend writes a PowerShell script to a temp .ps1 file.
  2. Backend calls ShellExecuteW("runas", "powershell", ...) which triggers
     a standard Windows UAC dialog on the user's desktop.
  3. The elevated PS process runs Get-Tpm, Confirm-SecureBootUEFI, Win32_Tpm
     and writes JSON results to a temp output file.
  4. Backend polls for the output file (up to timeout), reads it, cleans up.
  5. Results are returned to the caller / stored in module-level cache.

No mock data. No simulation. Requires user to click "Yes" on the UAC prompt.
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── State ──────────────────────────────────────────────────────────────────────
_lock          = threading.Lock()
_last_result:  dict[str, Any] | None = None
_scan_running: bool = False
_last_error:   str  = ""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_admin() -> bool:
    """Return True if the current Python process has admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_status() -> dict[str, Any]:
    """Return current elevation scan status."""
    with _lock:
        return {
            "is_admin":    is_admin(),
            "scan_running": _scan_running,
            "last_error":  _last_error,
            "has_result":  _last_result is not None,
            "result_time": _last_result.get("scan_time") if _last_result else None,
        }


def get_cached_result() -> dict[str, Any] | None:
    """Return the cached elevated scan result (or None if not run yet)."""
    with _lock:
        return dict(_last_result) if _last_result else None


# ── PowerShell script that runs elevated ────────────────────────────────────

_PS_TEMPLATE = r"""
# Elevated PowerShell – HIDS Sentinel firmware/TPM probe
# Writes JSON to: {outfile}

$ErrorActionPreference = 'SilentlyContinue'
$result = @{{}}

# --- Secure Boot ---
try {{
    $sb = Confirm-SecureBootUEFI
    $result['secure_boot'] = @{{
        enabled = $true
        status  = 'Enabled'
        value   = $sb
    }}
}} catch {{
    $result['secure_boot'] = @{{
        enabled = $false
        status  = "Error: $($_.Exception.Message)"
    }}
}}

# --- TPM (Get-Tpm) ---
try {{
    $tpm = Get-Tpm
    $result['tpm'] = @{{
        present          = [bool]$tpm.TpmPresent
        ready            = [bool]$tpm.TpmReady
        enabled          = [bool]$tpm.TpmEnabled
        activated        = [bool]$tpm.TpmActivated
        owned            = [bool]$tpm.TpmOwned
        lockout          = [bool]$tpm.LockoutCount
        lockout_count    = [int]$tpm.LockoutCount
    }}
}} catch {{
    $result['tpm'] = @{{ error = $_.Exception.Message }}
}}

# --- TPM spec version via CIM ---
try {{
    $cim = Get-CimInstance -ClassName Win32_Tpm -Namespace root/cimv2/security/MicrosoftTpm
    if ($cim) {{
        $ver = ($cim.SpecVersion -split ',')[0].Trim()
        if (-not $result['tpm']) {{ $result['tpm'] = @{{}} }}
        $result['tpm']['spec_version']    = $ver
        $result['tpm']['manufacturer_id'] = $cim.ManufacturerIdTxt
        $result['tpm']['manufacturer']    = $cim.ManufacturerVersion
        $result['tpm']['present']         = $true
    }}
}} catch {{
    if (-not $result['tpm']) {{
        $result['tpm'] = @{{ cim_error = $_.Exception.Message }}
    }}
}}

# --- Firmware type via UEFI check ---
try {{
    # If Confirm-SecureBootUEFI didn't throw access denied, we know it's UEFI
    $result['firmware_type'] = 'UEFI'
}} catch {{
    $result['firmware_type'] = 'Unknown'
}}

# --- Windows Defender detailed ---
try {{
    $mpstatus = Get-MpComputerStatus
    $result['windows_defender'] = @{{
        am_service_enabled         = [bool]$mpstatus.AMServiceEnabled
        realtime_protection        = [bool]$mpstatus.RealTimeProtectionEnabled
        behavior_monitor           = [bool]$mpstatus.BehaviorMonitorEnabled
        ioav_protection            = [bool]$mpstatus.IoavProtectionEnabled
        antivirus_enabled          = [bool]$mpstatus.AntivirusEnabled
        antispyware_enabled        = [bool]$mpstatus.AntispywareEnabled
        signature_version          = $mpstatus.AntivirusSignatureVersion
        signature_last_updated     = "$($mpstatus.AntivirusSignatureLastUpdated)"
        engine_version             = $mpstatus.AMEngineVersion
        product_version            = $mpstatus.AMProductVersion
        full_scan_age              = $mpstatus.FullScanAge
        quick_scan_age             = $mpstatus.QuickScanAge
    }}
}} catch {{
    $result['windows_defender'] = @{{ error = $_.Exception.Message }}
}}

# --- Write output (UTF-8 without BOM so Python json.loads doesn't choke) ---
$result['scan_time']    = (Get-Date -Format 'o')
$result['elevated']     = $true
$result['ran_as_admin'] = $true

$json = $result | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText('{outfile}', $json, [System.Text.Encoding]::UTF8)
"""


# ── ShellExecute UAC launcher ────────────────────────────────────────────────

def _launch_elevated_ps(script_path: str) -> bool:
    """
    Launch PowerShell elevated using ShellExecuteW("runas").
    Returns True if ShellExecute accepted the request (UAC dialog shown).
    The user must still click "Yes" on the UAC prompt.
    """
    if sys.platform != "win32":
        return False

    # ShellExecuteW: hwnd, verb, file, params, dir, show
    result = ctypes.windll.shell32.ShellExecuteW(
        None,                   # parent window handle (None = desktop)
        "runas",                # verb = trigger UAC elevation
        "powershell.exe",
        f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script_path}"',
        None,
        1,                      # SW_SHOWNORMAL (1) – show PS window briefly
    )
    # ShellExecute returns > 32 on success
    return int(result) > 32


def request_elevated_scan(timeout_seconds: int = 120) -> dict[str, Any]:
    """
    Trigger a UAC-elevated PowerShell scan and return the results.

    This function:
      1. Writes the PS script to a temp file.
      2. Calls ShellExecuteW("runas") → Windows UAC dialog appears.
      3. Polls the output file until written or timeout.
      4. Returns parsed JSON results.

    Raises RuntimeError if user cancels UAC or timeout reached.
    """
    global _scan_running, _last_result, _last_error

    with _lock:
        if _scan_running:
            raise RuntimeError("An elevated scan is already running.")
        _scan_running = True
        _last_error = ""

    # Temp files in the system temp dir
    tmp_dir  = Path(tempfile.gettempdir())
    ps_file  = tmp_dir / "hids_elev_scan.ps1"
    out_file = tmp_dir / "hids_elev_result.json"

    # Remove stale output file from any previous run
    try:
        out_file.unlink(missing_ok=True)
    except Exception:
        pass

    try:
        # Write the PowerShell script
        ps_file.write_text(
            _PS_TEMPLATE.format(outfile=str(out_file).replace("\\", "\\\\")),
            encoding="utf-8"
        )

        # Launch elevated process
        launched = _launch_elevated_ps(str(ps_file))
        if not launched:
            raise RuntimeError(
                "ShellExecuteW failed to launch the elevated process. "
                "The UAC prompt may have been blocked."
            )

        # Poll for the output file
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            time.sleep(1)
            if out_file.exists() and out_file.stat().st_size > 10:
                break
        else:
            raise RuntimeError(
                f"Elevated scan timed out after {timeout_seconds}s. "
                "Did you click 'Yes' on the UAC dialog? "
                "If so, try again — the process may have been slow."
            )

        # Read and parse results.
        # utf-8-sig silently strips the BOM that PS 5.1 adds.
        # Also strip manually as belt-and-suspenders.
        raw = out_file.read_text(encoding="utf-8-sig", errors="ignore").strip().lstrip("\ufeff")
        data = json.loads(raw)

        # Post-process: normalise TPM fields
        tpm = data.get("tpm", {})
        if isinstance(tpm, dict):
            data["tpm"] = {
                "present":      bool(tpm.get("present", False)),
                "ready":        bool(tpm.get("ready",   False)),
                "spec_version": str(tpm.get("spec_version", "Unknown")),
                "manufacturer": tpm.get("manufacturer", ""),
                "manufacturer_id": tpm.get("manufacturer_id", ""),
                "owned":        bool(tpm.get("owned", False)),
                "lockout_count": int(tpm.get("lockout_count", 0)),
                "name":         "Trusted Platform Module " + str(tpm.get("spec_version", "")),
                "status":       "OK" if tpm.get("present") else "Not detected",
                "source":       "elevated (Get-Tpm + CIM)",
                "note":         "Fetched with admin rights via UAC elevation",
            }

        # Post-process: normalise secure boot
        sb = data.get("secure_boot", {})
        if isinstance(sb, dict):
            data["secure_boot"] = {
                "enabled": bool(sb.get("enabled", False)),
                "status":  "Enabled" if sb.get("enabled") else sb.get("status", "Unknown"),
                "source":  "elevated (Confirm-SecureBootUEFI)",
            }

        data["elevated"]  = True
        data["scan_time"] = _utcnow()

        with _lock:
            _last_result   = data
            _scan_running  = False

        return data

    except Exception as exc:
        with _lock:
            _scan_running = False
            _last_error   = str(exc)
        raise

    finally:
        # Clean up temp files
        for f in (ps_file, out_file):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
