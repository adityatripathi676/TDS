from __future__ import annotations

import getpass
import platform
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

import psutil

from app.core.ai_classifier import ProcessIntelligence
from app.core.fim import CrossPlatformFIM
from app.core.os_event_log import CrossOSEventIngestor
from app.models.schemas import EventIn, HostSnapshot, MonitorStatus


# ─── Lightweight system-info helpers (no wmic) ────────────────────────────────

def _quick_os_name() -> str:
    """Return a friendly OS name using Python stdlib only — no wmic needed."""
    s = platform.system()
    if s == "Windows":
        try:
            ver = sys.getwindowsversion()
            build = ver.build
            release = platform.release()
            # Map Windows 10/11 by build number
            if build >= 22000:
                edition = "Windows 11"
            else:
                edition = f"Windows {release}"
            return f"{edition} (Build {build})"
        except Exception:
            return f"Windows {platform.release()}"
    elif s == "Linux":
        try:
            import distro  # type: ignore
            return distro.name(pretty=True) or f"Linux {platform.release()}"
        except ImportError:
            return f"Linux {platform.release()}"
    elif s == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    return f"{s} {platform.release()}"


def _quick_cpu_name() -> str:
    """Return CPU name string without wmic."""
    # Try Windows registry first (fast, no subprocess)
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            winreg.CloseKey(key)
            return name.strip()
        except Exception:
            pass
    return platform.processor() or "Unknown CPU"


def _quick_pc_manufacturer() -> tuple[str, str]:
    """Return (manufacturer, model) from registry (Windows) or /proc (Linux)."""
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\BIOS"
            )
            mfr, _ = winreg.QueryValueEx(key, "SystemManufacturer")
            model, _ = winreg.QueryValueEx(key, "SystemProductName")
            winreg.CloseKey(key)
            return mfr.strip(), model.strip()
        except Exception:
            pass
    elif sys.platform.startswith("linux"):
        try:
            mfr  = open("/sys/class/dmi/id/sys_vendor").read().strip()
            model = open("/sys/class/dmi/id/product_name").read().strip()
            return mfr, model
        except Exception:
            pass
    return "Unknown", "Unknown"


# ─── HostMonitor ──────────────────────────────────────────────────────────────

class HostMonitor:
    def __init__(self, interval_seconds: int = 15, on_event_callback: Callable[[EventIn], None] | None = None) -> None:
        self.interval_seconds = interval_seconds
        self.enabled = False
        self.on_event_callback = on_event_callback
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._last_snapshot: dict[str, Any] | None = None
        self._status = MonitorStatus(enabled=False, interval_seconds=interval_seconds, mode="disabled")
        self._process_intelligence = ProcessIntelligence()
        self.os_ingestor = CrossOSEventIngestor()
        self.fim = CrossPlatformFIM()
        # Cache static system info so we only compute it once
        self._static_info: dict[str, Any] = self._collect_static_info()

    def _collect_static_info(self) -> dict[str, Any]:
        """Collect slow/static system info once at startup."""
        vm = psutil.virtual_memory()
        manufacturer, model = _quick_pc_manufacturer()
        total_disk = 0.0
        for part in psutil.disk_partitions(all=False):
            try:
                total_disk += psutil.disk_usage(part.mountpoint).total
            except Exception:
                pass
        return {
            "os":                _quick_os_name(),
            "os_version":        platform.version(),
            "os_build":          str(sys.getwindowsversion().build) if sys.platform == "win32" else platform.release(),
            "os_arch":           platform.machine(),
            "cpu_name":          _quick_cpu_name(),
            "cpu_count":         psutil.cpu_count(logical=True) or 0,
            "cpu_physical_cores": psutil.cpu_count(logical=False) or 0,
            "total_memory_gb":   round(vm.total / 1024**3, 2),
            "disk_total_gb":     round(total_disk / 1024**3, 2),
            "platform":          platform.system(),
            "python_version":    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "manufacturer":      manufacturer,
            "model":             model,
        }

    def _utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    def collect_snapshot(self) -> HostSnapshot:
        cpu_percent = round(psutil.cpu_percent(interval=0.2), 2)
        memory_percent = round(psutil.virtual_memory().percent, 2)
        try:
            disk_percent = round(psutil.disk_usage("/").percent, 2)
        except Exception:
            # Windows: try C: drive
            try:
                disk_percent = round(psutil.disk_usage("C:\\").percent, 2)
            except Exception:
                disk_percent = 0.0
        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        active_connections = len(psutil.net_connections(kind="inet"))
        logical_cpus = max(psutil.cpu_count(logical=True) or 1, 1)
        users_logged_in = sorted(
            {
                session.name
                for session in psutil.users()
                if getattr(session, "name", None)
            }
        )
        if not users_logged_in:
            users_logged_in = [getpass.getuser()]

        process_rows: list[dict[str, Any]] = []
        processes: list[psutil.Process] = []

        # Prime per-process CPU measurement so the next sample is meaningful.
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(None)
                processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        time.sleep(0.15)

        for proc in processes:
            try:
                info = proc.as_dict(attrs=["pid", "name", "username", "memory_percent", "exe", "cmdline", "ppid"])
                process_cpu = round(max(proc.cpu_percent(None) / logical_cpus, 0.0), 2)
                row = {
                    "pid": info.get("pid"),
                    "name": info.get("name") or "unknown",
                    "username": info.get("username") or "n/a",
                    "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
                    "cpu_percent": process_cpu,
                    "exe": info.get("exe") or "",
                    "command_line": " ".join(info.get("cmdline") or []),
                    "parent_pid": info.get("ppid"),
                }
                process_rows.append(row)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        grouped_processes: dict[tuple[str, str], dict[str, Any]] = {}
        for row in process_rows:
            raw_name = (row.get("name") or "unknown").strip()
            lowered = raw_name.lower()

            # Drop low-signal kernel/idle entries so the list feels more like Task Manager.
            if lowered in {"system idle process", "idle", "registry"} or row.get("pid") == 0:
                continue

            key = (raw_name, row.get("username") or "n/a")
            group = grouped_processes.setdefault(
                key,
                {
                    "pid": row.get("pid"),
                    "name": raw_name,
                    "username": row.get("username") or "n/a",
                    "cpu_percent": 0.0,
                    "memory_percent": 0.0,
                    "process_count": 0,
                },
            )
            group["cpu_percent"] += float(row.get("cpu_percent") or 0.0)
            group["memory_percent"] += float(row.get("memory_percent") or 0.0)
            group["process_count"] += 1

        top_processes = sorted(
            grouped_processes.values(),
            key=lambda item: (item["cpu_percent"], item["memory_percent"], item["process_count"]),
            reverse=True,
        )[:8]

        for item in top_processes:
            item["cpu_percent"] = round(item["cpu_percent"], 2)
            item["memory_percent"] = round(item["memory_percent"], 2)
            if item["process_count"] > 1:
                item["name"] = f"{item['name']} ({item['process_count']})"

        host_context = {
            "hostname": socket.gethostname(),
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "disk_percent": disk_percent,
            "active_connections": active_connections,
            "users_logged_in": users_logged_in,
        }
        suspicious_processes = self._process_intelligence.classify_processes(process_rows, host_context)

        si = self._static_info
        monitor_mode = "active" if self.enabled else "passive"

        return HostSnapshot(
            hostname=host_context["hostname"],
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_percent=disk_percent,
            boot_time=boot_time,
            active_connections=active_connections,
            total_processes=len(process_rows),
            suspicious_processes=suspicious_processes[:10],
            top_processes=top_processes,
            users_logged_in=users_logged_in,
            # Enriched system info
            os=si["os"],
            os_version=si["os_version"],
            os_build=si["os_build"],
            os_arch=si["os_arch"],
            cpu_name=si["cpu_name"],
            cpu_count=si["cpu_count"],
            cpu_physical_cores=si["cpu_physical_cores"],
            total_memory_gb=si["total_memory_gb"],
            disk_total_gb=si["disk_total_gb"],
            monitor_mode=monitor_mode,
            platform=si["platform"],
            python_version=si["python_version"],
            manufacturer=si["manufacturer"],
            model=si["model"],
        )

    def scan_now(self) -> HostSnapshot:
        snapshot = self.collect_snapshot()
        with self._lock:
            self._last_snapshot = snapshot.model_dump(mode="json")
            self._status.last_scan_time = snapshot.scan_time
            self._status.scans_completed += 1
        return snapshot

    def get_snapshot(self) -> dict[str, Any]:
        with self._lock:
            if self._last_snapshot is None:
                snapshot = self.collect_snapshot().model_dump(mode="json")
                self._last_snapshot = snapshot
                self._status.last_scan_time = datetime.fromisoformat(snapshot["scan_time"].replace("Z", "+00:00"))
                self._status.scans_completed += 1
            return dict(self._last_snapshot)

    def note_detection_result(self, had_alert: bool) -> None:
        with self._lock:
            self._status.events_generated += 1
            if had_alert:
                self._status.alerts_generated += 1

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            self._status.enabled = self.enabled
            self._status.mode = "active" if self.enabled else "passive"
            return self._status.model_dump(mode="json")

    def reset_counters(self) -> None:
        with self._lock:
            self._last_snapshot = None
            self._status.last_scan_time = None
            self._status.scans_completed = 0
            self._status.events_generated = 0
            self._status.alerts_generated = 0

    def _run(self) -> None:
        while self.enabled:
            snapshot = self.scan_now()
            if self.on_event_callback:
                try:
                    from app.api.routes import _event_from_snapshot
                    events = _event_from_snapshot(snapshot.model_dump(mode="json"))
                    for evt in events:
                        self.on_event_callback(evt)
                except Exception:
                    pass
            time.sleep(self.interval_seconds)

    def collect_real_os_events(self) -> list[EventIn]:
        os_events = self.os_ingestor.collect_os_events()
        fim_events = self.fim.collect_fim_events()
        return os_events + fim_events

    def start(self) -> None:
        if self.enabled:
            return
        self.enabled = True
        self._status.enabled = True
        self._status.mode = "active"
        self.fim.start()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.enabled = False
        self._status.enabled = False
        self._status.mode = "passive"
        self.fim.stop()
