from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models.schemas import EventIn


def _get_hostname() -> str:
    return socket.gethostname()


class CrossOSEventIngestor:
    def __init__(self) -> None:
        self.hostname = _get_hostname()
        self.platform = sys.platform  # 'win32', 'linux', 'darwin'
        self._last_win_event_record_id: int = 0
        self._last_log_file_pos: dict[str, int] = {}

    def collect_os_events(self) -> list[EventIn]:
        if self.platform == "win32":
            return self._collect_windows_events()
        elif self.platform.startswith("linux"):
            return self._collect_linux_events()
        elif self.platform == "darwin":
            return self._collect_macos_events()
        return []

    # ─── WINDOWS EVENT LOG INGESTOR ──────────────────────────────────────────
    def _collect_windows_events(self) -> list[EventIn]:
        events: list[EventIn] = []

        # Attempt native win32evtlog first if available
        try:
            import win32evtlog  # type: ignore

            server = None
            log_type = "Security"
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            handle = win32evtlog.OpenEventLog(server, log_type)
            try:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                for record in (records or [])[:15]:
                    event_id = record.EventID & 0xFFFF
                    mapped = self._parse_windows_event_record(event_id, record.StringInserts or [], record.SourceName)
                    if mapped:
                        events.append(mapped)
            finally:
                win32evtlog.CloseEventLog(handle)
        except Exception:
            # Fallback to wevtutil XML reader if win32evtlog fails or lacks elevation
            events.extend(self._collect_windows_events_wevtutil())

        return events

    def _collect_windows_events_wevtutil(self) -> list[EventIn]:
        events: list[EventIn] = []
        try:
            cmd = [
                "wevtutil",
                "qe",
                "Security",
                "/q:*[System[(EventID=4625 or EventID=4624 or EventID=4672 or EventID=4688)]]",
                "/c:10",
                "/rd:true",
                "/f:RenderedXml",
            ]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            if not output.strip():
                return events

            # Wrap in root element for XML parsing
            wrapped_xml = f"<Events>{output}</Events>"
            root = ET.fromstring(wrapped_xml)

            for evt in root.findall(".//{*}Event"):
                event_id_elem = evt.find(".//{*}EventID")
                if event_id_elem is None or not event_id_elem.text:
                    continue
                event_id = int(event_id_elem.text)

                data_dict: dict[str, str] = {}
                for data in evt.findall(".//{*}Data"):
                    name = data.attrib.get("Name")
                    if name and data.text:
                        data_dict[name] = data.text

                mapped = self._parse_windows_event_data(event_id, data_dict)
                if mapped:
                    events.append(mapped)
        except Exception:
            pass
        return events

    def _parse_windows_event_record(self, event_id: int, inserts: list[str], source: str) -> EventIn | None:
        if event_id == 4625:  # Failed Logon
            user = inserts[1] if len(inserts) > 1 else "unknown"
            ip = inserts[19] if len(inserts) > 19 else "127.0.0.1"
            return EventIn(
                host=self.hostname,
                user=user,
                event_type="login_failure",
                process_name="lsass.exe",
                source_ip=ip if ip != "-" else "127.0.0.1",
                metadata={
                    "failed_login_count": 1,
                    "event_source": f"Windows-Security-{event_id}",
                    "raw_inserts": inserts[:5],
                },
            )
        elif event_id == 4672:  # Privilege Escalation / Special Privileges
            user = inserts[1] if len(inserts) > 1 else "system"
            return EventIn(
                host=self.hostname,
                user=user,
                event_type="privilege_escalation",
                process_name="lsass.exe",
                metadata={
                    "privilege_escalation": True,
                    "event_source": f"Windows-Security-{event_id}",
                },
            )
        elif event_id == 4688:  # Process Creation
            proc_name = inserts[5] if len(inserts) > 5 else "unknown.exe"
            user = inserts[1] if len(inserts) > 1 else "system"
            cmd_line = inserts[8] if len(inserts) > 8 else ""
            return EventIn(
                host=self.hostname,
                user=user,
                event_type="process_start",
                process_name=Path(proc_name).name,
                command_line=cmd_line,
                metadata={
                    "event_source": f"Windows-Security-{event_id}",
                    "new_process": proc_name,
                },
            )
        return None

    def _parse_windows_event_data(self, event_id: int, data: dict[str, str]) -> EventIn | None:
        if event_id == 4625:
            return EventIn(
                host=self.hostname,
                user=data.get("TargetUserName", "unknown"),
                event_type="login_failure",
                process_name="lsass.exe",
                source_ip=data.get("IpAddress", "127.0.0.1"),
                metadata={
                    "failed_login_count": 1,
                    "failure_reason": data.get("Status", "0xC000006D"),
                    "event_source": "Windows-Security-4625",
                },
            )
        elif event_id == 4672:
            return EventIn(
                host=self.hostname,
                user=data.get("SubjectUserName", "admin"),
                event_type="privilege_escalation",
                process_name="lsass.exe",
                metadata={
                    "privilege_escalation": True,
                    "privileges": data.get("PrivilegeList", "SeDebugPrivilege"),
                    "event_source": "Windows-Security-4672",
                },
            )
        elif event_id == 4688:
            proc_path = data.get("NewProcessName", "")
            return EventIn(
                host=self.hostname,
                user=data.get("SubjectUserName", "system"),
                event_type="process_start",
                process_name=Path(proc_path).name if proc_path else "unknown.exe",
                command_line=data.get("CommandLine", ""),
                metadata={
                    "event_source": "Windows-Security-4688",
                    "parent_process": data.get("ParentProcessName", ""),
                },
            )
        return None

    # ─── LINUX LOG INGESTOR ──────────────────────────────────────────────────
    def _collect_linux_events(self) -> list[EventIn]:
        events: list[EventIn] = []
        log_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]

        for path in log_paths:
            if not os.path.exists(path) or not os.access(path, os.R_OK):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    pos = self._last_log_file_pos.get(path, max(0, os.path.getsize(path) - 10000))
                    handle.seek(pos)
                    lines = handle.readlines()
                    self._last_log_file_pos[path] = handle.tell()

                    for line in lines[-20:]:
                        evt = self._parse_linux_log_line(line)
                        if evt:
                            events.append(evt)
            except Exception:
                pass
        return events

    def _parse_linux_log_line(self, line: str) -> EventIn | None:
        # Failed SSH password
        if "Failed password for" in line:
            match = re.search(r"Failed password for (invalid user )?(\w+) from ([\d\.]+) port", line)
            if match:
                user = match.group(2)
                ip = match.group(3)
                return EventIn(
                    host=self.hostname,
                    user=user,
                    event_type="login_failure",
                    process_name="sshd",
                    source_ip=ip,
                    metadata={"failed_login_count": 1, "event_source": "Linux-AuthLog"},
                )

        # Sudo privilege escalation
        if "sudo:" in line and "COMMAND=" in line:
            match = re.search(r"(\w+) : TTY=\S+ ; PWD=\S+ ; USER=(\w+) ; COMMAND=(.*)", line)
            if match:
                user = match.group(1)
                cmd = match.group(3)
                return EventIn(
                    host=self.hostname,
                    user=user,
                    event_type="privilege_escalation",
                    process_name="sudo",
                    command_line=cmd,
                    metadata={"privilege_escalation": True, "event_source": "Linux-SudoLog"},
                )
        return None

    # ─── MACOS LOG INGESTOR ──────────────────────────────────────────────────
    def _collect_macos_events(self) -> list[EventIn]:
        events: list[EventIn] = []
        try:
            cmd = [
                "log",
                "show",
                "--predicate",
                'process == "sudo" or eventMessage contains "FAILED"',
                "--last",
                "2m",
                "--style",
                "syslog",
            ]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=3).decode("utf-8", errors="ignore")
            for line in output.splitlines()[-15:]:
                if "sudo" in line and "TTY=" in line:
                    events.append(
                        EventIn(
                            host=self.hostname,
                            user="user",
                            event_type="privilege_escalation",
                            process_name="sudo",
                            command_line=line[:120],
                            metadata={"privilege_escalation": True, "event_source": "macOS-UnifiedLog"},
                        )
                    )
        except Exception:
            pass
        return events
