from __future__ import annotations

import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.models.schemas import EventIn


class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, buffer: list[dict[str, Any]], lock: threading.Lock) -> None:
        super().__init__()
        self.buffer = buffer
        self.lock = lock

    def _record(self, action: str, path: str) -> None:
        # Ignore noisy build/temp/cache/database directories and WAL files
        if any(ign in path for ign in [".git", "__pycache__", "node_modules", "dist", ".gemini", ".idea", ".vscode", "data", ".db", ".wal", ".shm", ".sqlite", ".log"]):
            return
        with self.lock:
            self.buffer.append(
                {
                    "action": action,
                    "path": path,
                    "filename": Path(path).name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record("created", str(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record("modified", str(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record("deleted", str(event.src_path))


class CrossPlatformFIM:
    def __init__(self, watch_paths: list[str] | None = None) -> None:
        self.hostname = socket.gethostname()
        self._lock = threading.Lock()
        self._event_buffer: list[dict[str, Any]] = []
        self._observer: Observer | None = None
        self.enabled = False

        if watch_paths:
            self.watch_paths = [p for p in watch_paths if os.path.exists(p)]
        else:
            # Default cross-platform watch paths
            root_path = str(Path(__file__).resolve().parent.parent.parent)
            self.watch_paths = [root_path]

    def start(self) -> None:
        if self.enabled:
            return
        try:
            handler = FIMEventHandler(self._event_buffer, self._lock)
            self._observer = Observer()
            for path in self.watch_paths:
                if os.path.exists(path):
                    self._observer.schedule(handler, path, recursive=True)
            self._observer.start()
            self.enabled = True
        except Exception:
            self.enabled = False

    def stop(self) -> None:
        if not self.enabled or not self._observer:
            return
        try:
            self._observer.stop()
            self._observer.join(timeout=2)
        except Exception:
            pass
        finally:
            self.enabled = False

    def collect_fim_events(self) -> list[EventIn]:
        events: list[EventIn] = []
        with self._lock:
            if not self._event_buffer:
                return []
            buffered = list(self._event_buffer)
            self._event_buffer.clear()

        # Group by velocity
        total_mods = len(buffered)
        sample_path = buffered[-1]["path"] if buffered else "unknown"
        sample_name = buffered[-1]["filename"] if buffered else "unknown"

        events.append(
            EventIn(
                host=self.hostname,
                user="system",
                event_type="file_integrity_change",
                process_name="fim-watcher",
                metadata={
                    "file_modifications": total_mods,
                    "last_modified_file": sample_name,
                    "last_modified_path": sample_path,
                    "fim_active": True,
                    "actions_captured": [b["action"] for b in buffered[:10]],
                },
            )
        )
        return events
