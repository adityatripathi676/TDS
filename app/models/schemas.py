from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventIn(BaseModel):
    host: str
    user: str
    event_type: str
    process_name: str | None = None
    source_ip: str | None = None
    command_line: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)


class EventRecord(EventIn):
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utcnow)


class AlertRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utcnow)
    event_id: str
    host: str
    score: float
    severity: str
    summary: str
    reasons: list[str]
    recommendations: list[str]
    mitre_tags: list[str]
    anomaly_score: float
    rule_score: float
    event: EventRecord


class DetectionResult(BaseModel):
    event: EventRecord
    alert: AlertRecord | None
    accepted: bool = True


class HostSnapshot(BaseModel):
    hostname: str
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    boot_time: datetime | None = None
    active_connections: int
    total_processes: int
    suspicious_processes: list[dict[str, Any]] = Field(default_factory=list)
    top_processes: list[dict[str, Any]] = Field(default_factory=list)
    users_logged_in: list[str] = Field(default_factory=list)
    scan_time: datetime = Field(default_factory=utcnow)

    # ── Enriched system info (shown in Host Telemetry Snapshot tile) ──────────
    os: str | None = None                  # e.g. "Windows 11 Pro"
    os_version: str | None = None          # e.g. "10.0.22631"
    os_build: str | None = None
    os_arch: str | None = None
    cpu_name: str | None = None            # e.g. "Intel Core i7-12700H"
    cpu_count: int | None = None           # logical CPU count
    cpu_physical_cores: int | None = None
    total_memory_gb: float | None = None
    disk_total_gb: float | None = None
    monitor_mode: str | None = None        # "active" / "passive" / "disabled"
    platform: str | None = None            # "Windows" / "Linux" / "macOS"
    python_version: str | None = None
    manufacturer: str | None = None        # PC / motherboard manufacturer
    model: str | None = None              # PC model name


class MonitorStatus(BaseModel):
    enabled: bool
    interval_seconds: int
    last_scan_time: datetime | None = None
    scans_completed: int = 0
    events_generated: int = 0
    alerts_generated: int = 0
    mode: str = "passive"                  # "active" | "passive" | "disabled"
