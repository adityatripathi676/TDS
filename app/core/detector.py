from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean, pstdev
from typing import Any

from app.models.schemas import AlertRecord, DetectionResult, EventIn, EventRecord


SUSPICIOUS_PROCESSES = {
    "mimikatz.exe": 35,
    "psexec.exe": 28,
    "powershell.exe": 12,
    "rclone.exe": 30,
    "wmic.exe": 14,
    "cmd.exe": 8,
    "net.exe": 10,
}

EVENT_TYPE_WEIGHTS = {
    "login_failure": 18,
    "privilege_escalation": 35,
    "process_start": 10,
    "file_integrity_change": 22,
    "network_connection": 12,
    "data_exfiltration": 38,
    "lateral_movement": 36,
}

MITRE_MAP = {
    "login_failure": "T1110 Brute Force",
    "privilege_escalation": "T1068 Privilege Escalation",
    "process_start": "T1059 Command and Scripting Interpreter",
    "file_integrity_change": "T1486 Data Encrypted for Impact",
    "network_connection": "T1021 Remote Services",
    "data_exfiltration": "T1041 Exfiltration Over C2 Channel",
    "lateral_movement": "T1021 Remote Services",
}

FEATURE_KEYS = [
    "failed_login_count",
    "file_modifications",
    "outbound_connections",
    "data_transfer_mb",
    "new_services_installed",
]


class ThreatDetector:
    def __init__(self, baseline_events: list[dict[str, Any]] | None = None) -> None:
        self.baseline_events = baseline_events or []
        self.profile = self._build_profile(self.baseline_events)

    def _build_profile(self, baseline_events: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
        feature_samples: dict[str, list[float]] = defaultdict(list)
        for event in baseline_events:
            metadata = event.get("metadata", {})
            for key in FEATURE_KEYS:
                feature_samples[key].append(float(metadata.get(key, 0) or 0))

        profile: dict[str, dict[str, float]] = {}
        for key in FEATURE_KEYS:
            samples = feature_samples.get(key, [0.0]) or [0.0]
            profile[key] = {
                "mean": round(mean(samples), 3),
                "std": round(max(pstdev(samples), 1.0), 3),
            }
        return profile

    def refresh_baseline(self, baseline_events: list[dict[str, Any]]) -> None:
        self.baseline_events = baseline_events
        # Combine with default prior if event count is small
        combined = list(baseline_events)
        if len(combined) < 10 and self.baseline_events:
            combined.extend(self.baseline_events)
        self.profile = self._build_profile(combined if combined else self.baseline_events)

    def refresh_baseline_from_db(self, store: Any) -> dict[str, dict[str, float]]:
        db_events = store.get_events(limit=1000)
        self.refresh_baseline(db_events)
        return self.profile

    def _anomaly_score(self, metadata: dict[str, Any]) -> tuple[float, list[str]]:
        reasons: list[str] = []
        score_parts: list[float] = []
        for key in FEATURE_KEYS:
            current = float(metadata.get(key, 0) or 0)
            baseline = self.profile.get(key, {"mean": 0.0, "std": 1.0})
            z_score = abs(current - baseline["mean"]) / max(baseline["std"], 1.0)
            score_parts.append(min(z_score * 8, 35))
            if z_score >= 2.5:
                reasons.append(f"{key.replace('_', ' ')} deviates from baseline (z={z_score:.2f})")
        return round(sum(score_parts) / max(len(score_parts), 1), 2), reasons

    def _rule_score(self, event: EventRecord) -> tuple[float, list[str], list[str], list[str]]:
        metadata = event.metadata
        score = float(EVENT_TYPE_WEIGHTS.get(event.event_type, 6))
        reasons: list[str] = []
        recommendations: list[str] = []
        mitre_tags = [MITRE_MAP.get(event.event_type, "T1070 Indicator Removal on Host")]

        if event.process_name:
            process_weight = SUSPICIOUS_PROCESSES.get(event.process_name.lower(), 0)
            if process_weight:
                score += process_weight
                reasons.append(f"suspicious process detected: {event.process_name}")
                recommendations.append(f"isolate activity spawned by {event.process_name}")

        failed_logins = float(metadata.get("failed_login_count", 0) or 0)
        if failed_logins >= 8:
            score += min(failed_logins, 20)
            reasons.append(f"excessive failed logins: {int(failed_logins)}")
            recommendations.append("lock or throttle the affected account and review source IPs")

        if metadata.get("privilege_escalation"):
            score += 25
            reasons.append("privilege escalation flag present")
            recommendations.append("review admin group changes and token elevation activity")

        file_mods = float(metadata.get("file_modifications", 0) or 0)
        if file_mods >= 20:
            score += 25
            reasons.append("high-volume file modifications suggest ransomware-like behavior")
            recommendations.append("stop the process and inspect modified files")

        data_transfer = float(metadata.get("data_transfer_mb", 0) or 0)
        if data_transfer >= 500:
            score += 28
            reasons.append(f"large outbound transfer observed: {data_transfer:.0f} MB")
            recommendations.append("inspect outbound sessions for exfiltration")

        if metadata.get("new_services_installed", 0):
            score += 18
            reasons.append("new service installation detected")
            recommendations.append("audit new services and scheduled tasks")

        if metadata.get("lateral_tools_used"):
            score += 22
            reasons.append("lateral movement tooling observed")
            recommendations.append("inspect remote execution traces and east-west traffic")

        return round(score, 2), reasons, recommendations, mitre_tags

    def _severity_for_score(self, total_score: float) -> str:
        if total_score >= 75:
            return "critical"
        if total_score >= 55:
            return "high"
        if total_score >= 35:
            return "medium"
        return "low"

    def analyze(self, event_input: EventIn) -> DetectionResult:
        event = EventRecord(**event_input.model_dump())
        anomaly_score, anomaly_reasons = self._anomaly_score(event.metadata)
        rule_score, rule_reasons, recommendations, mitre_tags = self._rule_score(event)
        total_score = round((anomaly_score * 0.45) + (rule_score * 0.75), 2)
        severity = self._severity_for_score(total_score)
        reasons = anomaly_reasons + rule_reasons
        summary = f"{event.event_type.replace('_', ' ').title()} detected on {event.host}"

        alert = None
        if severity in {"medium", "high", "critical"}:
            alert = AlertRecord(
                event_id=event.id,
                host=event.host,
                score=total_score,
                severity=severity,
                summary=summary,
                reasons=reasons[:6],
                recommendations=(recommendations or ["review the host timeline and validate the event"])[:5],
                mitre_tags=list(dict.fromkeys(mitre_tags)),
                anomaly_score=anomaly_score,
                rule_score=rule_score,
                event=event,
            )
        return DetectionResult(event=event, alert=alert)

    @staticmethod
    def build_metrics(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> dict[str, Any]:
        severity_counts = Counter(alert.get("severity", "low") for alert in alerts)
        targeted_hosts = Counter(event.get("host") for event in events if event.get("host"))
        event_counts = Counter(event.get("event_type", "unknown") for event in events)
        return {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "critical_alerts": severity_counts.get("critical", 0),
            "high_alerts": severity_counts.get("high", 0),
            "medium_alerts": severity_counts.get("medium", 0),
            "benign_events": max(len(events) - len(alerts), 0),
            "most_targeted_host": targeted_hosts.most_common(1)[0][0] if targeted_hosts else None,
            "top_event_type": event_counts.most_common(1)[0][0] if event_counts else None,
        }

    def get_profile(self) -> dict[str, dict[str, float]]:
        return self.profile
