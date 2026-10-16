from __future__ import annotations

import datetime
import json
import re
import urllib.request
from threading import Lock
from typing import Optional

from app.config import SOAR_ALERT_THRESHOLD, SOAR_ENABLED, SOAR_WEBHOOK_URL
from app.core.response import ThreatContainmentEngine


class SOAREngine:
    def __init__(self, containment: Optional[ThreatContainmentEngine] = None) -> None:
        self.containment = containment or ThreatContainmentEngine()
        self.enabled = SOAR_ENABLED
        self.threshold = SOAR_ALERT_THRESHOLD
        self.webhook_url = SOAR_WEBHOOK_URL
        self._history: list[dict] = []
        self._lock = Lock()
        self.playbooks = {
            "auto_kill_process": True,
            "auto_block_ip": True,
            "webhook_notify": True,
        }

    def get_status(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "threshold": self.threshold,
                "webhook_url": self.webhook_url or "not_configured",
                "playbooks": self.playbooks.copy(),
                "total_actions_executed": len(self._history),
            }

    def toggle_soar(self, enabled: bool) -> dict:
        with self._lock:
            self.enabled = enabled
        return self.get_status()

    def set_threshold(self, threshold: float) -> dict:
        with self._lock:
            self.threshold = threshold
        return self.get_status()

    def get_history(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def evaluate_alert(self, alert: dict, event: Optional[dict] = None) -> list[dict]:
        if not self.enabled:
            return []

        score = float(alert.get("score", 0.0))
        severity = str(alert.get("severity", "")).lower()

        # Trigger playbook if score >= threshold or severity is critical
        if score < self.threshold and severity != "critical":
            return []

        results: list[dict] = []
        event = event or {}
        meta = event.get("metadata", {})

        # Playbook 1: Auto Kill Malicious Process
        if self.playbooks.get("auto_kill_process"):
            pid = meta.get("observed_pid") or meta.get("pid") or event.get("pid")
            if not pid and "PID" in str(alert.get("summary", "")):
                m = re.search(r"PID\s*(\d+)", alert.get("summary", ""))
                if m:
                    pid = int(m.group(1))

            if pid and isinstance(pid, int) and pid > 0:
                kill_res = self.containment.kill_process(pid)
                action_entry = {
                    "id": f"soar-{len(self._history) + 1}",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "playbook": "auto_kill_process",
                    "trigger_alert_id": alert.get("id"),
                    "target": f"PID {pid}",
                    "status": kill_res.get("status", "unknown"),
                    "detail": kill_res.get("message", ""),
                }
                with self._lock:
                    self._history.append(action_entry)
                results.append(action_entry)

        # Playbook 2: Auto Block Outbound C2 IP
        if self.playbooks.get("auto_block_ip"):
            ip = meta.get("remote_ip") or meta.get("c2_ip") or meta.get("ip_address")
            if not ip and "IP" in str(alert.get("summary", "")):
                m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(alert.get("summary", "")))
                if m:
                    ip = m.group(0)

            if ip and isinstance(ip, str) and ip != "127.0.0.1":
                block_res = self.containment.block_ip(ip)
                action_entry = {
                    "id": f"soar-{len(self._history) + 1}",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "playbook": "auto_block_ip",
                    "trigger_alert_id": alert.get("id"),
                    "target": f"IP {ip}",
                    "status": block_res.get("status", "unknown"),
                    "detail": block_res.get("message", ""),
                }
                with self._lock:
                    self._history.append(action_entry)
                results.append(action_entry)

        # Playbook 3: Webhook Notification
        if self.playbooks.get("webhook_notify") and self.webhook_url:
            notify_res = self._dispatch_webhook(alert)
            action_entry = {
                "id": f"soar-{len(self._history) + 1}",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "playbook": "webhook_notify",
                "trigger_alert_id": alert.get("id"),
                "target": self.webhook_url,
                "status": notify_res.get("status", "unknown"),
                "detail": notify_res.get("message", ""),
            }
            with self._lock:
                self._history.append(action_entry)
            results.append(action_entry)

        return results

    def _dispatch_webhook(self, alert: dict) -> dict:
        try:
            payload = json.dumps({
                "event": "soar_alert_notification",
                "alert": alert,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                return {"status": "success", "message": f"Webhook returned HTTP {response.status}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


soar_engine = SOAREngine()
