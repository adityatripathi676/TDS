from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib import error, request


GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

HIGH_RISK_NAMES = {
    "mimikatz.exe",
    "psexec.exe",
    "rclone.exe",
    "wmic.exe",
    "net.exe",
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "cscript.exe",
    "wscript.exe",
}

HIGH_RISK_NAME_PARTS = (
    "cheatengine",
    "mimikatz",
    "psexec",
    "rclone",
    "wmic",
)

SHELL_NAMES = {"powershell.exe", "pwsh.exe", "cmd.exe"}

SUSPICIOUS_ARGUMENTS = (
    "encodedcommand",
    " -enc",
    "frombase64string",
    "downloadstring",
    "invoke-webrequest",
    "iwr ",
    " -nop",
    " -w hidden",
    "bypass",
    "schtasks",
    "psexec",
    "rundll32",
    "regsvr32",
    "certutil",
)

STRONG_GENERIC_MARKERS = (
    "encodedcommand",
    " -enc",
    "frombase64string",
    "downloadstring",
    "invoke-webrequest",
    " -nop",
    " -w hidden",
    "bypass",
)


class LocalMLClassifier:
    def __init__(self) -> None:
        self.model = None
        self._init_model()

    def _init_model(self) -> None:
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest

            # Train on typical benign baseline process feature vectors
            # Features: [cpu_pct, mem_pct, cmdline_len, high_risk_flag, shell_flag, suspicious_arg_count]
            synthetic_benign = np.array([
                [0.5, 1.2, 25, 0, 0, 0],
                [1.0, 2.5, 45, 0, 0, 0],
                [2.0, 3.0, 60, 0, 1, 0],
                [0.1, 0.5, 15, 0, 0, 0],
                [3.5, 4.0, 80, 0, 0, 0],
                [0.8, 1.8, 30, 0, 0, 0],
                [4.2, 5.1, 110, 0, 1, 0],
                [0.2, 0.8, 20, 0, 0, 0],
            ])
            self.model = IsolationForest(contamination=0.15, random_state=42)
            self.model.fit(synthetic_benign)
        except Exception:
            self.model = None

    def _extract_features(self, process: dict[str, Any]) -> list[float]:
        name = (process.get("name") or "").lower()
        cmd = (process.get("command_line") or "").lower()
        cpu = float(process.get("cpu_percent", 0.0) or 0.0)
        mem = float(process.get("memory_percent", 0.0) or 0.0)
        cmd_len = float(len(cmd))
        high_risk = 1.0 if (name in HIGH_RISK_NAMES or any(p in name for p in HIGH_RISK_NAME_PARTS)) else 0.0
        shell = 1.0 if name in SHELL_NAMES else 0.0
        arg_count = float(sum(1 for m in SUSPICIOUS_ARGUMENTS if m in cmd))
        return [cpu, mem, cmd_len, high_risk, shell, arg_count]

    def assess(self, process: dict[str, Any]) -> dict[str, Any] | None:
        if not self.model:
            return None
        features = self._extract_features(process)
        score = float(self.model.decision_function([features])[0])
        prediction = int(self.model.predict([features])[0])  # -1 = anomaly, 1 = normal

        is_high_risk = features[3] > 0 or features[5] > 0

        if prediction == -1 or is_high_risk:
            confidence = int(min(98, max(72, round(85 - (score * 50)))))
            return {
                "suspicious": True,
                "confidence": confidence,
                "category": "IsolationForest Anomaly",
                "reason": f"Local IsolationForest ML algorithm detected anomalous process behavior (anomaly score: {score:.3f}).",
            }
        return None


class ProcessIntelligence:
    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self._local_ml = LocalMLClassifier()

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    def _ai_assess(self, process: dict[str, Any], host_context: dict[str, Any]) -> dict[str, Any] | None:
        if not self.api_key:
            return None

        prompt = {
            "process": process,
            "host_context": host_context,
            "task": (
                "You are a host intrusion detection assistant. "
                "Classify whether this process is genuinely suspicious or likely benign in an enterprise Windows host. "
                "Be conservative: do not mark common admin shells suspicious unless the command line or context is risky. "
                "Return strict JSON with keys: suspicious (boolean), confidence (0-100 integer), "
                "category (string), reason (string)."
            ),
        }

        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": json.dumps(prompt)
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        req = request.Request(
            GEMINI_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=15) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            return None

        try:
            text = raw["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            return None
        return self._extract_json(text)

    def _fallback_assess(self, process: dict[str, Any]) -> dict[str, Any]:
        name = (process.get("name") or "").lower()
        command_line = (process.get("command_line") or "").lower()

        if name in HIGH_RISK_NAMES or any(part in name for part in HIGH_RISK_NAME_PARTS):
            return {
                "suspicious": True,
                "confidence": 92,
                "category": "high-risk tooling",
                "reason": f"{process.get('name')} is commonly associated with dual-use tooling, memory tampering, or attacker tradecraft.",
            }

        if name in SHELL_NAMES:
            if any(marker in command_line for marker in SUSPICIOUS_ARGUMENTS):
                return {
                    "suspicious": True,
                    "confidence": 76,
                    "category": "suspicious shell activity",
                    "reason": "The shell command line contains encoded, hidden, download, or remote execution indicators.",
                }
            return {
                "suspicious": False,
                "confidence": 70,
                "category": "common shell usage",
                "reason": "Generic shell activity without risky arguments is treated as benign by fallback logic.",
            }

        if any(marker in command_line for marker in SUSPICIOUS_ARGUMENTS):
            return {
                "suspicious": True,
                "confidence": 74,
                "category": "suspicious arguments",
                "reason": "The process command line contains patterns often used in intrusion or staged execution.",
            }

        return {
            "suspicious": False,
            "confidence": 60,
            "category": "benign",
            "reason": "No strong suspicious indicators were found in fallback logic.",
        }

    def _candidate(self, process: dict[str, Any]) -> bool:
        name = (process.get("name") or "").lower()
        command_line = (process.get("command_line") or "").lower()
        return (
            name in HIGH_RISK_NAMES
            or any(part in name for part in HIGH_RISK_NAME_PARTS)
            or name in SHELL_NAMES
            or any(marker in command_line for marker in STRONG_GENERIC_MARKERS)
        )

    def classify_processes(
        self,
        processes: list[dict[str, Any]],
        host_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        suspicious: list[dict[str, Any]] = []

        for process in processes:
            if not self._candidate(process):
                continue

            result = (
                self._ai_assess(process, host_context)
                or self._local_ml.assess(process)
                or self._fallback_assess(process)
            )
            if not result.get("suspicious"):
                continue

            enriched = dict(process)
            enriched["ai_confidence"] = int(result.get("confidence", 0) or 0)
            enriched["ai_category"] = result.get("category", "suspicious")
            enriched["ai_reason"] = result.get("reason", "Flagged by process intelligence analysis.")
            if self.api_key:
                enriched["detection_source"] = "gemini"
            elif result.get("category") == "IsolationForest Anomaly":
                enriched["detection_source"] = "local_ml_isolation_forest"
            else:
                enriched["detection_source"] = "fallback"
            suspicious.append(enriched)

        suspicious.sort(
            key=lambda item: (item.get("ai_confidence", 0), item.get("cpu_percent", 0), item.get("memory_percent", 0)),
            reverse=True,
        )
        return suspicious[:10]
