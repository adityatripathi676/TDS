from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


YARA_RULES = [
    {
        "name": "Mimikatz_Credential_Dumping",
        "category": "Credential Access",
        "mitre_id": "T1003.001",
        "severity": "critical",
        "patterns": [
            r"sekurlsa::logonpasswords",
            r"lsadump::sam",
            r"privilege::debug",
            r"wdigest\.dll",
            r"mimikatz",
        ],
    },
    {
        "name": "Ransomware_Mass_Encryption_Indicator",
        "category": "Impact",
        "mitre_id": "T1486",
        "severity": "critical",
        "patterns": [
            r"HOW_TO_DECRYPT",
            r"YOUR_FILES_ARE_ENCRYPTED",
            r"\.locked$",
            r"\.crypto$",
            r"vssadmin\.exe\s+delete\s+shadows",
            r"wbadmin\s+delete\s+catalog",
        ],
    },
    {
        "name": "CobaltStrike_Beacon_Payload",
        "category": "Command and Control",
        "mitre_id": "T1071.001",
        "severity": "critical",
        "patterns": [
            r"ReflectiveLoader",
            r"beacon\.dll",
            r"%COMSPEC%\s+/c",
            r"syswow64\\rundll32\.exe",
        ],
    },
    {
        "name": "Webshell_Execution_Pattern",
        "category": "Persistence",
        "mitre_id": "T1505.003",
        "severity": "high",
        "patterns": [
            r"eval\s*\(\s*base64_decode",
            r"shell_exec\s*\(",
            r"passthru\s*\(",
            r"system\s*\(\s*\$_POST",
            r"cscript\.exe\s+.*\.vbs",
        ],
    },
]


class YARASignatureScanner:
    def scan_text(self, text: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for rule in YARA_RULES:
            for pattern in rule["patterns"]:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(
                        {
                            "rule_name": rule["name"],
                            "category": rule["category"],
                            "mitre_id": rule["mitre_id"],
                            "severity": rule["severity"],
                            "matched_pattern": pattern,
                        }
                    )
                    break
        return matches

    def scan_file(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return {"status": "error", "message": f"File '{file_path}' not found.", "matches": []}

        try:
            # Read first 512 KB to avoid excessive memory usage on large files
            with open(path, "rb") as handle:
                raw_bytes = handle.read(512 * 1024)
            text_content = raw_bytes.decode("utf-8", errors="ignore")
            matches = self.scan_text(text_content)

            # Check filename pattern as well
            filename_matches = self.scan_text(path.name)
            for m in filename_matches:
                if m not in matches:
                    matches.append(m)

            return {
                "status": "scanned",
                "file_path": str(path),
                "file_name": path.name,
                "file_size": path.stat().st_size,
                "is_malicious": len(matches) > 0,
                "match_count": len(matches),
                "matches": matches,
            }
        except Exception as err:
            return {"status": "error", "message": str(err), "file_path": str(path), "matches": []}

    def scan_process(self, process_dict: dict[str, Any]) -> dict[str, Any]:
        name = process_dict.get("name", "")
        cmd = process_dict.get("command_line", "")
        text = f"{name} {cmd}"
        matches = self.scan_text(text)
        return {
            "pid": process_dict.get("pid"),
            "name": name,
            "is_malicious": len(matches) > 0,
            "match_count": len(matches),
            "matches": matches,
        }
