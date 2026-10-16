from __future__ import annotations

from random import choice, randint, uniform

from app.models.schemas import EventIn


HOSTS = ["finance-ws-02", "hr-laptop-01", "eng-build-03", "dc-01", "sales-ws-07"]
USERS = ["analyst1", "admin", "hr.user", "devops", "intern"]
IPS = ["10.0.0.15", "10.0.0.24", "172.16.4.8", "185.220.101.4", "45.155.205.233"]


def benign_event() -> EventIn:
    return EventIn(
        host=choice(HOSTS),
        user=choice(USERS),
        event_type=choice(["process_start", "network_connection", "login_failure"]),
        process_name=choice(["chrome.exe", "teams.exe", "explorer.exe", "outlook.exe"]),
        source_ip=choice(IPS[:3]),
        metadata={
            "failed_login_count": randint(0, 2),
            "file_modifications": randint(0, 4),
            "outbound_connections": randint(1, 8),
            "data_transfer_mb": round(uniform(1, 35), 2),
            "new_services_installed": 0,
        },
    )


def attack_event() -> EventIn:
    attack_type = choice(
        ["login_failure", "privilege_escalation", "file_integrity_change", "data_exfiltration", "lateral_movement"]
    )
    process_map = {
        "login_failure": "powershell.exe",
        "privilege_escalation": "cmd.exe",
        "file_integrity_change": "rclone.exe",
        "data_exfiltration": "rclone.exe",
        "lateral_movement": "psexec.exe",
    }
    return EventIn(
        host=choice(HOSTS),
        user=choice(["admin", "analyst1", "svc-backup"]),
        event_type=attack_type,
        process_name=process_map[attack_type],
        source_ip=choice(IPS[2:]),
        command_line="encoded execution against remote share",
        metadata={
            "failed_login_count": randint(8, 24),
            "file_modifications": randint(18, 120),
            "outbound_connections": randint(10, 40),
            "data_transfer_mb": round(uniform(450, 1800), 2),
            "new_services_installed": randint(0, 2),
            "privilege_escalation": attack_type == "privilege_escalation",
            "lateral_tools_used": attack_type == "lateral_movement",
        },
    )


def generate_events(mode: str, count: int) -> list[EventIn]:
    events: list[EventIn] = []
    for _ in range(max(count, 1)):
        if mode == "benign":
            events.append(benign_event())
        elif mode == "attack":
            events.append(attack_event())
        else:
            events.append(attack_event() if randint(0, 1) else benign_event())
    return events
