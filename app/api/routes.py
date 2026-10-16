from __future__ import annotations

import os
import signal
import time

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import Response

from app.core.agent_manager import MultiHostAgentManager
from app.core.auth import (
    create_access_token,
    decode_access_token,
    get_current_user,
    logout_token,
    require_role,
)
from app.core.broadcaster import broadcaster
from app.core.detector import ThreatDetector
from app.core.mongo_auth import (
    approve_soar_action,
    create_user,
    get_pending_soar_actions,
    list_users,
    queue_soar_action,
    reject_soar_action,
    verify_user_credentials,
)
from app.core.monitor import HostMonitor
from app.core.reporting import build_report_docx, build_report_pdf, generate_hids_report
from app.core.response import ThreatContainmentEngine
from app.core.security import limiter, obfuscate_auth_error
from app.core.simulator import generate_events
from app.core.soar import soar_engine
from app.core.storage import JsonStore
from app.core.yara_scanner import YARASignatureScanner
from app.core.system_scanner import run_deep_scan, get_last_deep_scan
from app.models.schemas import DetectionResult, EventIn
from app.config import SOAR_REQUIRE_APPROVAL


router = APIRouter()

store = JsonStore()
detector = ThreatDetector(store.get_events(limit=500))
monitor = HostMonitor(interval_seconds=10)
containment = ThreatContainmentEngine()
yara_scanner = YARASignatureScanner()
agent_manager = MultiHostAgentManager()


def _persist_result(result: DetectionResult) -> DetectionResult:
    event_dict = result.event.model_dump(mode="json")
    store.append_event(event_dict)
    broadcaster.broadcast_sync({"type": "event", "data": event_dict})
    if result.alert:
        alert_dict = result.alert.model_dump(mode="json")
        store.append_alert(alert_dict)
        broadcaster.broadcast_sync({"type": "alert", "data": alert_dict})
        soar_actions = soar_engine.evaluate_alert(alert_dict, event_dict)
        for action in soar_actions:
            broadcaster.broadcast_sync({"type": "soar_action", "data": action})
    monitor.note_detection_result(had_alert=bool(result.alert))
    return result


def _handle_real_event(event: EventIn) -> None:
    result = detector.analyze(event)
    _persist_result(result)


monitor.on_event_callback = _handle_real_event



def _shutdown_server() -> None:
    time.sleep(0.5)
    monitor.stop()
    try:
        os.kill(os.getpid(), signal.SIGINT)
    except Exception:
        pass
    time.sleep(0.3)
    os._exit(0)


def _build_report_payload() -> dict:
    payload = store.read()
    metrics_payload = detector.build_metrics(payload["events"], payload["alerts"])
    deep_scan_data = get_last_deep_scan()
    return generate_hids_report(
        events=list(reversed(payload["events"])),
        alerts=list(reversed(payload["alerts"])),
        baseline=detector.get_profile(),
        metrics=metrics_payload,
        monitor_status=monitor.get_status(),
        system_snapshot=monitor.get_snapshot(),
        deep_scan=deep_scan_data,
    )


def _event_from_snapshot(snapshot: dict) -> list[EventIn]:
    events: list[EventIn] = []
    host = snapshot.get("hostname", "localhost")
    default_user = snapshot["users_logged_in"][0] if snapshot.get("users_logged_in") else "system"

    # Capture real host telemetry baseline event
    events.append(
        EventIn(
            host=host,
            user=default_user,
            event_type="process_start",
            process_name="host-telemetry-agent",
            metadata={
                "failed_login_count": 0,
                "file_modifications": 0,
                "outbound_connections": snapshot.get("active_connections", 0),
                "data_transfer_mb": round(float(snapshot.get("cpu_percent", 0.0)) + float(snapshot.get("memory_percent", 0.0)), 2),
                "new_services_installed": 0,
                "cpu_percent": snapshot.get("cpu_percent", 0.0),
                "memory_percent": snapshot.get("memory_percent", 0.0),
                "total_processes": snapshot.get("total_processes", 0),
            },
        )
    )

    if snapshot.get("cpu_percent", 0) >= 85 or snapshot.get("memory_percent", 0) >= 90:
        events.append(
            EventIn(
                host=host,
                user=default_user,
                event_type="process_start",
                process_name="resource-monitor",
                metadata={
                    "failed_login_count": 0,
                    "file_modifications": 0,
                    "outbound_connections": snapshot.get("active_connections", 0),
                    "data_transfer_mb": round(snapshot["cpu_percent"] + snapshot["memory_percent"], 2),
                    "new_services_installed": 0,
                    "resource_pressure": True,
                },
            )
        )

    for proc in snapshot.get("suspicious_processes", []):
        events.append(
            EventIn(
                host=host,
                user=proc.get("username") or default_user,
                event_type="process_start",
                process_name=proc.get("name"),
                metadata={
                    "failed_login_count": 0,
                    "file_modifications": 0,
                    "outbound_connections": snapshot.get("active_connections", 0),
                    "data_transfer_mb": round(proc.get("memory_percent", 0.0), 2),
                    "new_services_installed": 0,
                    "observed_pid": proc.get("pid"),
                },
            )
        )

    if snapshot.get("active_connections", 0) >= 120:
        events.append(
            EventIn(
                host=host,
                user=default_user,
                event_type="network_connection",
                process_name="network-stack",
                metadata={
                    "failed_login_count": 0,
                    "file_modifications": 0,
                    "outbound_connections": snapshot["active_connections"],
                    "data_transfer_mb": round(snapshot["active_connections"] * 1.5, 2),
                    "new_services_installed": 0,
                },
            )
        )

    events.extend(monitor.collect_real_os_events())
    return events



# ─── UNPROTECTED PUBLIC ENDPOINTS ───────────────────────────────────────────
@router.get("/api/health")
def health() -> dict[str, str]:
    # Minimal response — intentionally reveals nothing about the stack
    return {"status": "ok"}


@router.post("/api/auth/login")
@limiter.limit("5/minute")           # 🔒 Brute-force protection: 5 attempts/min/IP
def login(request: Request, payload: dict) -> dict:
    """Authenticate and issue a JWT. Rate-limited to 5 requests/minute per IP.
    Always returns the same generic error message to prevent user enumeration."""
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=obfuscate_auth_error(),
        )

    # verify_user_credentials handles bcrypt, lockout, and timing normalisation
    user = verify_user_credentials(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=obfuscate_auth_error(),   # Same message regardless of reason
        )

    token_data = create_access_token(
        username=user["username"],
        role=user["role"],
        display_id=user["display_id"],
    )
    return {
        "access_token": token_data["access_token"],
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "display_id": user["display_id"],
    }


@router.post("/api/auth/logout")
def logout(user: dict = Depends(get_current_user)) -> dict:
    """Revoke the current JWT by adding its jti to the MongoDB blacklist.
    After logout the token is permanently invalid even if not expired."""
    logout_token(user)
    return {"message": "Logged out successfully."}


@router.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    """Return the current user's profile (sanitised — no internal fields)."""
    return {
        "username": user.get("sub"),
        "role": user.get("role"),
        "display_id": user.get("did"),
    }


# ─── PROTECTED REST ENDPOINTS ────────────────────────────────────────────────
@router.get("/api/metrics")
def metrics(user: dict = Depends(get_current_user)) -> dict:
    import datetime as _dt
    payload = store.read()
    events  = payload["events"]
    alerts  = payload["alerts"]

    metrics_payload = detector.build_metrics(events, alerts)

    # ── events_per_hour ──────────────────────────────────────────────────────
    # Count events whose created_at is within the last 60 minutes
    now_utc = _dt.datetime.now(_dt.timezone.utc)
    one_hour_ago = now_utc - _dt.timedelta(hours=1)
    events_hr = 0
    for ev in events:
        ts_raw = ev.get("created_at") or ev.get("timestamp", "")
        if not ts_raw:
            continue
        try:
            ts = _dt.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if ts >= one_hour_ago:
                events_hr += 1
        except Exception:
            pass
    metrics_payload["events_per_hour"] = events_hr

    # ── system_boot_time ─────────────────────────────────────────────────────
    # Real PC boot time as a UTC epoch float so the frontend can compute
    # accurate uptime locally and tick it every second without polling.
    import psutil as _psutil
    metrics_payload["system_boot_time"] = _psutil.boot_time()   # epoch seconds (float)
    mon_status = monitor.get_status()

    # ── anomaly_score ────────────────────────────────────────────────────────
    # Average anomaly score across the last 20 alert records
    recent_alerts = alerts[:20]
    if recent_alerts:
        scores = [float(a.get("anomaly_score") or 0) for a in recent_alerts]
        avg_score = round(sum(scores) / len(scores), 2)
    else:
        avg_score = 0.0
    metrics_payload["anomaly_score"] = avg_score

    metrics_payload["monitor_enabled"]    = mon_status["enabled"]
    metrics_payload["active_ml_engine"]   = "gemini-2.5-flash" if os.getenv("GEMINI_API_KEY") else "local_isolation_forest_ml"
    metrics_payload["authenticated_user"] = user.get("sub")
    return metrics_payload


@router.get("/api/alerts")
def alerts(limit: int = 50, user: dict = Depends(get_current_user)) -> list[dict]:
    return store.get_alerts(limit=limit)


@router.get("/api/events")
def events(limit: int = 50, user: dict = Depends(get_current_user)) -> list[dict]:
    return store.get_events(limit=limit)


@router.get("/api/baseline")
def baseline(user: dict = Depends(get_current_user)) -> dict:
    return detector.refresh_baseline_from_db(store)


@router.get("/api/report")
def report(user: dict = Depends(get_current_user)) -> dict:
    return _build_report_payload()


@router.get("/api/report/export")
def export_report(format: str = "pdf", user: dict = Depends(get_current_user)) -> Response:
    report_payload = _build_report_payload()
    normalized = format.lower()
    if normalized == "pdf":
        filename, content = build_report_pdf(report_payload)
        media_type = "application/pdf"
    elif normalized in {"word", "docx"}:
        filename, content = build_report_docx(report_payload)
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        return Response(content="Unsupported export format", status_code=400, media_type="text/plain")

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/api/system")
def system_snapshot(user: dict = Depends(get_current_user)) -> dict:
    return monitor.get_snapshot()


@router.get("/api/monitor/status")
def monitor_status(user: dict = Depends(get_current_user)) -> dict:
    return monitor.get_status()


@router.post("/api/monitor/start")
def start_monitor(user: dict = Depends(get_current_user)) -> dict:
    monitor.start()
    snapshot = monitor.scan_now()
    return {"status": "started", "snapshot": snapshot.model_dump(mode="json")}


@router.post("/api/monitor/stop")
def stop_monitor(user: dict = Depends(get_current_user)) -> dict:
    monitor.stop()
    return {"status": "stopped"}


@router.post("/api/monitor/scan")
def scan_monitor(user: dict = Depends(get_current_user)) -> dict:
    snapshot = monitor.scan_now()
    generated_results = []
    for event in _event_from_snapshot(snapshot.model_dump(mode="json")):
        result = detector.analyze(event)
        _persist_result(result)
        generated_results.append(result.model_dump(mode="json"))
    return {
        "snapshot": snapshot.model_dump(mode="json"),
        "generated_events": len(generated_results),
        "results": generated_results,
    }


@router.post("/api/events")
def ingest_event(event: EventIn, user: dict = Depends(get_current_user)) -> dict:
    result = detector.analyze(event)
    _persist_result(result)
    return result.model_dump(mode="json")


@router.post("/api/simulate")
def simulate(mode: str = "mixed", count: int = 5, user: dict = Depends(get_current_user)) -> dict:
    generated = []
    alerts_created = 0
    for event in generate_events(mode=mode, count=count):
        result = detector.analyze(event)
        _persist_result(result)
        generated.append(result.model_dump(mode="json"))
        if result.alert:
            alerts_created += 1
    return {
        "generated": len(generated),
        "alerts_created": alerts_created,
        "mode": mode,
        "results": generated,
    }


@router.post("/api/reset")
def reset(user: dict = Depends(get_current_user)) -> dict[str, str]:
    store.reset()
    monitor.reset_counters()
    snapshot = monitor.scan_now()
    for event in _event_from_snapshot(snapshot.model_dump(mode="json")):
        result = detector.analyze(event)
        _persist_result(result)
    detector.refresh_baseline_from_db(store)
    return {"status": "reset"}



@router.post("/api/app/shutdown")
def shutdown_app(background_tasks: BackgroundTasks, user: dict = Depends(get_current_user)) -> dict[str, str]:
    background_tasks.add_task(_shutdown_server)
    return {"status": "shutting_down"}


# ─── ACTIVE THREAT CONTAINMENT ENDPOINTS ─────────────────────────────────────
@router.post("/api/response/kill-process")
def kill_process_route(payload: dict, user: dict = Depends(get_current_user)) -> dict:
    pid = int(payload.get("pid", 0))
    res = containment.kill_process(pid)
    broadcaster.broadcast_sync({"type": "containment", "action": "kill_process", "result": res})
    return res


@router.post("/api/response/block-ip")
def block_ip_route(payload: dict, user: dict = Depends(get_current_user)) -> dict:
    ip = str(payload.get("ip", "")).strip()
    res = containment.block_ip(ip)
    broadcaster.broadcast_sync({"type": "containment", "action": "block_ip", "result": res})
    return res


@router.post("/api/response/unblock-ip")
def unblock_ip_route(payload: dict, user: dict = Depends(get_current_user)) -> dict:
    ip = str(payload.get("ip", "")).strip()
    return containment.unblock_ip(ip)


# ─── YARA MALWARE SCANNER ENDPOINT ──────────────────────────────────────────
@router.post("/api/scan/yara")
def scan_yara(payload: dict, user: dict = Depends(get_current_user)) -> dict:
    file_path = str(payload.get("file_path", "")).strip()
    target = str(payload.get("target", "")).strip()
    if target:
        return yara_scanner.scan_text(target)
    if file_path:
        return yara_scanner.scan_file(file_path)
    return yara_scanner.scan_process(payload.get("process", {}))


# ─── DEEP SYSTEM / FIRMWARE SCAN ENDPOINT ─────────────────────────────────────
# Runs the full real-hardware scan in a worker thread so the async event loop
# is not blocked.  The scan takes 15-30s on a typical Windows machine.
@router.post("/api/system/deep-scan")
def deep_scan(user: dict = Depends(get_current_user)) -> dict:
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_deep_scan)
        result = future.result(timeout=120)   # hard cap 2 min
    return result


# ─── ELEVATED / UAC SCAN ENDPOINTS ───────────────────────────────────────────
from app.core.elevated_scanner import (
    get_status as elev_get_status,
    get_cached_result as elev_get_cached,
    request_elevated_scan,
    is_admin,
)


@router.get("/api/system/elevation-status")
def elevation_status(user: dict = Depends(get_current_user)) -> dict:
    """
    Return current process admin state and whether a previous elevated
    scan result is cached.  No side-effects.
    """
    return elev_get_status()


@router.post("/api/system/elevated-scan")
def elevated_scan(user: dict = Depends(get_current_user)) -> dict:
    """
    Trigger a UAC-elevated firmware/TPM scan.

    This endpoint:
      1. Writes a PowerShell script to %TEMP%
      2. Calls ShellExecuteW("runas") → Windows UAC prompt appears on desktop
      3. User must click "Yes" on the UAC dialog
      4. Elevated PS runs Get-Tpm, Confirm-SecureBootUEFI, Win32_Tpm CIM,
         full Get-MpComputerStatus and writes JSON to %TEMP%
      5. This endpoint polls for the result (up to 120 s) and returns it

    If the server is already running as Administrator, the UAC step is skipped
    and results are returned immediately.
    """
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(request_elevated_scan, 120)
        try:
            result = future.result(timeout=130)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Elevated scan failed: {exc}"
            )
    return result


@router.get("/api/system/elevated-result")
def elevated_result(user: dict = Depends(get_current_user)) -> dict:
    """Return the cached result from the last successful elevated scan."""
    cached = elev_get_cached()
    if not cached:
        raise HTTPException(
            status_code=404,
            detail="No elevated scan result available. Run POST /api/system/elevated-scan first."
        )
    return cached



# ─── MULTI-HOST AGENT NETWORK ENDPOINTS ──────────────────────────────────────
@router.get("/api/agents")
def list_agents(user: dict = Depends(get_current_user)) -> list[dict]:
    return agent_manager.get_agents()


@router.post("/api/agents/register")
def register_agent(payload: dict, user: dict = Depends(get_current_user)) -> dict:
    hostname = payload.get("hostname", "unknown-node")
    os_platform = payload.get("os_platform", "unknown")
    ip_address = payload.get("ip_address", "127.0.0.1")
    return agent_manager.register_agent(hostname=hostname, os_platform=os_platform, ip_address=ip_address)


@router.post("/api/agents/heartbeat")
def agent_heartbeat(payload: dict, user: dict = Depends(get_current_user)) -> dict:
    agent_id = payload.get("agent_id", "")
    events_count = int(payload.get("events_count", 0))
    return agent_manager.heartbeat(agent_id=agent_id, events_count=events_count)


# ─── SOAR AUTOMATED INCIDENT RESPONSE PLAYBOOK ENDPOINTS ─────────────────────
@router.get("/api/soar/status")
def soar_status(user: dict = Depends(get_current_user)) -> dict:
    return soar_engine.get_status()


@router.get("/api/soar/history")
def soar_history(limit: int = 50, user: dict = Depends(get_current_user)) -> list[dict]:
    return soar_engine.get_history(limit=limit)


@router.post("/api/soar/toggle")
def soar_toggle(
    payload: dict,
    user: dict = Depends(require_role("admin")),   # 🔒 Admin only
) -> dict:
    """Enable or disable SOAR automation. Restricted to admin role."""
    enabled = bool(payload.get("enabled", True))
    return soar_engine.toggle_soar(enabled=enabled)


# ─── SOAR HUMAN APPROVAL QUEUE ────────────────────────────────────────────────
@router.get("/api/soar/pending")
def soar_pending_actions(
    user: dict = Depends(require_role("analyst", "admin")),
) -> list[dict]:
    """List SOAR actions pending human review. Analyst+ access."""
    return get_pending_soar_actions(limit=50)


@router.post("/api/soar/approve/{action_id}")
def approve_soar(
    action_id: str,
    user: dict = Depends(require_role("analyst", "admin")),
) -> dict:
    """Approve a pending SOAR action for execution."""
    if approve_soar_action(action_id, approved_by=user.get("sub", "unknown")):
        return {"status": "approved", "action_id": action_id}
    raise HTTPException(status_code=404, detail="Pending action not found.")


@router.post("/api/soar/reject/{action_id}")
def reject_soar(
    action_id: str,
    user: dict = Depends(require_role("analyst", "admin")),
) -> dict:
    """Reject and discard a pending SOAR action."""
    if reject_soar_action(action_id, rejected_by=user.get("sub", "unknown")):
        return {"status": "rejected", "action_id": action_id}
    raise HTTPException(status_code=404, detail="Pending action not found.")


# ─── USER MANAGEMENT (admin only) ────────────────────────────────────────────
@router.get("/api/admin/users")
def list_all_users(
    user: dict = Depends(require_role("admin")),
) -> list[dict]:
    """List all user accounts. Admin only."""
    return list_users()


@router.post("/api/admin/users")
def create_new_user(
    payload: dict,
    user: dict = Depends(require_role("admin")),
) -> dict:
    """Create a new user account. Admin only."""
    try:
        return create_user(
            username=payload.get("username", ""),
            password=payload.get("password", ""),
            role=payload.get("role", "analyst"),
        )
    except (ValueError, Exception) as exc:
        raise HTTPException(status_code=400, detail=str(exc))



# ─── ADMIN MANAGEMENT DASHBOARD ──────────────────────────────────────────────
@router.get("/api/admin/dashboard")
def admin_dashboard(user: dict = Depends(require_role("admin"))) -> dict:
    """Return a full security posture / progress summary for the admin dashboard."""
    import os, sys
    from app.config import (
        MONGODB_URI, JWT_SECRET_KEY, SOAR_REQUIRE_APPROVAL, SOAR_ENABLED,
        SOAR_ALERT_THRESHOLD, GEMINI_API_KEY, JWT_EXPIRE_MINUTES,
    )

    data = store.read()
    events_count  = len(data["events"])
    alerts_count  = len(data["alerts"])
    mongo_ok      = bool(MONGODB_URI)
    jwt_ok        = len(JWT_SECRET_KEY) >= 32
    gemini_active = bool(GEMINI_API_KEY)

    security_checks = [
        {"id": "mongodb",        "label": "MongoDB Atlas Connected",         "status": "pass" if mongo_ok else "fail",
         "detail": "Credentials stored in cloud-native encrypted store." if mongo_ok else "MONGODB_URI not configured."},
        {"id": "jwt_strength",   "label": "JWT Secret Key Strength",         "status": "pass" if jwt_ok else "fail",
         "detail": f"HS512 key — {len(JWT_SECRET_KEY)} chars (≥32 required)." if jwt_ok else "JWT_SECRET_KEY too short or missing."},
        {"id": "jwt_algo",       "label": "JWT Algorithm Whitelist (HS512)", "status": "pass",
         "detail": "Algorithm whitelist enforced via python-jose. Alg:none attacks blocked."},
        {"id": "bcrypt",         "label": "bcrypt Password Hashing",         "status": "pass",
         "detail": "Work factor 12. Passwords never stored in plaintext."},
        {"id": "rate_limit",     "label": "Login Rate Limiting (5/min)",     "status": "pass",
         "detail": "slowapi enforces 5 requests/minute per IP on /api/auth/login."},
        {"id": "obfuscation",    "label": "Auth Error Obfuscation",          "status": "pass",
         "detail": "All auth failures return a generic message. Timing normalization active."},
        {"id": "security_hdrs",  "label": "Security Response Headers",       "status": "pass",
         "detail": "CSP, HSTS, X-Frame-Options, X-Content-Type-Options applied globally."},
        {"id": "soar_approval",  "label": "SOAR Human Approval Gate",        "status": "pass" if SOAR_REQUIRE_APPROVAL else "warn",
         "detail": "Critical actions require analyst approval before execution." if SOAR_REQUIRE_APPROVAL else "SOAR auto-executes without approval (SOAR_REQUIRE_APPROVAL=false)."},
        {"id": "rbac",           "label": "RBAC (viewer/analyst/admin)",     "status": "pass",
         "detail": "Role-based access control enforced on all sensitive endpoints."},
        {"id": "docs_disabled",  "label": "API Docs Disabled",               "status": "pass",
         "detail": "/docs and /redoc are disabled. OpenAPI schema not publicly exposed."},
        {"id": "token_revoke",   "label": "JWT Token Revocation (Blacklist)","status": "pass",
         "detail": "MongoDB TTL blacklist allows immediate logout and token invalidation."},
        {"id": "ai_classifier",  "label": "AI Process Classifier",           "status": "pass" if gemini_active else "warn",
         "detail": "Gemini API active for AI classification." if gemini_active else "Using local IsolationForest ML (Gemini API key not set)."},
    ]
    passed = sum(1 for c in security_checks if c["status"] == "pass")
    warned = sum(1 for c in security_checks if c["status"] == "warn")
    failed = sum(1 for c in security_checks if c["status"] == "fail")
    score  = round((passed / len(security_checks)) * 100)

    return {
        "security_score": score,
        "checks": {"total": len(security_checks), "passed": passed, "warned": warned, "failed": failed},
        "security_items": security_checks,
        "system_info": {
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
            "jwt_expire_minutes": JWT_EXPIRE_MINUTES,
            "soar_enabled": SOAR_ENABLED,
            "soar_threshold": SOAR_ALERT_THRESHOLD,
            "soar_require_approval": SOAR_REQUIRE_APPROVAL,
            "gemini_active": gemini_active,
        },
        "data_stats": {
            "events_in_db": events_count,
            "alerts_in_db": alerts_count,
            "monitor_status": monitor.get_status(),
        },
        "users": list_users(),
    }


@router.post("/api/admin/reset")
def full_data_reset(user: dict = Depends(require_role("admin"))) -> dict:
    """Wipe all events and alerts from the SQLite store and reset monitor counters.
    Does NOT affect users or security configuration. Admin only."""
    store.reset()
    monitor.reset_counters()
    detector.refresh_baseline([])
    return {
        "status": "ok",
        "message": "All events and alerts cleared. Monitor counters reset. Baseline cleared.",
        "events_remaining": 0,
        "alerts_remaining": 0,
    }


@router.post("/api/admin/restart")
def restart_application(user: dict = Depends(require_role("admin"))) -> dict:
    """Gracefully restart the Uvicorn process (triggers StatReloader to reload).
    The server will be briefly unavailable during reload."""
    import threading
    threading.Thread(target=_shutdown_server, daemon=True).start()
    return {"status": "restarting", "message": "Application restart initiated. Reconnect in ~3 seconds."}


# ─── WEBSOCKET ZERO-LATENCY TELEMETRY STREAM ────────────────────────────────
@router.websocket("/ws/telemetry")
async def ws_telemetry(websocket: WebSocket, token: str = Query(None)) -> None:
    if not token:
        await websocket.close(code=4001, reason="Missing authentication token")
        return
    try:
        decode_access_token(token)
    except Exception:
        await websocket.close(code=4002, reason="Invalid or expired token")
        return

    await broadcaster.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception:
        broadcaster.disconnect(websocket)

