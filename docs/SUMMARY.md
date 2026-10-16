# AI-HIDS & Threat Detection System (TDS) - Upgrade Summary

Summary of architectural enhancements, security upgrades, real telemetry enforcement, and CoinPulse Electric UI redesigns implemented in this project.

---

## 1. UI Contrast & Styling Fix
* **File**: `frontend/src/styles.css`
* **Fix**: Applied explicit text color styling (`#f8fafc`) to `.ov-stat` and `.ov-stat-val` metric cards. Metric numbers (**Events**, **Alerts**, **Critical**, **Benign**) now render in crisp, high-contrast, ultra-readable white text on dark backgrounds.

---

## 2. Server Shutdown Reliability
* **File**: `app/api/routes.py`
* **Fix**: Enhanced `_shutdown_server()` with `os._exit(0)` to guarantee that clicking **Stop Application** in the UI instantly terminates both Uvicorn supervisor and worker processes cleanly on Windows.

---

## 3. Real Cross-OS Security Event Log Ingestion
* **File**: `app/core/os_event_log.py`
* **Features**: Replaced synthetic simulation with real OS security log collectors:
  - **Windows**: Ingests Security & System Event IDs `4625` (Failed Logon), `4624` (Success Logon), `4672` (Special Privileges), `7045` (Service Installation), `4688` (Process Creation with Command Line). Features dual-mode parsing (`win32evtlog` handles + `wevtutil` fallback XML).
  - **Linux**: Reads `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, `/var/log/audit/audit.log` for failed SSH logons and `sudo` privilege escalations.
  - **macOS**: Queries unified logs for authorization failures and privileged commands.

---

## 4. Real-Time File Integrity Monitoring (FIM)
* **File**: `app/core/fim.py`
* **Features**: Uses `watchdog` to monitor critical OS directories across Windows, Linux, and macOS for file creation, modification, and deletion. Calculates file modification velocity to detect ransomware-like mass modification activity.

---

## 5. Local SQLite Storage Engine (`data/tds.db`)
* **Files**: `app/config.py`, `app/core/storage.py`
* **Features**: Replaced flat JSON file storage (`data/store.json`) with a self-contained, thread-safe SQLite database (`data/tds.db`).
  - Uses SQLite **WAL mode** (`PRAGMA journal_mode=WAL;`) with a 5000ms busy timeout for safe concurrent thread reads/writes.
  - Relational schema for `events` and `alerts` tables with indexes on `timestamp`, `event_type`, `severity`, and `created_at`.

---

## 6. Dynamic Rolling Host Baseline Engine
* **File**: `app/core/detector.py`
* **Features**: Added `refresh_baseline_from_db()` to compute moving statistical mean and standard deviation Z-score parameters dynamically from SQLite host history (`data/tds.db`).

---

## 7. Local IsolationForest Machine Learning Classifier
* **File**: `app/core/ai_classifier.py`
* **Features**: Added `LocalMLClassifier` powered by Scikit-Learn (`sklearn.ensemble.IsolationForest`).
  - Extracts 6-dimensional feature vectors per process (`cpu_percent`, `memory_percent`, `cmdline_length`, `high_risk_binary_flag`, `shell_flag`, `suspicious_argument_count`).
  - Automatically activates when `GEMINI_API_KEY` is absent, giving 100% local, offline ML threat classification.

---

## 8. Enterprise Security Suite Upgrades
* **Active Threat Response & Containment (`app/core/response.py`)**:
  - `kill_process(pid)`: Immediately terminates malicious processes using `psutil`.
  - `block_ip(ip)`: Cross-OS firewall blocking via `netsh advfirewall` (Windows) / `iptables` (Linux) / `pfctl` (macOS).
* **Zero-Latency WebSocket Stream (`app/core/broadcaster.py`)**:
  - Direct WebSocket push `/ws/telemetry` streaming events and critical threat alerts to the React console in sub-second real-time.
* **YARA Malware Signature Scanner (`app/core/yara_scanner.py`)**:
  - Scans files and process strings against compiled YARA signature rules (Mimikatz credential dumping, Ransomware file extensions & commands, Cobalt Strike beacons, Webshells).
* **Multi-Host Agent Fleet Manager (`app/core/agent_manager.py`)**:
  - Manages enterprise endpoint fleet registration, status tracking, and heartbeats.
* **Console Integration (`frontend/src/App.jsx`)**:
  - Interactive 1-click active response controls on Alert Queue and Suspicious Process inspector.
  - Dedicated **YARA Scan** and **Agent Fleet** navigation tabs.

---

## 9. API Authentication & JWT Token Security (P1 Priority)
* **Auth Core (`app/core/auth.py`)**:
  - Standard-compliant HS256 JWT encoding, payload expiration verification, HMAC analyst credential comparison, and FastAPI `HTTPBearer` security dependency.
  - WebSocket query parameter authentication (`/ws/telemetry?token=<jwt_token>`).
* **Protected Routes (`app/api/routes.py`)**:
  - Unprotected endpoints: `/api/health`, `/api/auth/login`.
  - Secured endpoints: All metrics, events, alerts, containment, YARA scan, agent, baseline, report, simulation, reset, and WebSocket routes return `401 Unauthorized` without a valid Bearer token.
* **Analyst Authentication Portal (`frontend/src/App.jsx`)**:
  - Dedicated SOC Analyst Portal authentication screen (Default credentials: `admin` / `admin123`).
  - Automatic `Authorization: Bearer <token>` header injection for API fetch requests.
  - Token persistence in `localStorage` with explicit Logout capability.
* **Testing (`tests/test_auth.py`)**: Added full test suite covering auth verification, login endpoints, 401 Unauthorized protection, token expiration, and valid token access.

---

## 10. SOAR Automated Incident Playbook Engine (P2 Priority)
* **SOAR Core Engine (`app/core/soar.py`)**:
  - Automatically evaluates incoming threat alerts against threshold (`score >= 85.0` or `critical` severity).
  - Executable Playbooks: **Auto-Kill Malicious Process**, **Auto-Block Outbound C2 IP**, and **SIEM / Webhook Dispatcher**.
  - Maintains a thread-safe in-memory audit trail of executed automated containment actions.
* **Pipeline & API Integration (`app/api/routes.py`)**:
  - Evaluates alerts inside `_persist_result()` and broadcasts execution results over WebSocket (`soar_action`).
  - Added protected endpoints `/api/soar/status`, `/api/soar/history`, `/api/soar/toggle`.
* **Console Operations (`frontend/src/App.jsx`)**:
  - SOAR status card & toggle control on the **Monitor** page.
  - Real-time **SOAR Response Audit Log** displaying automated process terminations and IP blocks.
* **Testing (`tests/test_soar.py`)**: Added unit tests for threshold evaluation, auto-kill execution, auto-block execution, and history tracking.

---

## 11. OS Background Service Wrapper (Ops & Deployment)
* **Windows Background Service (`scripts/install_windows_service.ps1` & `uninstall_windows_service.ps1`)**:
  - Elevated PowerShell installation scripts creating service `AIHIDSSentinel` via Windows Service Control Manager (`sc.exe`).
  - Automatically configures service recovery options to auto-restart background worker on failure.
* **Linux Systemd Service (`scripts/ai-hids.service`, `install_linux_service.sh` & `uninstall_linux_service.sh`)**:
  - Standard Systemd unit file running Python host protection daemon continuously on system boot.
* **Cross-OS Service Helper (`scripts/service_manager.py`)**:
  - Command-line helper querying OS service state and outputting system-specific installation commands.
* **Testing (`tests/test_service_manager.py`)**: Unit tests verifying service status detection and script asset integrity.

---

## 12. CoinPulse Electric Design System & Complete UI Overhaul
* **Design System Specification**:
  - **Color Palette**: Permanent high-density dark mode (`#09090B` app background, `#18181B` card surface, `#2563EB` Electric Blue primary, `#84CC16` Lime secondary, `#F59E0B` Amber tertiary, `#71717A` Zinc neutral, `#EF4444` Loss/Error).
  - **Typography**: Google Fonts **Space Mono** (Headlines, Code, Badges, Tabular Numerals) + **DM Sans** (Body, Labels, Subheads).
  - **Glow Elevation**: Standard drop shadows replaced with colored dark-mode glow effects (`8px - 24px` electric blue/lime/red glows).
  - **Data Precision**: Tabular monospaced numerals enforced across all metrics, PIDs, IP addresses, and timestamps.
* **Behavioral Baseline (`PageBaseline`)**:
  - Dynamic Gaussian distribution ($\mu \pm 3\sigma$) cards, interactive category filter chips (*All*, *Auth*, *Filesystem*, *Network*, *Process*), 3-Sigma anomaly bounds, gradient variance envelope bars, and a feature distribution matrix table.
* **OWASP Security Assessment Report (`PageReport`)**:
  - Posture Score Ring Gauge (`88 / 100 Grade A · Secure`), PDF/Word export toolbar, Executive Summary brief callout (`info-note`), 2-column OWASP Security Alignment Matrix (**Security Findings** vs **Mitigation Recommendations**), Priority Threat Findings, and a numbered **Remediation Action Plan** checklist (`01`, `02`, `03`).
* **Adversary Simulation Console (`PageSimulate`)**:
  - Glassmorphic Hero Banner, 4 simulation preset cards (*Mixed Stream*, *Red Team Burst*, *High-Egress Exfiltration*, *Purge Store*), Custom Threat Injection Configurator (slider for 1–50 events, mode toggle chips), and a **MITRE ATT&CK Adversary Coverage Matrix** table (`T1110`, `T1003`, `T1486`, `T1041`, `T1068`).
* **Process Telemetry & Inspector Console (`PageProcesses`)**:
  - High-density Hero Banner with live KPI cards (*Tracked Workloads*, *Suspicious Flags*, *Alert Queue*).
  - Real-time search/filter input bar for searching active host processes by PID, Name, or Username.
  - Telemetry charts featuring Electric Blue (`#2563EB`) CPU stream, Lime (`#84CC16`) Memory stream, and CPU vs Memory BarChart.
  - Tabular monospaced workload table with PID pills, mini progress bars, and 1-click **Suspicious Process Inspector Modal** with MITRE ATT&CK tags and anomaly details.


---

## 13. 100% Real Live Host OS Telemetry Enforcement
* **Real Host Telemetry Loop**:
  - System operates strictly on **100% real host OS data** by default.
  - Removed mock `sample_events.json` initialization from startup and reset routes.
  - `HostMonitor` continuously ingests real host snapshots (`psutil` CPU %, Memory %, Disk %, Active connections, PIDs), real OS Security Event Logs (`CrossOSEventIngestor` for Windows Event Viewer IDs 4625, 4624, 4672, 4688, 7045 / Linux syslog & auth.log / macOS unified logs), and real File Integrity Monitoring (`CrossPlatformFIM` via `watchdog`).
  - Synthetic simulation events generated by `generate_events()` are strictly isolated to user actions on the Simulation tab (`/api/simulate`).

---

## 14. Verification & Test Suite Status
* **Vite Production Build**: Compiled clean (`dist/assets/index-BNLy0rN6.css` 23.92 kB, `dist/assets/index-buPN66og.js` 587.17 kB).
* **Backend Unit Tests**: All **34 unit tests pass** (`python -m unittest discover -s tests -v`).
