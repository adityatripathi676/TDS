# AI-HIDS Sentinel — Professional SOC & Cybersecurity Review

> **Reviewer Profile**: Senior SOC Analyst / Threat Detection Engineer  
> **Review Scope**: Full-stack code, detection logic, auth system, SOAR engine, data layer, FIM, OS event ingestion  
> **Rating**: ⭐⭐⭐☆☆ (3/5) — Solid proof-of-concept with critical production gaps

---

## Executive Summary

AI-HIDS Sentinel is a well-structured host intrusion detection system prototype. It demonstrates genuine depth — real OS telemetry ingestion, MITRE ATT&CK mapping, local ML anomaly detection, SOAR automation, and a polished React dashboard. However, **from a production SOC deployment standpoint**, there are critical security vulnerabilities, architectural flaws, and detection-quality issues that would make this unfit for real-world use without significant hardening. This review categorizes findings by severity and closes with a professional future-scope roadmap.

---

## 🔴 CRITICAL — Must Fix Before Any Real Deployment

### C-1: Hardcoded Credentials in Source Code
**File**: [`config.py`](file:///d:/Aditya/TDS_v2/app/config.py#L25-L26)

```python
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
```

**Risk**: If `.env` is not configured, the system falls back to `admin/admin123`. The frontend login hint even reads `"Default: admin / changeme"`. This is a **credential exposure** risk — any attacker who can reach the login page has pre-knowledge of default creds.

**Fix**:
- Remove all defaults. Raise `RuntimeError` at startup if credentials are not set via env
- Enforce minimum 16-char password complexity at startup validation
- Add password hashing (bcrypt/argon2) — currently comparing plain text via `hmac.compare_digest`

---

### C-2: JWT Secret Key is Hardcoded and Weak
**File**: [`config.py`](file:///d:/Aditya/TDS_v2/app/config.py#L22)

```python
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "ai-hids-sentinel-secret-key-9812739182739")
```

**Risk**: The 43-character default secret is predictable. An attacker who knows this (e.g., via source code leak, GitHub) can **forge valid JWT tokens**, bypassing all auth entirely. This is a **complete authentication bypass**.

**Fix**:
- No default. Crash at startup: `if not JWT_SECRET_KEY: raise RuntimeError("JWT_SECRET_KEY must be set")`
- Enforce minimum 64-char cryptographically random secret (e.g., `secrets.token_hex(64)`)
- Consider rotating to RS256 (asymmetric) so the public key can be distributed separately

---

### C-3: Custom JWT Implementation Instead of Battle-Tested Library
**File**: [`auth.py`](file:///d:/Aditya/TDS_v2/app/core/auth.py#L30-L89)

The project implements JWT signing/verification manually using raw `hmac`, `base64`, and `json` operations.

**Risk**:
- Algorithm confusion attacks: the `alg` field in the header is read from the token but never validated against the expected algorithm — an attacker can forge tokens using `"alg": "none"`
- Missing `nbf` (not-before) claim validation
- No token revocation / blacklist mechanism
- Subtle timing side-channels possible despite `hmac.compare_digest`

**Fix**: Replace with `python-jose` or `PyJWT`:
```python
from jose import jwt, JWTError
token = jwt.encode({"sub": user, "exp": exp}, SECRET, algorithm="HS256")
payload = jwt.decode(token, SECRET, algorithms=["HS256"])  # algorithm list = whitelist
```

---

### C-4: SOAR Auto-Kill and Auto-Block Without Any Human Approval Gate
**File**: [`soar.py`](file:///d:/Aditya/TDS_v2/app/core/soar.py#L68-L111)

```python
# Playbook 1: Auto Kill Malicious Process
if self.playbooks.get("auto_kill_process"):
    kill_res = self.containment.kill_process(pid)
```

**Risk**: Fully autonomous process termination and IP blocking triggered by an ML model/rule engine with **no human-in-the-loop approval**. False positives could kill critical business processes (e.g., `wmic.exe` used by an IT admin) or block legitimate infrastructure IPs. This is an **operational security nightmare** in production.

**Fix**:
- Add a `require_approval` flag per playbook type
- Queue critical SOAR actions to a human-review list before execution
- Add a confirmation TTL (e.g., auto-execute only if no rejection within 5 minutes for medium severity, require explicit approval for critical)
- Alert-deduplication: don't re-execute SOAR on the same PID/IP within a cooldown window

---

### C-5: Unauthenticated `/api/health` Leaks System Info
**File**: [`routes.py`](file:///d:/Aditya/TDS_v2/app/api/routes.py#L166-L168)

```python
@router.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ai-hids"}
```

**Risk**: Low individually, but fingerprints the service for attackers. In a real deployment this should require at minimum rate-limiting. The FastAPI `/docs` and `/redoc` endpoints also expose the full API schema publicly.

**Fix**:
- Disable `/docs` and `/redoc` in production: `FastAPI(docs_url=None, redoc_url=None)`
- Add `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` headers globally

---

## 🟠 HIGH — Significant Security/Reliability Risks

### H-1: No Rate Limiting on Login Endpoint
**File**: [`routes.py`](file:///d:/Aditya/TDS_v2/app/api/routes.py#L171-L181)

The `/api/auth/login` endpoint has no brute-force protection. An attacker can try unlimited password combinations.

**Fix**: Add `slowapi` rate limiter — `5 req/min per IP` on the login endpoint:
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@router.post("/api/auth/login")
@limiter.limit("5/minute")
def login(request: Request, payload: dict):
    ...
```

---

### H-2: SOAR History Stored In-Memory Only
**File**: [`soar.py`](file:///d:/Aditya/TDS_v2/app/core/soar.py#L20)

```python
self._history: list[dict] = []
```

All SOAR action history is lost on server restart. This is a **critical audit trail failure** — in a real incident, you need to know exactly what automated actions were taken.

**Fix**: Persist SOAR actions to the SQLite `alerts` table or a dedicated `soar_actions` table.

---

### H-3: Detection Engine Metrics Missing Key Fields
**File**: [`detector.py`](file:///d:/Aditya/TDS_v2/app/core/detector.py#L180-L193)

`build_metrics()` calculates `events_per_hour` is missing — the dashboard shows 0 for Events/hr because the field isn't in this method. Also `monitor_uptime` and `anomaly_score` are not populated.

**Fix**: Add the missing fields:
```python
"events_per_hour": round(len(events) / max((time_span_hours), 1), 1),
"monitor_uptime": monitor_uptime_seconds,
"anomaly_score": round(mean_anomaly_score, 2),
```

---

### H-4: WebSocket Token Passed in Query String
**File**: [`routes.py`](file:///d:/Aditya/TDS_v2/app/api/routes.py#L392)

```python
async def ws_telemetry(websocket: WebSocket, token: str = Query(None))
```

**Risk**: Query-string tokens appear in:
- Server access logs (visible to anyone with log access)
- Browser history
- Proxy/CDN logs
- Referrer headers

**Fix**: Use the WebSocket `Sec-WebSocket-Protocol` subprotocol field to pass the token, or upgrade to a `ticket`-based auth (exchange JWT for a short-lived WebSocket ticket via REST first).

---

### H-5: FIM Watches Entire Project Directory — Noisy and Fragile
**File**: [`fim.py`](file:///d:/Aditya/TDS_v2/app/core/fim.py#L63-L64)

```python
root_path = str(Path(__file__).resolve().parent.parent.parent)
self.watch_paths = [root_path]  # Watches the entire TDS_v2 project root
```

**Risk**: Watching the entire application directory for file changes means the FIM triggers on its own database writes, log rotations, temp files, and React hot-module reloads. This creates a **continuous storm of low-quality FIM events** that dilutes genuine alerts.

**Fix**: Watch only OS-critical paths:
```python
# Windows
["C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Program Files"]
# Linux
["/etc", "/bin", "/usr/bin", "/lib", "/boot"]
```

---

### H-6: IP Blocking Only Handles IPv4
**File**: [`response.py`](file:///d:/Aditya/TDS_v2/app/core/response.py#L38)

```python
if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_clean):
    return {"status": "error", "message": f"Invalid IPv4 address format: '{ip_address}'"}
```

Modern attackers heavily use IPv6. The blocker silently fails for any IPv6 C2 address.

---

## 🟡 MEDIUM — Quality and Detection Effectiveness Issues

### M-1: Single-User Authentication — No RBAC
The system has one hardcoded `admin/analyst` account. A real SOC has Tier-1 analysts, Tier-2 analysts, SOC managers, and incident responders — each with different permissions.

**Fix**: Implement Role-Based Access Control:
| Role | Can View | Can Act | Can Configure |
|------|----------|---------|---------------|
| `viewer` | ✅ | ❌ | ❌ |
| `analyst` | ✅ | ✅ | ❌ |
| `admin` | ✅ | ✅ | ✅ |

---

### M-2: MITRE ATT&CK Mapping is Oversimplified
**File**: [`detector.py`](file:///d:/Aditya/TDS_v2/app/core/detector.py#L30-L38)

```python
MITRE_MAP = {
    "network_connection": "T1021 Remote Services",
    "lateral_movement":   "T1021 Remote Services",  # Same tag for both!
```

- Multiple event types map to the same ATT&CK technique
- No sub-technique granularity (e.g., `T1021.001` for SMB, `.002` for RDP)
- No ATT&CK tactic classification (Initial Access, Execution, Persistence, etc.)

**Fix**: Integrate the official MITRE ATT&CK STIX dataset for proper technique/tactic/sub-technique resolution.

---

### M-3: Anomaly Scoring Model Trained on Synthetic Data
**File**: [`ai_classifier.py`](file:///d:/Aditya/TDS_v2/app/core/ai_classifier.py#L78-L89)

```python
synthetic_benign = np.array([
    [0.5, 1.2, 25, 0, 0, 0],
    ...  # 8 hardcoded rows
])
self.model = IsolationForest(contamination=0.15, random_state=42)
self.model.fit(synthetic_benign)
```

The IsolationForest is trained on **8 synthetic data points** — this is not a model, it's a heuristic disguised as ML. A real ML-based anomaly detector needs at minimum 7-14 days of real host baseline data.

**Fix**: Train the model on actual collected events after a 7-day baseline collection period, then retrain weekly.

---

### M-4: Brute Force Detection Counts Single Events, Not Sequences
**File**: [`detector.py`](file:///d:/Aditya/TDS_v2/app/core/detector.py#L109-L113)

```python
failed_logins = float(metadata.get("failed_login_count", 0) or 0)
if failed_logins >= 8:
    score += min(failed_logins, 20)
```

Each event carries `failed_login_count: 1`. The threshold of 8 requires a **single event to report 8 failures** — it won't catch an attacker making 7 failed attempts spread across 7 separate events (the classic slow-brute pattern).

**Fix**: Implement a sliding window counter per (user, host, source_ip) tuple — alert when cumulative failures exceed threshold within a configurable time window.

---

### M-5: No Alert Deduplication
If the same threat condition persists (e.g., mimikatz.exe running), a new alert is generated every 10-15 seconds, flooding the alert queue. In a real SOC this is called **alert fatigue** — the number one reason analysts miss real threats.

**Fix**: Implement alert deduplication by fingerprinting (host + event_type + process_name) with a 5-minute suppression window.

---

### M-6: `events_per_hour` and `monitor_uptime` Always Show 0
**File**: [`detector.py`](file:///d:/Aditya/TDS_v2/app/core/detector.py#L183-L193)

These key dashboard metrics are never populated by `build_metrics()`, so the Overview tiles always show `0`. The monitor uptime is tracked in `MonitorStatus` but never passed into the metrics payload.

---

## 🔵 LOW — Code Quality & Operational Polish

### L-1: Circular Import in Monitor
**File**: [`monitor.py`](file:///d:/Aditya/TDS_v2/app/core/monitor.py#L184)

```python
def _run(self) -> None:
    ...
    from app.api.routes import _event_from_snapshot  # ← circular import at runtime
```

A core module importing from the API layer is an architectural inversion. The routes module already imports from core — creating a circular dependency resolved only by deferred import.

---

### L-2: No Request Logging / Audit Trail
There is no structured access log. In a real SOC environment, every API call — especially authentication events, SOAR actions, and kill/block commands — must be logged to an immutable audit store (SIEM).

---

### L-3: SQLite Not Suitable for Multi-Host Production
SQLite works for single-host demos. Multi-host deployments need PostgreSQL/TimescaleDB with proper connection pooling, retention policies, and partitioning for high-volume telemetry.

---

### L-4: No TLS / HTTPS Enforcement
The server runs HTTP only. Any credential, JWT token, or sensitive alert data is transmitted in plaintext. For any deployment beyond localhost, TLS is mandatory.

---

## 🚀 Professional Future Scope Roadmap

### Phase 1 — Security Hardening (Weeks 1-2)
| Priority | Task |
|----------|------|
| 🔴 | Replace custom JWT with `python-jose`, enforce RS256 |
| 🔴 | Remove all credential defaults, enforce env-only secrets |
| 🔴 | Add bcrypt password hashing |
| 🔴 | Add login rate limiting (slowapi) |
| 🟠 | Add SOAR human-approval queue for critical actions |
| 🟠 | Persist SOAR history to DB |
| 🟠 | Disable `/docs`, `/redoc` in production |
| 🟠 | Add security response headers (CSP, HSTS, X-Frame-Options) |

### Phase 2 — Detection Quality (Weeks 3-5)
| Priority | Task |
|----------|------|
| 🟠 | Sliding-window brute force detection (Redis-backed counters) |
| 🟠 | Alert deduplication with fingerprint + suppression window |
| 🟠 | FIM watch real OS-critical paths instead of app directory |
| 🟠 | MITRE ATT&CK sub-technique + tactic integration |
| 🟡 | Train IsolationForest on 7-day real baseline, retrain weekly |
| 🟡 | IPv6 support in firewall block engine |
| 🟡 | Fix `events_per_hour` / `monitor_uptime` metrics |

### Phase 3 — SOC Operations (Weeks 6-9)
| Priority | Task |
|----------|------|
| 🟠 | RBAC: viewer / analyst / admin roles |
| 🟠 | Alert case management (assign, acknowledge, close, notes) |
| 🟠 | Incident timeline view: chain related alerts into one incident |
| 🟡 | Structured audit log (every auth event, every SOAR action) |
| 🟡 | SOC shift handover report (auto-generated PDF/email) |
| 🟡 | Multi-tenant: manage multiple monitored hosts from one console |

### Phase 4 — Enterprise Scale (Weeks 10-16)
| Priority | Task |
|----------|------|
| 🟡 | Migrate from SQLite → PostgreSQL + TimescaleDB |
| 🟡 | SIEM integration: syslog/CEF/LEEF export to Splunk, QRadar, Elastic SIEM |
| 🟡 | TLS termination + reverse proxy (Nginx/Caddy) |
| 🟡 | Agent-based deployment: deploy lightweight Python agents to remote hosts |
| 🟡 | Threat intelligence feed integration (MISP, OTX, VirusTotal) |
| 🟡 | Network-level detection: Suricata/Zeek integration for NDR coverage |

### Phase 5 — AI/ML Maturity
| Priority | Task |
|----------|------|
| 🔵 | Behavioral baselining per user (UEBA) — detect insider threats |
| 🔵 | Graph-based lateral movement detection (process trees, network graphs) |
| 🔵 | LLM-powered alert narrative generation for Tier-1 analysts |
| 🔵 | Automated threat hunting playbooks via RAG + ATT&CK knowledge base |
| 🔵 | Fine-tuned open-source LLM for on-premise process classification |

---

## Summary Score Card

| Domain | Score | Key Gap |
|--------|-------|---------|
| **Authentication & Auth** | 2/10 | Hardcoded creds, custom JWT, no rate limit |
| **Detection Quality** | 5/10 | Good rules, weak sequence detection, no dedup |
| **SOAR / Response** | 4/10 | Good structure, zero human oversight |
| **Data Persistence** | 6/10 | SQLite works for demo, not production |
| **FIM** | 3/10 | Watches wrong paths, no hash-based integrity |
| **Frontend Security** | 5/10 | Token expiry now fixed, no CSP |
| **Scalability** | 3/10 | Single-host, in-memory state, no multi-tenancy |
| **SOC Operations** | 2/10 | No alert management, no RBAC, no audit log |
| **Code Quality** | 7/10 | Clean architecture, circular import, good typing |
| **Overall** | **4/10** | Strong PoC, significant production hardening needed |

---

> **Bottom line**: This system demonstrates strong conceptual understanding of HIDS, SOAR, and ML-based anomaly detection. With the security hardening in Phase 1-2 addressed, it could serve as a genuine internal SOC tool for small-medium environments. At current state it should **not** be deployed to monitor production infrastructure without the critical fixes above.
