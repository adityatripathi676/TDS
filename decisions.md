# Architectural Decision Record (ADR) — Security Hardening

## Context
A professional SOC review of the AI-HIDS Sentinel project revealed critical vulnerabilities:
1. Hardcoded default credentials (`admin/admin123`)
2. Predictable, hardcoded JWT secret
3. Custom JWT implementation vulnerable to `alg:none` forgery
4. Lack of rate limiting on the login endpoint
5. SOAR auto-execution lacking human oversight
6. No Role-Based Access Control (RBAC)
7. Leaky API errors enabling user enumeration

## Decisions

### 1. MongoDB Atlas for Credentials & Blacklist
**Decision**: Migrate all credential storage from config defaults to a MongoDB Atlas cluster.
**Rationale**: Cloud-native, TLS-encrypted by default, and allows horizontal scaling.
**Impact**: Requires a MongoDB URI to start the application. The system will seed a default admin account from `ADMIN_USERNAME`/`ADMIN_PASSWORD` on the very first run, and never use those variables again.

### 2. bcrypt Password Hashing
**Decision**: Use `bcrypt` with a work factor of 12 for all stored passwords.
**Rationale**: `bcrypt` is the industry standard for adaptive-cost password hashing, protecting against offline cracking.
**Impact**: The `verify_user_credentials` function now does a constant-time bcrypt verification.

### 3. Industrial JWT with `python-jose`
**Decision**: Rip out the custom JWT implementation and replace it with `python-jose`.
**Rationale**: `python-jose` correctly implements JWT RFCs, specifically allowing strict algorithm whitelisting (`HS512` only) to prevent "algorithm confusion" attacks.
**Impact**: Tokens are now significantly more secure. We also added a `jti` (JWT ID) claim to allow for explicit token revocation (logout) via a MongoDB blacklist.

### 4. Rate Limiting with `slowapi`
**Decision**: Implement in-memory rate limiting on the login endpoint (5 requests per minute per IP).
**Rationale**: Prevents brute-force password attacks. `slowapi` works perfectly with FastAPI.
**Impact**: An attacker trying to guess passwords will be blocked after 5 attempts for a minute.

### 5. Error Obfuscation & Timing Normalization
**Decision**: All auth failures (wrong user, wrong pass, locked out) return the exact same generic message: `"Authentication failed. Check credentials and try again."` A synthetic delay is added to all login requests.
**Rationale**: Prevents an attacker from guessing if a username exists based on the error message or the response time.

### 6. SOAR Human Approval Queue
**Decision**: Added a "Pending Approval" queue to the SOAR engine. Critical automated actions (kill process, block IP) can be configured to require an analyst's explicit approval before execution.
**Rationale**: Automated process termination without oversight is a major operational risk in production (false positives killing critical business services).

### 7. Security Headers & CORS Lockdown
**Decision**: Added a middleware that injects `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, and `X-Content-Type-Options`. CORS is restricted to localhost only.
**Rationale**: Essential defense-in-depth against XSS, clickjacking, and MIME-sniffing.

## Future Scope / Roadmap Implications
This foundational security upgrade sets the stage for:
- **Phase 3 (SOC Operations)**: With MongoDB in place, we can now add alert case management, audit logs, and analyst assignments.
- **Phase 4 (Enterprise Scale)**: The application is now stateless (JWT + MongoDB), making it easy to run multiple Uvicorn worker instances behind a load balancer.

---

## Management Dashboard (Phase 2.1)

### 8. Security Admin Dashboard (`/api/admin/dashboard` + `PageAdmin`)
**Decision**: Built a dedicated in-app admin management dashboard accessible via the sidebar only to users with the `admin` role.
**Rationale**: Without a live view of the security posture, it is impossible to know whether the hardening changes are actually active at runtime. The dashboard answers this in real-time.
**What it shows**:
- **Security Score** (0–100%) — computed from how many of the 12 security controls are passing.
- **Hardening Checklist** — 12 live checks: MongoDB, bcrypt, JWT algorithm, rate limiting, SOAR approval gate, RBAC, API docs disabled, token revocation, security headers, and AI classifier status.
- **System Configuration** — JWT expiry, SOAR threshold, approval gate status, Python version.
- **User Accounts (IAM)** — list of all registered users with role, active status, last login time, and display ID.
- **Danger Zone** — admin-only buttons for data reset and application restart.
**Future Impact**: This panel becomes the central operations console as the SOC team grows.

### 9. Full Data Reset (`/api/admin/reset`)
**Decision**: Added a one-click "Clear All Data" endpoint and UI button with a confirmation modal.
**Rationale**: Needed to remove all accumulated mock/demo/test data from SQLite without restarting or wiping the full database file. It clears events, alerts, resets monitor counters, and resets the ML baseline.
**Security**: Admin-only via RBAC. Requires a two-step confirmation in the UI.

### 10. Application Restart (`/api/admin/restart`)
**Decision**: Added a restart button that triggers the server's StatReloader via SIGINT, causing Uvicorn to reload the application process.
**Rationale**: After environment variable changes or configuration updates, a restart is needed without terminal access. The frontend auto-reconnects after 5 seconds.

### 11. Login Credential Hint Removed
**Decision**: Removed the "Default: admin / changeme" hint from the login screen.
**Rationale**: This hint was a critical information disclosure vulnerability. The login screen now shows "Secured by bcrypt + JWT · MongoDB Atlas" instead.

### 12. Server-Side Logout with JWT Blacklist
**Decision**: Updated the frontend logout flow to call `/api/auth/logout` before clearing localStorage.
**Rationale**: Previously, logout only removed the token from the browser — the JWT was still valid on the server until expiry. Now the `jti` is immediately added to the MongoDB revocation blacklist, making logout instant and server-enforced.
