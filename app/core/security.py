"""
Security Utilities
==================
Rate limiting, security response headers, and response obfuscation helpers.
These utilities are wired into FastAPI middleware and route decorators.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any

from fastapi import Request, Response
from slowapi import Limiter
from slowapi.util import get_remote_address


# ─── Rate Limiter (singleton) ─────────────────────────────────────────────────
# Key function: rate limit by real client IP (respects X-Forwarded-For from proxies)
def _get_client_ip(request: Request) -> str:
    """Extract real client IP, preferring X-Forwarded-For if behind a proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_get_client_ip)


# ─── Obfuscation helpers ──────────────────────────────────────────────────────
# Maps internal error detail strings to generic, non-leaking messages.
# This prevents:
#   - Username enumeration ("user not found" vs "wrong password")
#   - Technology fingerprinting ("bcrypt error: ...")
#   - Implementation detail leakage

_GENERIC_AUTH_ERROR = "Authentication failed. Check credentials and try again."
_GENERIC_SERVER_ERROR = "An internal error occurred. Reference ID: {ref}"

# Errors that should be scrubbed and replaced with generic messages
_SENSITIVE_PATTERNS = re.compile(
    r"(bcrypt|mongodb|pymongo|motor|jwt|jose|token|password|hash|sql|traceback|exception|error at line)",
    re.IGNORECASE,
)


def obfuscate_error(detail: str, internal_log: bool = True) -> str:
    """Return a safe, non-leaking error message for API responses.
    If the detail contains sensitive terms, replace with a reference-code error.
    """
    if _SENSITIVE_PATTERNS.search(detail):
        ref = hashlib.sha256(detail.encode()).hexdigest()[:8].upper()
        return _GENERIC_SERVER_ERROR.format(ref=ref)
    return detail


def obfuscate_auth_error() -> str:
    """Generic authentication error message — same for wrong user, wrong password,
    and locked account. Prevents username enumeration."""
    return _GENERIC_AUTH_ERROR


# ─── Security response headers ────────────────────────────────────────────────
SECURITY_HEADERS: dict[str, str] = {
    # Prevent clickjacking
    "X-Frame-Options": "DENY",
    # Block MIME type sniffing
    "X-Content-Type-Options": "nosniff",
    # Enforce HTTPS (1 year, includes subdomains)
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    # Restrict referrer information leakage
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Content Security Policy — restrict origins for scripts, styles, connections
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' ws://localhost:* wss://localhost:*; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    ),
    # Disable browser features that HIDS doesn't need
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # Remove server fingerprint (overrides FastAPI/uvicorn defaults)
    "Server": "HIDS-Gateway",
    # Do not cache sensitive API responses
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
}


def add_security_headers(response: Response) -> Response:
    """Attach all security headers to a response object."""
    for key, value in SECURITY_HEADERS.items():
        response.headers[key] = value
    # Remove headers that fingerprint the stack
    response.headers.pop("X-Powered-By", None)
    return response


# ─── API response sanitisation ────────────────────────────────────────────────
def sanitise_response(data: Any) -> Any:
    """Recursively remove internal fields from API responses.
    Fields like 'password_hash', '_id' should never reach the client.
    """
    BLOCKED_KEYS = {"password_hash", "password", "_id", "secret", "token_hash"}
    if isinstance(data, dict):
        return {k: sanitise_response(v) for k, v in data.items() if k not in BLOCKED_KEYS}
    if isinstance(data, list):
        return [sanitise_response(item) for item in data]
    return data
