"""
Authentication Module — Industrial Grade
=========================================
Uses python-jose for JWT with:
  - HS512 algorithm (stronger than HS256, uses same symmetric key)
  - Algorithm whitelist to prevent alg:none attacks
  - jti (JWT ID) claim for token revocation via MongoDB blacklist
  - RBAC role claim embedded in token
  - No hardcoded secret — crashes at startup if JWT_SECRET_KEY not set

Obfuscation:
  - Auth errors are always generic (same message for wrong user / wrong pass / locked)
  - Token validation errors return 401 with no internal detail
"""
from __future__ import annotations

import os
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.mongo_auth import is_token_revoked, revoke_token
from app.core.security import obfuscate_auth_error, obfuscate_error


# ─── Secret key validation ────────────────────────────────────────────────────
_JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "")
if not _JWT_SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is not set.\n"
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(64))\"\n"
        "Then add it to your .env file."
    )
if len(_JWT_SECRET_KEY) < 32:
    raise RuntimeError(
        f"JWT_SECRET_KEY is too short ({len(_JWT_SECRET_KEY)} chars). "
        "Minimum 32 characters required. Use 64+ chars for production."
    )

# ── Algorithm whitelist — prevents alg:none and algorithm-confusion attacks ──
_JWT_ALGORITHM = "HS512"          # Stronger than HS256, same key material
_ALLOWED_ALGORITHMS = ["HS512"]   # Strict whitelist — python-jose enforces this

# ── Token expiry (configurable, default 8 hours) ──────────────────────────────
_JWT_EXPIRE_MINUTES: int = int(os.environ.get("JWT_EXPIRE_MINUTES", "480"))

# ── FastAPI security scheme ───────────────────────────────────────────────────
security = HTTPBearer(auto_error=False)


# ─── Token creation ───────────────────────────────────────────────────────────
def create_access_token(
    username: str,
    role: str,
    display_id: str,
    expires_delta_minutes: Optional[int] = None,
) -> dict[str, str]:
    """Create a signed JWT.
    Returns dict with token string and jti for client reference.
    """
    expire_mins = expires_delta_minutes or _JWT_EXPIRE_MINUTES
    now = int(time.time())
    jti = secrets.token_urlsafe(16)  # Unique token ID for revocation

    payload = {
        "sub": username,
        "role": role,
        "did": display_id,           # Obfuscated display ID
        "jti": jti,
        "iat": now,
        "exp": now + (expire_mins * 60),
    }

    token = jwt.encode(payload, _JWT_SECRET_KEY, algorithm=_JWT_ALGORITHM)
    return {"access_token": token, "jti": jti}


# ─── Token decoding & validation ──────────────────────────────────────────────
def decode_access_token(token: str) -> dict:
    """Decode and fully validate a JWT.
    Raises HTTP 401 on any validation failure (generic message — no detail leak).
    """
    _UNAUTH = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=obfuscate_auth_error(),
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            _JWT_SECRET_KEY,
            algorithms=_ALLOWED_ALGORITHMS,  # Strict whitelist
        )
    except JWTError:
        # Catches: expired, invalid signature, alg:none, malformed, nbf, etc.
        raise _UNAUTH

    # ── Extra validations ─────────────────────────────────────────────────────
    if not payload.get("sub"):
        raise _UNAUTH

    jti = payload.get("jti")
    if not jti:
        raise _UNAUTH

    # Check token revocation blacklist in MongoDB
    if is_token_revoked(jti):
        raise _UNAUTH

    return payload


# ─── FastAPI dependency — current user ────────────────────────────────────────
def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    """FastAPI dependency: extract and validate the Bearer token.
    Returns the decoded payload (sub, role, jti, did).
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=obfuscate_auth_error(),
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_access_token(credentials.credentials)


# ─── RBAC role enforcement ────────────────────────────────────────────────────
def require_role(*allowed_roles: str):
    """Factory that returns a FastAPI dependency checking the user's role.

    Usage:
        @router.post("/api/admin/something")
        def admin_only(user: dict = Depends(require_role("admin"))):
            ...

    Roles hierarchy: viewer < analyst < admin
    """
    def _check(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this operation.",
            )
        return user
    return _check


# ─── Logout (token revocation) ────────────────────────────────────────────────
def logout_token(user_payload: dict) -> None:
    """Revoke the token by adding its jti to the MongoDB blacklist."""
    jti = user_payload.get("jti")
    exp = user_payload.get("exp")
    if jti and exp:
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        revoke_token(jti, expires_at)


# ─── WebSocket token verification ─────────────────────────────────────────────
def verify_ws_token(token: Optional[str] = Query(None)) -> dict:
    """Validate a token passed as a WebSocket query parameter."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=obfuscate_auth_error(),
        )
    return decode_access_token(token)


# ─── Legacy compatibility alias ───────────────────────────────────────────────
# Routes that used verify_analyst_credentials now use MongoDB
def verify_analyst_credentials(username: str, password: str) -> bool:
    """Legacy shim — kept for compatibility. Real verification is in mongo_auth."""
    from app.core.mongo_auth import verify_user_credentials
    return verify_user_credentials(username, password) is not None
