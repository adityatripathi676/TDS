"""
Application Configuration
==========================
All secrets MUST be supplied via environment variables.
No hardcoded defaults for credentials or JWT keys.
Startup will raise RuntimeError if required vars are missing.

Load order: System env → .env file → RuntimeError
"""
import os
from pathlib import Path

from dotenv import load_dotenv


# ── Load .env file if present ─────────────────────────────────────────────────
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE, override=False)  # System env takes priority


# ── Directory layout ──────────────────────────────────────────────────────────
BASE_DIR           = Path(__file__).resolve().parent.parent
DATA_DIR           = BASE_DIR / "data"
STATIC_DIR         = BASE_DIR / "app" / "static"
TEMPLATE_DIR       = BASE_DIR / "app" / "templates"
FRONTEND_DIR       = BASE_DIR / "frontend"
FRONTEND_DIST_DIR  = FRONTEND_DIR / "dist"
FRONTEND_ASSETS_DIR = FRONTEND_DIST_DIR / "assets"
STORE_PATH         = DATA_DIR / "runtime_store.json"
DB_PATH            = DATA_DIR / "tds.db"
SAMPLE_EVENTS_PATH = DATA_DIR / "sample_events.json"

DEFAULT_STORE = {"events": [], "alerts": []}


# ─── Startup validation ───────────────────────────────────────────────────────
def _require_env(key: str, min_len: int = 1) -> str:
    """Read an env var and crash hard if it is missing or too short.
    This is intentionally loud — missing secrets should never silently fall back."""
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(
            f"\n\n{'='*60}\n"
            f"STARTUP FAILURE: Required environment variable '{key}' is not set.\n"
            f"Add it to your .env file and restart.\n"
            f"{'='*60}\n"
        )
    if len(value) < min_len:
        raise RuntimeError(
            f"\n\n{'='*60}\n"
            f"STARTUP FAILURE: '{key}' is too short (got {len(value)}, need {min_len}+).\n"
            f"Use a stronger value.\n"
            f"{'='*60}\n"
        )
    return value


# ─── JWT configuration ────────────────────────────────────────────────────────
# NOTE: JWT_SECRET_KEY validation also happens in auth.py at import time.
# This is defence-in-depth — both layers will catch a missing key.
JWT_SECRET_KEY     = _require_env("JWT_SECRET_KEY", min_len=32)
JWT_ALGORITHM      = "HS512"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "480"))  # 8 hours


# ─── Admin credentials (only used to seed first user into MongoDB) ────────────
# After the first run these are NOT used for auth — MongoDB holds the source of truth.
ADMIN_USERNAME     = os.environ.get("ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD     = os.environ.get("ADMIN_PASSWORD", "").strip()


# ─── MongoDB Atlas ────────────────────────────────────────────────────────────
MONGODB_URI        = _require_env("MONGODB_URI", min_len=20)
MONGODB_DB_NAME    = os.environ.get("MONGODB_DB_NAME", "hids_sentinel")


# ─── AI / Gemini ─────────────────────────────────────────────────────────────
GEMINI_API_KEY     = os.environ.get("GEMINI_API_KEY", "").strip()


# ─── SOAR configuration ───────────────────────────────────────────────────────
SOAR_ENABLED           = os.environ.get("SOAR_ENABLED", "true").lower() == "true"
SOAR_ALERT_THRESHOLD   = float(os.environ.get("SOAR_ALERT_THRESHOLD", "85.0"))
SOAR_WEBHOOK_URL       = os.environ.get("SOAR_WEBHOOK_URL", "")
# Require human approval for kill-process and block-ip when severity is critical
SOAR_REQUIRE_APPROVAL  = os.environ.get("SOAR_REQUIRE_APPROVAL", "true").lower() == "true"
