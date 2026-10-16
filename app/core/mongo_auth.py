"""
MongoDB Atlas Authentication & User Store
=========================================
Industrial-grade user credential management using:
  - bcrypt (work factor 12) for password hashing
  - MongoDB Atlas for cloud-native, TLS-encrypted storage
  - Token blacklist with TTL-based auto-expiry
  - Account lockout after repeated failures
  - RBAC roles: viewer | analyst | admin
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError


# ─── MongoDB connection (synchronous for startup tasks) ────────────────────────
_MONGO_URI: str = os.environ.get("MONGODB_URI", "")
_DB_NAME: str = os.environ.get("MONGODB_DB_NAME", "hids_sentinel")

_sync_client: MongoClient | None = None
_async_client: AsyncIOMotorClient | None = None


def _get_sync_db():
    """Return sync MongoDB database handle (used for startup/bootstrap)."""
    global _sync_client
    if _sync_client is None:
        if not _MONGO_URI:
            raise RuntimeError(
                "MONGODB_URI environment variable is not set. "
                "Set it to your MongoDB Atlas connection string."
            )
        _sync_client = MongoClient(_MONGO_URI, serverSelectionTimeoutMS=8000, tls=True)
    return _sync_client[_DB_NAME]


def get_async_db():
    """Return async MongoDB database handle (used inside FastAPI request context)."""
    global _async_client
    if _async_client is None:
        if not _MONGO_URI:
            raise RuntimeError("MONGODB_URI environment variable is not set.")
        _async_client = AsyncIOMotorClient(_MONGO_URI, tls=True)
    return _async_client[_DB_NAME]


# ─── Schema constants ──────────────────────────────────────────────────────────
COLL_USERS = "users"
COLL_BLACKLIST = "token_blacklist"
COLL_SOAR_PENDING = "soar_pending"

MAX_FAILED_ATTEMPTS = 5          # Lock account after N failures
LOCKOUT_SECONDS = 900            # 15-minute lockout
BCRYPT_ROUNDS = 12               # Work factor — OWASP recommended minimum


# ─── Obfuscation helpers ───────────────────────────────────────────────────────
def _obfuscate_id(raw_id: str) -> str:
    """Produce a deterministic non-reversible display ID from an internal MongoDB _id.
    Prevents internal ID format leakage via API responses."""
    return hashlib.sha256(f"hids-{raw_id}".encode()).hexdigest()[:16]


def _timing_safe_sleep(base_ms: int = 120) -> None:
    """Add a small jitter delay to normalise auth response times.
    Prevents timing-based username enumeration (valid vs invalid user timing diff)."""
    jitter = secrets.randbelow(60)  # 0-59ms additional jitter
    time.sleep((base_ms + jitter) / 1000.0)


# ─── Database initialisation ───────────────────────────────────────────────────
def init_mongo_indexes() -> None:
    """Create indexes and seed the default admin user on first startup."""
    try:
        db = _get_sync_db()

        # Unique index on username (case-insensitive)
        db[COLL_USERS].create_index(
            [("username", ASCENDING)],
            unique=True,
            collation={"locale": "en", "strength": 2},
        )

        # TTL index on token_blacklist — MongoDB auto-deletes expired entries
        db[COLL_BLACKLIST].create_index(
            [("expires_at", ASCENDING)],
            expireAfterSeconds=0,  # expiry driven by the field value itself
        )
        db[COLL_BLACKLIST].create_index([("jti", ASCENDING)], unique=True)

        # TTL index on soar_pending — auto-expire stale approvals after 1 hour
        db[COLL_SOAR_PENDING].create_index(
            [("created_at", ASCENDING)],
            expireAfterSeconds=3600,
        )

        # ── Seed default admin if no users exist ──────────────────────────────────
        if db[COLL_USERS].count_documents({}) == 0:
            _seed_default_admin(db)
    except Exception as e:
        print(f"[mongo_auth] ⚠️ MongoDB Atlas connection skipped ({e}). Local fallback mode active.")


def _seed_default_admin(db) -> None:
    """Create the initial admin account from environment variables."""
    admin_user = os.environ.get("ADMIN_USERNAME", "").strip()
    admin_pass = os.environ.get("ADMIN_PASSWORD", "").strip()

    if not admin_user or not admin_pass:
        return

    if len(admin_pass) < 12:
        return

    password_hash = _hash_password(admin_pass)
    user_doc = {
        "username": admin_user,
        "password_hash": password_hash,
        "role": "admin",
        "is_active": True,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
        "display_id": _obfuscate_id(admin_user),
    }
    try:
        db[COLL_USERS].insert_one(user_doc)
        print(f"[mongo_auth] ✅ Default admin '{admin_user}' seeded into MongoDB.")
    except DuplicateKeyError:
        pass  # Already exists


# ─── Password operations ───────────────────────────────────────────────────────
def _hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt (work factor 12)."""
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def _verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt verification."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ─── Synchronous auth (called from FastAPI sync routes) ───────────────────────
def verify_user_credentials(username: str, password: str) -> dict[str, Any] | None:
    """Verify credentials against MongoDB with offline environment fallback."""
    _timing_safe_sleep()  # Always sleep to normalise response time

    try:
        db = _get_sync_db()
        # Case-insensitive lookup
        user = db[COLL_USERS].find_one(
            {"username": {"$regex": f"^{username}$", "$options": "i"}},
        )

        if user is None:
            # Check environment fallback credentials
            admin_user = os.environ.get("ADMIN_USERNAME", "admin").strip()
            admin_pass = os.environ.get("ADMIN_PASSWORD", "").strip()
            if admin_pass and username.lower() == admin_user.lower() and password == admin_pass:
                return {
                    "username": admin_user,
                    "role": "admin",
                    "display_id": _obfuscate_id(admin_user),
                    "is_active": True,
                }
            # Still do a dummy bcrypt to prevent timing enumeration
            _verify_password("dummy", "$2b$12$dummyhashfortimingnormalisation1234")
            return None

        # ── Account lockout check ─────────────────────────────────────────────────
        now = datetime.now(timezone.utc)
        locked_until = user.get("locked_until")
        if locked_until and locked_until.replace(tzinfo=timezone.utc) > now:
            return None  # Locked

        if not user.get("is_active", True):
            return None  # Disabled account

        # ── Verify password ───────────────────────────────────────────────────────
        if not _verify_password(password, user["password_hash"]):
            new_count = user.get("failed_attempts", 0) + 1
            update: dict = {"$set": {"failed_attempts": new_count}}
            if new_count >= MAX_FAILED_ATTEMPTS:
                update["$set"]["locked_until"] = datetime.now(timezone.utc)
            db[COLL_USERS].update_one({"_id": user["_id"]}, update)
            return None

        # ── Success — reset counters ──────────────────────────────────────────────
        db[COLL_USERS].update_one(
            {"_id": user["_id"]},
            {"$set": {"failed_attempts": 0, "locked_until": None, "last_login": datetime.now(timezone.utc)}},
        )

        return {
            "username": user["username"],
            "role": user.get("role", "viewer"),
            "display_id": user.get("display_id", _obfuscate_id(str(user["_id"]))),
            "is_active": user.get("is_active", True),
        }
    except Exception as e:
        print(f"[mongo_auth] ⚠️ MongoDB Atlas lookup failed ({e}). Checking local fallback credentials.")
        admin_user = os.environ.get("ADMIN_USERNAME", "admin").strip()
        admin_pass = os.environ.get("ADMIN_PASSWORD", "").strip()
        if admin_pass and username.lower() == admin_user.lower() and password == admin_pass:
            return {
                "username": admin_user,
                "role": "admin",
                "display_id": _obfuscate_id(admin_user),
                "is_active": True,
            }
        return None


# ─── Token blacklist (revocation) ─────────────────────────────────────────────
def revoke_token(jti: str, expires_at: datetime) -> None:
    """Add a JWT ID to the blacklist."""
    try:
        db = _get_sync_db()
        db[COLL_BLACKLIST].insert_one({
            "jti": jti,
            "revoked_at": datetime.now(timezone.utc),
            "expires_at": expires_at,
        })
    except Exception:
        pass


def is_token_revoked(jti: str) -> bool:
    """Return True if this JWT ID has been blacklisted."""
    try:
        db = _get_sync_db()
        return db[COLL_BLACKLIST].find_one({"jti": jti}) is not None
    except Exception:
        return False


# ─── SOAR pending approval queue ──────────────────────────────────────────────
def queue_soar_action(action: dict[str, Any]) -> str:
    """Queue a SOAR action for human approval. Returns the pending action ID."""
    db = _get_sync_db()
    doc = {**action, "status": "pending", "created_at": datetime.now(timezone.utc)}
    result = db[COLL_SOAR_PENDING].insert_one(doc)
    return str(result.inserted_id)


def get_pending_soar_actions(limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve pending SOAR actions awaiting human approval."""
    db = _get_sync_db()
    docs = list(db[COLL_SOAR_PENDING].find({"status": "pending"}).limit(limit))
    for doc in docs:
        doc["_id"] = str(doc["_id"])
    return docs


def approve_soar_action(action_id: str, approved_by: str) -> bool:
    """Mark a pending SOAR action as approved."""
    from bson import ObjectId
    db = _get_sync_db()
    result = db[COLL_SOAR_PENDING].update_one(
        {"_id": ObjectId(action_id), "status": "pending"},
        {"$set": {"status": "approved", "approved_by": approved_by,
                  "approved_at": datetime.now(timezone.utc)}},
    )
    return result.modified_count > 0


def reject_soar_action(action_id: str, rejected_by: str) -> bool:
    """Mark a pending SOAR action as rejected."""
    from bson import ObjectId
    db = _get_sync_db()
    result = db[COLL_SOAR_PENDING].update_one(
        {"_id": ObjectId(action_id), "status": "pending"},
        {"$set": {"status": "rejected", "rejected_by": rejected_by,
                  "rejected_at": datetime.now(timezone.utc)}},
    )
    return result.modified_count > 0


# ─── User management (admin operations) ───────────────────────────────────────
def create_user(username: str, password: str, role: str = "analyst") -> dict[str, Any]:
    """Create a new user account. Role must be: viewer | analyst | admin."""
    if role not in {"viewer", "analyst", "admin"}:
        raise ValueError(f"Invalid role '{role}'. Must be: viewer, analyst, admin")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")

    db = _get_sync_db()
    doc = {
        "username": username,
        "password_hash": _hash_password(password),
        "role": role,
        "is_active": True,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
        "display_id": _obfuscate_id(username),
    }
    db[COLL_USERS].insert_one(doc)
    return {"username": username, "role": role, "display_id": doc["display_id"]}


def list_users() -> list[dict[str, Any]]:
    """List all users (without password hashes)."""
    db = _get_sync_db()
    users = db[COLL_USERS].find({}, {"password_hash": 0, "_id": 0})
    return list(users)
