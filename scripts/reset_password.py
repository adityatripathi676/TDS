#!/usr/bin/env python3
"""
Password Management & Reset Tool for MongoDB Atlas
==================================================
Allows testing, listing, creating, and resetting user credentials directly
in the MongoDB Atlas backend used by AI-HIDS Sentinel.

Usage:
    # List all users in MongoDB
    python scripts/reset_password.py --list

    # Test login credentials
    python scripts/reset_password.py --test --username admin --password "HIDSAdmin@2026!"

    # Change/Reset password for a user
    python scripts/reset_password.py --username admin --password "NewSecurePassword123!"

    # Optionally update .env ADMIN_PASSWORD automatically
    python scripts/reset_password.py --username admin --password "NewSecurePassword123!" --update-env
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
import bcrypt
from pymongo import MongoClient

ENV_FILE = ROOT / ".env"
load_dotenv(ENV_FILE)

BCRYPT_ROUNDS = 12
COLL_USERS = "users"


def get_mongo_db():
    uri = os.environ.get("MONGODB_URI", "").strip()
    db_name = os.environ.get("MONGODB_DB_NAME", "hids_sentinel").strip()
    if not uri:
        print("[ERROR] MONGODB_URI environment variable is missing from .env.")
        sys.exit(1)
    client = MongoClient(uri, serverSelectionTimeoutMS=8000, tls=True)
    return client[db_name]


def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def list_users():
    db = get_mongo_db()
    users = list(db[COLL_USERS].find())
    print("\n" + "=" * 70)
    print(f"MongoDB User Registry ('{COLL_USERS}' collection):")
    print("=" * 70)
    if not users:
        print("  (No users found in database)")
    for u in users:
        uname = u.get("username", "<unknown>")
        role = u.get("role", "viewer")
        active = u.get("is_active", True)
        failed = u.get("failed_attempts", 0)
        locked = u.get("locked_until", None)
        last_login = u.get("last_login", "Never")
        print(f"  * Username:       {uname}")
        print(f"    Role:           {role}")
        print(f"    Active:         {active}")
        print(f"    Failed Tries:   {failed}")
        print(f"    Locked Until:   {locked}")
        print(f"    Last Login:     {last_login}")
        print("-" * 70)


def test_credentials(username: str, password: str) -> bool:
    db = get_mongo_db()
    user = db[COLL_USERS].find_one({"username": {"$regex": f"^{re.escape(username)}$", "$options": "i"}})
    if not user:
        print(f"\n[FAIL] User '{username}' was not found in MongoDB.")
        return False

    phash = user.get("password_hash", "")
    is_match = verify_password(password, phash)
    print("\n" + "=" * 60)
    print(f"Testing Authentication for: {username}")
    print("=" * 60)
    print(f"  Account Active:      {user.get('is_active', True)}")
    print(f"  Failed Attempts:     {user.get('failed_attempts', 0)}")
    print(f"  Locked Until:        {user.get('locked_until')}")
    print(f"  Password Matches:    {is_match}")
    if is_match:
        print("\n[SUCCESS] Credentials verified successfully! Login will succeed.")
    else:
        print("\n[FAIL] Password does not match the stored bcrypt hash.")
    return is_match


def change_password(username: str, new_password: str, update_env: bool = False):
    if len(new_password) < 12:
        print("[WARNING] Best practice: password should be at least 12 characters.")

    db = get_mongo_db()
    new_hash = hash_password(new_password)

    result = db[COLL_USERS].update_one(
        {"username": {"$regex": f"^{re.escape(username)}$", "$options": "i"}},
        {
            "$set": {
                "password_hash": new_hash,
                "failed_attempts": 0,
                "locked_until": None,
                "is_active": True,
                "updated_at": datetime.now(timezone.utc),
            }
        },
    )

    if result.matched_count == 0:
        print(f"[FAIL] User '{username}' does not exist in MongoDB.")
        sys.exit(1)

    print(f"\n[SUCCESS] Password for user '{username}' successfully updated in MongoDB!")
    print("  - Bcrypt hash updated (work factor 12)")
    print("  - Failed attempts reset to 0")
    print("  - Lockout status cleared")
    print("  - Account marked active")

    if update_env and ENV_FILE.exists():
        content = ENV_FILE.read_text(encoding="utf-8")
        if f"ADMIN_PASSWORD=" in content:
            new_content = re.sub(r"ADMIN_PASSWORD=.*", f"ADMIN_PASSWORD={new_password}", content)
            ENV_FILE.write_text(new_content, encoding="utf-8")
            print("  - Updated ADMIN_PASSWORD in .env file.")


def main():
    parser = argparse.ArgumentParser(description="AI-HIDS MongoDB Password Reset & Verification Tool")
    parser.add_argument("--list", action="store_true", help="List all users in the MongoDB database")
    parser.add_argument("--test", action="store_true", help="Test credentials without making changes")
    parser.add_argument("-u", "--username", help="Target username")
    parser.add_argument("-p", "--password", help="Password to test or set")
    parser.add_argument("--update-env", action="store_true", help="Also update ADMIN_PASSWORD in .env file if matching")

    args = parser.parse_args()

    if args.list:
        list_users()
        return

    if args.test:
        if not args.username or not args.password:
            print("[ERROR] --test requires both --username and --password.")
            sys.exit(1)
        test_credentials(args.username, args.password)
        return

    if args.username and args.password:
        change_password(args.username, args.password, update_env=args.update_env)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
