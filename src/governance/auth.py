"""Layer 1: Identity & Authentication (per-user, database-backed).

Accounts live in the `users` table of company.db (seeded by
scripts/seed_users.py): username + bcrypt hash + full profile + role +
department + clearance (L1..L5). Passwords are NEVER stored in plaintext:
bcrypt cost 12 for seeded accounts, with a constant-time SHA-256 fallback
that keeps the original users.yaml bootstrap valid on a fresh clone.

JWT (HS256, algorithm pinned server-side), scoped claims:
    sub (username), role, dept, clr (clearance), uid (user_id),
    name (full_name), iat, exp, jti
The role claim is the ONLY input the RBAC engine (Layer 3) trusts, so the
token is signed and its algorithm is never taken from the payload itself.
Default session lifetime is 60 minutes (config: session.token_exp_minutes).
"""
import hashlib
import json
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass, field

import jwt

from src.common.paths import COMPANY_DB, CONFIG_DIR, PROJECT_ROOT, load_yaml

_SECRET_FILE = PROJECT_ROOT / "secrets.json"


def _secret() -> str:
    """Prefer JWT_SECRET env; else generate once and store with 0600 perms."""
    import os
    env = os.environ.get("JWT_SECRET")
    if env:
        return env
    if _SECRET_FILE.exists():
        return json.loads(_SECRET_FILE.read_text())["jwt_secret"]
    value = secrets.token_urlsafe(48)
    _SECRET_FILE.write_text(json.dumps({"jwt_secret": value}))
    _SECRET_FILE.chmod(0o600)
    return value


@dataclass
class UserCtx:
    username: str
    role: str
    department: str
    user_id: int = 0
    clearance: str = "L1"
    full_name: str = ""
    email: str = ""
    session_id: str = ""          # jti - used by the CIA-A session registry
    active: bool = True


# Fallback identity store (fresh clone before seeding).
_YAML_USERS = {u["username"]: u
               for u in load_yaml(CONFIG_DIR / "users.yaml")["users"]}

_CLEARANCE_ORDER = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}


def clearance_level(clearance: str) -> int:
    """L1 < L2 < L3 < L4 < L5. Unknown labels are treated as L0 (no access)."""
    return _CLEARANCE_ORDER.get((clearance or "").upper(), 0)


def _db_user(username: str) -> dict | None:
    """Look the user up in company.db; None when table/file is absent."""
    try:
        conn = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except (sqlite3.Error, OSError):
        return None


def authenticate(username: str, password: str) -> UserCtx | None:
    """Verify credentials against the users table (bcrypt), falling back to
    the YAML bootstrap store. Inactive accounts never authenticate."""
    user = _db_user(username)
    if user is None:
        user = _YAML_USERS.get(username)
        if user is None:
            return None
        stored = user["password_hash"]
        if not secrets.compare_digest(
                hashlib.sha256(password.encode()).hexdigest(), stored):
            return None
        return UserCtx(user["username"], user["role"], user["department"],
                       user_id=0, clearance=user.get("clearance", "L2"),
                       full_name=user.get("full_name",
                                          user["username"]),
                       email=user.get("email", ""))
    if not user.get("is_active", 1):
        return None
    from src.db.seed_users import verify_password
    if not verify_password(password, user["password_hash"]):
        return None
    return UserCtx(user["username"], user["role"], user["department"],
                   user_id=user["user_id"],
                   clearance=user["clearance"],
                   full_name=user["full_name"], email=user["email"],
                   active=True)


def issue_token(user: UserCtx, algorithm: str = "HS256",
                exp_minutes: int = 60) -> str:
    now = int(time.time())
    payload = {"sub": user.username, "role": user.role,
               "dept": user.department, "clr": user.clearance,
               "uid": user.user_id, "name": user.full_name,
               "iat": now, "exp": now + exp_minutes * 60,
               "jti": uuid.uuid4().hex}
    return jwt.encode(payload, _secret(), algorithm=algorithm)


def verify_token(token: str, algorithm: str = "HS256") -> UserCtx:
    """Raises jwt.PyJWTError on any tamper/expiry. Algorithm is pinned here,
    so a token claiming 'alg: none' or 'HS512' is rejected before decode.
    Optional claims (clr/uid/name/jti) carry safe defaults so legacy tokens
    still verify - the role/dept claims remain authoritative for RBAC."""
    payload = jwt.decode(token, _secret(), algorithms=[algorithm])
    return UserCtx(
        payload["sub"], payload["role"], payload.get("dept", ""),
        user_id=int(payload.get("uid", 0) or 0),
        clearance=payload.get("clr", "L2"),
        full_name=payload.get("name", ""),
        email="", session_id=payload.get("jti", ""), active=True)


def profile(username: str) -> dict:
    """Full profile for /api/me (JWT claims + fresh DB row when available)."""
    user = _db_user(username)
    if user:
        return {k: user.get(k) for k in
                ("user_id", "username", "full_name", "email", "role",
                 "department", "clearance", "is_active", "last_login")}
    fallback = _YAML_USERS.get(username, {})
    return {"user_id": 0, "username": username,
            "full_name": fallback.get("full_name", username),
            "email": fallback.get("email", ""),
            "role": fallback.get("role", ""),
            "department": fallback.get("department", ""),
            "clearance": fallback.get("clearance", "L2"),
            "is_active": 1, "last_login": None}
