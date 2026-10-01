"""Layer 1: Identity & Authentication (per-user, database-backed).

Accounts live in the `users` table of company.db (seeded by
scripts/seed_users.py): username + bcrypt hash (cost 12) + full profile +
role + department + clearance (L1..L5). Passwords are NEVER stored in
plaintext and NEVER in any file-based fallback store.

Security posture (audit remediation):
  - AUTH-02/03: the legacy users.yaml SHA-256 bootstrap store was REMOVED.
    Authentication fails CLOSED when the users table is missing or the
    account is absent/inactive - deletion from company.db revokes access.
  - DEPLOY-01: the JWT secret resolution is env var -> file on a WRITABLE
    path (SECRETS_DIR) -> FAIL FAST with an operator-readable error. The
    app refuses to start insecurely instead of crashing on a read-only
    filesystem at first login.
  - AUTH-06: verify_token() re-validates the account row on every request
    (role/dept/clearance/active come from the DB, not from stale claims).
  - AUTH-07: tokens missing required claims are REJECTED; a missing
    clearance claim defaults to L0 (no access), never to a working level.
  - AUTH-09: user lookup uses one cached read-only connection per thread;
    unknown users run a dummy bcrypt verify so response timing does not
    reveal which usernames exist.

JWT (HS256, algorithm pinned server-side), scoped claims:
    sub (username), role, dept, clr (clearance), uid (user_id),
    name (full_name), iat, exp, jti
The role claim is only a bootstrapping hint - the RBAC engine receives the
FRESH role from the database on every request.
Default session lifetime is 60 minutes (config: session.token_exp_minutes).
"""
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

import bcrypt as _bcrypt
import jwt

from src.common.paths import COMPANY_DB, PROJECT_ROOT, app_config, get_nested

_SECRET_PATH = Path(os.environ.get("SECRETS_DIR", PROJECT_ROOT)) / "secrets.json"


class SecretUnavailable(RuntimeError):
    """Raised at boot/first use when no JWT secret source is available."""


def _secret() -> str:
    """Resolve the JWT signing secret. Order:
    1) JWT_SECRET env var (compose/K8s/secrets manager - the production path)
    2) session.jwt_secret from app_config.yaml (DEPLOY-05: the documented
       config key is now actually read)
    3) secrets.json inside SECRETS_DIR (defaults to PROJECT_ROOT for dev)
    Otherwise raise SecretUnavailable - never generate into a read-only
    application directory and crash at first login (DEPLOY-01)."""
    env = os.environ.get("JWT_SECRET")
    if env:
        return env
    cfg = app_config()
    from_cfg = get_nested(cfg, "session.jwt_secret", "")
    if from_cfg:
        return str(from_cfg)
    try:
        if _SECRET_PATH.exists():
            value = json.loads(_SECRET_PATH.read_text())["jwt_secret"]
            if value:
                return value
            raise KeyError("jwt_secret empty")
        value = secrets.token_urlsafe(48)
        _SECRET_PATH.write_text(json.dumps({"jwt_secret": value}))
        _SECRET_PATH.chmod(0o600)
        return value
    except OSError as exc:
        raise SecretUnavailable(
            "No JWT secret available: set JWT_SECRET (env) or mount a "
            "writable SECRETS_DIR volume. Refusing to start insecurely."
        ) from exc
    except (KeyError, json.JSONDecodeError) as exc:
        raise SecretUnavailable(
            f"secrets.json at {_SECRET_PATH} is unreadable/corrupt: {exc}. "
            "Delete it or set JWT_SECRET explicitly.") from exc


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


_CLEARANCE_ORDER = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}

# Dummy hash used to equalise timing when a username does not exist
# (AUTH-09: prevents username enumeration via response-time deltas).
_DUMMY_BCRYPT = _bcrypt.hashpw(b"timing-equaliser-dummy",
                               _bcrypt.gensalt(rounds=4))

_thread_local = threading.local()


def clearance_level(clearance: str) -> int:
    """L1 < L2 < L3 < L4 < L5. Unknown labels are treated as L0 (no access)."""
    return _CLEARANCE_ORDER.get((clearance or "").upper(), 0)


def _db_conn() -> sqlite3.Connection:
    """Cached per-thread read-only connection (AUTH-09: no per-call dial)."""
    conn = getattr(_thread_local, "company_ro", None)
    if conn is None:
        conn = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        _thread_local.company_ro = conn
    return conn


def _db_user(username: str) -> dict | None:
    """Look the user up in company.db; None when absent (no fallback)."""
    try:
        row = _db_conn().execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None
    except (sqlite3.Error, OSError):
        return None


def verify_password(password: str, stored_hash) -> bool:
    """bcrypt verification shared with scripts/seed_users.py. Accepts the
    hash as str or bytes (sqlite may return BLOBs either way)."""
    if isinstance(stored_hash, bytes):
        stored_hash = stored_hash.decode("utf-8", "ignore")
    try:
        return _bcrypt.checkpw((password or "").encode(),
                               (stored_hash or "").encode())
    except (ValueError, TypeError):
        return False


def authenticate(username: str, password: str) -> UserCtx | None:
    """Verify credentials against the users table (bcrypt only).

    Fail-closed guarantees (AUTH-02/AUTH-03):
      - no users table / unreadable DB  -> None (deny)
      - unknown username                -> None (timing-equalised)
      - inactive account                -> None (offboarding revokes access)
    """
    user = _db_user(username)
    if user is None:
        verify_password(password or "", _DUMMY_BCRYPT)   # constant-ish time
        return None
    if not user.get("is_active", 1):
        return None
    if not verify_password(password or "", user["password_hash"]):
        return None
    return UserCtx(user["username"], user["role"], user["department"],
                   user_id=user["user_id"],
                   clearance=user["clearance"],
                   full_name=user["full_name"], email=user["email"],
                   active=True)


def refresh_ctx(user: UserCtx) -> UserCtx:
    """AUTH-06: re-read the account row on every request. Role, department,
    clearance and active-status are taken from the LIVE database row, so a
    downgraded, offboarded or deactivated account loses its powers on its
    very next call instead of at token expiry (<= 60 min window)."""
    row = _db_user(user.username)
    if row is None or not row.get("is_active", 1):
        return replace(user, active=False, clearance="L0", role="",
                       department="")
    return replace(user, role=row["role"], department=row["department"],
                   clearance=row["clearance"], user_id=row["user_id"],
                   full_name=row["full_name"], email=row["email"],
                   active=True)


_REQUIRED_CLAIMS = ("sub", "role", "dept")


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

    Fail-closed claims (AUTH-07): tokens missing sub/role/dept are rejected
    outright; a missing/unknown clearance claim maps to L0 (no access) -
    the former default of L2 was a privilege hole."""
    payload = jwt.decode(token, _secret(), algorithms=[algorithm])
    missing = [c for c in _REQUIRED_CLAIMS if not payload.get(c)]
    if missing:
        raise jwt.InvalidTokenError(f"missing claims: {missing}")
    clr = payload.get("clr") or "L0"
    if clearance_level(clr) == 0 and clr.upper() != "L0":
        clr = "L0"
    return UserCtx(
        payload["sub"], payload["role"], payload["dept"],
        user_id=int(payload.get("uid", 0) or 0),
        clearance=clr,
        full_name=payload.get("name", ""),
        email="", session_id=payload.get("jti", ""), active=True)


def profile(username: str) -> dict:
    """Full profile for /api/me (fresh DB row; fails closed when absent)."""
    user = _db_user(username)
    if user:
        return {k: user.get(k) for k in
                ("user_id", "username", "full_name", "email", "role",
                 "department", "clearance", "is_active", "last_login")}
    return {"user_id": 0, "username": username, "full_name": username,
            "email": "", "role": "", "department": "",
            "clearance": "L0", "is_active": 0, "last_login": None}


# ---- brute-force lockout + token revocation -------------------------------
# In-process state (single-node demo). Multi-node production would back these
# with Redis; the interfaces below are the swap point.

import threading as _threading  # noqa: E402
from collections import defaultdict as _defaultdict  # noqa: E402

LOCKOUT_AFTER_FAILURES = 5
LOCKOUT_WINDOW_S = 900          # failures counted within 15 minutes
LOCKOUT_DURATION_S = 300        # account locked for 5 minutes

_fails: dict[str, list[float]] = _defaultdict(list)
_fails_lock = _threading.Lock()
_revoked: dict[str, float] = {}
_revoked_lock = _threading.Lock()


def login_lockout(username: str) -> tuple[bool, int]:
    """Returns (locked, retry_after_seconds). 5 failed attempts inside the
    window lock the account for LOCKOUT_DURATION_S."""
    now = time.time()
    with _fails_lock:
        marks = [t for t in _fails.get(username, [])
                 if now - t < LOCKOUT_WINDOW_S]
        _fails[username] = marks
        if len(marks) < LOCKOUT_AFTER_FAILURES:
            return False, 0
        retry = int(LOCKOUT_DURATION_S - (now - marks[-1]))
        return (retry > 0), max(retry, 1)


def record_login_failure(username: str) -> None:
    with _fails_lock:
        _fails[username].append(time.time())


def record_login_success(username: str) -> None:
    with _fails_lock:
        _fails.pop(username, None)


def revoke_token(session_id: str, exp: int) -> None:
    """Logout: denylist the token's jti until its natural expiry."""
    if session_id:
        with _revoked_lock:
            _revoked[session_id] = float(exp)


def is_revoked(session_id: str) -> bool:
    if not session_id:
        return False
    now = time.time()
    with _revoked_lock:
        exp = _revoked.get(session_id)
        if exp is None:
            return False
        if exp < now:                      # expired entries self-clean
            _revoked.pop(session_id, None)
            return False
        return True


def validate_password_policy(password: str) -> tuple[bool, str]:
    """Production password policy (enforced when provisioning users):
    >= 10 chars with upper, lower, digit and symbol classes."""
    if len(password or "") < 10:
        return False, "minimum length is 10 characters"
    checks = [any(c.isupper() for c in password),
              any(c.islower() for c in password),
              any(c.isdigit() for c in password),
              any(not c.isalnum() for c in password)]
    if not all(checks):
        return False, "must include upper, lower, digit and symbol"
    return True, ""
