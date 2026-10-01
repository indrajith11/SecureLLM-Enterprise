"""User management (Wave 2.2) - Admin identity administration, in code.

The users table was previously seed-only: accounts existed because
scripts/seed_users.py created them. Enterprise operation needs lifecycle
management - provisioning, role changes, offboarding, password resets -
WITHOUT touching the DB by hand, and WITH the same governance guarantees
as the chat pipeline:

  - bcrypt cost 12 everywhere (never plaintext, never reversible);
  - every mutation bumps `role_version`, so every outstanding JWT for
    that account is rejected on its very next request (Wave 2.1) - a
    role downgrade takes effect in zero seconds, not at token expiry;
  - every mutation is written to the hash-chained audit chain by the
    caller (routes in src/api/main.py), with actor + target + fields;
  - Admin self-protection is FAIL-CLOSED:
      * creating/role-changing INTO Admin requires the actor to be in
        the SECURELLM_SUPERADMINS env allow-list (unset -> nobody can,
        Admins exist only via the seed - deliberate);
      * the last active Admin cannot be disabled or demoted (409);
      * provisioning always sets must_change_password=1: the temp
        password is single-purpose, /api/chat refuses until the user
        sets their own (POST /api/me/password).

This module is the ONLY writer of the users table outside seed_users.py.
Connections here are WRITABLE (sqlite3.connect, not mode=ro) and short-
lived: admin operations are rare; per-thread caching is unnecessary.
"""
import re
import sqlite3

from src.common.paths import COMPANY_DB, get_nested, app_config
from src.governance import rbac
from src.governance.auth import validate_password_policy, verify_password
from src.db.seed_users import hash_password

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
CLEARANCES = ("L1", "L2", "L3", "L4", "L5")

SUPERADMIN_ENV = "SECURELLM_SUPERADMINS"

#: config key for the temp-password length (admin-provisioned secrets)
TEMP_PASSWORD_ENV = "SECURELLM_TEMP_PASSWORD"


class UserAdminError(ValueError):
    """Validation failure -> 422 at the route layer."""


class AdminGrantForbidden(UserAdminError):
    """An operation would grant Admin power to an actor outside the
    SECURELLM_SUPERADMINS allow-list -> 403 (self-elevation blocked)."""


class LastAdminError(RuntimeError):
    """An operation would remove the last active Admin -> 409."""


def superadmins() -> set[str]:
    """Usernames allowed to grant Admin power (fail closed when unset)."""
    raw = __import__("os").environ.get(SUPERADMIN_ENV, "")
    return {u.strip().lower() for u in raw.split(",") if u.strip()}


def _wconn() -> sqlite3.Connection:
    conn = sqlite3.connect(COMPANY_DB)
    conn.row_factory = sqlite3.Row
    return conn


def _get(conn: sqlite3.Connection, username: str) -> dict | None:
    row = conn.execute("SELECT * FROM users WHERE username = ?",
                       (username,)).fetchone()
    return dict(row) if row else None


def _bump_rv(conn: sqlite3.Connection, username: str) -> None:
    conn.execute("UPDATE users SET role_version = COALESCE(role_version, 1) + 1"
                 " WHERE username = ?", (username,))


def list_users() -> list[dict]:
    """All accounts, NO password hashes. For GET /admin/users."""
    conn = _wconn()
    try:
        rows = conn.execute(
            "SELECT user_id, username, full_name, email, role, department,"
            " clearance, is_active, role_version, must_change_password,"
            " created_at, last_login FROM users ORDER BY user_id").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _validate_role(role: str) -> None:
    known = rbac.known_roles()
    if role not in known:
        raise UserAdminError(f"unknown role '{role}' (known: {known})")


def _validate_clearance(clearance: str) -> None:
    if clearance not in CLEARANCES:
        raise UserAdminError(
            f"clearance must be one of {CLEARANCES}")


def create_user(*, username: str, password: str, full_name: str,
                email: str, role: str, department: str, clearance: str,
                actor: str) -> dict:
    """Provision an account with a TEMP password (must_change_password=1).
    Admin grants require the actor to be a superadmin (env allow-list)."""
    username = (username or "").strip().lower()
    if not USERNAME_RE.match(username):
        raise UserAdminError(
            "username must match [a-z0-9_]{3,32}")
    if not password or not password.strip():
        raise UserAdminError("initial (temp) password is required")
    ok, why = validate_password_policy(password)
    if not ok:
        raise UserAdminError(f"password policy: {why}")
    _validate_role(role)
    _validate_clearance(clearance)
    if role == "Admin" and actor.lower() not in superadmins():
        raise AdminGrantForbidden(
            f"creating an Admin requires membership of the "
            f"{SUPERADMIN_ENV} allow-list (fail closed: unset means nobody)")
    conn = _wconn()
    try:
        if _get(conn, username):
            raise UserAdminError(f"username '{username}' already exists")
        conn.execute(
            "INSERT INTO users (username, password_hash, full_name, email,"
            " role, department, clearance, is_active, role_version,"
            " must_change_password)"
            " VALUES (?,?,?,?,?,?,?,1,1,1)",
            (username, hash_password(password), full_name or username,
             email or f"{username}@corp.example.com", role, department,
             clearance))
        conn.commit()
        return _get(conn, username)
    finally:
        conn.close()


def set_role(*, username: str, actor: str, role: str | None = None,
             department: str | None = None,
             clearance: str | None = None) -> dict:
    """Update role / department / clearance. Any change bumps role_version
    (instant permission update). Granting Admin follows the superadmin
    rule; demoting the LAST active Admin is refused."""
    conn = _wconn()
    try:
        user = _get(conn, username)
        if not user:
            raise UserAdminError(f"unknown user '{username}'")
        new_role = role or user["role"]
        _validate_role(new_role)
        new_clearance = clearance or user["clearance"]
        _validate_clearance(new_clearance)
        if new_role == "Admin" and user["role"] != "Admin" and \
                actor.lower() not in superadmins():
            raise AdminGrantForbidden(
                f"granting the Admin role requires the {SUPERADMIN_ENV} "
                "allow-list (fail closed: unset means nobody)")
        if user["role"] == "Admin" and new_role != "Admin":
            active_admins = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role='Admin' AND "
                "is_active=1").fetchone()[0]
            if active_admins <= 1:
                raise LastAdminError(
                    "cannot demote the last active Admin (409)")
        fields, params = [], []
        if role and role != user["role"]:
            fields.append("role=?"); params.append(new_role)
        if department and department != user["department"]:
            fields.append("department=?"); params.append(department)
        if clearance and clearance != user["clearance"]:
            fields.append("clearance=?"); params.append(new_clearance)
        if fields:
            params.append(username)
            conn.execute(f"UPDATE users SET {', '.join(fields)} "
                         "WHERE username=?", params)
            _bump_rv(conn, username)
            conn.commit()
        return _get(conn, username)
    finally:
        conn.close()


def set_active(*, username: str, actor: str, active: bool) -> dict:
    """Enable / disable (offboarding) an account. Disabling the last
    active Admin is refused; disabling yourself is refused (footgun)."""
    conn = _wconn()
    try:
        user = _get(conn, username)
        if not user:
            raise UserAdminError(f"unknown user '{username}'")
        if not active:
            if username == actor:
                raise UserAdminError("you cannot disable your own account")
            if user["role"] == "Admin" and user["is_active"]:
                active_admins = conn.execute(
                    "SELECT COUNT(*) FROM users WHERE role='Admin' AND "
                    "is_active=1").fetchone()[0]
                if active_admins <= 1:
                    raise LastAdminError(
                        "cannot disable the last active Admin (409)")
        conn.execute("UPDATE users SET is_active=? WHERE username=?",
                     (1 if active else 0, username))
        _bump_rv(conn, username)      # disabled -> every live token dies
        conn.commit()
        return _get(conn, username)
    finally:
        conn.close()


def reset_password(*, username: str, new_password: str, actor: str,
                   temp: bool = True) -> dict:
    """Admin password reset. Sets a TEMP secret (must_change_password=1)
    and bumps role_version so every outstanding session dies: a reset is
    also a credential-compromise response, so instant revocation matters."""
    ok, why = validate_password_policy(new_password)
    if not ok:
        raise UserAdminError(f"password policy: {why}")
    conn = _wconn()
    try:
        user = _get(conn, username)
        if not user:
            raise UserAdminError(f"unknown user '{username}'")
        conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=? "
            "WHERE username=?",
            (hash_password(new_password), 1 if temp else 0, username))
        _bump_rv(conn, username)
        conn.commit()
        return _get(conn, username)
    finally:
        conn.close()


def change_own_password(*, username: str, current_password: str,
                        new_password: str) -> dict:
    """Self-service change (POST /api/me/password). Requires the CURRENT
    password (anti-hijack), validates the policy, clears the temp flag and
    revokes all sessions (rv bump) - including the caller's."""
    conn = _wconn()
    try:
        user = _get(conn, username)
        if not user or not verify_password(current_password or "",
                                           user["password_hash"]):
            raise UserAdminError("current password is incorrect")
        ok, why = validate_password_policy(new_password)
        if not ok:
            raise UserAdminError(f"password policy: {why}")
        conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=0 "
            "WHERE username=?", (hash_password(new_password), username))
        _bump_rv(conn, username)
        conn.commit()
        return _get(conn, username)
    finally:
        conn.close()
