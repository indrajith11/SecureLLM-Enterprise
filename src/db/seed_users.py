"""Seed the per-user authentication table (Improvement 2).

Creates `users` inside company.db (the corporate identity store) with 13
accounts: the 10 role/clearance demo users plus the 3 legacy accounts that
the original red-team corpus uses, so every historical measurement remains
reproducible.

Passwords are stored as bcrypt hashes (cost 12) - NEVER plaintext, never
reversible, and there is NO file-based fallback store (audit AUTH-02: the
legacy SHA-256 users.yaml path was removed; authentication fails closed
until this script has been run).
"""
import sqlite3

import bcrypt

from src.common.paths import COMPANY_DB

_BCRYPT_ROUNDS = 12

# username, password, full_name, email, role, department, clearance
DEMO_USERS = [
    ("admin",      "Admin@123",  "System Administrator", "admin@corp.example.com",
     "Admin",            "IT",        "L5"),
    ("ceo",        "Ceo@123",    "Rajesh Kumar",         "rajesh.kumar@corp.example.com",
     "Executive",        "Executive", "L5"),
    ("cto",        "Cto@123",    "Priya Sharma",         "priya.sharma@corp.example.com",
     "Executive",        "Executive", "L5"),
    ("hr_manager", "HrM@123",    "Anjali Verma",         "anjali.verma@corp.example.com",
     "HR_Manager",       "HR",        "L4"),
    ("hr_emp1",    "HrE@123",    "Suresh Patel",         "suresh.patel@corp.example.com",
     "HR_Employee",      "HR",        "L3"),
    ("tech_lead",  "TechL@123",  "Vikram Singh",         "vikram.singh@corp.example.com",
     "Tech_Lead",        "Tech",      "L4"),
    ("tech_eng1",  "TechE@123",  "Arun Mehta",           "arun.mehta@corp.example.com",
     "Tech_Engineer",    "Tech",      "L3"),
    ("tech_eng2",  "TechE2@123", "Neha Gupta",           "neha.gupta@corp.example.com",
     "Tech_Engineer",    "Tech",      "L3"),
    ("biz_analyst", "BizA@123",  "Rahul Joshi",          "rahul.joshi@corp.example.com",
     "Business_Analyst", "Business",  "L3"),
    ("fin_manager", "FinM@123",  "Meera Iyer",           "meera.iyer@corp.example.com",
     "Finance_Manager",  "Finance",   "L4"),
    # legacy identities used by the red-team corpus (kept reproducible)
    ("alice",      "alice123",   "Alice Fernandes",      "alice.fernandes@corp.example.com",
     "Tech_Employee",    "Tech",      "L2"),
    ("hr_hari",    "hari123",    "Hari Krishnan",        "hari.krishnan@corp.example.com",
     "HR_Manager",       "HR",        "L4"),
    ("ceo_meera",  "meera123",   "Meera Nair",           "meera.nair@corp.example.com",
     "Executive",        "Executive", "L5"),
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL,
    department    TEXT NOT NULL,
    clearance     TEXT NOT NULL,
    is_active     INTEGER DEFAULT 1,
    role_version  INTEGER DEFAULT 1,
    must_change_password INTEGER DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP
);
"""


def _migrate(conn: sqlite3.Connection) -> None:
    """Idempotent column migrations (Wave 2.1/2.2).

    role_version          - bumped on every role/permission/password change;
                            embedded as the JWT `rv` claim, so a token issued
                            before the change fails validation on its very
                            next request (instant revocation-on-change,
                            complements the jti denylist).
    must_change_password  - set when an Admin provisions a temp password;
                            the account can log in but /api/chat refuses
                            until the password is changed (self-service).
    """
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    if "role_version" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN role_version INTEGER "
                     "DEFAULT 1")
    if "must_change_password" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN must_change_password "
                     "INTEGER DEFAULT 0")


def hash_password(plain: str, rounds: int = _BCRYPT_ROUNDS) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=rounds))\
        .decode()


def verify_password(plain: str, stored) -> bool:
    """bcrypt-only (audit AUTH-02: the legacy SHA-256 path was removed -
    SHA-256 is not a password hash). Accepts str or bytes hashes as stored
    by different sqlite drivers."""
    if isinstance(stored, bytes):
        stored = stored.decode("utf-8", "ignore")
    stored = stored or ""
    if not stored.startswith("$2"):
        return False                     # unknown format: fail closed
    try:
        return bcrypt.checkpw(plain.encode(), stored.encode())
    except ValueError:
        return False


def ensure_users_table() -> None:
    # fresh-clone safe: db/ may not exist yet (seeding order should not matter)
    COMPANY_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(COMPANY_DB)
    conn.executescript(_SCHEMA)
    _migrate(conn)
    conn.commit()
    conn.close()


def seed() -> int:
    """Insert/refresh the 13 demo accounts. Idempotent: re-running refreshes
    hashes and flags without duplicating rows."""
    ensure_users_table()
    conn = sqlite3.connect(COMPANY_DB)
    for (username, password, full_name, email, role, dept, clearance) \
            in DEMO_USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash, full_name, email, "
            "role, department, clearance, is_active) VALUES (?,?,?,?,?,?,?,1) "
            "ON CONFLICT(username) DO UPDATE SET password_hash=excluded."
            "password_hash, full_name=excluded.full_name, email=excluded."
            "email, role=excluded.role, department=excluded.department, "
            "clearance=excluded.clearance, is_active=1",
            (username, hash_password(password), full_name, email, role, dept,
             clearance))
    conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return n


def main():
    total = seed()
    print(f"users table: {total} accounts seeded into company.db "
          f"(bcrypt, cost {_BCRYPT_ROUNDS})")
    print("demo credentials: admin/Admin@123  hr_manager/HrM@123  "
          "tech_eng1/TechE@123  (full table in docs/demo_users.md)")


if __name__ == "__main__":
    main()
