"""Wave 2.4: employee rows for the demo identities (self-scope backing).

RBAC 2.0 self-scope answers "my salary / my email / my phone" by querying
`employees WHERE username = ?` (bound parameter, UNIQUE index). The
generated 120-row dataset has no username column and the 13 demo accounts
are not among those rows - so this idempotent seeder:

  1. migrates the employees table: adds `username TEXT` plus a PARTIAL
     UNIQUE index (real HRIS rows keep username NULL);
  2. inserts one employee row per demo account (by username), with the
     account's email, the account's department (IT normalised to Tech -
     the dataset's department vocabulary), a deterministic salary per
     role, and a deterministic Indian-format mobile.

Production note: in a real deployment this mapping comes from the HRIS /
IdP (Wave 5.2 OIDC provisioning), not from a seed script. The governance
guarantees do not depend on the source of the username mapping - Layer 3
still whitelists every column, and the self query is a bound-parameter
SELECT against a read-only connection.
"""
import sqlite3

from src.common.paths import COMPANY_DB
from src.db.seed_users import DEMO_USERS

# Deterministic per-role salary band (matches the dataset's magnitude).
_ROLE_PROFILE = {
    "Admin":            ("System Administrator", 215000),
    "Executive":        ("Director",             240000),
    "HR_Manager":       ("HR Manager",           165000),
    "HR_Employee":      ("HR Specialist",         88000),
    "Tech_Lead":        ("Tech Lead",            178000),
    "Tech_Engineer":    ("Software Engineer",    132000),
    "Business_Analyst": ("Business Analyst",     112000),
    "Finance_Manager":  ("Finance Manager",      155000),
    "Tech_Employee":    ("Support Engineer",      94000),
}

_JOIN_DATE = "2023-04-01"


def ensure_employee_self_rows() -> int:
    """Idempotent: migrate + insert missing demo rows. Returns the number
    of self rows present afterwards."""
    COMPANY_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(COMPANY_DB)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(employees)")}
        if not cols:
            return 0                      # employees table not generated yet
        if "username" not in cols:
            conn.execute("ALTER TABLE employees ADD COLUMN username TEXT")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_username "
            "ON employees(username) WHERE username IS NOT NULL")
        added = 0
        for (username, _pw, full_name, email, role, dept,
             _clr) in DEMO_USERS:
            exists = conn.execute(
                "SELECT 1 FROM employees WHERE username = ?",
                (username,)).fetchone()
            if exists:
                continue
            title, salary = _ROLE_PROFILE.get(role, ("Associate", 90000))
            department = "Tech" if dept == "IT" else dept
            # deterministic Indian-format mobile (dataset vocabulary)
            phone = "9" + f"{int.from_bytes(username.encode(), 'big') % 10**9:09d}"
            conn.execute(
                "INSERT INTO employees (name, department, role, email,"
                " phone, salary, designation, bonus, join_date, username)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (full_name, department, title, email, phone, salary, title,
                 0, _JOIN_DATE, username))
            added += 1
        conn.commit()
        n = conn.execute(
            "SELECT COUNT(*) FROM employees WHERE username IS NOT NULL"
        ).fetchone()[0]
        return n
    finally:
        conn.close()


if __name__ == "__main__":
    n = ensure_employee_self_rows()
    print(f"employee self-rows ready: {n} demo identities "
          f"(username-indexed, self-scope backing)")
