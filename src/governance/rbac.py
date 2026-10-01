"""Layer 3: RBAC Policy Engine (the access control list).

Reads config/rbac_config.yaml and is the ONLY component allowed to decide
which tables, columns, and vector namespaces exist for a request.

Design guarantees worth saying out loud in an interview:
- The policy is declarative YAML -> an auditor can review access rules
  without reading code (governance evidence).
- Query building is whitelist-only: identifiers must exist in the table
  catalog, values are bound parameters, and only SELECT is ever emitted.
- The DB connection is opened read-only at the SQLite level (mode=ro), so
  even a bug in this engine cannot mutate data (OWASP LLM03: Excessive
  Agency - the agent physically cannot write).
"""
import re
import sqlite3
from dataclasses import dataclass, field

from src.common.paths import (COMPANY_DB, CONFIG_DIR, EXECUTIVES_DB,
                              get_nested, load_yaml)

_RBAC = load_yaml(CONFIG_DIR / "rbac_config.yaml")
_ROLES = _RBAC["roles"]
_CATALOG = _RBAC["table_catalog"]

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_DB_FILES = {"company": COMPANY_DB, "executives": EXECUTIVES_DB}


@dataclass
class Policy:
    role: str
    departments: list[str] = field(default_factory=list)
    allowed_tables: list[str] = field(default_factory=list)
    allowed_columns: dict[str, list[str]] = field(default_factory=dict)
    allowed_namespaces: list[str] = field(default_factory=list)
    sensitive_patterns: list[str] = field(default_factory=list)

    def can(self, table: str) -> bool:
        return table in self.allowed_tables


def get_policy(role: str) -> Policy:
    r = _ROLES.get(role, _ROLES["default"])
    return Policy(role, r.get("departments", []), r.get("allowed_tables", []),
                  r.get("allowed_columns", {}), r.get("allowed_namespaces", []),
                  r.get("sensitive_patterns", []))


def _conn(table: str) -> sqlite3.Connection:
    """Read-only connection to the DB file that owns this table."""
    db_key = _CATALOG[table]["db"]
    return sqlite3.connect(f"file:{_DB_FILES[db_key]}?mode=ro", uri=True)


def build_query(policy: Policy, table: str, columns: list[str],
                dept: str | None = None) -> tuple[str, list, sqlite3.Connection]:
    """Return (sql, params, read-only conn). Raises ValueError on any
    identifier not present in the YAML policy - injection by construction
    has nothing to inject into."""
    if not policy.can(table):
        raise PermissionError(f"table '{table}' is not allowed for role {policy.role}")
    allowed_cols = policy.allowed_columns.get(table, [])
    cols = [c for c in columns if c in allowed_cols] or allowed_cols
    for ident in [table, *cols]:
        if not _IDENT.match(ident):
            raise ValueError(f"illegal identifier: {ident}")
    sql = f"SELECT {', '.join(cols)} FROM {table}"
    params: list = []
    if dept and "department" in allowed_cols:
        sql += " WHERE department = ?"
        params.append(dept)
    sql += " LIMIT 50"
    return sql, params, _conn(table)


def run_select(policy: Policy, table: str, columns: list[str],
               dept: str | None = None) -> list[dict]:
    sql, params, conn = build_query(policy, table, columns, dept)
    try:
        rows = conn.execute(sql, params).fetchall()
        cols = [d[0] for d in conn.execute(sql, params).description]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        conn.close()


def intent_tables(question: str, policy: Policy) -> list[str]:
    """Tiny deterministic intent router: which policy-allowed tables could
    answer this question? Cross-department requests die here first, because
    a table the role cannot see is simply never queried."""
    q = question.lower()
    wanted: list[str] = []
    if any(k in q for k in ("bonus", "executive", "ceo", "board")):
        wanted.append("executives")
    if any(k in q for k in ("employee", "team", "staff", "salary", "salaries",
                            "earn", "payroll", "email", "phone", "who", "list",
                            "colleague", "people", "compare", "csv", "export")):
        wanted.append("employees")
        if "employees_tech_view" in policy.allowed_tables:
            wanted.append("employees_tech_view")
        if "employees_public_view" in policy.allowed_tables:
            wanted.append("employees_public_view")
    # No fallback: a question that matches no data intent is answered from
    # RAG documents only - never by dumping a whole table "just in case"
    # (data minimisation).
    return [t for t in wanted if policy.can(t)]
