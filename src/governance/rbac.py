"""Layer 3: RBAC Policy Engine (the access control list).

Reads config/rbac_config.yaml and is the ONLY component allowed to decide
which tables, columns, and vector namespaces exist for a request.

Design guarantees:
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
from src.governance.denials import ReasonCode

_RBAC = load_yaml(CONFIG_DIR / "rbac_config.yaml")
_ROLES = _RBAC["roles"]
_CATALOG = _RBAC["table_catalog"]

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_DB_FILES = {"company": COMPANY_DB, "executives": EXECUTIVES_DB}


class PermissionDenied(PermissionError):
    """Policy denial carrying a machine-readable ReasonCode (Denial Engine,
    Wave 1.1). Subclasses PermissionError so any existing handler keeps
    working; new call sites read `.code` / `.detail` to render the official
    refusal and write denied_code into the audit chain."""

    def __init__(self, code: ReasonCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


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

    def summary(self) -> str:
        """Human-readable 'You can view' line for the Denial Engine and the
        admin permission preview (Wave 2.3). Built ONLY from granted
        permissions - describing what the role CAN see leaks nothing about
        what it cannot."""
        parts: list[str] = []
        for table in self.allowed_tables:
            cols = self.allowed_columns.get(table) or []
            parts.append(f"{table} ({', '.join(cols)})" if cols else table)
        if self.allowed_namespaces:
            parts.append("documents in " + ", ".join(self.allowed_namespaces))
        return "; ".join(parts) if parts else "no company data"


def get_policy(role: str) -> Policy:
    r = _ROLES.get(role, _ROLES["default"])
    return Policy(role, r.get("departments", []), r.get("allowed_tables", []),
                  r.get("allowed_columns", {}), r.get("allowed_namespaces", []),
                  r.get("sensitive_patterns", []))


def _conn(table: str) -> sqlite3.Connection:
    """Read-only connection to the DB file that owns this table.
    RAG-06: connections are cached per-thread (mode=ro connections are
    safe to reuse); no per-query dial cost."""
    db_key = _CATALOG[table]["db"]
    path = _DB_FILES[db_key]
    key = str(path)
    conn = _TLS.__dict__.get(key)
    if conn is None:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        _TLS.__dict__[key] = conn
    return conn


import threading as _threading  # noqa: E402
_TLS = _threading.local()


def build_query(policy: Policy, table: str, columns: list[str],
                dept: str | None = None, name_like: str | None = None,
                limit: int = 50) -> tuple[str, list, sqlite3.Connection]:
    """Return (sql, params, read-only conn). Raises ValueError on any
    identifier not present in the YAML policy - injection by construction
    has nothing to inject into. name_like adds a parameterised
    `WHERE name LIKE ?` (RAG-02 entity-aware retrieval); limit is bounded
    to the policy maximum so no code path can dump a whole table."""
    if not policy.can(table):
        raise PermissionDenied(
            ReasonCode.AUTHZ_TABLE,
            f"table '{table}' is not allowed for role {policy.role}")
    allowed_cols = policy.allowed_columns.get(table, [])
    cols = [c for c in columns if c in allowed_cols] or allowed_cols
    for ident in [table, *cols]:
        if not _IDENT.match(ident):
            raise ValueError(f"illegal identifier: {ident}")
    limit = max(1, min(int(limit), 50))          # hard cap: data minimisation
    sql = f"SELECT {', '.join(cols)} FROM {table}"
    params: list = []
    wheres = []
    if dept and "department" in allowed_cols:
        wheres.append("department = ?")
        params.append(dept)
    if name_like and "name" in allowed_cols:
        wheres.append("name LIKE ?")
        params.append(f"%{name_like}%")
    if wheres:
        sql += " WHERE " + " AND ".join(wheres)
    sql += f" LIMIT {limit}"
    return sql, params, _conn(table)


def run_select(policy: Policy, table: str, columns: list[str],
               dept: str | None = None, name_like: str | None = None,
               limit: int = 50) -> list[dict]:
    sql, params, conn = build_query(policy, table, columns, dept,
                                    name_like, limit)
    try:
        rows = conn.execute(sql, params).fetchall()
        cols = [d[0] for d in conn.execute(sql, params).description]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        pass   # connection is cached per-thread, not closed (RAG-06)


# ---- Denial Engine (Wave 1.1): field-intent authorisation -----------------
# Sensitive-field vocabulary -> the column class it maps to. Deliberately
# SMALL and auditable: this check refuses, so false positives cost users a
# polite denial - every term must unambiguously name compensation/contact
# data, never a policy document topic.
_FIELD_TERMS: dict[str, tuple[str, ...]] = {
    "salary": ("salary", "salaries", "income", "compensation", "payroll",
               "wage", "wages", "earn", "earns", "earned", "earning",
               "paid", "ctc"),
    "bonus": ("bonus", "bonuses"),
    "email": ("email", "e-mail"),
    "phone": ("phone", "mobile", "phone number", "contact number"),
}

# A field ask is only a RESTRICTED-FIELD ask when it targets a PERSON's
# data (possessives, "salary of <Name>", "who earns the most", "my ...").
# Questions like "what is the salary advance policy?" name a field topic
# but not a person - they stay on the normal RAG path (no over-blocking).
# Case sensitivity MATTERS: "<field> of <Name>" relies on a Capitalised
# name, so that alternative is a separate case-sensitive pattern (a bare
# "of all" must never count). Common contractions ("Let's") are excluded
# from the possessive signal.
_PERSON_SIGNAL_CI = re.compile(
    r"\b(my|mine)\b"
    r"|\b(salary|salaries|bonus|bonuses|email|phone|income|compensation)"
    r"\s+(of|for)\b"
    r"|\b(who|which|whose)\b[^.?!]*\b(earn|earns|earned|earning|paid|"
    r"salary|salaries|bonus|bonuses|highest|most|income)\b"
    r"|\b(earn|earns|earned|earning)\b", re.I)
_PERSON_SIGNAL_CASE = re.compile(r"\b(of|for)\s+[A-Z][a-z]+")
_POSSESSIVE = re.compile(r"\b([A-Za-z]+)'s\b")
_POSSESSIVE_STOP = {"let", "it", "that", "there", "what", "he", "she", "is",
                    "one", "everyone", "someone", "anyone", "here", "today"}


def _person_signal(question: str) -> bool:
    """True when the question targets a person's data (not a policy doc)."""
    q = question or ""
    if _PERSON_SIGNAL_CI.search(q):
        return True
    if _PERSON_SIGNAL_CASE.search(q):
        return True
    return any(w.lower() not in _POSSESSIVE_STOP
               for w in _POSSESSIVE.findall(q))


def field_intent_violation(policy: Policy, question: str) \
        -> tuple[str, str] | None:
    """Deterministic field-authorisation pre-check (Denial Engine 1.1).

    Runs AFTER the data-intent router and BEFORE retrieval: when a question
    clearly targets a PERSON's sensitive field that NO allowed table
    provides, we refuse with an official denial instead of retrieving a
    context that is missing the field (which made a 0.5B model either
    hallucinate around the gap or soft-miss like a broken search).

    Returns (field, detail) on violation, None otherwise. Pure function:
    unit-testable without HTTP, DB or model.
    """
    q = (question or "").lower()
    if not _person_signal(question):
        return None
    if not intent_tables(question, policy):   # no data intent -> RAG path
        return None
    for fld, terms in _FIELD_TERMS.items():
        if any(t in q for t in terms):
            available = any(fld in policy.allowed_columns.get(tb, [])
                            for tb in policy.allowed_tables)
            if not available:
                return fld, (f"restricted field '{fld}' is not provisioned "
                             f"for role {policy.role}")
    return None


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
