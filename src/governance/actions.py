"""Layer 3.5: Human-in-the-Loop agency gate - OWASP LLM03 (Excessive Agency)
implemented as code, and the NIST AI RMF "Manage" function in action.

The chatbot is read-only by construction (L3 emits SELECT-only SQL on a
mode=ro connection). But a user - or a hijacked model following an injected
instruction - can still ASK for a high-risk ACTION ("delete employee Bob",
"update salaries", "transfer funds"). The AI must never execute such an
action, and it must never "just say no" silently either.

Instead the request is converted into a PENDING ACTION REQUEST:

  1. detect()        - config-driven regexes spot action intent in the prompt
  2. the /chat pipeline creates a pending record and returns
     "Action Pending - waiting for admin approval" (never executes)
  3. an authorised human approves/rejects via
     POST /api/action/confirm/{request_id}  (approver_roles only)
  4. even an APPROVED action is executed by a deliberately read-only
     sandboxed executor in this demo - the point is the GATE, and that the
     blast radius of a compromised approver is still zero

Every step is hash-chained into the Layer 7 audit log. Segregation of
duties: the person who can chat is (by default) not the person who can
approve destructive operations.
"""
import re
import sqlite3
import threading
import time
from dataclasses import dataclass

from src.common.paths import AUDIT_DB, app_config, get_nested

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, user_id TEXT, role TEXT, source TEXT,
    action_type TEXT, target TEXT, justification TEXT,
    status TEXT DEFAULT 'pending',
    decided_by TEXT, decided_ts TEXT, result TEXT
);
"""

_LOCK = threading.Lock()

# Risky-action patterns are CONFIG (config/app_config.yaml -> action_gate),
# so an auditor can review what counts as "high risk" without reading code.
_DEFAULT_PATTERNS = [
    r"(delete|remove|fire|terminate)\s+(\w+\s+){0,3}(employee|record|row|user|staff|account|person)",
    r"(update|change|modify|edit)\s+(\w+\s+){0,3}(salary|record|employee|role|department|bonus|status)",
    r"(drop|truncate)\s+table",
    r"(transfer|move|wire)\s+(\w+\s+){0,3}(employee|amount|money|funds|department|salary)",
    r"(promote|demote)\s+\w",
    r"(reset|change)\s+(\w+\s+){0,3}(password|credentials?)",
    r"(send|draft|email)\s+(\w+\s+){0,3}(email|message|mail)",
    r"(approve|issue|pay)\s+(\w+\s+){0,3}(payment|invoice|bonus|raise)",
    r"(execute|run)\s+(\w+\s+){0,3}(command|script|sql|code|query)",
    r"(export|download)\s+(\w+\s+){0,3}(csv|report|data|records?|employees?)",
    r"(delete|drop|erase|wipe)\s+(all|everything|entire)",
]


@dataclass
class ActionIntent:
    action_type: str
    matched: str
    target: str


def _patterns() -> list[tuple[str, re.Pattern]]:
    cfg = app_config()
    enabled = bool(get_nested(cfg, "action_gate.enabled", True))
    if not enabled:
        return []
    raw = get_nested(cfg, "action_gate.risky_patterns", None) or _DEFAULT_PATTERNS
    out = []
    for entry in raw:
        # entries look like "label :: regex" (label preferred) or a bare regex
        if "::" in entry:
            label, pattern = entry.split("::", 1)
            label = label.strip()
        else:
            label, pattern = entry.split()[0].upper(), entry
        out.append((label, re.compile(pattern.strip(), re.I)))
    return out


def detect(prompt: str) -> ActionIntent | None:
    """Return the first high-risk action intent found in the prompt."""
    for label, pattern in _patterns():
        m = pattern.search(prompt)
        if m:
            return ActionIntent(action_type=label.lower(),
                                matched=pattern.pattern[:60],
                                target=m.group().strip())
    return None


class PendingActionStore:
    """SQLite-backed pending-action queue (lives in the audited db/audit.db)."""

    def __init__(self):
        AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(AUDIT_DB, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def create(self, *, user_id: str, role: str, source: str,
               action_type: str, target: str, justification: str = "") -> int:
        with _LOCK:
            cur = self.conn.execute(
                "INSERT INTO pending_actions (ts,user_id,role,source,"
                "action_type,target,justification) VALUES (?,?,?,?,?,?,?)",
                (time.strftime("%Y-%m-%dT%H:%M:%S%z"), user_id, role, source,
                 action_type, target, justification))
            self.conn.commit()
            return cur.lastrowid

    def get(self, request_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM pending_actions WHERE id=?", (request_id,)).fetchone()
        return dict(row) if row else None

    def list_open(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, user_id, role, source, action_type, target, "
            "status FROM pending_actions WHERE status='pending' "
            "ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def resolve(self, request_id: int, approve: bool, decider: str,
                result: str | None = None) -> dict | None:
        """Transition pending -> approved/rejected. Returns the row or None."""
        with _LOCK:
            row = self.conn.execute(
                "SELECT status FROM pending_actions WHERE id=?",
                (request_id,)).fetchone()
            if not row or row["status"] != "pending":
                return None
            status = "approved" if approve else "rejected"
            self.conn.execute(
                "UPDATE pending_actions SET status=?, decided_by=?, "
                "decided_ts=?, result=? WHERE id=?",
                (status, decider, time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 result, request_id))
            self.conn.commit()
            return self.get(request_id)


def sandboxed_execute(action: dict) -> dict:
    """What an APPROVED action would run - deliberately read-only here.

    In production this is where a scoped, least-privilege executor with its
    own RBAC identity and approval reference would act. In this demo the
    executor performs only a READ-ONLY existence check on the target, so
    even a fully approved destructive request cannot mutate demo data:
    the gate is the product, and honest labelling is part of governance.
    """
    import sqlite3 as _sq
    from src.common.paths import COMPANY_DB
    target = action.get("target", "")
    token = next((w for w in target.split() if w.isalpha() and len(w) > 2
                  and w.lower() not in ("delete", "employee", "remove",
                                        "fire", "terminate", "record",
                                        "update", "salary", "change",
                                        "modify", "drop", "table")), None)
    found = None
    if token:
        try:
            conn = _sq.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
            found = conn.execute(
                "SELECT id, name, department FROM employees "
                "WHERE name LIKE ? LIMIT 1", (f"%{token}%",)).fetchone()
            conn.close()
        except Exception:
            found = None
    return {
        "executed": False,
        "processed": True,
        "workflow_status": "EXECUTED (sandboxed verification, no mutation)",
        "action_type": action.get("action_type"),
        "target": target,
        "target_found": bool(found),
        "target_row": list(found) if found else None,
        "note": ("Sandboxed demo executor is READ-ONLY by design: an "
                 "approved action is verified and logged, never applied. "
                 "Wire this to a scoped executor with its own RBAC identity "
                 "and the approval reference in production."),
    }
