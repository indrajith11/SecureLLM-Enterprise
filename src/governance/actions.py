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

CODE-01 remediation (audit findings, HITL races):
  - claim() atomically transitions pending -> executing INSIDE the lock,
    so two concurrent confirms can no longer both execute (TOCTOU fixed);
  - approve/reject of your OWN request is rejected (requester != approver
    is now ENFORCED, not just commented);
  - pending actions EXPIRE (config action_gate.expiry_minutes, default 60):
    a stale approval can no longer execute an old request.
CODE-02 remediation: the pattern corpus is compiled ONCE at import (config
reload is explicit via reload_patterns()), and the sandbox target
tokeniser filters stop-words so "remove the underperformer" extracts
'underperformer', not 'the'.
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
    # v2 families: mass wipe verbs + privilege escalation
    r"(wipe|purge|nuke|erase)\s+(\w+\s+){0,3}(table|database|records?|employees?|payroll)",
    r"(grant|give|make)\s+(me|us|\w+)\s+.{0,20}(admin|executive|root|approver|elevated|manager)",
    r"(elevate|escalate)\s+(my|the)?\s*.{0,15}(privileges?|permissions?|clearance|role|access)",
    r"(approve|confirm)\s+(my|the)\s+own",
    r"(dump|export|download)\s+(the\s+)?(entire\s+)?(database|db|table|payroll|employee\s+data)",
]


@dataclass
class ActionIntent:
    action_type: str
    matched: str
    target: str


def _compile() -> list[tuple[str, re.Pattern]]:
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


_COMPILED: list[tuple[str, re.Pattern]] = _compile()   # CODE-02: once


def reload_patterns() -> int:
    """Explicit config reload (admin operation); returns pattern count."""
    global _COMPILED
    _COMPILED = _compile()
    return len(_COMPILED)


def detect(prompt: str) -> ActionIntent | None:
    """Return the first high-risk action intent found in the prompt."""
    for label, pattern in _COMPILED:
        m = pattern.search(prompt)
        if m:
            return ActionIntent(action_type=label.lower(),
                                matched=pattern.pattern[:60],
                                target=m.group().strip())
    return None


# ---- CODE-02: stop-word target tokeniser -----------------------------------
_TOKEN_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "for", "from", "with",
    "delete", "remove", "fire", "terminate", "employee", "record", "records",
    "row", "update", "change", "modify", "edit", "salary", "drop", "table",
    "database", "please", "all", "entire", "everything", "his", "her",
    "their", "this", "that", "user", "account", "staff", "person", "data",
    "mine", "our", "them", "it", "is", "was", "be", "been", "being",
}


def extract_target_token(target: str) -> str | None:
    """Best candidate for 'which record does this action target?':
    the longest alphabetic word that is not a stop-word - so
    'remove the underperformer' yields 'underperformer', not 'the'."""
    best = None
    for w in re.findall(r"[A-Za-z][A-Za-z'-]{1,}", target):
        wl = w.lower().strip("'-")
        if wl in _TOKEN_STOP or len(wl) < 3:
            continue
        if best is None or len(wl) > len(best):
            best = wl
    return best


class PendingActionStore:
    """SQLite-backed pending-action queue (lives in the audited db/audit.db).
    Transitions are ATOMIC under the lock (CODE-01): claim() is the only
    path into 'executing', so a request can never be executed twice."""

    EXPIRY_MINUTES = 60

    def __init__(self):
        AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(AUDIT_DB, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        # S8 speed: pending-action polling (admin queue) is a hot path
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_status "
            "ON pending_actions(status)")
        self.conn.commit()

    def _expiry_minutes(self) -> int:
        return int(get_nested(app_config(), "action_gate.expiry_minutes",
                              self.EXPIRY_MINUTES))

    def _expired(self, row: dict) -> bool:
        """CODE-01: pending requests older than the expiry window are dead.
        ts format: YYYY-mm-ddTHH:MM:SS+zzzz (strftime %z)."""
        try:
            created = time.mktime(time.strptime(row["ts"][:19],
                                                "%Y-%m-%dT%H:%M:%S"))
            return (time.time() - created) > self._expiry_minutes() * 60
        except (ValueError, TypeError, KeyError):
            return False

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

    def claim(self, request_id: int) -> dict | None:
        """CODE-01: atomically transition pending -> executing. Returns the
        claimed row, or None when the request is missing, already decided,
        claimed by someone else, or EXPIRED. This closes the TOCTOU window:
        exactly one caller can ever hold the executing state."""
        with _LOCK:
            row = self.conn.execute(
                "SELECT * FROM pending_actions WHERE id=?",
                (request_id,)).fetchone()
            if not row:
                return None
            rec = dict(row)
            if rec["status"] != "pending":
                return None
            if self._expired(rec):
                self.conn.execute(
                    "UPDATE pending_actions SET status='expired', "
                    "decided_ts=?, result='expired: approval window elapsed' "
                    "WHERE id=?",
                    (time.strftime("%Y-%m-%dT%H:%M:%S%z"), request_id))
                self.conn.commit()
                return None
            self.conn.execute(
                "UPDATE pending_actions SET status='executing' WHERE id=?",
                (request_id,))
            self.conn.commit()
            return self.get(request_id)

    def finalise(self, request_id: int, approve: bool, decider: str,
                 result: str | None = None) -> dict | None:
        """Transition executing -> approved/rejected (called by the single
        claim holder after execution)."""
        with _LOCK:
            row = self.conn.execute(
                "SELECT status FROM pending_actions WHERE id=?",
                (request_id,)).fetchone()
            if not row or row["status"] != "executing":
                return None
            status = "approved" if approve else "rejected"
            self.conn.execute(
                "UPDATE pending_actions SET status=?, decided_by=?, "
                "decided_ts=?, result=? WHERE id=?",
                (status, decider, time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 result, request_id))
            self.conn.commit()
            return self.get(request_id)

    def resolve(self, request_id: int, approve: bool, decider: str,
                result: str | None = None) -> dict | None:
        """Direct pending -> approved/rejected (rejection path; never
        executes anything)."""
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
    token = extract_target_token(target)
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
        "target_token": token,
        "target_found": bool(found),
        "target_row": list(found) if found else None,
        "note": ("Sandboxed demo executor is READ-ONLY by design: an "
                 "approved action is verified and logged, never applied. "
                 "Wire this to a scoped executor with its own RBAC identity "
                 "and the approval reference in production."),
    }
