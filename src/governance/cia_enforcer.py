"""CIA Triad enforcement - per-user, per-request (Improvement 3).

Every authenticated request is validated against all three pillars before
the model is allowed to answer. This module is the single decision point;
the pipeline (src/api/main.py) calls it right after Layer 1 (identity) and
Layer 2 (input governance), so a CIA refusal happens BEFORE any retrieval
and BEFORE the model ever sees the prompt.

    C  Confidentiality  - who may know      (clearance + department isolation)
    I  Integrity        - who may change    (write ops are Admin-only + HITL)
    A  Availability     - who may consume   (session cap + rate-limit feed)

Confidentiality model
---------------------
Data is classified by a deterministic, auditable keyword classifier:

    (department, sensitivity)  ~  question keywords

Sensitivity tiers map to clearance levels (users carry L1..L5):

    Public       L1      (any authenticated user)
    Internal     L2      (own department only - isolation below)
    Confidential L3      (cross-department employee/compensation data)
    Restricted   L5      (Executive / board material - rule 3)

Rule order mirrors the CIA policy doc (docs/cia_enforcement.md):
    1. clearance >= sensitivity requirement
    2. department isolation (Executive + Admin exempt)
    3. Executive department requires L5 regardless of role

Integrity model
---------------
READ is the default posture. DELETE / UPDATE / INSERT are write operations:
non-Admin users are blocked (CIA-I), and an Admin's write intent is NEVER
executed inline - it is converted into a pending action for Layer 3.5 HITL
approval (OWASP LLM03 / NIST AI RMF "Manage"). The AI therefore has zero
direct mutation capability, and even approved actions run through a
deliberately read-only sandboxed executor.

Availability model
------------------
Per-user concurrent session cap (default 3 live JWT sessions) plus the
Layer 2 sliding-window rate limiter, whose rejections are recorded as
CIA-A violations in the audit chain (DoS prevention = availability pillar).
"""
import re
import threading
import time
from collections import defaultdict

from src.governance.auth import UserCtx, clearance_level

# ---- sensitivity tiers -----------------------------------------------------
SENSITIVITY_CLEARANCE = {"Public": "L1", "Internal": "L2",
                         "Confidential": "L3", "Restricted": "L5"}
CLEARANCE_ORDER = ["L1", "L2", "L3", "L4", "L5"]
WRITE_OPS = {"DELETE", "UPDATE", "INSERT", "WRITE", "DROP"}

# ---- deterministic question classifier (auditable, no ML) ------------------
_RE_EXEC = re.compile(
    r"\b(ceo|cto|cfo|coo|ciso|chro|executive|executives|board|bonus|bonuses|"
    r"stock\s+options?|m&a|merger|acquisition|succession|investor|"
    r"leadership\s+team?)\b", re.I)
_RE_SALARY = re.compile(
    r"\b(salary|salaries|compensation|earn|earns|earned|paid|payroll|income|"
    r"wages?)\b", re.I)
_RE_DEPT = re.compile(
    r"\b(HR|Tech(?:nical)?|Business|Finance|Sales|Executive)\s+"
    r"(department|dept|team|staff|employees?|people|division)\b"
    r"|\b(HR|Tech|Business|Finance|Sales)\b", re.I)
_RE_HR_DOC = re.compile(
    r"\b(leave|vacation|holiday|benefits?|parental|maternity|paternity|"
    r"grievance|referral|attendance|handbook|code\s+of\s+conduct|appraisal|"
    r"recruit(?:ment|ing)?|hiring|onboarding|posh)\b", re.I)
_RE_TECH_DOC = re.compile(
    r"\b(deployment|deploy|runbook|incident|architecture|on-?call|backup|"
    r"disaster\s+recovery|access\s+management|sre|secure\s+coding|"
    r"microservices?|kafka|infrastructure)\b", re.I)
_RE_BIZ_DOC = re.compile(
    r"\b(strategy|competitor|pricing|playbook|partner|market\s+research|"
    r"sales\s+plan|go[- ]to[- ]market|pipeline)\b", re.I)
_RE_FIN_DOC = re.compile(
    r"\b(budget|forecast|expense|procurement|cashflow|cash\s+flow|treasury|"
    r"invoice)\b", re.I)

_CANON = {"hr": "HR", "tech": "Tech", "technical": "Tech",
          "business": "Business", "finance": "Finance", "sales": "Sales",
          "executive": "Executive"}


def classify_question(question: str, user_department: str) -> tuple[str, str]:
    """Map a question onto (department, sensitivity) for the CIA-C check.

    Returns department in {"General"} (no isolation) when the question does
    not target a recognisable data domain. Deterministic by design: the same
    question always yields the same classification, which makes every block
    explainable - and every audit row reproducible."""
    q = question or ""
    if _RE_EXEC.search(q):
        return "Executive", "Restricted"
    dept_hit = None
    m = _RE_DEPT.search(q)
    if m:
        token = (m.group(1) or m.group(3) or "").lower()
        dept_hit = _CANON.get(token)
    if dept_hit and _RE_SALARY.search(q):
        # named-department compensation ask -> Confidential cross-dept data
        return dept_hit, "Confidential"
    if _RE_SALARY.search(q):
        # generic people/compensation ask -> your OWN department's directory
        return user_department or "General", "Internal"
    if _RE_HR_DOC.search(q):
        return "HR", "Internal"
    if _RE_FIN_DOC.search(q):
        return "Finance", "Internal"
    if _RE_TECH_DOC.search(q):
        return "Tech", "Internal"
    if _RE_BIZ_DOC.search(q):
        return "Business", "Internal"
    return "General", "Internal"


class SessionRegistry:
    """In-memory per-user session table for the CIA-A availability check.

    A session = one live JWT (its jti), first seen when the token is used.
    When a user exceeds max_sessions distinct live tokens, the newest login
    is refused: a stolen-credential flood cannot multiply sessions, and a
    shared account cannot become a covert multi-user seat."""

    def __init__(self, max_sessions: int = 3, ttl_minutes: int = 60):
        self.max = max_sessions
        self.ttl = ttl_minutes * 60
        self._live: dict[str, dict[str, float]] = defaultdict(dict)
        self._lock = threading.Lock()

    def check_and_register(self, username: str, session_id: str) \
            -> tuple[bool, str]:
        now = time.time()
        sid = session_id or f"anon:{username}"
        with self._lock:
            live = self._live[username]
            for k in [k for k, t in live.items() if now - t > self.ttl]:
                live.pop(k, None)
            if sid in live:
                live[sid] = now
                return True, "existing session"
            if len(live) >= self.max:
                return False, (f"Too many concurrent sessions "
                               f"({len(live)}/{self.max}). Close a session "
                               f"or wait for expiry.")
            live[sid] = now
            return True, "new session registered"

    def active_count(self, username: str) -> int:
        now = time.time()
        with self._lock:
            live = self._live[username]
            return len([1 for t in live.values() if now - t <= self.ttl])

    def reset(self, username: str | None = None) -> None:
        with self._lock:
            if username:
                self._live.pop(username, None)
            else:
                self._live.clear()


class CIAEnforcer:
    """Stateless rule engine + session state. One instance per process."""

    def __init__(self, max_sessions: int = 3, session_ttl_minutes: int = 60):
        self.sessions = SessionRegistry(max_sessions, session_ttl_minutes)

    # ---- C: Confidentiality ------------------------------------------------
    def check_confidentiality(self, user: UserCtx, requested_data_type: str,
                              data_department: str, data_sensitivity: str) \
            -> tuple[bool, str]:
        """Rule 1 clearance, rule 2 department isolation, rule 3 Executive L5."""
        required = SENSITIVITY_CLEARANCE.get(data_sensitivity, "L5")
        if clearance_level(user.clearance) < clearance_level(required):
            return False, (
                f"Confidentiality violation: clearance {user.clearance} is "
                f"insufficient for {data_sensitivity} {requested_data_type} "
                f"(requires {required})")
        if data_department not in ("General", "*") and \
                user.role not in ("Executive", "Admin"):
            if user.department != data_department:
                return False, (
                    f"Confidentiality violation: {user.role} "
                    f"({user.department}) cannot access "
                    f"{data_department} {requested_data_type}")
        if data_department == "Executive" and \
                clearance_level(user.clearance) < 5:
            return False, ("Confidentiality violation: Executive data "
                           "requires L5 clearance")
        return True, "Allowed"

    # ---- C: Confidentiality (data-driven verification, CHAT-06) ------------
    def check_retrieved_docs(self, user: UserCtx,
                             sources: list[dict]) -> tuple[bool, str]:
        """AUTHORITATIVE confidentiality check on what was ACTUALLY
        retrieved (CHAT-06). The keyword question classifier stays only as a
        cheap pre-filter; this method reads the sensitivity metadata
        attached to each retrieved document, so synonyms that slip past the
        keyword list ('income', 'pay', 'CTC', 'comp plan'...) are still
        caught whenever the matched document is above the user's clearance.

        Department isolation for documents is enforced ARCHITECTURALLY by
        the RBAC namespace allow-list (L4 can only search granted
        namespaces), so this check enforces the clearance tier only - it
        must not contradict an explicit RBAC grant."""
        for src in sources or []:
            meta = src.get("meta") or {}
            sens = meta.get("sensitivity")
            if not sens:
                continue
            required = SENSITIVITY_CLEARANCE.get(sens, "L5")
            if clearance_level(user.clearance) < clearance_level(required):
                return False, (
                    f"Confidentiality violation: retrieved document "
                    f"'{src.get('id', '?')}' is classified {sens} "
                    f"(requires {required}); your clearance {user.clearance} "
                    f"is insufficient")
        return True, "Allowed"

    # ---- I: Integrity -------------------------------------------------------
    def check_integrity(self, operation_type: str, user_role: str) \
            -> tuple[bool, str]:
        """Rule 1: only Admin may even REQUEST a write operation (and that
        request then goes to HITL approval - never inline execution).
        Rule 2 (AI output faithfulness) is enforced by Layer 6."""
        op = (operation_type or "READ").upper()
        if op in WRITE_OPS and user_role != "Admin":
            return False, (
                f"Integrity violation: {user_role} cannot perform "
                f"{op}. Write operations are Admin-only and additionally "
                f"require human-in-the-loop approval")
        return True, "Allowed"

    # ---- A: Availability ----------------------------------------------------
    def check_availability(self, user: UserCtx) -> tuple[bool, str]:
        """Session cap (rate limiting itself lives in Layer 2a; its
        rejections are logged as CIA-A violations there)."""
        ok, why = self.sessions.check_and_register(user.username,
                                                   user.session_id)
        if not ok:
            return False, f"Availability violation: {why}"
        return True, "Allowed"
