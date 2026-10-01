"""Official refusal replies - the Denial Engine (Wave 1.1).

Why this exists
---------------
Before this module a governance denial reached the user as one terse
security line ("Access Denied. Confidentiality violation: ...") with no
explanation of WHAT the policy allows and WHAT to do next. Users
experienced every denial as a security incident; helpdesk tickets
followed, and the product felt like a wall instead of a governed
assistant.

The Denial Engine turns every policy refusal into an OFFICIAL, consistent
4-part reply (the "denial contract"):

  1. HEAD  - the reserved verdict phrase. "Access Denied" / "Request
             blocked" stay RESERVED for real governance blocks (the
             meta-prompt forbids the model from using them for ordinary
             data gaps), so users can always tell a policy denial apart
             from an ordinary miss in the knowledge base.
  2. BODY  - the machine reason, verbatim, plus a citation of the policy
             that produced it, tied to the user's role (auditor-friendly,
             reproducible).
  3. CAN   - "You can view: ..." generated ONLY from the user's own
             policy grants - describing what the role CAN see leaks
             nothing about what it cannot. This is the constructive
             alternative to a dead end.
  4. PATH  - the escalation path (access request via manager / data
             owner) and the audit disclosure.

Every rendered denial carries a stable ReasonCode. The API surfaces it as
`denied_code` (body) and `meta.denied_code` (machine clients) and writes
it into the hash-chained audit record (`denied_code=<CODE>` inside the
reason field), so denial analytics - which fields and departments are
most requested, by whom - become a governance signal instead of
anecdote.

This module is deliberately dependency-free (stdlib only) so rbac.py can
import the ReasonCode without an import cycle.
"""
from dataclasses import dataclass
from enum import Enum


class ReasonCode(str, Enum):
    """Stable machine codes for every official denial class.

    AUTHZ_*  -> Layer 3 RBAC (what your role may query)
    CIA_C_*  -> CIA triad confidentiality (clearance + department)
    DLP_*    -> Layer 6 output governance (what the reply may contain)
    INPUT_*  -> Layer 2 input firewall (how you may ask)
    """

    AUTHZ_TABLE = "AUTHZ_TABLE"      # table not allow-listed for the role
    AUTHZ_FIELD = "AUTHZ_FIELD"      # column excluded from the role's whitelist
    AUTHZ_ROW = "AUTHZ_ROW"          # row-level scope violation (RBAC 2.0)
    CIA_C_DOC = "CIA_C_DOC"          # clearance / department isolation deny
    DLP_OUTPUT = "DLP_OUTPUT"        # output withheld by Layer 6 DLP
    INPUT_BLOCKED = "INPUT_BLOCKED"  # prompt stopped by the Layer 2 firewall


@dataclass(frozen=True)
class DenialTemplate:
    """The 4-part denial contract for one ReasonCode.

    head      - the reserved verdict phrase (first thing the user reads)
    body      - what happened, in plain language ({role} interpolated)
    citation  - the policy/control that produced the decision
    path      - the escalation path (never a dead end)
    """

    head: str
    body: str
    citation: str
    path: str


_TEMPLATES: dict[ReasonCode, DenialTemplate] = {
    ReasonCode.AUTHZ_TABLE: DenialTemplate(
        head="Access Denied - this data source is outside your role.",
        body="You asked about a data source that your role ({role}) is not "
             "provisioned to query. The source was removed from the "
             "retrieval plan before any database statement was built.",
        citation="Role-based access control, Layer 3 "
                 "(config/rbac_config.yaml - table whitelist)",
        path="If you need this data for your work, raise an access request "
             "with your manager - the data owner approves role changes. "
             "This event is recorded in the tamper-evident audit chain.",
    ),
    ReasonCode.AUTHZ_FIELD: DenialTemplate(
        head="Access Denied - restricted field.",
        body="Your role ({role}) may query this data source, but the field "
             "you asked about is excluded from your column whitelist, so it "
             "was removed from the query before it reached the database.",
        citation="Role-based access control, Layer 3 "
                 "(config/rbac_config.yaml - column whitelist)",
        path="If you need this field for your work, raise an access request "
             "with your manager - the data owner approves field-level "
             "access. This event is recorded in the tamper-evident audit "
             "chain.",
    ),
    ReasonCode.AUTHZ_ROW: DenialTemplate(
        head="Access Denied - outside your row scope.",
        body="Your role ({role}) may see rows within an assigned scope "
             "only, and the requested record falls outside it.",
        citation="Role-based access control, Layer 3 (row scope)",
        path="Raise a scoped-access request with your manager if this "
             "record is required for your work. This event is recorded in "
             "the tamper-evident audit chain.",
    ),
    ReasonCode.CIA_C_DOC: DenialTemplate(
        head="Access Denied - confidentiality policy.",
        body="The data you asked about is classified above your clearance "
             "or belongs to another department. The request was evaluated "
             "under your role's data policy before any retrieval ran.",
        citation="CIA triad enforcement - confidentiality "
                 "(clearance tiers L1-L5 + department isolation)",
        path="If you need this data for your work, raise an access request "
             "with your manager - clearance and department exceptions are "
             "granted by the data owner, never by the assistant.",
    ),
    ReasonCode.DLP_OUTPUT: DenialTemplate(
        head="Access Denied - response withheld.",
        body="The draft reply contained data your role is not permitted to "
             "receive, so it was withheld before delivery and queued for "
             "human review.",
        citation="Layer 6 output governance - role-aware data-loss "
                 "prevention (OWASP LLM02)",
        path="A reviewer will inspect the flagged response. Contact your "
             "manager if you expected access to this information.",
    ),
    ReasonCode.INPUT_BLOCKED: DenialTemplate(
        head="Request blocked by the input firewall.",
        body="The prompt matched injection patterns and never reached the "
             "model or the data layer.",
        citation="Layer 2 input governance (OWASP LLM01 - prompt "
                 "injection)",
        path="Rephrase the request in plain language. Repeated injection "
             "attempts are logged to the audit chain and reviewed.",
    ),
}


def template(code: ReasonCode | str) -> DenialTemplate:
    """Look up the DenialTemplate for a code (accepts the raw string)."""
    return _TEMPLATES[ReasonCode(code)]


def render(code: ReasonCode | str, role: str, detail: str = "",
           allowed: str = "", head: str | None = None) -> str:
    """Render the official 4-part denial message.

    head    - override the template verdict with a LEGACY head (used by the
              existing _deny/_cia_deny paths so their published reply
              contract stays byte-compatible: "Access Denied. <reason>. "
              / "Request blocked by <layer> ...").
    detail  - the machine reason, embedded VERBATIM (auditors must be able
              to reproduce the decision from the reply alone).
    allowed - the caller's Policy.summary() text for the "You can view"
              part; empty -> a safe generic line.
    """
    t = template(code)
    head_line = head or t.head
    cite = f"Policy basis: {t.citation} (your role: {role})."
    reason = " ".join(x.strip() for x in (detail, cite) if x and x.strip())
    can = (f"You can view: {allowed}." if allowed
           else "You can view: no company data under the current role.")
    parts = (head_line, reason, can, t.path)
    return "\n\n".join(p for p in parts if p and p.strip())


def denied_codes() -> list[str]:
    """All stable codes (for /api/me, dashboards and docs)."""
    return [c.value for c in ReasonCode]
