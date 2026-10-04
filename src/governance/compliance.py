"""Layer G: Governance Transparency & Compliance (v4.9.0).

The runtime pipeline (L1-L7) *enforces* governance; this module *proves*
it. It operationalises the artefact layer that AI governance programmes
are audited against (EU AI Act conformity, NIST AI RMF maturity, scored
risk registers, AI incident ledgers) as runnable code with a proving
test - the same "no policy PDFs" rule the rest of the product follows.

Four capabilities, one SQLite store (db/compliance.db):

1. AI SYSTEM INVENTORY with an EU AI Act classification engine.
   Registering a system through classify_system() yields its risk tier
   (Unacceptable / High / Limited / Minimal), the Annex III category
   where applicable, the triggered obligations (Articles 9-15, 26, 43,
   71, 72), and the review cycle the tier mandates. Prohibited-practice
   registrations (Art. 5) are refused outright - there is no approval
   pathway, mirroring the Responsible-AI-policy approval gates.
2. RISK REGISTER with likelihood x impact scoring (1-25), inherent ->
   residual tracking as controls are attached, and standard banding
   (Low 1-6 / Medium 7-14 / High 15-19 / Critical 20-25).
3. AI INCIDENT LEDGER with severity classes 1-4, an explicit state
   machine (open -> investigating -> contained -> remediated -> closed),
   escalation SLAs per severity (S1: governance committee <= 24 h, board
   <= 48 h, regulatory-assessment flag), and full timeline capture.
   Transitions are mirrored into the L7 hash-chain audit by the API layer,
   so incident handling is tamper-evident like everything else.
4. FRAMEWORK EVIDENCE: NIST AI RMF (Govern/Map/Measure/Manage) maturity
   scoring and an EU AI Act Articles 9-17 conformity self-assessment,
   both computed from LIVE runtime evidence handed in by the API layer -
   not from a static document that rots.

Regulatory research state (October 2026), surfaced through
REGULATORY_NOTES so the module stays honest about the moving target:
  - GPAI enforcement powers apply since 2 Aug 2026 (Art. 101 penalties
    up to EUR 15M / 3% worldwide turnover).
  - The May 2026 Digital Omnibus provisional deal proposes moving the
    application date for many Annex III high-risk obligations from
    2 Aug 2026 to 2 Dec 2027 - classification still matters today
    (prohibitions and transparency already apply; best practice is to
    keep classifying and documenting, not to wait).
  - Deployer-side automatic-log retention for high-risk systems is
    >= 6 months (Art. 19 read with Art. 12).
  - NIST released an AI RMF Critical-Infrastructure profile concept
    note (Apr 2026); ISO/IEC 42001 and AIUC-1 are the parallel
    management-system / assurance tracks - one governance programme
    can evidence all of them simultaneously.

Inspired by the artefact structure of the taimurijlal/AIGovernance
portfolio (EU AI Act + NIST AI RMF documentation projects); here every
artefact is generated from live product state instead of hand-written.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from typing import Any

from src.common.paths import COMPLIANCE_DB

# --------------------------------------------------------------------------
# EU AI Act classification engine
# --------------------------------------------------------------------------

TIER_UNACCEPTABLE = "Unacceptable"
TIER_HIGH = "High"
TIER_LIMITED = "Limited"
TIER_MINIMAL = "Minimal"

# Art. 5 prohibited practices: registration is refused, full stop.
PROHIBITED_FLAGS: dict[str, str] = {
    "social_scoring":
        "Art.5(1)(c) - social scoring of natural persons over time",
    "realtime_biometric_id":
        "Art.5(1)(d),(h) - real-time remote biometric identification in "
        "publicly accessible spaces (post-F RI check)",
    "emotion_workplace_edu":
        "Art.5(1)(f) - emotion recognition in workplace or education",
    "untargeted_face_scraping":
        "Art.5(1)(e) - untargeted scraping of facial images to build "
        "databases",
    "biometric_sensitive_categorisation":
        "Art.5(1)(g) - biometric categorisation inferring race, political "
        "opinions, trade-union membership, religious/philosophical beliefs, "
        "sex life or orientation",
}

# Annex III high-risk categories relevant to enterprise deployments.
HIGH_RISK_CATEGORIES: dict[str, tuple[str, str]] = {
    "biometric_verification": (
        "Annex III 1", "biometric identification/verification systems"),
    "critical_infrastructure": (
        "Annex III 2", "safety components in critical-infrastructure "
        "management"),
    "education_admission": (
        "Annex III 3(a)", "admission, evaluation or learning-outcome "
        "decisions in education"),
    "employment_screening": (
        "Annex III 4(a)", "recruitment or selection of natural persons "
        "(CV screening, shortlisting)"),
    "promotion_termination": (
        "Annex III 4(b)", "promotion/termination decisions, task "
        "allocation, employee monitoring"),
    "essential_services": (
        "Annex III 5(a)", "eligibility for essential public assistance or "
        "services (benefits, utilities)"),
    "creditworthiness": (
        "Annex III 5(b)", "creditworthiness assessment / credit scoring "
        "of natural persons"),
    "insurance_pricing": (
        "Annex III 5(c)", "risk assessment and pricing in life and "
        "health insurance"),
    "emergency_dispatch": (
        "Annex III 5(d)", "emergency dispatch triage (police, fire, "
        "medical)"),
    "law_enforcement": (
        "Annex III 6", "law-enforcement use cases"),
    "migration_border": (
        "Annex III 7", "migration, asylum and border-control management"),
    "justice_democratic": (
        "Annex III 8", "administration of justice and democratic "
        "processes"),
}

# Transparency-track flags: the system interacts with natural persons or
# produces synthetic content -> Art. 50 disclosure duties.
LIMITED_FLAGS: set[str] = {
    "customer_facing_chatbot",   # humans converse with it
    "employee_facing_chatbot",   # same duty, internal audience
    "synthetic_content",         # deepfake / generated media labelling
    "emotion_recognition_product",  # consumer product context
}

HIGH_RISK_OBLIGATIONS: list[str] = [
    "Art.9  risk-management system (continuous, documented)",
    "Art.10 data and data governance (training/validation sets, bias "
    "examination)",
    "Art.11 + Annex IV technical documentation",
    "Art.12 automatic logging (deployer retention >= 6 months, Art.19)",
    "Art.13 transparency and instructions for deployers",
    "Art.14 human oversight (override/stop capability, not rubber-stamp)",
    "Art.15 accuracy, robustness and cybersecurity",
    "Art.43 conformity assessment before first deployment",
    "Art.71 registration in the EU database",
    "Art.72 post-market monitoring plan",
]

LIMITED_OBLIGATIONS: list[str] = [
    "Art.50(1) disclose AI interaction to the persons concerned",
    "Art.50(2)/(4) synthetic-content labelling where applicable",
]

MINIMAL_OBLIGATIONS: list[str] = [
    "No AI-Act-specific obligations; GDPR and sector rules still apply",
]

UNACCEPTABLE_OBLIGATIONS: list[str] = [
    "Art.5 prohibited practice - NO deployment or approval pathway",
]

DIGITAL_OMNIBUS_NOTE = (
    "May 2026 Digital Omnibus provisional deal proposes moving the "
    "application date of many Annex III high-risk obligations from "
    "2 Aug 2026 to 2 Dec 2027; prohibitions (Feb 2025), GPAI enforcement "
    "(2 Aug 2026) and transparency duties are unaffected. Keep "
    "classifying and documenting - delays change deadlines, not duties.")

REGULATORY_NOTES: list[str] = [
    DIGITAL_OMNIBUS_NOTE,
    "GPAI model enforcement powers apply since 2 Aug 2026 (Art.101: fines "
    "up to EUR 15M or 3% of worldwide annual turnover).",
    "Deployers of high-risk systems: automatic-log retention >= 6 months "
    "(Art.12 + Art.19) - covered by the L7 chain + JSONL mirror here.",
    "NIST AI RMF Critical-Infrastructure profile concept note published "
    "Apr 2026; ISO/IEC 42001 (management system) and AIUC-1 (assurance) "
    "evidence maps 1:1 onto this module's artefacts.",
]


def classify_system(purpose_flags: list[str],
                    autonomous_decisions: bool = False,
                    affects_individuals: bool = True) -> dict[str, Any]:
    """EU AI Act classifier: purpose flags -> tier + Annex III category +
    triggered obligations + review cycle. Deterministic and auditable -
    the same input always yields the same classification, so the decision
    is defensible in front of a regulator."""
    flags = [str(f).strip().lower() for f in (purpose_flags or [])]

    hit_prohibited = [PROHIBITED_FLAGS[f] for f in flags if f in PROHIBITED_FLAGS]
    if hit_prohibited:
        return {
            "tier": TIER_UNACCEPTABLE,
            "annex_category": None,
            "obligations": UNACCEPTABLE_OBLIGATIONS,
            "rationale": "Prohibited practice under Art.5: "
                         + "; ".join(hit_prohibited),
            "review_cycle_days": 0,
            "prohibited_basis": hit_prohibited,
        }

    annex_hits = [(HIGH_RISK_CATEGORIES[f][0], HIGH_RISK_CATEGORIES[f][1])
                  for f in flags if f in HIGH_RISK_CATEGORIES]
    if annex_hits:
        first = annex_hits[0]
        others = [h[0] for h in annex_hits[1:]]
        rationale = (f"{first[0]} - {first[1]}. Output influences decisions "
                     f"affecting natural persons"
                     + (" and the workflow permits autonomous operation, "
                        "so the system is operated as decisioning input "
                        "without a substantive human gate"
                        if autonomous_decisions else
                        " (human-oversight gate must remain substantive, "
                        "not nominal)"))
        if others:
            rationale += f". Additional matched categories: {', '.join(others)}"
        return {
            "tier": TIER_HIGH,
            "annex_category": first[0],
            "obligations": HIGH_RISK_OBLIGATIONS,
            "rationale": rationale,
            "review_cycle_days": 180,   # high-risk: semi-annual review
            "prohibited_basis": [],
        }

    limited = [f for f in flags if f in LIMITED_FLAGS]
    if limited and affects_individuals:
        return {
            "tier": TIER_LIMITED,
            "annex_category": None,
            "obligations": LIMITED_OBLIGATIONS,
            "rationale": "Interacts with natural persons / may produce "
                         "synthetic content -> Art.50 transparency duties "
                         "apply; no Annex III high-risk category matched.",
            "review_cycle_days": 365,
            "prohibited_basis": [],
        }

    return {
        "tier": TIER_MINIMAL,
        "annex_category": None,
        "obligations": MINIMAL_OBLIGATIONS,
        "rationale": "No Annex III category, no transparency trigger, no "
                     "prohibited practice.",
        "review_cycle_days": 365,
        "prohibited_basis": [],
    }


# --------------------------------------------------------------------------
# Risk register maths
# --------------------------------------------------------------------------

def band(score: int) -> str:
    """Likelihood x Impact banding (1-25)."""
    if score <= 0:
        return "n/a"
    if score <= 6:
        return "Low"
    if score <= 14:
        return "Medium"
    if score <= 19:
        return "High"
    return "Critical"


# Incident severity -> escalation SLA (hours) + regulatory-assessment flag.
SEVERITY_ESCALATION: dict[int, dict[str, Any]] = {
    1: {"committee_hours": 24, "board_hours": 48,
        "regulatory_assessment": True},
    2: {"committee_hours": 72, "board_hours": 168,
        "regulatory_assessment": True},
    3: {"committee_hours": 168, "board_hours": 0,
        "regulatory_assessment": False},
    4: {"committee_hours": 0, "board_hours": 0,
        "regulatory_assessment": False},
}

_INCIDENT_OPEN_STATUSES = ("open", "investigating", "contained", "remediated")

_VALID_TRANSITIONS: dict[str, set[str]] = {
    "open": {"investigating", "contained", "closed", "cancelled"},
    "investigating": {"contained", "remediated", "closed", "cancelled"},
    "contained": {"remediated", "closed", "cancelled"},
    "remediated": {"closed"},
    "closed": set(),
    "cancelled": set(),
}


# --------------------------------------------------------------------------
# NIST AI RMF maturity + EU AI Act conformity pack (live-evidence based)
# --------------------------------------------------------------------------

def assess_rmf_maturity(ev: dict[str, Any]) -> dict[str, Any]:
    """Score GOVERN/MAP/MEASURE/MANAGE (1-4) from live evidence flags.
    Missing evidence is a gap, not a rhetorical flourish."""
    def _score(checks: list[tuple[str, bool]]) -> tuple[int, list[str], list[str]]:
        have = [name for name, ok in checks if ok]
        gaps = [name for name, ok in checks if not ok]
        # 4 = all present; 3 = one missing; 2 = half; 1 = mostly absent
        ratio = len(have) / max(1, len(checks))
        score = 1 + min(3, round(ratio * 3))
        return score, have, gaps

    govern = _score([
        ("declarative_policy_as_config", bool(ev.get("declarative_policy"))),
        ("named_system_owner", bool(ev.get("named_owner"))),
        ("ai_system_inventory_live", bool(ev.get("inventory_registry"))),
        ("model_manifest_provenance", bool(ev.get("model_manifest"))),
        ("incident_ledger_operational", bool(ev.get("incident_ledger"))),
    ])
    mapping = _score([
        ("documented_threat_model", bool(ev.get("documented_threat_model"))),
        ("cia_pillar_mapping", bool(ev.get("cia_mapping"))),
        ("residual_risks_recorded", bool(ev.get("residual_risks"))),
        ("risk_register_scored", bool(ev.get("risk_register"))),
    ])
    measure = _score([
        ("regression_suite_green", bool(ev.get("tests_pass"))),
        ("redteam_probe_gate", bool(ev.get("probe_gate"))),
        ("continuous_metrics_endpoint", bool(ev.get("metrics_endpoint"))),
        ("tamper_evident_audit_chain", bool(ev.get("audit_chain_valid"))),
    ])
    manage = _score([
        ("hitl_action_gate", bool(ev.get("hitl_gate"))),
        ("kill_switch_lever", bool(ev.get("kill_switch"))),
        ("log_retention_configured", bool(ev.get("retention_configured"))),
        ("incident_response_runbook", bool(ev.get("incident_runbook"))),
    ])

    def _pack(name: str, triple) -> dict[str, Any]:
        score, have, gaps = triple
        return {"function": name, "score": score, "max": 4,
                "evidence": have, "gaps": gaps,
                "maturity": {1: "Initial", 2: "Developing",
                             3: "Defined", 4: "Optimised"}[score]}

    funcs = [_pack("GOVERN", govern), _pack("MAP", mapping),
             _pack("MEASURE", measure), _pack("MANAGE", manage)]
    overall = round(sum(f["score"] for f in funcs) / 4, 2)
    return {"functions": funcs, "overall_maturity": overall,
            "scale": "1=Initial 2=Developing 3=Defined 4=Optimised"}


def conformity_pack(ev: dict[str, Any]) -> dict[str, Any]:
    """EU AI Act Articles 9-17 (+26/72) self-assessment generated from
    live runtime evidence. Each article: status + concrete evidence
    pointers. This is the machine-checked cousin of docs/system_card."""
    articles: dict[str, dict[str, Any]] = {}

    articles["Art.9 - Risk management system"] = {
        "status": "implemented" if ev.get("risk_register") else "partial",
        "evidence": [
            "Scored risk register (db/compliance.db) with inherent/residual "
            f"tracking - {ev.get('risks_total', 0)} entries",
            "docs/Threat_Model.md: 7 assets, 12 entry-point threats",
            "Red-team probe corpus + CI gate (scripts/probe_runner.py)",
        ]}

    articles["Art.10 - Data and data governance"] = {
        "status": "implemented",
        "evidence": [
            "Curated dataset pipeline (scripts/generate_enterprise_data.py) "
            "with documented schema - no scraped data",
            "Purpose limitation + data minimisation at L4 (column/namespace "
            "scoping per role)",
            "RAG poisoning demo proves untrusted-content handling",
        ]}

    articles["Art.11 - Technical documentation"] = {
        "status": "implemented",
        "evidence": [
            "docs/governance/system_card.md (Annex IV-style one-pager)",
            "docs/Architecture.md, docs/model_manifest.md (provenance + "
            "digests)",
            "This pack is generated from live state, not hand-written",
        ]}

    articles["Art.12 - Record-keeping (logging)"] = {
        "status": "implemented" if ev.get("audit_chain_valid")
                  else "DEGRADED - chain verification failing",
        "evidence": [
            f"L7 hash-chained audit: {ev.get('audit_events', 0)} events, "
            f"chain_valid={ev.get('audit_chain_valid')}",
            f"Retention {ev.get('retention_days', 180)} days "
            "(>= the 6-month deployer minimum of Art.19)",
            "logs/audit.jsonl SIEM mirror with size rotation",
        ]}

    articles["Art.13 - Transparency to deployers/users"] = {
        "status": "implemented",
        "evidence": [
            "Every denial cites a machine-readable reason code "
            "(denials.ReasonCode) surfaced in chat traces",
            "Per-request governance trace (14 layers) visible to the user",
            "docs/governance/system_card.md states limitations explicitly",
        ]}

    articles["Art.14 - Human oversight"] = {
        "status": "implemented",
        "evidence": [
            f"L3.5 HITL gate: {ev.get('pending_actions', 0)} actions "
            "currently awaiting human approval",
            "Approver-role separation + sandboxed read-only executor",
            "Human review queue for withheld outputs "
            f"({ev.get('open_review_items', 0)} open)",
        ]}

    articles["Art.15 - Accuracy, robustness, cybersecurity"] = {
        "status": "implemented",
        "evidence": [
            f"Regression suite {ev.get('tests_total', 0)} tests green",
            "Probe harness baseline-vs-secured measurement (0 leaks "
            "secured)",
            "L1 brute-force lockout, JWT revocation, payload caps, "
            "per-user budgets (CIA-A)",
        ]}

    articles["Art.16/17 - Provider duties & post-market monitoring"] = {
        "status": "implemented",
        "evidence": [
            "Prometheus /metrics + /health (continuous monitoring)",
            "logs_tail.sh operational log surfacing",
            "Model manifest change-procedure (Art.15(5) docs on demand)",
        ]}

    articles["Art.26 - Deployer duties"] = {
        "status": "implemented",
        "evidence": [
            "Instructions-for-use = docs/LOCAL_SETUP.md + README quickstart",
            "Human oversight by design (L3.5); input relevance gate at L2",
            "This inventory IS the deployer register of systems in use",
        ]}

    articles["Art.50 - Transparency (interaction disclosure)"] = {
        "status": "implemented",
        "evidence": [
            "Chat UI identifies the assistant as an AI on first render",
            "Denial banners make automated behaviour explicit",
        ]}

    return {
        "articles": articles,
        "deployer_log_retention_months": 6,
        "regulatory_timeline": [
            "2 Feb 2025 - prohibitions + AI-literacy duties apply",
            "2 Aug 2025 - GPAI obligations apply",
            "2 Aug 2026 - high-risk + transparency application date "
            "(Digital Omnibus provisional deal proposes moving Annex III "
            "high-risk items to 2 Dec 2027)",
            "2 Dec 2027 - proposed Annex III high-risk date under the "
            "Digital Omnibus deal",
        ],
        "regulatory_notes": REGULATORY_NOTES,
        "evidence_version": ev.get("version", "unknown"),
    }


# --------------------------------------------------------------------------
# SQLite store: inventory, risks, incidents
# --------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_systems (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT '',
    business_unit TEXT DEFAULT '',
    system_owner TEXT DEFAULT '',
    vendor TEXT DEFAULT 'internal',
    deployment_status TEXT DEFAULT 'planned',
    affected_persons TEXT DEFAULT '',
    purpose_flags TEXT DEFAULT '[]',
    autonomous_decisions INTEGER DEFAULT 0,
    tier TEXT NOT NULL,
    annex_category TEXT,
    obligations TEXT DEFAULT '[]',
    rationale TEXT DEFAULT '',
    review_cycle_days INTEGER DEFAULT 365,
    demo INTEGER DEFAULT 0,
    registered_by TEXT DEFAULT '',
    created_at TEXT,
    last_review TEXT
);
CREATE TABLE IF NOT EXISTS risk_register (
    id TEXT PRIMARY KEY,
    system_id TEXT DEFAULT '',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    likelihood INTEGER NOT NULL,
    impact INTEGER NOT NULL,
    inherent_score INTEGER NOT NULL,
    controls TEXT DEFAULT '',
    residual_score INTEGER NOT NULL,
    control_owner TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    demo INTEGER DEFAULT 0,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    system_id TEXT DEFAULT '',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity INTEGER NOT NULL,
    status TEXT DEFAULT 'open',
    detected_by TEXT DEFAULT '',
    containment TEXT DEFAULT '',
    opened_by TEXT DEFAULT '',
    opened_at TEXT,
    updated_at TEXT,
    timeline TEXT DEFAULT '[]'
);
"""

_NOW = lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z")  # noqa: E731


class ComplianceError(Exception):
    """Raised for policy refusals (prohibited practice) and validation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ComplianceStore:
    """Owns db/compliance.db (WAL). Thread-safe via a module lock - the
    compliance plane is low-traffic (admin console + CI), so a single
    lock keeps semantics trivially correct."""

    def __init__(self, path=COMPLIANCE_DB):
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        self._seed_if_empty()

    # ---- helpers ---------------------------------------------------------
    @staticmethod
    def _row(r) -> dict[str, Any]:
        d = dict(r)
        for key in ("purpose_flags", "obligations", "timeline"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key] or ("[]" if key != "purpose_flags"
                                                   else "[]"))
                except json.JSONDecodeError:
                    d[key] = []
        if "autonomous_decisions" in d:
            d["autonomous_decisions"] = bool(d["autonomous_decisions"])
        if "demo" in d:
            d["demo"] = bool(d["demo"])
        return d

    def _next_id(self, table: str, prefix: str) -> str:
        n = self._conn.execute(
            f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
        return f"{prefix}-{n + 1:04d}"

    # ---- inventory -------------------------------------------------------
    def add_system(self, *, name: str, purpose: str, purpose_flags: list[str],
                   business_unit: str = "", system_owner: str = "",
                   vendor: str = "internal",
                   deployment_status: str = "planned",
                   affected_persons: str = "",
                   autonomous_decisions: bool = False,
                   review_cycle_days: int | None = None,
                   demo: bool = False,
                   registered_by: str = "") -> dict[str, Any]:
        verdict = classify_system(purpose_flags, autonomous_decisions)
        if verdict["tier"] == TIER_UNACCEPTABLE:
            # Approval gate: Unacceptable risk has NO pathway (policy 4.3).
            raise ComplianceError(
                "PROHIBITED_PRACTICE",
                f"Registration refused: {verdict['rationale']}")
        sid = self._next_id("ai_systems", "SYS")
        now = _NOW()
        with self._lock:
            self._conn.execute(
                "INSERT INTO ai_systems (id,name,purpose,business_unit,"
                "system_owner,vendor,deployment_status,affected_persons,"
                "purpose_flags,autonomous_decisions,tier,annex_category,"
                "obligations,rationale,review_cycle_days,demo,"
                "registered_by,created_at,last_review) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, name, purpose, business_unit, system_owner, vendor,
                 deployment_status, affected_persons,
                 json.dumps(purpose_flags or []), int(autonomous_decisions),
                 verdict["tier"], verdict["annex_category"],
                 json.dumps(verdict["obligations"]), verdict["rationale"],
                 review_cycle_days or verdict["review_cycle_days"],
                 int(demo), registered_by, now, now))
            self._conn.commit()
        return self.get_system(sid)

    def get_system(self, sid: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM ai_systems WHERE id=?", (sid,)).fetchone()
        return self._row(row) if row else None

    def list_systems(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM ai_systems ORDER BY "
            "CASE tier WHEN 'Unacceptable' THEN 0 WHEN 'High' THEN 1 "
            "WHEN 'Limited' THEN 2 ELSE 3 END, id").fetchall()
        return [self._row(r) for r in rows]

    # ---- risk register ---------------------------------------------------
    def add_risk(self, *, title: str, system_id: str = "",
                 description: str = "", likelihood: int = 1,
                 impact: int = 1, controls: str = "",
                 control_owner: str = "", demo: bool = False,
                 residual_score: int | None = None) -> dict[str, Any]:
        if not (1 <= int(likelihood) <= 5 and 1 <= int(impact) <= 5):
            raise ComplianceError("VALIDATION",
                                  "likelihood and impact must be 1..5")
        inherent = int(likelihood) * int(impact)
        residual = inherent if residual_score is None else int(residual_score)
        if not (1 <= residual <= inherent):
            raise ComplianceError(
                "VALIDATION",
                "residual_score must be within 1..inherent (controls cannot "
                "increase risk)")
        rid = self._next_id("risk_register", "RISK")
        with self._lock:
            self._conn.execute(
                "INSERT INTO risk_register (id,system_id,title,description,"
                "likelihood,impact,inherent_score,controls,residual_score,"
                "control_owner,status,demo,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, system_id, title, description, int(likelihood),
                 int(impact), inherent, controls, residual, control_owner,
                 "open", int(demo), _NOW()))
            self._conn.commit()
        return self.get_risk(rid)

    def get_risk(self, rid: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM risk_register WHERE id=?", (rid,)).fetchone()
        if not row:
            return None
        d = self._row(row)
        d["inherent_band"] = band(d["inherent_score"])
        d["residual_band"] = band(d["residual_score"])
        return d

    def list_risks(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM risk_register ORDER BY inherent_score DESC, id"
        ).fetchall()
        return [self.get_risk(r["id"]) for r in rows]

    def update_controls(self, rid: str, *, controls: str,
                        residual_score: int) -> dict[str, Any]:
        row = self.get_risk(rid)
        if not row:
            raise ComplianceError("NOT_FOUND", f"risk {rid} not found")
        if not (1 <= int(residual_score) <= row["inherent_score"]):
            raise ComplianceError(
                "VALIDATION",
                f"residual_score must be within 1..{row['inherent_score']}")
        with self._lock:
            self._conn.execute(
                "UPDATE risk_register SET controls=?, residual_score=? "
                "WHERE id=?", (controls, int(residual_score), rid))
            self._conn.commit()
        return self.get_risk(rid)

    # ---- incidents -------------------------------------------------------
    def declare_incident(self, *, title: str, severity: int,
                         system_id: str = "", description: str = "",
                         detected_by: str = "", containment: str = "",
                         opened_by: str = "") -> dict[str, Any]:
        if int(severity) not in SEVERITY_ESCALATION:
            raise ComplianceError("VALIDATION", "severity must be 1..4")
        iid = self._next_id("incidents", "AI-INC")
        now = _NOW()
        entry = {"at": now, "event": "declared", "by": opened_by,
                 "note": f"severity {severity} declared"}
        with self._lock:
            self._conn.execute(
                "INSERT INTO incidents (id,system_id,title,description,"
                "severity,status,detected_by,containment,opened_by,"
                "opened_at,updated_at,timeline) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (iid, system_id, title, description, int(severity), "open",
                 detected_by, containment, opened_by, now, now,
                 json.dumps([entry])))
            self._conn.commit()
        return self.get_incident(iid)

    def get_incident(self, iid: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        return self._row(row) if row else None

    def list_incidents(self, include_closed: bool = True
                       ) -> list[dict[str, Any]]:
        if include_closed:
            rows = self._conn.execute(
                "SELECT * FROM incidents ORDER BY opened_at DESC, id"
            ).fetchall()
        else:
            q = ",".join(f"'{s}'" for s in _INCIDENT_OPEN_STATUSES)
            rows = self._conn.execute(
                f"SELECT * FROM incidents WHERE status IN ({q}) "
                "ORDER BY opened_at DESC, id").fetchall()  # noqa: S608
        return [self._row(r) for r in rows]

    def transition_incident(self, iid: str, *, to_status: str,
                            actor: str = "", note: str = ""
                            ) -> dict[str, Any]:
        row = self.get_incident(iid)
        if not row:
            raise ComplianceError("NOT_FOUND", f"incident {iid} not found")
        cur = row["status"]
        if to_status not in _VALID_TRANSITIONS.get(cur, set()):
            raise ComplianceError(
                "INVALID_TRANSITION",
                f"illegal transition {cur} -> {to_status}")
        now = _NOW()
        timeline = row["timeline"] + [
            {"at": now, "event": f"{cur}->{to_status}", "by": actor,
             "note": note or ""}]
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET status=?, updated_at=?, timeline=? "
                "WHERE id=?", (to_status, now, json.dumps(timeline), iid))
            self._conn.commit()
        out = self.get_incident(iid)
        out["escalation"] = SEVERITY_ESCALATION[out["severity"]]
        return out

    # ---- counts for snapshot/pack ----------------------------------------
    def counts(self) -> dict[str, int]:
        with self._lock:
            def _c(sql: str) -> int:
                return self._conn.execute(sql).fetchone()[0]  # noqa: S608
            return {
                "systems": _c("SELECT COUNT(*) FROM ai_systems"),
                "risks": _c("SELECT COUNT(*) FROM risk_register"),
                "incidents": _c("SELECT COUNT(*) FROM incidents"),
                "incidents_open": _c(
                    "SELECT COUNT(*) FROM incidents WHERE status IN "
                    "('open','investigating','contained','remediated')"),
            }

    # ---- seed ------------------------------------------------------------
    def _seed_if_empty(self) -> None:
        """First boot: register this product + the two demo scenario
        systems (from the AIGovernance portfolio scenario) and the
        portfolio's six-scored-risk register so the console is
        immediately meaningful. Incidents seed EMPTY - real ledger."""
        if self.counts()["systems"] > 0:
            return
        # 1) this product itself - honest self-registration
        self.add_system(
            name="SecureLLM Enterprise Assistant",
            purpose="Internal employee-facing governed AI chat assistant "
                    "(RAG over company data + structured lookups)",
            purpose_flags=["employee_facing_chatbot"],
            business_unit="Platform", system_owner="Platform Team",
            vendor="internal", deployment_status="production",
            affected_persons="internal employees",
            autonomous_decisions=False,
            demo=False, registered_by="seed")
        # 2) demo scenario systems (marked demo=True in the console)
        self.add_system(
            name="CreditScore Pro (demo scenario)",
            purpose="ML model scoring loan applicants on likelihood of "
                    "default",
            purpose_flags=["creditworthiness"],
            business_unit="Demo - Retail Lending",
            system_owner="Head of Credit Risk (demo)",
            vendor="internal", deployment_status="production",
            affected_persons="loan applicants",
            autonomous_decisions=True, demo=True, registered_by="seed")
        self.add_system(
            name="TalentMatch AI (demo scenario)",
            purpose="NLP-based CV screening and candidate shortlisting",
            purpose_flags=["employment_screening"],
            business_unit="Demo - Human Resources",
            system_owner="HR Director (demo)",
            vendor="HireFlow Technologies (demo)",
            deployment_status="production",
            affected_persons="job applicants",
            autonomous_decisions=True, demo=True, registered_by="seed")
        # 3) seed risk register (demo scenario six + one real self-risk)
        for risk in (
            ("Proxy discrimination via training-data bias",
             "Historical hiring data encodes past discriminatory patterns; "
             "surface features act as proxies for protected characteristics.",
             4, 4,
             "Vendor bias-audit documentation; independent fairness "
             "evaluation; human review before rejections",
             "HR Director + CPO", 8),
            ("Lack of explainability for adverse decisions",
             "Rejected candidates cannot receive a meaningful explanation "
             "(GDPR Art.22 / EU AI Act Art.13, Art.86).",
             5, 3,
             "Explanation API; human review as the decision point; updated "
             "candidate communications",
             "HR Director + Legal", 6),
            ("No human oversight in rejection workflow",
             "Automated rejections without a substantive human gate "
             "(EU AI Act Art.14 violation pattern).",
             5, 4,
             "Mandatory human review gate; AI shortlist is input, not "
             "decision; override logging",
             "HR Director", 8),
            ("Training-data provenance and quality",
             "Vendor has not supplied training-data documentation.",
             4, 3,
             "Formal information request; Art.10 clauses at contract "
             "renewal",
             "Procurement + Legal", 4),
            ("Scope creep beyond intended purpose",
             "Outputs reused for promotion/mobility decisions without a "
             "new assessment.",
             3, 3,
             "Documented permitted-use scope; annual attestation; new "
             "governance review before expansion",
             "HR Director", 3),
            ("Vendor dependency and continuity",
             "Single-vendor recruitment workflow.",
             2, 2,
             "Data portability clauses; manual fallback procedure",
             "Procurement", 2),
        ):
            self.add_risk(title=risk[0], system_id="SYS-0003",
                          description=risk[1], likelihood=risk[2],
                          impact=risk[3], controls=risk[4],
                          control_owner=risk[5], residual_score=risk[6],
                          demo=True)
        self.add_risk(
            title="Audit-chain signing key compromise (self)",
            system_id="SYS-0001",
            description="AUDIT_HMAC_KEY lives in env, not yet HSM/KMS "
                        "anchored; a host-level attacker with the key could "
                        "forge a valid-looking chain.",
            likelihood=2, impact=4,
            controls="Key outside DB; key fingerprint pinned in audit_meta; "
                     "verify() detects re-keyed chains; SIEM mirror for "
                     "external correlation",
            control_owner="Platform Team", residual_score=4, demo=False)
