"""DPDPA (India) compliance module - Digital Personal Data Protection
Act 2023 + DPDP Rules 2025.

Maps the running SecureLLM-Enterprise controls to the DPDPA obligations a
Data Fiduciary must meet, with honest status per duty. The demo corpus is
synthetic, but the enforcement surfaces are real: L6 output DLP redacts
PII shapes at runtime, the incident ledger drives breach notification, and
the audit chain provides accountability evidence.

Statutory references (verified Oct 2026):
  - DPDP Act 2023 (No. 22 of 2023, assented 11 Aug 2023) - meity.gov.in
    ss. 4 (purpose limitation), 5 (ground of consent), 6 (consent
    manager-free consent), 8 (duties of Data Fiduciary incl. security
    safeguards s.8(5)), 9 (children), 10 (significant fiduciaries),
    13 (right to erasure), 14 (right to correction/completion),
    17 (rights to information), 18 (redressal of grievances).
  - DPDP Rules 2025 (notified 14 Nov 2025) - Rule 7: personal-data breach
    intimation to the Data Protection Board without delay AND a detailed
    report within 72 hours; affected Data Principals informed without
    delay. Enforcement horizon: obligations phased in over ~18 months
    from notification (industry guidance: ~May 2027 full effect).

Statuses mirror the ISO SoA module: implemented / partial / planned /
not-applicable, each tied to a live control or an honest gap.
"""
from __future__ import annotations

from typing import Any

OBLIGATIONS = [
    {
        "id": "consent",
        "title": "Lawful ground: consent + notice",
        "ref": "DPDP Act ss. 5, 6; Rules 2025 r.3-5",
        "status": "partial",
        "control": ("Login-bound sessions with explicit role/clearance "
                    "grant = granular, purpose-scoped access request; "
                    "denial engine states exactly what the principal may "
                    "see (notice-in-action)."),
        "gap": ("No standalone consent-artifact registry (consent strings, "
                "versioning, withdrawal ledger) - designed in "
                "dpdp_compliance schema notes; roadmap F-item."),
    },
    {
        "id": "purpose_limitation",
        "title": "Purpose limitation & data minimisation",
        "ref": "DPDP Act s. 4, s. 8(1); Rules 2025 r.6",
        "status": "implemented",
        "control": ("Purpose-tagged namespaces (hr_docs, finance_docs, "
                    "exec_docs...); per-field denial engine; employees PII "
                    "(Aadhaar/PAN class) structurally OUTSIDE the model "
                    "catalog; L4 retrieval scoped to role allowlists."),
        "gap": (""),
    },
    {
        "id": "security_safeguards",
        "title": "Reasonable security safeguards",
        "ref": "DPDP Act s. 8(5); Rules 2025 r.6 (log retention >= 1 yr "
               "for breach traces)",
        "status": "implemented",
        "control": ("7-layer pipeline (L1-L7): input WAF, RBAC+CIA, HITL, "
                    "output DLP, HMAC audit chain (tamper-evident, "
                    "online-verifiable); rate limiting + concurrency "
                    "gates; fail-closed kill switch."),
        "gap": ("Key custody is config/env, not HSM - recorded as a real "
                "self-risk in the register (inherent 8 -> residual 4)."),
    },
    {
        "id": "breach_notification",
        "title": "Breach notification: DPB + data principals",
        "ref": "DPDP Rules 2025, Rule 7 (72h detailed report to DPB; "
               "principals without delay)",
        "status": "implemented",
        "control": ("Incident ledger (db/compliance.db): S1 severity "
                    "escalates to committee <= 24h / board <= 48h with "
                    "state machine open->investigating->contained->"
                    "remediated->closed; every transition written to the "
                    "HMAC audit chain. SLA clock <= Rule 7's 72h."),
        "gap": ("Automated DPB e-filing integration is out of demo scope; "
                "the runbook + ledger evidence is the deliverable."),
    },
    {
        "id": "data_principal_rights",
        "title": "Data principal rights: erasure, correction, access",
        "ref": "DPDP Act ss. 13, 14, 17, 18",
        "status": "partial",
        "control": ("Self-scope grant (RBAC 2.0) = per-principal access "
                    "view; /api/me/password + user admin lifecycle; "
                    "vector index rebuild gives a clean-erase path for "
                    "indexed content."),
        "gap": ("No self-service rights-request queue with SLA tracking - "
                "the incident ledger is the interim vehicle."),
    },
    {
        "id": "children_data",
        "title": "Children's data (no tracking/behavioural ads)",
        "ref": "DPDP Act s. 9; Rules 2025 r.10",
        "status": "not-applicable",
        "control": ("Synthetic adult-only demo corpus; no age-unknown "
                    "processing, no ad-tech surfaces."),
        "gap": (""),
    },
    {
        "id": "cross_border",
        "title": "Cross-border transfer restrictions",
        "ref": "DPDP Act s. 16; Rules 2025 r.15",
        "status": "implemented",
        "control": ("Local-only deployment by design: Ollama local "
                    "inference, local SQLite/vector store - no personal "
                    "data leaves the host."),
        "gap": (""),
    },
    {
        "id": "grievance_redressal",
        "title": "Grievance redressal machinery",
        "ref": "DPDP Act s. 18; Rules 2025 r.12",
        "status": "partial",
        "control": ("/api/audit/me gives the principal their own request "
                    "trail; telegram bridge provides human contact "
                    "channel; review queue holds blocked items for human "
                    "release."),
        "gap": ("A dedicated grievance endpoint with response SLA is a "
                "roadmap item."),
    },
    {
        "id": "accountability",
        "title": "Accountability & audit evidence",
        "ref": "DPDP Act s. 8; Rules 2025 r.6",
        "status": "implemented",
        "control": ("L7 HMAC-chained audit (verify endpoint), audit_meta "
                    "for compliance actions, incident ledger, compliance "
                    "console snapshot - all queryable in one call."),
        "gap": (""),
    },
]

BREACH_RUNBOOK = {
    "rule": "DPDP Rules 2025, Rule 7",
    "steps": [
        {"t": "T+0", "action": "Incident declared in ledger (severity "
                               "S1/S2, SLA clock starts)"},
        {"t": "without delay", "action": "Intimation to Data Protection "
                                         "Board of India + affected data "
                                         "principals (fact, nature, "
                                         "contact)"},
        {"t": "<= 24h", "action": "S1: governance committee review; "
                                  "containment actions recorded as "
                                  "transitions"},
        {"t": "<= 48h", "action": "Board/executive escalation per "
                                  "SEVERITY_ESCALATION"},
        {"t": "<= 72h", "action": "Detailed report to DPB: scope, affected "
                                  "principals, root cause, remediation "
                                  "(ledger + audit chain export as "
                                  "evidence)"},
        {"t": "closure", "action": "State machine -> remediated -> closed; "
                                   "RCA appended to chain"},
    ],
    "evidence_links": ["/admin/compliance/incidents",
                       "/admin/audit/verify",
                       "db/compliance.db incidents table"],
}


def dpdp_status(ev: dict[str, Any]) -> dict[str, Any]:
    """Render the DPDPA obligation map from live evidence."""
    out = []
    for ob in OBLIGATIONS:
        row = dict(ob)
        if ob["id"] == "security_safeguards":
            row["live"] = {"chain_valid": ev.get("chain_valid"),
                           "hitl_depth": ev.get("hitl_depth"),
                           "retention_days": ev.get("retention_days")}
        if ob["id"] == "breach_notification":
            row["runbook"] = BREACH_RUNBOOK
        out.append(row)
    by_status: dict[str, int] = {}
    for row in out:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
    return {
        "law": "Digital Personal Data Protection Act 2023 + DPDP Rules 2025",
        "source_url": "https://www.meity.gov.in/data-protection-framework",
        "breach_sla": "Rule 7: DPB detailed report within 72h; principals "
                      "without delay",
        "enforcement_note": ("Rules notified 14 Nov 2025; obligations phase "
                             "in over ~18 months (~May 2027)."),
        "obligations": out,
        "status_summary": by_status,
        "note": ("Self-assessment. The demo corpus is synthetic; statuses "
                 "describe the enforcement surfaces a fiduciary deployment "
                 "would inherit from this codebase."),
    }
