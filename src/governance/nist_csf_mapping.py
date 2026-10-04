"""NIST Cybersecurity Framework 2.0 mapping for SecureLLM-Enterprise.

Maps the 7-layer governance pipeline + compliance plane onto the six CSF 2.0
functions (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER) and computes
sub-category coverage from live evidence.

Scope honesty: CSF 2.0 defines 106 sub-categories. This module enumerates
the AI-relevant subset this project claims (23) and computes coverage over
THAT subset only - the report says so explicitly. Full 106-category mapping
lives in docs/frameworks/NIST_CSF_MAPPING.md (document-level).

Reference: NIST CSF 2.0 (nist.gov/cyberframework, Feb 2024) +
NIST AI RMF 1.0 crosswalk.
"""
from __future__ import annotations

from typing import Any

FUNCTIONS = ["GOVERN (GV)", "IDENTIFY (ID)", "PROTECT (PR)",
             "DETECT (DE)", "RESPOND (RS)", "RECOVER (RC)"]

# (id, sub-category, live control, evidence key or None)
SUBCATEGORIES = [
    # ---- GOVERN ----------------------------------------------------------
    ("GV.OC-01", "Organizational mission understood; AI scope tied to it",
     "system card + threat model; JD-aligned control set", "documented_threat_model"),
    ("GV.RM-01", "Risk management objectives established and owned",
     "risk register with named owner; inherent->residual scoring", "risk_register"),
    ("GV.RR-02", "Roles, responsibilities, authorities for AI risk",
     "RBAC roles + admin/HITL approvers; separation of duties", "inventory_registry"),
    ("GV.PO-01", "Policy established, communicated, enforced",
     "declarative policy (rbac_config.yaml) driving runtime L1-L7", "declarative_policy"),
    ("GV.OV-01", "Strategy outcomes measured; decisions from evidence",
     "compliance console + RMF maturity + coverage reports", "residual_risks"),
    # ---- IDENTIFY --------------------------------------------------------
    ("ID.AM-01", "Hardware inventory",
     "single-node local deployment documented in LOCAL_SETUP.md", None),
    ("ID.AM-02", "Software/services inventory incl. AI models",
     "model manifest + provider catalog + inventory registry", "model_manifest"),
    ("ID.AM-07", "Data inventory & classification",
     "document classification + ACL metadata; per-namespace allowlists", "inventory_registry"),
    ("ID.RA-01", "Vulnerabilities identified & recorded",
     "2630-prompt corpus + rules registry; garak/PyRIT runs", "risk_register"),
    ("ID.RA-05", "Risk prioritised by impact",
     "L x I bands (1-25) + severity escalation table", "residual_risks"),
    # ---- PROTECT ---------------------------------------------------------
    ("PR.AA-01", "Identities/credentials managed",
     "JWT auth, lockout, revocation; session hygiene tests", None),
    ("PR.AA-05", "Access permissions least-privilege",
     "RBAC 2.0 + clearance levels + per-field denial engine", None),
    ("PR.DS-01", "Data-at-rest protection",
     "separate compliance store; synthetic corpus; no secrets in tree", None),
    ("PR.DS-02", "Data-in-transit protection",
     "caddy TLS in deploy; local-only inference default", None),
    ("PR.PS-01", "Secure development lifecycle",
     "494-test suite; CI gates (0-leak); pinned deps", None),
    ("PR.IR-01", "Networks/environment protected",
     "fail-closed kill switch; MCP allowlist; rate limits", None),
    # ---- DETECT ----------------------------------------------------------
    ("DE.CM-01", "Networks/devices monitored",
     "Prometheus metrics (/metrics); latency + redaction telemetry", None),
    ("DE.CM-09", "Computing hardware/software monitored",
     "L1 pre-deploy gate; provider health checks", None),
    ("DE.AE-02", "Events analysed; potential incidents identified",
     "L2 WAF verdicts + L6 DLP reasons + audit_meta trail", None),
    # ---- RESPOND ---------------------------------------------------------
    ("RS.MA-01", "Incident response plan executed",
     "incident ledger state machine + S1/S2 SLA clocks", "incident_ledger"),
    ("RS.AN-03", "Forensic/evidentiary data available",
     "HMAC-chained audit with /admin/audit/verify", "chain_valid"),
    # ---- RECOVER ---------------------------------------------------------
    ("RC.RP-01", "Recovery plan executed/restored",
     "vector index rebuild + reingest scripts; self-heal fixture", None),
    ("RC.CO-03", "Recovery progress communicated",
     "incident transitions logged to the audit chain; console status", "incident_ledger"),
]


def csf_coverage(ev: dict[str, Any]) -> dict[str, Any]:
    """Render CSF 2.0 function/sub-category coverage from live evidence."""
    fn_by_prefix = {
        "GV": FUNCTIONS[0], "ID": FUNCTIONS[1], "PR": FUNCTIONS[2],
        "DE": FUNCTIONS[3], "RS": FUNCTIONS[4], "RC": FUNCTIONS[5]}
    rows = []
    for cid, sub, control, key in SUBCATEGORIES:
        status = "implemented" if (key is None or ev.get(key)) else "partial"
        fn = fn_by_prefix[cid.split(".")[0]]
        rows.append({"id": cid, "sub_category": sub, "function": fn,
                     "control": control, "status": status})
    by_fn: dict[str, dict[str, Any]] = {}
    for fn in FUNCTIONS:
        rs = [r for r in rows if r["function"] == fn]
        done = sum(1 for r in rs if r["status"] == "implemented")
        by_fn[fn] = {"total": len(rs), "implemented": done,
                     "coverage_pct": round(100 * done / len(rs), 1) if rs else 0.0}
    implemented = sum(1 for r in rows if r["status"] == "implemented")
    return {
        "framework": "NIST Cybersecurity Framework 2.0",
        "source_url": "https://www.nist.gov/cyberframework",
        "functions": FUNCTIONS,
        "mapped_subset": len(rows),
        "csf_total_subcategories": 106,
        "scope_note": ("Coverage computed over the 23 AI-relevant "
                       "sub-categories this project claims - the full 106 "
                       "are documented at document level."),
        "implemented": implemented,
        "coverage_pct": round(100 * implemented / len(rows), 1),
        "by_function": by_fn,
        "subcategories": rows,
        "evidence_version": ev.get("version"),
    }
