# DPDP Act 2023 (India) — Compliance Mapping

**Status: engineering self-assessment, not legal advice.** India's Digital Personal Data Protection Act, 2023 (DPDPA) regulates processing of digital personal data; the DPDP Rules, 2025 operationalise it. This document maps the Act's duties to the project's running controls. Named in the EY JD — India-specific compliance is a first-class concern here: the output DLP already recognises **Aadhaar, PAN and +91 mobile shapes**, and the audit chain is designed as **CERT-In-ready tamper-evident evidence**.

---

## The eight duty areas → running controls

| # | DPDPA duty (Act / Rules) | Project control | Layer | Evidence |
|---|---|---|---|---|
| 1 | **Lawful grounds & consent** (Sec 4, 6) — free, specific, informed, unambiguous consent; or legitimate uses | No web-scraped data: the corpus is a **synthetic enterprise dataset** generated in-repo (`scripts/generate_enterprise_data.py`); 13 seeded users authenticate before any query — processing ground is demonstrable at request level via JWT claims | L1 | `test_login.py`; dataset script is the provenance record |
| 2 | **Purpose limitation** (Sec 5(2), 6(7)) — use only for the stated purpose | Intent router separates company-data QA from general chat; role-scoped retrieval restricts every query to the department's declared purpose; requests carry `action_type` | L3, L4 | `test_intent_router.py`; `config/rbac_config.yaml` table/namespace scoping |
| 3 | **Data minimisation** (Sec 6(1), 8(1)) — process only what is needed | Retrieval is column-scoped (role → columns whitelist), not document dumps; context budgets cap how much personal data even reaches the model | L4 | `test_rbac.py` (self_scope, row_scope, aggregate whitelists) |
| 4 | **Accuracy of personal data** (Sec 8(4)) | Faithfulness check: every number in an answer must exist (digit-normalised) in retrieved context — the model cannot invent personal data; human-correction path = HITL gate for write-intent asks | L6, L3.5 | probe corpus unit tests; `test_hitl.py` |
| 5 | **Security safeguards** (Sec 8(5)) — reasonable security to prevent breaches | The whole pipeline: bcrypt(12) + pinned-alg JWT, brute-force lockout, RBAC default-deny, 22-family input firewall, output DLP, bounded queues; hash-chained audit detects tampering | L1–L7 | 489/489 tests; 0/84 red-team leaks |
| 6 | **Storage limitation / erasure** (Sec 8(7)) — erase when purpose is done | Retention purge job **with audit-chain re-anchoring** — deletion is enforceable *and* the tamper-evident log survives it correctly | L7 | `test_audit_remediation.py` |
| 7 | **Breach notification** (Sec 8(9); **DPDP Rules 2025 Rule 7**: intimate affected Data Principals without delay + detailed report to the Data Protection Board **within 72 hours**) | Incident ledger with severity SLAs (S1: 24 h committee / 48 h board / regulatory-assessment flag = stricter than the 72 h floor); every incident transition is hash-chained — the timeline the Board sees is tamper-evident | Compliance plane | `POST /admin/compliance/incidents`; `test_compliance.py` SLA tests |
| 8 | **Grievance redressal** (Sec 13) | Every denial carries a `denied_code` + human-readable reason; admin console shows the same evidence the user was refused on — disputes are answerable from the chain | L7, UI | `docs/CIA_Mapping.md`; governance trace |

---

## Data Principal rights (Sec 11–14) → system capability

| Right | What the Act says | How the system serves it |
|---|---|---|
| **Access to information** (Sec 11) | Summary of personal data processed, processing activities, identities of fiduciaries | Per-message governance trace shows which docs/tables were retrieved for *this* user; system card + model manifest name the processing stack |
| **Correction & completion** (Sec 12) | Get inaccurate data corrected | Write-intent requests never execute silently — they become HITL approval requests; an approver executing a correction is audited with requester ≠ approver |
| **Erasure** (Sec 12(c), 8(7)) | Erasure on consent withdrawal or purpose completion | Retention purge with re-anchoring (above); namespace-scoped corpus means deletion targets are narrow and enumerable |
| **Nomination** (Sec 14) | Nominee in case of death/incapacity | Org-level control: executive role model (clearance-inheriting) is the design seam; explicitly listed as a gap below |

---

## Where the Output DLP directly serves DPDPA

The L6 output filter is the Act's "reasonable security safeguard" made concrete at the model boundary:

- **Aadhaar shape** (`XXXX-XXXX-XXXX` 12-digit with Verhoeff-style grouping), **PAN** (`ABCDE1234F`), **+91 mobile**, and lakh/crore currency figures are recognised shapes, redact-before-block with role-aware allow-lists.
- **Cross-authority leakage** (the DPDP worst case: HR salary data reaching a Tech user) is *also* stopped upstream at L3/L4 — DLP is the backstop, not the only wall.
- **Injection-residue check** at L6 prevents indirect prompt injection from tricking the model into disclosing personal data hidden in documents (RAG exfiltration path).

---

## Research note (verified Oct 2026)

Under the DPDP Rules 2025 **Rule 7**: a Data Fiduciary must send an *immediate* intimation of a personal data breach to affected Data Principals, and a *detailed* report to the Data Protection Board of India **within 72 hours** (extended timelines only where the Board directs). Penalties under the Schedule reach **up to ₹250 crore** for failure of security safeguards — which is why the project's S1 severity class (24 h internal committee SLA, regulatory-assessment flag true) is deliberately *stricter* than the statutory floor. Cross-border transfer (Sec 16) is negative-list based; this project is **local-only by design** (no cloud API in the default path), making the transfer question structurally trivial.

## Honest gaps

1. **No consent-artifact store.** Synthetic corpus = no real principals; a production deployment needs consent records keyed to data subjects (the JWT claim plumbing is the seam).
2. **Nomination (Sec 14)** has no UI; design seam noted above.
3. **Grievance workflow** is evidence-first (denied codes + chain), not a ticketing system.
4. **Legal review.** This mapping is engineering work product; EY's advisory practice would treat it as the technical half of a compliance assessment, paired with counsel's legal opinion.
