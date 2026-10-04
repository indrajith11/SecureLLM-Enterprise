# ISO/IEC 42001:2023 — AI Management System (AIMS) Mapping

**Status: self-assessed mapping, not a certification.** ISO/IEC 42001 certification requires an accredited external audit; this document maps the project's *existing, running* controls to the standard's clauses and Annex A controls so an auditor (or interviewer) can see concretely where evidence lives. Missing items are listed as gaps, not hidden. Evidence pointers reference code, tests and live endpoints — the project's rule is **no policy PDF that the running system doesn't obey**.

---

## How this project implements an AIMS

ISO 42001 asks an organisation to manage AI systems through a Plan-Do-Check-Act loop with documented roles, impact assessment, lifecycle controls and performance evaluation. SecureLLM-Enterprise implements the same loop at single-system scale:

- **Plan** — declarative policy (`config/rbac_config.yaml`), documented threat model, scored risk register (`/admin/compliance/risks`).
- **Do** — 7-layer runtime pipeline (L1–L7) + compliance plane (inventory, classification, incidents).
- **Check** — 489/489 test suite, 84-attack red-team gate (0/84 leaks), HMAC hash-chain verification, `/metrics`, NIST AI RMF maturity scoring from live evidence.
- **Act** — incident ledger with severity SLAs and state machine, residual-risk register with control owners, roadmap-driven upgrades (`docs/ROADMAP.md`).

---

## Clause-by-clause mapping (Clauses 4–10)

| Clause | Title | Project evidence | Status |
|---|---|---|---|
| 4.1–4.4 | Context of the organisation; AIMS scope | README scope statement; `docs/Threat_Model.md` (7 assets, 12 entry-point threats); single-product scope = the assistant itself | **Covered** |
| 5.1–5.3 | Leadership, policy, roles/authorities | Policy-as-config (YAML) is the authority, not prose; named owners on every risk (`control_owner` field); admin/HR/Tech role model in RBAC | **Covered** |
| 6.1.1–6.1.3 | Risks & opportunities; AI risk assessment; treatment | Scored risk register: likelihood × impact, inherent → residual with validated residual ≤ inherent (`POST /admin/compliance/risks`); 7 seeded risks incl. 1 real self-risk (audit-key not HSM-anchored 8→4) | **Covered** |
| 6.2 | AI objectives | Measured objectives in README: 0/84 leaks, 489/489 tests, chain_valid=true; targets are numeric, not aspirational | **Covered** |
| 6.3 | Change planning | Versioned releases (v4.0→v4.9.0); every governance change lands with tests; audit chain re-anchoring documented for retention purge | **Covered** |
| 7.2–7.3 | Competence, awareness | Demo users with distinct clearance levels; per-user governance trace visible in chat teaches the model of authority | **Partially covered** (no formal training records — single-team project) |
| 7.5 | Documented information | `docs/` tree: Architecture, CIA_Mapping, Threat_Model, SECURITY_FIXES (42-finding register), governance/system_card, frameworks/ (this set) | **Covered** |
| 8.1–8.6 | Operational planning; AI impact assessment; lifecycle; data; third-party | Impact assessment operationalised as EU AI Act classification at registration (5 Art.5 flags + 12 Annex III categories); lifecycle stages tracked via `deployment_status`; third-party = vendor model manifest + demo vendor-risk entries | **Covered** |
| 9.1–9.3 | Monitoring, measurement, internal audit, management review | `/health` + `/metrics`; `/admin/audit/verify` chain verdict; conformity pack generator (`/admin/compliance/conformity-pack`) = repeatable internal-audit evidence; CISO briefing surface | **Covered** |
| 10.1–10.2 | Nonconformity, corrective action | Incident ledger: `open → investigating → contained → remediated → closed` state machine with illegal transitions rejected 422; SECURITY_FIXES.md is a 42-finding corrective-action register | **Covered** |

---

## Annex A control mapping (38 controls in 10 groups)

Legend: **Y** = implemented with testable evidence · **P** = partially implemented · **N** = gap (documented).

| Group | Controls | Project implementation | Status |
|---|---|---|---|
| A.2 Policies, roles & responsibilities (5) | AI policy; governance board; roles; segregation; whistle-blowing | Policy-as-config; risk `control_owner` fields; HITL approver ≠ requester separation (atomic claim); platform-team ownership | 4 Y, 1 P (no board — self-governed) |
| A.3 Internal organisation (4) | AI roles; resource docs; risk framework; supplier review | RBAC YAML; risk framework = L×I with residual validation; supplier items in register (HireFlow demo, vendor dependency risk) | 3 Y, 1 P |
| A.4 Resources for AI systems (4) | Data, tooling, human oversight, budget | Human oversight is strong: L3.5 HITL gate, pending-approval queue, override logging; kill-switch lever (`AI_ENABLED` + kill-switch tests) | 2 Y, 2 P |
| A.5 Assessing impacts (3) | Impact assessment process; documenting; evaluating | Registration-time EU AI Act classification (deterministic, tested); fairness/explanation risks carried in register (proxy discrimination, explainability Art.86) | 2 Y, 1 P |
| A.6 AI system lifecycle (8) | Requirements, design, dev, verification, deployment, change, disposal | 489-test regression suite; red-team gate; visible degradation banners; model hot-reload audited as `MODEL_SELECT`; retention purge with chain re-anchoring | 6 Y, 2 P |
| A.7 Data for AI systems (7) | Training/validation data provenance, PII handling, quality | RAG corpus under governance; namespace isolation per role; poisoned-doc demo + faithfulness check; data provenance carried as register risk (managed, not hidden) | 4 Y, 3 P |
| A.8 Information for interested parties (3) | System description, transparency, communication | `docs/governance/system_card.md`; model manifest; per-answer governance trace; degradation banners (user-visible honesty) | 3 Y |
| A.9 Responsible use of AI (5) | Human oversight, limits, safety, personal data, content labelling | HITL gate; input firewall + output DLP; canary + faithfulness; synthetic-content flag in classifier | 4 Y, 1 P |
| A.10 Third-party & customer relationships (2) | Supplier obligations, customer duties | Vendor risk entries; MCP server/client model: third-party tool consumption would follow same rulebook (pinned, hashed, fenced) | 1 Y, 1 P |

**Annex A self-score: 29 of 38 controls fully evidenced (76%), 9 partial, 0 unaddressed-but-hidden.** Every "P" has a named owner or a documented roadmap item.

---

## Honest gaps

1. **No certification.** This is a self-assessment against the standard's text; ISO 42001 certification requires an accredited body, management review context and multi-site evidence.
2. **Governance board.** A.2's board role is a single platform team; the SEVERITY_ESCALATION table (S1: 24 h committee / 48 h board) shows the *design* for a real board but no committee exists.
3. **Training records.** 7.2 competence is demonstrated by artefacts, not by HR training logs.
4. **Formal impact-assessment template.** Impact assessment is classification-driven (EU AI Act tiers); a full ISO-style impact assessment template per system is future work (tracked in ROADMAP).

*Research note (Oct 2026): ISO 42001 and the emerging AIUC-1 certification scheme map largely 1:1 on control intent; the same evidence pack would serve both audits — already noted in `REGULATORY_NOTES` in `src/governance/compliance.py`.*
