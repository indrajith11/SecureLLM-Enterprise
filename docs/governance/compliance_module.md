# Governance Transparency & Compliance Module (v4.9.0)

*Layer G — the compliance plane that PROVES what L1–L7 enforce. Inspired by
the artefact structure of the [taimurijlal/AIGovernance](https://github.com/taimurijlal/AIGovernance)
portfolio (EU AI Act + NIST AI RMF documentation projects); here every
artefact is generated from live product state instead of hand-written.*

---

## 1. Why this module exists

The runtime pipeline (L1 auth, L2 firewall, L3 RBAC, L3.5 HITL, L4 context,
L5 model, L6 output, L7 audit) **enforces** governance on every request. An
auditor, DPO, or governance committee then asks a second class of question:
*which systems exist, what risk tier are they, which obligations attach,
what are the scored risks, and how were incidents handled?* Before v4.9.0
those answers lived in prose documents. This module turns them into
runnable, queryable, hash-chained state — the same "no policy PDFs" rule
the rest of the product follows.

Four capabilities live in `src/governance/compliance.py` with state in
`db/compliance.db` (a dedicated store — exportable without touching HR
data) and surfaces in the Admin compliance console (`/compliance.html`).

## 2. Capability 1 — AI system inventory + EU AI Act classification engine

`classify_system(purpose_flags, autonomous_decisions, affects_individuals)`
maps a system's purpose onto the EU AI Act's risk tiers, deterministically
(the same input always yields the same classification — defensible before a
regulator):

| Tier | Trigger | Obligations attached |
|---|---|---|
| **Unacceptable** | Art. 5 prohibited-practice flag (social scoring, real-time biometric ID in public spaces, workplace emotion recognition, untargeted face scraping, sensitive biometric categorisation) | No deployment pathway — **registration is refused with 403 `PROHIBITED_PRACTICE`** |
| **High** | Annex III category flag: creditworthiness 5(b), employment screening 4(a), promotion/termination 4(b), insurance pricing 5(c), essential services 5(a), education 3(a), critical infrastructure 2, law enforcement 6, migration 7, justice 8, biometric verification 1, emergency dispatch 5(d) | Art. 9 risk management · Art. 10 data governance · Art. 11 + Annex IV tech docs · Art. 12 logging (≥ 6-month deployer retention, Art. 19) · Art. 13 transparency · Art. 14 human oversight · Art. 15 accuracy/robustness/cybersecurity · Art. 43 conformity assessment · Art. 71 EU database registration · Art. 72 post-market monitoring. Review cycle 180 days |
| **Limited** | Interaction/synthesis flags (chatbot, synthetic content) | Art. 50(1) AI-interaction disclosure; Art. 50(2)/(4) labelling. Review 365 days |
| **Minimal** | Everything else | No AI-Act-specific duties; GDPR/sector rules still apply. Review 365 days |

The inventory ships seeded with three systems: **this product itself**
(self-registered, Limited risk — an honest self-assessment) and the two
**demo-scenario** systems from the AIGovernance benchmark (CreditScore Pro
→ Annex III 5(b), TalentMatch AI → Annex III 4(a)), marked `demo: true`.
Registrations are mirrored into the L7 hash chain (`action=COMPLIANCE`).

## 3. Capability 2 — scored risk register

Methodology matches enterprise AI-governance practice: **Likelihood (1–5) ×
Impact (1–5) = inherent score**, controls drive a **residual score** (which
is validated to be ≤ inherent — controls cannot increase risk), with
standard banding:

| Band | Score |
|---|---|
| Low | 1–6 |
| Medium | 7–14 |
| High | 15–19 |
| Critical | 20–25 |

Seeded with the benchmark's six-scored-risk register (proxy discrimination
16→8, explainability 15→6, human-oversight gap 20→8, data provenance 12→4,
scope creep 9→3, vendor dependency 4→2) **plus one real self-risk**:
the audit-chain signing key is env-based, not HSM/KMS anchored (2×4=8 →
residual 4 with the existing mitigations). Add risks and attach controls
via `POST /admin/compliance/risks` and `.../risks/{id}/controls`.

## 4. Capability 3 — AI incident ledger (hash-chained)

The incident runbook (`docs/governance/incident_response.md`) describes the
*levers*; the ledger records the *events*. Declaring an incident opens an
escalation SLA clock by severity class:

| Severity | Governance committee | Board | Regulatory assessment |
|---|---|---|---|
| 1 — Critical | ≤ 24 h | ≤ 48 h | mandatory |
| 2 — High | ≤ 72 h | ≤ 7 d | mandatory |
| 3 — Medium | ≤ 7 d | — | — |
| 4 — Low | — | — | — |

An explicit state machine prevents fantasy progress:
`open → investigating → contained → remediated → closed`
(`cancelled` from any live state; illegal jumps → 422 `INVALID_TRANSITION`).
**Every declaration and transition is written to the L7 HMAC hash chain**
(`action=INCIDENT`), so incident handling is tamper-evident like every
other governed event. API: `GET/POST /admin/compliance/incidents`,
`POST /admin/compliance/incidents/{id}/transition`.

## 5. Capability 4 — framework evidence endpoints (live, not stale)

- **`GET /admin/compliance/rmf`** — NIST AI RMF maturity per function
  (GOVERN / MAP / MEASURE / MANAGE, 1–4) scored from **live runtime
  evidence** flags: declarative policy-as-config, inventory registry,
  model manifest, threat model, probe gate, metrics endpoint, audit-chain
  validity, HITL gate, kill switch, retention config. Gaps are listed
  explicitly — the scorer never claims what the runtime cannot show.
- **`GET /admin/compliance/conformity-pack`** — EU AI Act **Articles 9–17
  (+26/50/72) conformity self-assessment**, each article with status and
  concrete evidence pointers generated from live state (audit event count,
  chain verdict, HITL queue depth, retention days, test counts).
- **`GET /admin/compliance`** — one-call snapshot (classified inventory,
  tier summary, risk bands, incident summary, RMF maturity, regulatory
  notes).

## 6. Regulatory state baked in (October 2026 research)

The module carries `REGULATORY_NOTES` so console readers see the moving
target honestly:

- **Digital Omnibus (May 2026, provisional deal)**: proposes moving the
  application date of many Annex III high-risk obligations from
  2 Aug 2026 to **2 Dec 2027**. Prohibitions (Feb 2025), GPAI enforcement
  (2 Aug 2026) and transparency duties are unaffected — so classification
  and documentation stay mandatory work, not busywork.
- **GPAI enforcement powers** apply since 2 Aug 2026 (Art. 101 penalties up
  to €15M / 3% worldwide turnover).
- **Deployer log retention** for high-risk systems: ≥ 6 months
  (Art. 12 + Art. 19) — covered by the L7 chain + JSONL mirror
  (default retention 180 days, `audit.retention_days`).
- **NIST AI RMF Critical-Infrastructure profile** concept note (Apr 2026);
  **ISO/IEC 42001** and **AIUC-1** map 1:1 onto this module's artefacts —
  one governance programme evidences all of them simultaneously.

## 7. Threat-model / CIA placement

| Concern | Control | Evidence |
|---|---|---|
| Un-tracked AI deployments (shadow AI) | Inventory + registration gate; Art. 5 registrations refused in code | `test_register_prohibited_system_refused_403` |
| Un-scored, un-owned risk | Risk register with validated residual math | `test_risk_validation_residual_cannot_exceed_inherent` |
| Un-traceable incident handling | Hash-chained incident ledger, state machine | `test_incident_transitions_are_hash_chained` |
| Stale compliance claims | Live-evidence scoring, no hand-written assertions | `test_rmf_maturity_live_scores` |
| Compliance-plane tampering | Dedicated store; writes mirrored into the L7 chain | `test_compliance_db_is_separate_store` |

CIA mapping: **Confidentiality** — Admin-gated endpoints + console; the
compliance DB holds no personal data beyond owner names. **Integrity** —
event-sourced via the L7 chain; risk math validated server-side.
**Availability** — read paths are single-table SELECTs; the plane is
admin-traffic-only and cannot starve the chat pipeline (CIA-A).

## 8. Test & operations quick reference

```bash
pytest tests/test_compliance.py          # 23 proving tests
# full suite: 489 passed (v4.9.0)

# live endpoints (Admin JWT):
GET  /admin/compliance                   # one-call snapshot
GET  /admin/compliance/inventory         # classified inventory
POST /admin/compliance/inventory         # register + auto-classify (403 on Art.5)
GET  /admin/compliance/risks             # scored register
POST /admin/compliance/risks             # add risk
POST /admin/compliance/risks/{id}/controls   # attach controls -> residual
GET  /admin/compliance/incidents         # ledger
POST /admin/compliance/incidents         # declare (opens SLA clock)
POST /admin/compliance/incidents/{id}/transition  # state machine (hash-chained)
GET  /admin/compliance/rmf               # NIST AI RMF maturity
GET  /admin/compliance/conformity-pack   # EU AI Act Art. 9-17 pack
GET  /compliance.html                    # Admin console UI
```

First boot auto-seeds the inventory (self + 2 demo systems) and the risk
register (7 entries); the incident ledger starts **empty** — real ledger.
To reset the plane: stop the stack, delete `db/compliance.db`, restart.
