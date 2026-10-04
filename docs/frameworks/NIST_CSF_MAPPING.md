# NIST Cybersecurity Framework (CSF) 2.0 — Mapping

**Status: self-assessed mapping.** CSF 2.0 organises cybersecurity outcomes into six functions — **GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER** — with GOVERN elevated to a full function in the 2.0 revision (Feb 2024). EY's JD names NIST CSF alongside the AI RMF; this document shows the same 7-layer pipeline satisfies both, because governance and security are the same control plane here. Category-level mapping below uses CSF 2.0's function/category codes.

---

## Function-by-function mapping

| Function | CSF categories with evidence | Status |
|---|---|---|
| **GOVERN (GV)** — the 2.0 headline function | *GV.OC* organisational context: threat model + scope in `docs/Threat_Model.md`. *GV.RM* risk strategy: scored register (L×I, inherent→residual, residual ≤ inherent enforced by API). *GV.RR* roles: `control_owner` on every risk; approver ≠ requester in HITL. *GV.PO* policy: declarative `config/rbac_config.yaml` — policy auditable without reading code. *GV.OV* oversight: compliance console + RMF maturity bars. *GV.SC* supply chain: vendor manifest, pinned model catalog, MCP tool-pinning design | **6/6 categories** |
| **IDENTIFY (ID)** | *ID.AM* asset management: live **AI system inventory** (`/admin/compliance/inventory`, auto-classified EU AI Act tier) + model catalog with live scoring. *ID.RA* risk assessment: 7-risk seeded register incl. one honest self-risk (audit-key not HSM-anchored). *ID.IM* improvement: 42-finding register in `docs/SECURITY_FIXES.md`; incident RCA timeline fields | **3/3 categories** |
| **PROTECT (PR)** | *PR.AA* access control: bcrypt(12) + JWT (pinned alg, 60-min, `rv` role-version revocation), JTI logout revocation, RBAC default-deny, clearance + department isolation. *PR.AT* awareness: per-user governance trace explains every decision. *PR.DS* data security: namespace/column scoping, UNTRUSTED-document fencing, output DLP (Aadhaar/PAN/+91/cards/canary). *PR.PS* platform security: no DB write path (read-only user, SELECT whitelist, bound params), kill-switch lever. *PR.IR* infrastructure: bounded global queue, concurrency caps, `Retry-After` | **5/5 categories** |
| **DETECT (DE)** | *DE.CM* continuous monitoring: `/health` + Prometheus `/metrics`; every request mirrored to rotated JSONL SIEM feed; per-message layer telemetry. *DE.AE* anomalies: rate limiter flags floods (429 with budgets), lockout counters, oversize-payload rejection; probe gate in CI (84 attacks, md5-stamped corpus) catches defensive drift. *DE.DP* processes: chain verification endpoint (`/admin/audit/verify` → `chain_valid`) is a standing detection control, not a one-off | **3/3 categories** |
| **RESPOND (RS)** | *RS.MA* incident management: incident ledger with severity S1–S4 SLAs (S1: 24 h committee / 48 h board / regulatory-assessment flag), state machine `open → investigating → contained → remediated → closed` (illegal transitions 422). *RS.AN* analysis: full timeline capture per incident; every transition hash-chained. *RS.CO* communication: admin-only console + runbook in `docs/governance/`; SLA clock visible in UI. *RS.MI* mitigation: the pipeline itself denies at 10 defence points; denied events are first-class audit records | **4/4 categories** |
| **RECOVER (RC)** | *RC.RP* recovery: graceful provider fallback with **visible** degradation banner (honesty about reduced posture); first-boot auto-rebuild of audit chain (empty chain on fresh clone). *RC.CO* communication: degradation banner is user-facing recovery comms; audit JSONL mirror survives purges for post-incident reconstruction | **2/2 categories** |

**CSF 2.0 self-score: 23/23 categories touched, with GOVERN — the function most orgs skip — being this project's strongest.**

---

## The twist worth saying out loud in an interview

Most engineering projects map badly to CSF 2.0 because GOVERN requires organisational artefacts (policy, oversight, roles) that engineers never build. This project approaches the framework from the *governance side first* — the compliance plane (inventory, classification, risk register, incident ledger, RMF maturity scoring) is GOVERN/IDENTIFY/RESPOND implemented as code — and then wraps it in the classical PROTECT/DETECT engineering. The result reads naturally to both an auditor (evidence pointers) and an engineer (endpoints, tests).

---

## Honest gaps

1. **Multi-node detection.** Rate limiting, lockout and sessions are in-process; CSF's DE.CM at enterprise scale assumes a central SIEM — the JSONL mirror is the seam, Redis is the documented upgrade.
2. **RC.CO at org scale.** Recovery communications are a banner + logs, not a comms plan with stakeholders.
3. **No SOC integration.** `/metrics` is exposed but no production alerting rules (Alertmanager thresholds) are shipped as config.
