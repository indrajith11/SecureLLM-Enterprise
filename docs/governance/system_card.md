# SecureLLM-Enterprise — System Card

*One page. What the system is, for whom, with which model, within which boundaries. Written for an auditor, a DPO, or a new engineer — the document you read before any other.*

---

## 1. Purpose (why this system exists)

SecureLLM-Enterprise is an **internal, employee-facing AI assistant** that answers questions over two governed company databases (employee records and executive records) plus an internal document corpus. It exists to give staff fast self-service answers ("what is my leave policy", "average salary per department") **without** creating the usual AI failure modes: data leakage across roles, prompt-injection-driven misbehaviour, untraceable decisions, or unaccountable model changes. It is also an **open reference implementation of AI Security Posture Management (AI-SPM)**: every governance control described here exists as runnable code with a proving test, not as a policy PDF.

## 2. Who uses it (and who it deliberately refuses)

- **Users:** internal staff in 13 seeded demo identities across 9 roles (HR, Tech, Finance, Business, Executive, Admin) — RBAC is default-deny: an unmapped role sees zero tables and zero namespaces.
- **Not for:** external customers, public internet traffic, or any user identity that has not been provisioned through the Admin user-management API.
- **Deliberate refusals:** cross-role salary lookups, blocked-field questions, out-of-scope tables, and every high-risk action are refused with an official, policy-citing denial (the Denial Engine) — refusal quality is a product feature.

## 3. Model & data (what brain, what memory)

- **Serving models:** `qwen2.5:0.5b` via Ollama (fast + reasoner slots; the two-model router can point at larger models). Provenance, digests and the change procedure: **`docs/model_manifest.md`**.
- **Retrieval:** FAISS-free in-house vector store over the document corpus; embedder is 256-dim feature hashing by default, `all-MiniLM-L6-v2` opt-in. Retrieved documents are fenced as **"data, never instructions"** (Layer-2b/indirect-injection defence).
- **Structured data:** SQLite `company.db` (employees, documents, users) + `executives.db` (separated store, higher clearance). All model access is SELECT-only, whitelisted, and checked **per call** inside the query runner.

## 4. The governance pipeline (how a request is processed)

Every request passes 7 layers — no code path skips them (sync and SSE share one pipeline):

| Layer | Control |
|---|---|
| L1 | AuthN: bcrypt (cost 12), JWT HS256 with `rv` role-version claim, JTI revocation, lockout, timing equalization |
| L2 | Rate limits + token budgets, per-user concurrency cap, bounded queue, payload cap, prompt-injection firewall (22 rule families, homoglyph/payload-split normalization) |
| CIA-C / I | Per-user confidentiality & integrity enforcement on intent + retrieved docs |
| L3.5 | Agency gate: high-risk actions require HITL approval (requester ≠ approver, atomic claim, expiry) |
| L3 | RBAC: table/column/row allowlists, self-scope & aggregate whitelists, read-only SQLite |
| L4 | Retrieval: clearance-filtered, entity-aware, context-budgeted |
| L5 | Model inference with intent routing, retry-before-fallback, **visible** degradation banner |
| L6 | Output DLP: canary, secret-shape, Aadhaar/PAN/±91/lakh-crore detection, redact-before-block, faithfulness |
| L7 | HMAC-SHA256 hash-chained audit log (covers prompt, context, response **and model identity**) + rotated JSONL SIEM mirror |

## 5. Boundaries (what this system must never do)

- Never execute writes against company data (read-only connections; writes exist only as human-approved HITL actions).
- Never reveal another user's self-scoped fields (salary, email) — enforced in SQL with bound parameters, not by prompt hoping.
- Never let retrieved or model text become instructions (fencing + L2b families + L6 injection-residue checks).
- Never degrade silently (fallback model ⇒ visible banner + `degraded` flag + audit meta).
- Never run without the hash chain verifiable (key change on a populated chain fails closed).

## 6. Risk classification (EU AI Act / DPDPA posture)

- **EU AI Act:** *limited-risk* internal system (transparency duty). Users see they are talking to an AI (login notice + degraded banners); no CE-marking obligations apply as it does not fall under high-risk Annex III employment-decision use — the system **informs**, it does not decide. Reasoning documented here; revisit if outputs begin feeding automated personnel decisions.
- **DPDPA (India):** processing purpose is employment-context self-service; data is employer-held HR data with role-based least privilege as the consent-equivalent control; erasure requests map to the user-admin disable/delete flow + audit retention (`audit.retention_days`). Retention purposes per data type: prompts+responses (audit integrity — retention window), audit chain (evidence — window + JSONL rotation), vectors (derived from documents — rebuilt, not independently personal).

## 7. Evidence map (prove it, don't claim it)

| Claim | Proof |
|---|---|
| 278 tests green | `pytest tests/` |
| 0/84 prompt-injection & exfiltration leaks (30/30 on the unprotected baseline) | `python -m scripts.probe_runner --gate` |
| Tamper-evident log | `GET /admin/audit/verify`, `tests/test_audit_meta.py` |
| Runtime controls | `/metrics` (Prometheus), `/admin/posture` (Admin), `AI_ENABLED` kill switch |
| Finding-by-finding remediation register | `docs/SECURITY_FIXES.md` (42 findings) |
| Incident response | `docs/governance/incident_response.md` |
| Weights provenance | `docs/model_manifest.md` |
| Pre-deploy red-team record | `docs/redteam_predeploy.md` |
