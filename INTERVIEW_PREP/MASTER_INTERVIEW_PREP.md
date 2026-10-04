# Master Interview Prep — EY AI Security & Governance

**Project**: SecureLLM-Enterprise v4.9.0 · **Positioning**: open reference implementation of AI Security Posture Management (AI-SPM) with a live compliance plane · **Repo**: `github.com/indrajith11/SecureLLM-Enterprise`

---

## The 60-second pitch (memorise this shape: problem → build → proof → frameworks)

> "Enterprises are deploying LLMs on internal data, and perimeter security can't see the new risk: data leaving *through the model*, unaccountable actions, and ungovernable operations. I built the counter-argument — a full governance stack around a small local model, where nothing is claimed that isn't measured. Every request is authenticated as a real user and walks a 7-layer pipeline: identity, consumption guard, a 22-family input firewall, per-request CIA-triad enforcement, a human-approval gate for risky actions, RBAC policy, scoped retrieval, model serving with visible degradation, and output DLP that knows Aadhaar, PAN and card shapes — then every decision lands in an HMAC hash-chained audit log. The same model on the same data leaks **100% of 84 red-team attacks unprotected and 0 of 84 with governance on** — 489 tests back it. On top of the enforcement sits a **compliance plane**: a live EU AI Act classifier that refuses prohibited systems at registration, a scored risk register with inherent-to-residual scoring, an incident ledger with severity SLAs, and NIST AI RMF maturity computed from running-system evidence. All eight frameworks the role demands — EU AI Act, NIST AI RMF, ISO 42001, DPDPA, NIST CSF 2.0, 800-53, MITRE ATLAS, OWASP LLM Top 10 — map to running code with evidence pointers, not policy PDFs."

**Rule**: if the interviewer cuts you off at 20 seconds, land this sentence: *"the same model leaks 100% unprotected and 0% governed — everything else is how."*

---

## Numbers you must not fumble

| Number | What it is | Where to show it live |
|---|---|---|
| **0/84 vs 100%** | Red-team leak rate secured vs baseline | `python scripts/probe_runner.py` report |
| **489/489** | Test suite | CI badge / `pytest -q` |
| **22 families / 84 attacks** | Input-firewall rule families / corpus size, md5-stamped | `tests/probes/jailbreaks.json` |
| **114 + 67** | Live red-team probes + E2E checks on real Ollama | README evidence row |
| **4 tiers** | EU AI Act classifier (Unacceptable/High/Limited/Minimal), 5 Art.5 flags + 12 Annex III categories | `/compliance.html` → register a system |
| **S1 = 24h/48h + regulatory flag** | Incident severity SLA (committee/board/reg-assessment) | `/compliance.html` → declare incident |
| **1→4** | NIST AI RMF maturity scale, scored from live evidence | `GET /admin/compliance/rmf` |
| **29/38** | ISO 42001 Annex A controls fully evidenced | `docs/frameworks/ISO_42001_MAPPING.md` |
| **34 controls** | NIST 800-53 across AC/AU/SI/RA | `docs/frameworks/NIST_800_53_MAPPING.md` |
| **16/18** | MITRE ATLAS techniques addressed (14 probe-backed) | `docs/frameworks/MITRE_ATLAS_COVERAGE.md` |

---

## 20 questions with answers that show depth

**1. Walk me through what happens when a request arrives.**
JWT is validated (pinned alg, 60-min, role-version claim) → L2a consumption guard (token budgets, concurrency 2, global queue 8, 4,000-char cap) → L2b input firewall (NFKC, homoglyph folding, zero-width strip, 22 families + heuristic score) → CIA checks on intent (clearance + department) → risky `action_type` diverts to HITL → RBAC builds a read-only scoped SELECT / namespace-scoped RAG → model router picks fast vs reasoner → L6 output DLP + canary + faithfulness + injection-residue → L7 writes prompt, context, response *and model identity* into the HMAC chain. One code path — no layer can be skipped by a different entry point.

**2. How do you know it actually works?**
Measured, not claimed: probe_runner runs 84 attacks across 22 categories with an md5-stamped corpus — baseline 100% leak, secured 0/84, with per-layer stop attribution. 489 unit/E2E tests. 67 live checks + 114 probes against real Ollama on a real model.

**3. What's the hardest attack class?**
Indirect injection through RAG content. The doc is untrusted, the user never typed anything malicious. Defence in depth: UNTRUSTED fencing at L4, then the L6 residue check assumes L4 will eventually be fooled — and the poisoned-doc demo shows retrieval ranking *is* attackable, which is exactly why L6 exists.

**4. Why HMAC chain instead of just append-only logs?**
Append-only is a promise; the chain is a proof. Each record's HMAC covers its content + the previous hash, so tampering breaks verification (`/admin/audit/verify` → `chain_valid`), re-keying is caught by a pinned key fingerprint, and the retention purge re-anchors the chain instead of quietly truncating history.

**5. What does the compliance plane add that the pipeline doesn't already do?**
The pipeline *enforces*; the plane *proves*. Inventory + classification answers "what AI do we run and what obligations attach"; the risk register gives inherent→residual with residual ≤ inherent validated at the API; the incident ledger gives SLAs and a state machine that 422s illegal transitions; RMF maturity is scored from live flags — missing evidence is a gap, not a rhetorical flourish.

**6. What happens if someone registers a prohibited AI system?**
Registration flags like `social_scoring` or `realtime_biometric_id` map to Art.5 — the API refuses with **403** and nothing is written. Tested.

**7. Why a small local model? Isn't this easier with a frontier API?**
Small local = full control of the stack, zero data egress (DPDPA cross-border becomes structurally trivial), reproducible measurements, and it makes the point that *governance, not model size, is the security variable*. The colibri adapter (OpenAI-compatible) proves the seam scales to frontier models — the pipeline doesn't care.

**8. How does DPDPA map onto engineering?**
Purpose limitation = role-scoped retrieval; minimisation = column whitelists; erasure = retention purge with chain re-anchoring; breach duty = incident ledger whose S1 SLA (24h) beats Rule 7's 72-hour Board report; safeguards = the pipeline, with the Output DLP literally recognising Aadhaar/PAN/+91 shapes.

**9. What's your biggest honest weakness?**
The audit HMAC key lives in env, not an HSM — it's *in the risk register* with residual 4/25 and controls listed (key fingerprint pinned, re-key detection, SIEM mirror). I'd rather show one real scored self-risk than a register of perfect demo risks.

**10. What would break first at enterprise scale?**
In-process rate limiting/sessions/lockout — single-node constructs. The seam is already clean (interfaces exist); Redis behind them is the documented next step, then vLLM serving for concurrency.

**11. Why is the model picker an audit event?**
Model identity is part of the audit record — "which model answered" matters for incident response and accountability. Hot-reload of a model is a governance action (`MODEL_SELECT`), so it goes through the chain like any other privileged function.

**12. Explain residual ≤ inherent. Why enforce it?**
Controls can't make risk worse. The API rejects a residual score above inherent — a small validation that stops the most common risk-register theatre.

**13. How does the system fail?**
Loudly and visibly. Provider fallback raises a degradation banner; rate limits return bounded 429/503 with `Retry-After`; denials return `denied_code`. No silent fallbacks — silent success is the failure mode that actually kills AI governance.

**14. Prompt injection will never be fully solved. Why bother?**
Because you don't need to solve the model — you need to bound the blast radius. My stack treats the model as untrusted *by design*: no write path, read-only DB user, tools behind human approval, output DLP as backstop. Injection that "succeeds" finds a model with nothing to steal and nothing to press.

**15. What did you take from the AIGovernance portfolio you integrated?**
Its artefact structure — inventory, EU AI Act classification, NIST RMF maturity, scored risks, incident timelines, conformity pack. The difference: those were documents; here they're runnable endpoints with proving tests. A portfolio tells; a compliance plane proves.

**16. How current is your regulatory picture?**
May-2026 Digital Omnibus provisional deal (Annex III high-risk application sliding to Dec 2027) is baked into the classifier's regulatory notes; GPAI enforcement since Aug 2026; deployer log-retention ≥6 months matches our retention config. Classifying-and-documenting now is still the right move — deadlines moved, duties didn't disappear.

**17. Show me an ISO 42001 gap you actually have.**
Governance board — A.2 wants a committee; the S1 escalation table (24h committee / 48h board) shows the design, but it's one platform team today. Also no formal training records. Both named in the mapping doc with a 29/38 Annex A score.

**18. What's in it for a CISO on day one?**
One console: every AI system with its tier, risks with owners and residual scores, incidents with SLA clocks, RMF maturity, and a generated conformity pack with evidence pointers — plus tamper-evident logs that make the incident timeline defensible in front of a regulator.

**19. Why FastAPI/Python and not a security product?**
Because the deliverable is a *reference implementation* — every control readable in code, reproducible on a laptop, forkable by an auditor. A product purchase can't teach an org what least-privilege-for-LLMs looks like; this can.

**20. What next?**
OIDC/SSO + MFA on the identity seam, Redis-backed multi-node guards, Llama Guard 3 behind the detector interface, HSM-anchored audit keys, SBOM/syft + digest pinning — all tracked with owners in the roadmap and risk register.

---

## Demo flow (8 steps, ~6 minutes)

Run `./DEMO_SCRIPT.sh` against a booted server (it prints each step). Order: OWASP coverage report → live attack → compliance console → register system (watch it classify; try Art.5 → 403) → risk register inherent→residual → incident with SLA clock → NIST RMF maturity → baseline-vs-secured table. Full script: `DEMO_SCRIPT.sh` at repo root.

## Before-the-interview checklist

- [ ] Boot: `./setup.sh` (or `python run.py` with venv active) → `/health` green
- [ ] Tunnel: `cloudflared tunnel --url http://localhost:8000` → paste URL into a fresh browser, login as `admin / Admin@123`
- [ ] Print `INTERVIEW_PREP/EY_AI_SECURITY_READINESS.pdf`
- [ ] Screenshots loaded on laptop: `INTERVIEW_PREP/screenshots/`
- [ ] Say the 60-second pitch out loud 20 times; the 0/84-vs-100% line is the landing
