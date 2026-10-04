# Master Interview Prep — EY AI Security & Governance

**Project**: SecureLLM-Enterprise v5.1.0 · **Positioning**: open reference implementation of AI Security Posture Management (AI-SPM) with a live compliance plane — now covering the OWASP Agentic AI Top 10 (2026) · **Repo**: `github.com/indrajith11/SecureLLM-Enterprise`

---

## The 60-second pitch (memorise this shape: problem → build → proof → frameworks)

> "Enterprises are deploying LLMs — and now autonomous agents — on internal data, and perimeter security can't see the new risk: data leaving *through the model*, hijacked agent goals, and ungovernable tool use. I built the counter-argument — a full governance stack around a small local model, where nothing is claimed that isn't measured. Every request is authenticated as a real user and walks a 7-layer pipeline: identity, consumption guard, a **48-rule WAF registry** covering both the OWASP LLM Top 10 and the new **OWASP Agentic AI Top 10 2026**, per-request CIA-triad enforcement, a human-approval gate for risky actions, scoped retrieval, and output DLP that knows Aadhaar, PAN and card shapes — then every decision lands in an HMAC hash-chained audit log. I fired a **2630-prompt red-team corpus** at it: the same naive model leaks **70.5% of attacks unprotected and 0% with governance on**, backed by 529 tests. The corpus also found three real output-DLP defects on day one — fixed — and the v5.1.0 test battery found a fourth, a latent crash in the streaming revoke path. On top of enforcement sits a **compliance plane**: a live EU AI Act classifier that refuses prohibited systems, a scored risk register, an incident ledger with severity SLAs, an **ISO 42001 Statement of Applicability with all 38 Annex A controls**, a **DPDPA module with the Rule 7 72-hour breach runbook**, and NIST CSF 2.0 + AI RMF maturity computed from running-system evidence. Nine frameworks map to running code with evidence pointers — every source cited — not policy PDFs."

**Rule**: if the interviewer cuts you off at 20 seconds, land this sentence: *"the same model leaks 70% of 2630 attacks unprotected and 0% governed — including the new Agentic AI attacks; everything else is how."*

---

## Numbers you must not fumble

| Number | What it is | Where to show it live |
|---|---|---|
| **70.49% → 0.0%** | Leak rate: baseline vs secured, 2630-attack corpus | `python -m tests.run_attacks --slice all --mode both` |
| **2630 attacks / 28 files** | Red-team corpus: LLM Top 10 = 1130, Agentic = 1000, advanced = 500 | `attacks/` + `manifest.jsonl` (per-attack OWASP+ATLAS metadata) |
| **48 rules / 65 signatures** | Auditable WAF registry, engine↔YAML parity-tested, no dead rules | `config/behavior_rules.yaml` + `pytest tests/test_rules_registry.py` |
| **529/529** | Test suite | CI badge / `pytest -q` |
| **20,000 / 10 min** | Per-session token budget (input + actual output) — the KV-cache exhaustion defense (v5.1.0) | `tests/test_token_budget.py` · exhaust a session and watch the 429 `L2-budget` |
| **400 / 2,000 chars** | Streaming-DLP forced scan window / flush cap — real-time DLP on the SSE token path (v5.1.0) | `tests/test_streaming_dlp.py` · canary never reaches the client |
| **10/10 + 10/10** | OWASP LLM Top 10 AND Agentic AI Top 10 2026 coverage | `python -m tests.run_attacks --slice asi --mode both` |
| **3 defects found by the corpus** | Redaction span-offset, missing SQL-exec block, self-scope email bypass — all fixed in v5.0.0 | `docs/reports/GAP_REPORT.md` + git history |
| **4th defect found by the v5.1.0 test battery** | SSE revoke paths called `.body` on a plain dict — a real mid-stream canary block would have crashed the stream instead of revoking it; fixed via `_deny_sse_body()` | `git log` (v5.1.0) + `tests/test_streaming_dlp.py` |
| **4 tiers** | EU AI Act classifier (Unacceptable/High/Limited/Minimal), 5 Art.5 flags + 12 Annex III categories | `/compliance.html` → register a system |
| **S1 = 24h/48h** | Incident severity SLA; Rule 7 (72h DPB report) runbook | `GET /admin/compliance/dpdp` |
| **1→4** | NIST AI RMF maturity scale, scored from live evidence | `GET /admin/compliance/rmf` |
| **38/38 (31 impl, 6 partial, 1 N/A)** | ISO 42001 Annex A controls in the live SoA | `GET /admin/compliance/iso42001-soa` |
| **6/6 functions (23-subcat subset)** | NIST CSF 2.0 evidence-scored | `GET /admin/compliance/csf` |
| **10 ATLAS techniques** | Mapped corpus-wide in manifest + registry | `docs/research/FRAMEWORK_MAPPINGS.md` |

---

## v5.1.0 talking points — inference economics (the "production depth" round)

These two features exist because an interviewer who runs production AI will push past prompts:

**Q: "What do you understand about LLM inference security?"**
> "Three things. First, production LLMs stream — so output DLP has to be real-time, not batch. My SSE pipeline scans each completed sentence before it is flushed, with a forced scan window so a punctuation-free run can't hide a canary, and the client gets a governed 'revoked' event instead of leaked text. Second, serving engines pin conversation state in the KV-cache — Qwen2.5-0.5B uses GQA, 2 KV heads across 14 query heads, so the cache is small — which is exactly why the DoS is cumulative, not per-request. I built a per-session token budget: 20,000 input+output tokens per rolling 10 minutes, keyed to the JWT session, enforced at admission AND mid-stream. Third, disaggregated serving splits prefill from decode — input governance belongs before prefill, output DLP in the decode token path, the budget must span both planes against one shared window — I documented that mapping in `docs/architecture/DISAGGREGATED_SECURITY.md`."

**Guardrails**: token counts are estimates (chars/4, same estimator as the rate limiter — say "estimated, labelled as such, with a drop-in path to Ollama's exact eval counts"); disaggregated serving is a design note, NOT built — say "documented as future work" if pushed; Qwen config numbers (24 layers, 14:2 GQA, rope_theta 1M, 32K context) are cited from the published config.json in `docs/architecture/LLM_INTERNALS.md`.

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
