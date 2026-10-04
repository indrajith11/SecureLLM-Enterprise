# Product Roadmap — feature inventory, research & hardening log

This document is the engineering research log behind v3.1. Every feature of
the product was inventoried, researched from a security engineer's point of
view (CIA triad first, then OWASP LLM Top 10, NIST AI RMF, and operational
hygiene), and improved in priority order: **security first, then harness,
then speed, then user experience**.

Status legend: ✅ shipped in v3.1 · 🔜 designed, next iteration · 💡 research

## 1. Feature inventory & research summary

| # | Feature | Research findings (gap analysis) | Improvements | Status |
|---|---|---|---|---|
| F1 | L2b Input firewall (rules) | 24 regexes recompiled per request; no Unicode normalisation (homoglyphs/zero-width evaded matching); no payload-splitting defence; missing delimiter-injection, tool-abuse and translation-extraction families; no per-rule observability | Ruleset **v2**: NFKC + zero-width + homoglyph-fold normalisation; payload-splitting check on the compacted stream; 3 new attack families; precompiled patterns; per-family Prometheus counter; ruleset version surfaced in trace/`/health` | ✅ |
| F2 | L1 Identity & auth | No brute-force protection (unlimited password guesses); no logout (stolen JWT valid 60 min); no browser hardening headers; no password policy | Brute-force lockout (5 fails/15 min → 5-min lock, audited); `/api/logout` with JTI revocation; CSP/X-Frame/nosniff/Referrer-Policy on every response; password-policy helper for provisioning | ✅ |
| F3 | CIA-Availability | Per-user rate + session caps existed, but no payload size cap (a 10 MB prompt still costs parsing/memory), no whole-system concurrency limit, 429s lacked `Retry-After` | 4,000-char prompt cap (audited `L2-size`); global 8-chat semaphore gate (`L2-load`, 503 + CIA-A); `Retry-After` on 429/503 | ✅ |
| F4 | L6 Output DLP | Money/email/phone/card shapes only; card check was shape-only; no cloud-key/JWT/private-key detection; no India-specific government-ID shapes (DPDP Act context) | Secret-shape family for every role: AWS `AKIA…`, JWTs, private-key blocks, Aadhaar, PAN; existing shapes retained | ✅ |
| F5 | L4/RAG context handling | Namespace isolation strong, but retrieved documents reached the model unfenced — nothing at prompt level marked them as untrusted (pure reliance on L6 assume-breach) | **Context fencing**: `UNTRUSTED DOCUMENT […] BEGIN/END` fences + system-prompt instruction-hierarchy rule ("data, never instructions") — OWASP LLM01 indirect-injection mitigation *before* the L6 residue check; poison demo unchanged (L6 still catches the echo) | ✅ |
| F6 | L3.5 Agency gate | 11 patterns missed privilege escalation ("grant me admin"), mass-wipe verbs ("purge the payroll database") and DB-dump asks | 4 new families in config (auditable) + defaults; all become pending HITL approvals | ✅ |
| F7 | Red-team harness | Hardcoded "8 categories" (stale); no per-category report; no latency evidence; no CI mode; corpus lacked the new attack families | Harness **v2**: 84 probes / 22 categories; per-category stop-layer table; per-probe latency → p50/p95 in report; `--gate` CI mode (exit 1 on any leak); corpus md5 + ruleset version stamped into evidence | ✅ |
| F8 | Performance (speed) | Regex recompilation per request; default-journal SQLite; no query-embedding cache; unbounded Ollama generation | Precompiled regexes; WAL + indexes on audit(user_id, ts), audit(action), pending_actions(status); bounded query-embedding LRU (256); Ollama `num_predict` cap. **Measured: p50 2 ms, p95 7 ms end-to-end (secured, full corpus)** | ✅ |
| F9 | Chat UX | Plain input+list; no feedback while waiting; trace chips always-on (visual noise); logout only cleared the client | ChatGPT-style: bubbles + timestamps + live latency badge, typing indicator, attack suggestion chips, collapsible governance trace `<details>`, Enter-to-send + auto-grow textarea, Sign-out calls the real revocation API | ✅ |
| F10 | Two databases (company.db + executives.db) | Both governed by L3/L4 policy; health reports both row counts | Verified access paths; indexes + WAL on the audit store; executives.db stays read-only (mode=ro) — no change needed | ✅ |
| F11 | L7 Audit chain | SHA-256 hash chain + JSONL mirror solid; trail reads full-scanned under load | Hot-path indexes + WAL (F8) | ✅ |
| F12 | Observability | Layer-level counters existed | Added `ai_input_rule_hits_total{category}` (WAF-style attribution) and `ai_auth_events_total{login\|denied\|locked\|logout}` | ✅ |
| F13 (v4.9.0) | Governance transparency & compliance plane | AIGovernance-benchmark gap analysis: runtime enforcement was complete, but the artefact layer auditors ask for (system inventory + EU AI Act classification, scored risk register, AI incident ledger, RMF maturity, conformity pack) lived in prose docs; regulatory research refreshed (Digital Omnibus May-2026 delay proposal, GPAI enforcement Aug-2026, Art.19 log retention) | `src/governance/compliance.py` + `db/compliance.db`: deterministic EU AI Act classifier (Art.5 registrations refused 403), L×I risk register with validated residual math, incident ledger with severity SLAs + state machine mirrored into the L7 HMAC chain, live-evidence RMF maturity scorer + Art. 9–17 conformity pack generator, `/compliance.html` Admin console, 23 proving tests (suite 489) | ✅ |

## 2. Why these priorities (security-engineer reasoning)

1. **CIA triad coverage gaps came first.** Confidentiality was strong (clearance
   + department isolation + DLP) but the *input plane* could be evaded with
   homoglyphs (C-flagged data reachable by obfuscated asks) and *integrity*
   missed privilege-escalation asks — both are direct triad violations, so
   S1 + S6 led the queue.
2. **Authentication is the root of every per-user control.** A pipeline that
   enforces CIA per user is only as strong as its weakest identity control,
   so brute-force lockout and token revocation preceded availability work.
3. **Assume-breach needs both ends of the pipe.** The L6 residue check already
   assumed L4 would be fooled; S5 adds the *preventive* instruction-hierarchy
   control so defence does not rest on detection alone.
4. **The harness is a security feature.** Numbers that cannot be regenerated,
   attributed per category, and gated in CI are claims, not controls — S7
   turned the measurement methodology itself into product.
5. **Speed is availability.** p50 2 ms / p95 7 ms with all layers active is
   the evidence that governance does not cost operability (CIA-A).

## 3. Designed next (researched, not yet built)

| Candidate | Research notes | Status |
|---|---|---|
| Semantic injection classifier (fine-tuned distilbert) behind the deterministic ruleset | Keep the v2 rules as the fast+auditable first stage; route only medium-score prompts (3–6) to the classifier; same `InputVerdict` interface | 🔜 |
| Redis-backed session registry & lockout store | Same interfaces (`login_lockout`, `SessionRegistry`); multi-node ready; TTL semantics preserved | 🔜 |
| SSE token streaming for the Ollama backend | ChatGPT-style streaming; L6 requires full-buffer scan, so stream with hold-back tail + final full-buffer verdict before the last chunk | 🔜 |
| ONNX local embeddings (bge-small) with FAISS | Replaces hashing embeddings; poison demo re-run to prove L6 still catches the echo; retrieval quality uplift for the 33-doc corpus | 🔜 |
| OIDC/SSO + MFA via identity provider | Replaces seeded local accounts in production mode; SCIM provisioning; per-role claims mapping | 🔜 |
| Shadow-AI detector (AI-SPM plane) | Egress-log scan for unauthorised LLM endpoints (OpenAI/Anthropic/gemini egress fingerprints) + shadow-tool inventory report | 💡 |
| Agentic tool-use sandbox (MCP-style) | Extends L3.5 with scoped tool grants, per-tool budgets, and reversible-action ledger | 💡 |
| Multi-tenant namespace encryption | Per-namespace envelope encryption so storage-level access cannot read cross-tenant documents | 💡 |
| Adversarial training loop | Replay confirmed attack prompts from the audit chain into probe corpus per release; corpus growth becomes automatic | 💡 |

## 4. Regression evidence for v3.1

- Test suite: **184 passed** (137 legacy + 47 new across 5 new test files)
- Probe harness: **0/84 secured leaks** vs **30/30 baseline subset leaks**
- Latency (secured, end-to-end): **p50 2 ms / p95 7 ms**
- CI gate: `python -m scripts.probe_runner --gate` → **GATE PASSED**
- New layer attribution: L2 44 (+1 size), CIA-C 20, L6 13, L3+L4 4, L3.5 2
