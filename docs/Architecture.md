# Architecture — the 7-layer request lifecycle

## 1. Request lifecycle (in order, order IS the control)

A `POST /chat` request moves through the layers in a fixed sequence. Every
step appends to a per-request `trace` that is returned to the caller and
logged — including on BLOCKED responses — so governance is observable,
not invisible.

1. **L1 — Identity & Authentication** (`src/governance/auth.py`)
   - `POST /token` checks the SHA-256 password hash and issues a JWT with
     claims `sub`, `role`, `dept`, `iat`, `exp`, `jti` (15-minute expiry).
   - HS256 is **pinned server-side**. A token claiming `alg: none` or a
     downgrade never decodes (tested: `test_alg_none_token_rejected`).
   - The `role` claim is the only input Layer 3 trusts.

2. **L2 — Input Governance** (`input_filter.py`, `rate_limiter.py`)
   - **L2a rate limit:** sliding window per user, two budgets (requests/min
     and estimated tokens/min at ~4 chars/token). Bounded `429` with retry
     window (OWASP LLM10).
   - **L2b LLM firewall:** 40+ regex patterns across 6 categories
     (instruction override, roleplay/DAN, prompt extraction, destructive
     SQL, encoding smuggling). Base64 / hex / ROT13 payloads are decoded
     and re-scanned, so "encode it and it passes" fails. A clean decode of
     a 24+ char blob is itself a block signal.
   - Heuristic score: weighted cues (override verbs, role-play markers,
     fabricated authority, sensitive-data keywords). Deterministic and
     auditable by design; the documented upgrade path is a fine-tuned
     classifier behind the same interface.

3. **L3.5 — Agency Gate / HITL** (`actions.py` + `app_config.yaml -> action_gate`)
   - The chatbot is read-only by construction, but a prompt asking for a
     high-risk ACTION (delete/update/fire/transfer/export...) must never be
     executed — and must not be silently refused either. The gate converts
     it into a **pending action request**: `Action Pending ... waiting for
     approval by ['Executive'] via POST /api/action/confirm/{id}`.
   - Risky-action patterns are declarative config (auditable); approver
     roles enforce segregation of duties (requester ≠ approver).
   - Even an APPROVED action runs through a deliberately read-only
     sandboxed executor — the gate is the product (OWASP LLM03, NIST
     Manage). Every lifecycle step (pending/approved/rejected) is
     hash-chained into L7 and counted in `ai_action_requests_total`.
   - Disabled in baseline mode, like L2 and L6 — honest measurement.

4. **L3 — RBAC Policy Engine** (`rbac.py` + `config/rbac_config.yaml`)
   - Policy is declarative YAML: role -> allowed tables, allowed columns,
     allowed vector namespaces, sensitive-pattern classes.
   - Query construction is whitelist-only: identifiers must exist in the
     YAML/table catalog, values are bound parameters, only SELECT is ever
     emitted, and the SQLite connection is opened with `mode=ro`
     (read-only at the file level — even a bug cannot mutate data).
   - Data minimisation: `employees_tech_view` structurally has no
     salary/email/phone columns for the Tech role.

5. **L4 — Context Retrieval** (`src/rag/retriever.py`)
   - Runs the policy-built SELECTs and namespace-scoped vector search.
     There is **no code path** that searches a namespace outside the
     role's allow-list (OWASP LLM08 mitigation).
   - Intent routing is deterministic (keyword router); a question that
     matches no data intent is answered from documents only — never by
     dumping a table "just in case".

6. **L5 — Model** (`src/model/`)
   - Strict system prompt: answer only from fenced context, scripted
     refusal, and the **canary token `CANARY-7f3a`**.
   - Provider abstraction: `auto -> Ollama qwen2.5:0.5b if reachable,
     else mock`. The mock is deliberately naive (obeys override language)
     so the baseline vulnerability measurement is honest. If Ollama dies
     mid-run, generation degrades to the mock and `GET /health` reports
     `fallback_reason` — availability with honesty.
   - `scripts/check_ollama.py` verifies daemon + model + one governed
     generation before a real-model demo.
   - Container hardening: non-root USER (deploy/Dockerfile), read-only
     rootfs + `cap_drop: ALL` + `no-new-privileges` (docker-compose),
     model weights separated, healthchecks on app and ollama services.

7. **L6 — Output Governance** (`output_filter.py`)
   - Role-aware DLP shapes: salary figures / emails / phones for Tech,
     bonuses for HR, card numbers for all.
   - Canary check: any output containing the canary = prompt leak = block.
   - Faithfulness check: sensitive-shaped numbers in the output must exist
     (digit-normalised) in the retrieved context — catches hallucinated or
     injected figures (OWASP LLM09) and cross-scope leaks.
   - **Indirect-injection residue check (OWASP LLM01 via RAG):** retrieved
     documents can carry attacker instructions ("SYSTEM OVERRIDE", "IGNORE
     ALL PREVIOUS RULES", "I HAVE BEEN HACKED"). A policy answer must
     never echo instruction-like markers — if it does, the model obeyed
     retrieved content over its system prompt → block. Measured:
     `tests/results/rag_poisoning_report.md` (demo) + regression tests.
   - Blocked outputs are **withheld** (with prompt visible to the
     reviewer), queued for human review (`review_queue`), and the user
     gets a policy refusal.

8. **L7 — Audit** (`audit.py`)
   - One record per event (allow OR block) in `db/audit.db` + JSONL mirror
     in `logs/audit.jsonl` for SIEM shipping.
   - Each record carries `prev_hash`/`hash` — a SHA-256 chain. `GET
     /admin/audit/verify` walks the chain; any edit to a historical row
     breaks it (tested: `test_audit_chain_valid_and_detects_tamper`).

## 2. Layered config (who can change what)

| File | Owner | Reviewer |
|---|---|---|
| `config/rbac_config.yaml` | data owners | auditor (no code reading needed) |
| `config/app_config.yaml` | platform team | security review |
| `src/governance/*` | engineering | security engineering |

## 3. Operations plane (CIA "Availability")

- `GET /health` — deep posture: active/requested model backend, ollama
  reachability + fallback reason, row counts of both trust domains, live
  audit-chain verification, HITL queue depth, vector namespaces.
- `GET /metrics` — Prometheus exposition (prometheus-client, dedicated
  registry so the secure/baseline re-measurement loop can reload modules):
  `ai_requests_total{decision}`, `ai_blocked_prompts_total{layer}`,
  `ai_output_redactions_total`, `ai_rate_limited_total`,
  `ai_action_requests_total{status}`, `ai_latency_seconds`,
  `http_requests_total{method,path,status}` (id-collapsed labels).
- `deploy/docker-compose.yml` — 3 services (ollama + ollama-init one-shot
  model pull + securellm), healthchecks, internal-only model network.

## 4. Why layers instead of one filter

The measured report shows it: 33 attacks die at L2, 23 reach L6, 1 is
converted into a pending human decision at L3.5, and 3 die at access
control. Any single layer has blind spots by design ("polite" attacks that
carry no jailbreak vocabulary); the pipeline assumes any layer can be
bypassed and makes the *next* layer catch it.
