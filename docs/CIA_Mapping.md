# CIA Triad Mapping

**v3 update — the triad is now enforced PER USER, PER REQUEST** by
`src/governance/cia_enforcer.py` (full detail: `docs/cia_enforcement.md`):
C = clearance tiers (L1..L5) + department isolation, checked before
retrieval; I = write operations Admin-only and routed to HITL approval;
A = 20 req/min + max 3 concurrent sessions per user. Every refusal is
counted per pillar (`ai_cia_blocks_total{pillar}`) and hash-chained into
the audit log with its `cia_violation` category. The table below lists the
deeper defence-in-depth controls that stand *behind* the CIA gate.

Each pillar is enforced by more than one independent control, so no single
failure breaks the pillar (defence in depth).

| Pillar | Goal in this project | Technical controls | Verified by |
|---|---|---|---|
| **Confidentiality** | A user gets only the data their role may see — nothing more | L1 signed role claim; L3 declarative RBAC (tables + **columns**); L3 minimised `employees_tech_view`; L4 namespace-isolated RAG; L6 role-aware DLP (salary/email/phone blocked for Tech; bonuses blocked for HR) | `test_tech_cannot_reach_executive_bonus`, `test_hr_sees_hr_salaries_but_not_bonus`, `test_tech_namespace_isolation`, EXF probes |
| **Integrity** | Data cannot be changed through the AI, and answers cannot contain figures the context never had | Read-only DB user (`mode=ro`) + SELECT-whitelist query builder + bound parameters; L6 faithfulness check (digit-normalised); L7 SHA-256 hash chain makes audit edits detectable | `test_sql_injection_via_chat_cannot_touch_data`, RAG probes, `test_audit_chain_valid_and_detects_tamper` |
| **Availability** | One user or one bug cannot exhaust the service — and operators can SEE the service's state | L2a sliding-window rate limit with request + token budgets (bounded 429); non-root hardened container (`read_only`, `cap_drop: ALL`); `GET /health` deep posture probe (model backend + fallback reason, row counts, live audit-chain verification, HITL queue depth); `GET /metrics` Prometheus exposition (`ai_requests_total`, `ai_blocked_prompts_total{layer}`, `ai_output_redactions_total`, `ai_latency_seconds`, ...); healthchecked docker-compose stack (app + ollama + one-shot model pull); graceful provider degradation (Ollama down → mock backend, honestly reported) | `test_rate_limiter_blocks_flood`, `tests/test_observability.py`, deploy/docker-compose.yml |

## The one-sentence version

> Confidentiality is decided **before** the model (identity + RBAC + scoped
> retrieval), integrity is enforced **after** the model (faithfulness + hash
> chain), and availability is protected **around** the model — rate limits,
> hardened runtime, and observability (`/health` + `/metrics`) so that
> degradation is detected, not discovered.
