# OWASP LLM Top 10 (2025) x NIST AI RMF — control mapping

## OWASP LLM Top 10 -> project controls

| OWASP (2025) | Risk in this project | Control | Layer | Evidence |
|---|---|---|---|---|
| LLM01 Prompt Injection | Employee overrides system rules; poisoned doc instructs the model | 40+ patterns + heuristic score + base64/hex/ROT13 decode-rescan (direct); **output-side injection-residue check** (indirect/RAG); poisoned-doc demo | L2, L6 | DIR/DAN/AUTH/ENC/RAG probes; 0/60 leaks; `rag_poisoning_report.md` |
| LLM02 Sensitive Information Disclosure | Salaries, PII, bonuses in answers | Role-aware DLP shapes; role-scoped columns/namespaces | L6, L3, L4 | EXF probes; `test_tech_cannot_reach_hr_salaries` |
| LLM03 Excessive Agency | Model "executes" SQL / writes data; user asks the AI to delete/update | No DB write path (read-only user, SELECT whitelist, bound params) **plus L3.5 HITL gate: risky asks become pending human-approval requests; even approved actions run in a read-only sandboxed executor** | L3, L3.5 | `test_sql_injection_via_chat_cannot_touch_data`; `tests/test_hitl.py`; EXF-02 stopped by L3.5 |
| LLM04 Data & Model Poisoning | Poisoned knowledge-base document | Controlled ingest script; downstream faithfulness + role DLP neutralise poisoned content | L4 governance, L6 | RAG-01..04 probes |
| LLM05 Improper Output Handling | Model output trusted as-is | Every output passes DLP/canary/faithfulness/residue before delivery | L6 | 23 attacks stopped at L6 |
| LLM06 Excessive Agency (agentic scope) | Chatbot granted beyond chat | The chatbot has zero tools/actions; it reads pre-filtered context only | L3/L4 design | Architecture.md |
| LLM07 System Prompt Leakage | Rules revealed, then dodged | Extraction patterns at input; canary `CANARY-7f3a` blocks any leak at output | L2, L6 | EXT probes; DIR-02 baseline leak shows why |
| LLM08 Vector & Embedding Weaknesses | Cross-tenant RAG retrieval | Namespace allow-list per role; no unscoped search API | L3, L4 | `test_tech_namespace_isolation` |
| LLM09 Misinformation | Confident hallucinated figures | Faithfulness check: output numbers must exist digit-normalised in context | L6 | unit-tested via probes |
| LLM10 Unbounded Consumption | Flooding the endpoint | Per-user request + token sliding-window budgets, bounded 429 | L2a | `test_rate_limiter_blocks_flood` |

## NIST AI RMF functions -> concrete project evidence

| Function | Question it answers | Concrete artefact in this repo |
|---|---|---|
| **GOVERN** | Who decided the rules, and are they reviewable? | 7-layer policy in code; declarative `config/rbac_config.yaml` (auditable without reading code); risk-based roles; documented residual risks (Threat_Model.md) |
| **MAP** | What can go wrong, and where? | `docs/Threat_Model.md`: 7 assets, 12 entry-point threats, 7 tested scenarios, residual risks |
| **MEASURE** | Is the protection real, and how do we know? | 60-probe red-team harness (`scripts/probe_runner.py`); measured baseline (100% raw-model leak) vs secured (0/60); RAG-poisoning demo (`scripts/demo_rag_poisoning.py`); 99-test regression suite; **continuous `/metrics` telemetry**; Garak instructions for real-model runs |
| **MANAGE** | How are risks reduced and monitored day-to-day? | L2/L6 preventive controls; **L3.5 HITL action gate with approver roles and sandboxed executor**; human review queue for withheld outputs; hash-chained audit with `/admin/audit/verify`; **`/health` + `/metrics` for continuous monitoring**; graceful provider fallback; hardcoded limitations in README |

## Bonus mappings

| Framework | Control in project |
|---|---|
| ISO/IEC 27001 A.8.16 (monitoring) | audit chain + JSONL mirror + Prometheus `/metrics` + `/health` |
| ISO/IEC 27001 A.5.15 (access control) | RBAC engine + tests |
| ISO/IEC 42001 (AI management system) | Govern artefacts: policy-as-config, risk register, measurement loop |
| SOC 2 (security, availability) | authn/authz tests, rate limiting, hardened deploy, `/health` + `/metrics`, healthchecked compose stack |
| DPDP Act 2023 (India) | purpose limitation + data minimisation enforced at L4 (column/namespace scoping) |
| CERT-In direction (India) | tamper-evident logs = reportable-incident evidence trail |
