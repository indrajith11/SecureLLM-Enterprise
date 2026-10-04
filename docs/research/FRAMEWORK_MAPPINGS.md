# Framework Cross-Reference — OWASP × MITRE ATLAS × Detection × NIST AI RMF

**Scope.** Per-category cross-reference for the 2,630-attack corpus and the 48-rule WAF registry (ruleset v3.0, `config/behavior_rules.yaml`). Every ATLAS id, rule family and rule count below is read from the repo's own artifacts — `attacks/manifest.jsonl` (per-attack ATLAS tags), `config/behavior_rules.yaml` (per-rule `owasp`/`atlas` fields) and `docs/reports/data/framework_coverage.json` — not asserted. Complements, without duplicating: `docs/OWASP_NIST_Mapping.md` (LLM Top 10 → controls + AI RMF function evidence), `docs/frameworks/MITRE_ATLAS_COVERAGE.md` (probe-level ATLAS matrix), `docs/frameworks/ISO_42001_MAPPING.md` (Annex A self-assessment).

**Legend.** Rule families cite the registry `name` field with rule-id ranges; counts are distinct registry rules. NIST AI RMF: **G** = Govern, **MAP** = Map, **MEAS** = Measure, **MNG** = Manage (function evidence in `docs/OWASP_NIST_Mapping.md`). Attack counts = rows in `manifest.jsonl`; leak percentages from `docs/research/COVERAGE_MATRIX.md`. All ATLAS ids resolve at `atlas.mitre.org` (e.g. AML.T0051 — LLM Prompt Injection; AML.T0054 — LLM Jailbreak; AML.T0056 — Extract LLM System Prompt; AML.T0048 — External Harms; AML.T0010 — ML Supply Chain Compromise; AML.T0020 — Poison Training Data).

## 1. OWASP LLM Top 10 (2025) ↔ MITRE ATLAS ↔ detection ↔ NIST AI RMF

| OWASP | Attack file (count) | ATLAS (manifest) | Rule families detecting it (`behavior_rules.yaml`) | NIST AI RMF touchpoints |
|---|---|---|---|---|
| LLM01 Prompt Injection | `llm01_prompt_injection.txt` (150) | AML.T0051, AML.T0048 | `instruction_override` (R01–R05), `roleplay_dan` (R06–R11), `encoding_smuggle` (R22–R25), `delimiter_injection` (R26–R28), `encoding_bypass` (R42), `roleplay_bypass` (R43), `hypothetical_framing` (R45), `token_smuggling` (R46), `adversarial_suffix` (R47), `payload_splitting` (R48) — 24 rules | G: registry is policy-as-config; MAP: Threat_Model entry points; MEAS: 94.7%→0.0%; MNG: L2 WAF + L6 residue check |
| LLM02 Sensitive Info Disclosure | `llm02_info_disclosure.txt` (120) | AML.T0050, AML.T0056 | `prompt_extraction` (R12–R18, shared with LLM07) — 7 rules | MAP: data classification + role model; MEAS: 86.7%→0.0%; MNG: L6 role-aware DLP + L3/L4 scoping |
| LLM03 Supply Chain | `llm03_supply_chain.txt` (100) | AML.T0010 | `supply_chain_trust` (R36) — 1 rule | G: vendor model manifest + supplier review; MEAS: 60.0%→0.0%; MNG: third-party components pinned + hashed (`docs/mcp.md`) |
| LLM04 Data & Model Poisoning | `llm04_data_poisoning.txt` (100) | AML.T0020, AML.T0053 | `memory_poisoning` (R38, shared with ASI06) — 1 rule | MAP: poisoned-doc threat; MEAS: RAG-poisoning demo, 72.0%→0.0%; MNG: controlled ingest; L6 faithfulness |
| LLM05 Improper Output Handling | `llm05_improper_output.txt` (120) | AML.T0049 | `destructive_sql` (R19–R21), `code_execution` (R37) — 4 rules | MEAS: 75.0%→0.0%; MNG: L6 `RE_SQLEXEC` hard block (v5.0.0) + read-only executor |
| LLM06 Excessive Agency | `llm06_excessive_agency.txt` (120) | AML.T0049, AML.T0051 | `tool_abuse` (R29–R31), `privilege_escalation` (R32), `destructive_sql` (R19–R21), `tool_misuse` (R34) — 8 rules | G: zero-direct-tool design decision; MEAS: 72.5%→0.0%; MNG: L3.5 HITL gate, approved actions run in a read-only sandbox |
| LLM07 System Prompt Leakage | `llm07_system_prompt_leak.txt` (120) | AML.T0056 | `prompt_extraction` (R12–R18) — 7 rules | G: canary policy (L5 embeds `CANARY-7f3a`); MEAS: 80.8%→0.0%; MNG: L2 extraction patterns + L6 canary hard block at output |
| LLM08 Vector & Embedding Weaknesses | `llm08_vector_weaknesses.txt` (100) | AML.T0050 | **none** — 0 WAF rules (L3/L4 scoped, by design) | MAP: cross-tenant retrieval threat; MEAS: `test_tech_namespace_isolation`, 62.0%→0.0%; MNG: L3 namespace RBAC + L4 allow-listed RAG |
| LLM09 Misinformation | `llm09_misinformation.txt` (100) | AML.T0048 | **none** — 0 WAF rules (L3/L4 scoped) | MEAS: faithfulness-gate tests, 3.0%→0.0%; MNG: L6 digit-normalised faithfulness check |
| LLM10 Unbounded Consumption | `llm10_unbounded_consumption.txt` (100) | AML.T0048 | `cascading_failure` (R40, recursion/parallel-spawn signatures shared with ASI08) — 1 rule | MEAS: `test_rate_limiter_blocks_flood`, 34.0%→0.0%; MNG: L2a request + token sliding-window budgets, bounded 429 |

## 2. OWASP Agentic AI Top 10 (2026) ↔ MITRE ATLAS ↔ detection ↔ NIST AI RMF

| OWASP | Attack file (count) | ATLAS (manifest) | Rule families detecting it | NIST AI RMF touchpoints |
|---|---|---|---|---|
| ASI01 Agent Goal Hijack | `asi01_goal_hijack.txt` (100) | AML.T0051, AML.T0052 | `instruction_override` (R01–R05), `agent_goal_hijack` (R33) — 6 rules | G: agentic risk entries in the register; MEAS: 77.0%→0.0%; MNG: L2 WAF + L3.5 HITL before any state change |
| ASI02 Tool Misuse | `asi02_tool_misuse.txt` (100) | AML.T0049, AML.T0052 | `tool_abuse` (R29–R31), `tool_misuse` (R34, shared with LLM06) — 4 rules | G: tool allowlist; MEAS: 71.0%→0.0%; MNG: L3.5 gate + write-ops Admin-only |
| ASI03 Identity & Privilege Abuse | `asi03_identity_abuse.txt` (100) | AML.T0056 | `privilege_escalation` (R32), `identity_abuse` (R35) — 2 rules | G: RBAC role model (`config/rbac_config.yaml`); MEAS: 71.0%→0.0%; MNG: L3 policy engine; identity asserted by JWT (L1), never by chat claims |
| ASI04 Agentic Supply Chain | `asi04_agentic_supply_chain.txt` (100) | AML.T0010 | `supply_chain_trust` (R36, shared with LLM03) — 1 rule | G: vendor manifest + supplier review (ISO 42001 A.3/A.10); MEAS: 61.0%→0.0%; MNG: pinned, hashed, fenced MCP model |
| ASI05 Unexpected Code Execution | `asi05_code_execution.txt` (100) | AML.T0049 | `code_execution` (R37, shared with LLM05) — 1 rule | MEAS: 72.0%→0.0%; MNG: sandboxed read-only executor; no eval/exec path from chat |
| ASI06 Memory & Context Poisoning | `asi06_memory_poisoning.txt` (100) | AML.T0051, AML.T0053 | `memory_poisoning` (R38, shared with LLM04) — 1 rule | MAP: persistence-poisoning threat; MEAS: 60.0%→0.0%; MNG: no durable memory writes outside reviewed ingest |
| ASI07 Insecure Inter-Agent Communication | `asi07_inter_agent.txt` (100) | AML.T0052 | `inter_agent_spoofing` (R39) — 1 rule | G: agent-to-agent rulebook (`docs/mcp.md`); MEAS: 70.0%→0.0%; MNG: handoff messages never trusted as identity proof |
| ASI08 Cascading Failures | `asi08_cascading_failures.txt` (100) | AML.T0048 | `cascading_failure` (R40, shared with LLM10) — 1 rule | MEAS: 64.0%→0.0%; MNG: recursion caps + L2a budgets + kill-switch (`AI_ENABLED`, tested) |
| ASI09 Human-Agent Trust Exploitation | `asi09_trust_exploitation.txt` (100) | AML.T0048, AML.T0051 | `authority_impersonation` (R44, shared with ADVANCED) — 1 rule | MEAS: 69.0%→0.0%; MNG: authority comes from L1 JWT, not asserted personas; HITL approver ≠ requester |
| ASI10 Rogue Agents | `asi10_rogue_agents.txt` (100) | AML.T0048 | `rogue_agent` (R41) — 1 rule | MEAS: 63.0%→0.0%; MNG: L7 hash-chained audit cannot be suppressed; HITL confirmation unskippable |

## 3. Advanced technique corpus (ADVANCED bucket: 500 attacks / 8 files)

ADVANCED files exercise the evasion layer rather than one OWASP category; every row is tagged `ADVANCED` in the manifest with per-row ATLAS. Bucket: 85.0% baseline → 0.0% secured. Listed families carry the `ADV` tag in the registry (17 rules).

| Attack file (count) | Techniques (manifest) | Rule families | ATLAS (manifest) |
|---|---|---|---|
| `encoding_bypasses.txt` (100) | base64 / hex / ROT13 / zero-width / homoglyph / leet / HTML-entity / URL / double-encode, incl. stacked encodings | `encoding_smuggle` (R22–R25) + `encoding_bypass` (R42) + stage-0 normalisation (NFKC, zero-width/bidi strip, homoglyph fold) | AML.T0051, AML.T0054 |
| `roleplay_attacks.txt` (100) | `dan_variant`, `developer_mode`, `evil_twin`, `grandma_frame`, stan/aim/mongo-tom personas | `roleplay_dan` (R06–R11) + `roleplay_bypass` (R43) | AML.T0054 |
| `authority_impersonation.txt` (50) | admin / CEO / auditor / IT / vendor claims | `authority_impersonation` (R44) — also the ASI09 detector | AML.T0051 |
| `hypothetical_framing.txt` (50) | novel / academic / CTF / counterfactual / conditional frames | `hypothetical_framing` (R45) | AML.T0054 |
| `multiturn_escalation.txt` (50) | ramp / context / urgency / recon / trust / commitment ladders | no dedicated family — caught by the `instruction_override` / `agent_goal_hijack` pattern set plus the stage-3 heuristic score (`stage3_block_score: 6.0`) | AML.T0051 |
| `payload_splitting.txt` (50) | table cells, plus/hyphen splits, numbered chips, combine-execute | `payload_splitting` (R48 — `stage: split`, 10 signatures on the whitespace-stripped stream, stage 2) | AML.T0051 |
| `token_smuggling.txt` (50) | acrostic, nth-word, emoji-position, caps-only, stego frames | `token_smuggling` (R46) | AML.T0051 |
| `adversarial_suffix.txt` (50) | GCG-style suffixes (`gcg_suffix`, `pair_refine`, `autodan_persona`) | `adversarial_suffix` (R47) | AML.T0051, AML.T0054 |

## 4. Pipeline-layer placement (who catches what, where)

The 48-rule registry is only the L2 story; the corpus results come from the full 7-layer pipeline (L1 auth → L2 input governance → CIA → L3.5 HITL → L3 RBAC → L4 retrieval → L5 model → L6 output governance → L7 audit). Three placements matter when reading the matrix. **LLM02** sensitive disclosure is largely an L6 story — role-aware DLP shapes plus L3/L4 column/namespace scoping; the WAF contributes only the extraction vector shared with LLM07. **LLM08 and LLM09 carry zero WAF rules by design** (matrix: "0 (L3/L4 scoped)") — cross-tenant retrieval is an authorization/scope problem owned by L3 RBAC + L4 allow-lists; misinformation is owned by the L6 faithfulness check. **LLM05** gained an explicit L6 `sqlexec` hard block in v5.0.0 (`RE_SQLEXEC`: the model can never report `DROP TABLE` / `rows affected`), layered on the read-only executor. Agency abuse (LLM06, ASI02/05) resolves at L3.5 HITL; volume/recursion abuse (LLM10, ASI08) at L2a budgets plus rule R40.

| Category family | WAF rules (L2) | Primary non-L2 control |
|---|---|---|
| LLM01, LLM03–LLM07, ADVANCED, ASI01–ASI10 | yes (R01–R48) | L3.5 HITL (agency), L6 DLP/canary/residue (LLM02/07), L7 audit (ASI10) |
| LLM02 | partial (extraction vector only) | L6 role-aware DLP + L3/L4 scoping |
| LLM08 | **0 — by design** | L3 namespace RBAC + L4 allow-listed retrieval |
| LLM09 | **0 — by design** | L6 faithfulness check |
| LLM05 | yes (R19–R21, R37) | L6 `sqlexec` hard block + read-only executor |
| LLM10 / ASI08 | yes (R40) | L2a sliding-window request/token budgets |

---

**Honesty footer.** All mappings are derived from the repo's own registry and manifest at build time (**2026-10-04**): rule families/counts from `config/behavior_rules.yaml` (ruleset v3.0), ATLAS ids from `attacks/manifest.jsonl`, roll-ups from `docs/reports/data/framework_coverage.json` and `docs/research/COVERAGE_MATRIX.md`. ATLAS technique ids cite `atlas.mitre.org` (manifest set: AML.T0048/49/50/51/52/53/54/56, AML.T0010, AML.T0020; note AML.T0050 and AML.T0020 appear at the attack layer but are tagged by no WAF rule). The mapping is testable: `tests/test_rules_registry.py` enforces YAML↔engine parity, and `tests/analyze_coverage.py` regenerates every count in this document from disk — re-run it after any registry change.
