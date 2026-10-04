# Changelog

Notable, honestly-labelled changes to SecureLLM-Enterprise. The project's
rule applies here too: every number is measured, every limitation named.

## v5.0.0 (2026-10-04) — the measured release

### Attack corpus (Phase 2)
- Added a **2630-prompt red-team corpus** under `attacks/` — 28 files, every
  prompt unique, deterministic rebuild via `scripts/gen/build_all.py`:
  - **OWASP LLM Top 10 2025**: 1130 attacks (LLM01 150, LLM02/05/06/07 120
    each, LLM03/04/08/09/10 100 each) — 100+ per category.
  - **OWASP Agentic AI Top 10 2026** (published Dec 9, 2025): 1000 attacks,
    100 per category ASI01–ASI10, grounded in real incidents (EchoLeak
    CVE-2025-32711, Replit agent production-DB deletion, GitHub MCP
    disclosures).
  - **Advanced techniques**: 500 prompts across encoding bypasses, roleplay,
    authority impersonation, hypothetical framing, multi-turn escalation,
    payload splitting, token smuggling, GCG/PAIR/AutoDAN-style adversarial
    suffixes.
- Every attack carries per-prompt metadata (id, OWASP id, technique, ATLAS
  ids, source note) in `attacks/manifest.jsonl`; `attacks/index.json` holds
  the machine-checkable totals.

### Rules engine v3.0 (Phase 3)
- `src/governance/input_filter.py` RULESET 2.0 → **3.0**: 16 new detection
  families (agent_goal_hijack, tool_misuse, identity_abuse,
  supply_chain_trust, code_execution, memory_poisoning,
  inter_agent_spoofing, cascading_failure, rogue_agent, encoding_bypass,
  roleplay_bypass, authority_impersonation, hypothetical_framing,
  token_smuggling, adversarial_suffix, payload-split additions) + 6 new
  heuristic cues.
- New auditable **48-rule registry** exported to `config/behavior_rules.yaml`
  (`scripts/gen/export_rules.py`); `tests/test_rules_registry.py` enforces
  engine↔YAML parity, contiguous R01–R48 ids, valid regexes, and that **every
  rule fires on the live corpus** (no dead rules).

### Governance modules (Phase 4)
- `src/governance/iso42001_soa.py` — ISO/IEC 42001:2023 **Statement of
  Applicability**: all 38 Annex A controls (objectives A.2–A.10) mapped to
  live controls with honest statuses (31 implemented / 6 partial / 1 N/A);
  endpoint `GET /admin/compliance/iso42001-soa`.
- `src/governance/dpdp_compliance.py` — **DPDPA** (DPDP Act 2023 + DPDP
  Rules 2025) obligation map: 9 duties incl. the **Rule 7 breach runbook**
  (DPB intimation without delay + detailed report within 72 hours) wired to
  the incident ledger; endpoint `GET /admin/compliance/dpdp`.
- `src/governance/nist_csf_mapping.py` — **NIST CSF 2.0** function coverage
  over a 23-subcategory AI-relevant subset (of 106), evidence-scored;
  endpoint `GET /admin/compliance/csf`.
- `tests/test_governance_v5.py` — 10 tests: structure, statutory refs,
  honesty invariants, admin gating (403 for non-admin).

### Output-DLP hardening (found by the new corpus)
- **Fixed redaction span-offset corruption** (`output_filter.redact`):
  faithfulness spans are now applied right-to-left; the old longest-first
  order produced shifted replacements that mangled markers and let real
  salary/phone/email spans survive (corpus finding ADV01-0031).
- **New hard block**: database/command execution confirmations
  (`RE_SQLEXEC` — "Query OK", "rows affected", DROP/DELETE/TRUNCATE) can no
  longer reach the user in any role (findings ADV01-0017/0021/0030).
- **Self-scope email bypass closed**: email addresses not present in the
  retrieved context are withheld even in self-scoped replies
  (context-aware faithfulness span "email address").

### Test runners, analyzers, reports (Phase 6)
- `tests/run_attacks.py` — the campaign runner (secured / baseline / live
  modes; llm/asi/adv/all slices; leak scoring with self-scope exemption;
  garak-compatible JSONL evidence; `--gate` CI mode) plus slice wrappers
  (`run_llm_top10.py`, `run_agentic_top10.py`, `run_advanced.py`) and
  `tests/compare_all.py`.
- Analyzers: `analyze_coverage.py` (machine-generated
  `docs/research/COVERAGE_MATRIX.md`), `analyze_frameworks.py`,
  `analyze_trends.py` (84 → 2630 growth tracked).
- Reports from real run data: `docs/reports/FULL_ATTACK_REPORT.md`,
  `COVERAGE_REPORT.md`, `GAP_REPORT.md`, `EXECUTIVE_SUMMARY.md`.
- **Measured headline**: baseline 70.49% leak rate (1854/2630) vs secured
  **0.0%** (100% containment) with the mock backend; per-slice runs and
  live-model mode (`--model qwen2.5:0.5b`) available. Mock-backend labelling
  is explicit everywhere.

### Research & citations (Phase 5)
- `docs/CITATIONS.md` + `docs/research/SOURCES.md` (full bibliography with
  [V]/[O]/[S] verification markers), `docs/research/INCIDENTS.md`
  (EchoLeak, Replit, GitHub MCP, EmailGPT → corpus + rules),
  `docs/research/FRAMEWORK_MAPPINGS.md` (LLM01-10 / ASI01-10 / advanced →
  ATLAS → rule families → NIST touchpoints).

### Interview pack (Phase 7)
- `INTERVIEW_PREP/SECURELLM_ENTERPRISE_V5.pdf` — 10-page evidence pack
  (cover, TOC, executive summary, architecture, coverage matrix, campaign
  results with chart, governance plane, 10 Q&A, honest limitations,
  reproduce + sources).
- `INTERVIEW_PREP/FRAMEWORK_COVERAGE.md` + `MASTER_INTERVIEW_PREP.md`
  updated to v5 numbers (70.49% → 0.0%, 48 rules, 504 tests, 38/38 SoA).
- `DEMO_SCRIPT.sh` — now 10 steps: agentic goal-hijack live demo, ISO SoA +
  DPDPA endpoints, campaign comparison, cloudflared tunnel step.

### Suite
- **504/504 tests pass** (489 pre-v5 + 5 registry + 10 governance-v5).
- Version strings: API 5.0.0; README badges; compliance-plane endpoint
  table updated.

## v4.9.0 / v4.9.1 (2026-10)
- Compliance plane (inventory + EU AI Act classifier + risk register +
  incident ledger + RMF maturity + Art. 9–17 conformity pack), AIGovernance
  integration, 5 framework mapping docs, interview pack v1 — see
  `docs/governance/compliance_module.md` and git history (af85b3a..c0f17b3).
