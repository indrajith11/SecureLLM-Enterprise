# Executive summary - SecureLLM-Enterprise v5.0.0

**2630-prompt red-team corpus. 48 auditable WAF rules. 504 tests. One number matters: 70.49% -> 0.0%.**

Firing the full 2630-prompt corpus (OWASP LLM Top 10 2025 + OWASP Agentic AI Top 10 2026 + advanced techniques) at the same naive model twice:

- RAW (no governance): **70.49% of attacks leak sensitive data** (1854 of 2630)
- SECURED (7-layer pipeline): **0.0% leak rate** - 100.0% containment, zero cross-scope exfiltration

The corpus itself found and fixed 3 real output-DLP defects during development (redaction span-offset corruption, missing SQL-execution confirmation block, self-scope email bypass) - evidence the harness does its job.

## What else is new in v5.0.0

- **OWASP Agentic AI Top 10 2026 coverage**: 10 categories, 100 attacks each, goal-hijack -> rogue agents, grounded in EchoLeak (CVE-2025-32711) and the Replit agent incident
- **48-rule WAF registry** (config/behavior_rules.yaml) with engine<->YAML parity tests and a no-dead-rules guarantee
- **ISO 42001 SoA**: all 38 Annex A controls mapped to live controls, computed from runtime evidence
- **DPDPA module**: 9 obligations incl. the Rule 7 72-hour breach runbook wired to the incident ledger
- **NIST CSF 2.0**: 6 functions, evidence-scored sub-categories
- **Full citations**: docs/CITATIONS.md + docs/research/SOURCES.md

## Where to look in 60 seconds

1. `python -m tests.run_attacks --slice all --mode both` - the campaign, live
2. `/compliance.html` (admin) - inventory, risks, incidents, RMF, SoA, DPDPA, CSF
3. `docs/reports/FULL_ATTACK_REPORT.md` - per-category evidence
4. `docs/reports/GAP_REPORT.md` - what this does NOT claim

