# Coverage report - v5.0.0

- Attacks: **2630** across 28 files (21 OWASP categories) - 31.3x the v4 84-probe corpus
- WAF rules: **48** (65 regex signatures), registry-audited in config/behavior_rules.yaml
- Pytest suite: **504 tests** (all green)

| Framework | Coverage | Evidence |
|---|---|---|
| OWASP LLM Top 10 2025 | 10/10 categories | 1130 attacks |
| OWASP Agentic AI Top 10 2026 | 10/10 (ASI01-ASI10) | 1000 attacks |
| MITRE ATLAS | 10 techniques mapped | manifest + 48-rule registry |
| NIST CSF 2.0 | 100.0% of the 23-subcategory mapped subset | /admin/compliance/csf |
| ISO 42001 | 38/38 Annex A controls in SoA | /admin/compliance/iso42001-soa |
| DPDPA | 9 obligations mapped (Rule 7 72h runbook) | /admin/compliance/dpdp |
| EU AI Act | Art. 9-17 (+26/50/72) conformity pack | /admin/compliance/conformity-pack |
| NIST AI RMF | maturity 1-4, live evidence | /admin/compliance/rmf |

See docs/research/COVERAGE_MATRIX.md for the per-category attack x rule x ATLAS table (machine-generated).

