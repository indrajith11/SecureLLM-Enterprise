# Framework Coverage Dashboard — SecureLLM-Enterprise v5.0.0

One page, nine frameworks, every cell backed by running code or a measured number. Detailed mappings: `docs/frameworks/` (ISO 42001, DPDPA, NIST CSF 2.0, NIST 800-53, MITRE ATLAS), `docs/research/` (full bibliography, cross-mappings, incidents) and `docs/OWASP_NIST_Mapping.md`.

| Framework | Coverage | Evidence (clickable, runnable) |
|---|---|---|
| **OWASP LLM Top 10 (2025)** | **10/10 risks, 1130 attacks** (100+ per category) | `attacks/llm01..llm10*.txt` + manifest.jsonl; campaign: 0 leaks secured vs 66–95% leak per category baseline |
| **OWASP Agentic AI Top 10 (2026)** | **10/10 (ASI01–ASI10), 1000 attacks** | `attacks/asi01..asi10*.txt` — goal hijack → rogue agents, anchored on EchoLeak CVE-2025-32711 + Replit incident; rules R33–R47 |
| **MITRE ATLAS** | **10 AI-specific techniques** mapped across corpus + 48-rule registry | `docs/research/FRAMEWORK_MAPPINGS.md` + `docs/frameworks/MITRE_ATLAS_COVERAGE.md`; ids in manifest.jsonl per attack |
| **NIST AI RMF 1.0** | **4/4 functions** scored live 1–4 from running-system evidence | `GET /admin/compliance/rmf` — maturity from live flags (chain verdict, HITL depth, retention), not prose |
| **NIST CSF 2.0** | **6/6 functions**, 23-subcategory AI-relevant subset scored from evidence | `GET /admin/compliance/csf` (NEW v5) + `docs/frameworks/NIST_CSF_MAPPING.md` |
| **NIST SP 800-53 R5** | **34 controls** across AC/AU/SI/RA + partial families | `docs/frameworks/NIST_800_53_MAPPING.md` — control-by-control with test evidence |
| **ISO/IEC 42001:2023** | **38/38 Annex A controls in live SoA**: 31 implemented, 6 partial, 1 N/A (0 hidden) | `GET /admin/compliance/iso42001-soa` (NEW v5) — Statement of Applicability computed from runtime evidence |
| **EU AI Act** | **4-tier classifier live** (5 Art.5 flags, 12 Annex III categories) + Art. 9–17 (+26/50/72) conformity pack; Digital Omnibus → 2 Dec 2027 timeline baked in | `POST /admin/compliance/inventory` → auto-classified; `GET /admin/compliance/conformity-pack`; Art.5 registration refused 403 |
| **DPDPA 2023 + Rules 2025 (India)** | **9 obligations mapped**: 5 implemented, 3 partial, 1 N/A — incl. **Rule 7 72-hour breach runbook** wired to the incident ledger | `GET /admin/compliance/dpdp` (NEW v5) + `docs/frameworks/DPDPA_MAPPING.md` |

## The numbers an interviewer remembers

- **2630-prompt red-team corpus** (31.3× the v4 84-probe corpus): LLM Top 10 = 1130, Agentic Top 10 = 1000, advanced techniques = 500 — every prompt unique, manifest with OWASP + ATLAS metadata per attack
- **70.49% → 0.0%**: same naive model, same data — baseline leak rate vs secured pipeline (`python -m tests.run_attacks --slice all --mode both`)
- **48 WAF rules / 65 regex signatures** in an auditable registry (`config/behavior_rules.yaml`) with engine↔YAML parity tests and a no-dead-rules guarantee (every rule fires on the live corpus)
- **504/504 tests** — including registry parity, SoA structure, DPDPA Rule 7 and CSF function tests
- **The corpus found 3 real output-DLP defects** on day one (redaction span-offset corruption, missing SQL-execution confirmation block, self-scope email bypass) — all fixed in v5.0.0 with tests
- Risk register with **inherent → residual** scoring; incident ledger with **S1–S4 SLA clock**; every governance decision **HMAC hash-chained**
- **ISO SoA 31/38 implemented** — the 6 partials and 1 N/A are named in the live endpoint, not hidden

## 60-second demo hooks

```bash
python -m tests.run_attacks --slice asi --mode both   # Agentic Top 10, live
python -m tests.compare_all                            # 70.49% -> 0.0% table
curl -s -H "$ADMIN" localhost:8000/admin/compliance/iso42001-soa | jq '.status_summary'
```

## Self-assessment disclaimer

All ISO 42001 / DPDPA / 800-53 / CSF rows are engineering self-assessments with evidence pointers — **not certifications or legal opinions**. Mock-backend numbers are labelled as such (naive raw-model stand-in); live-model numbers run with `--model qwen2.5:0.5b` via Ollama. Full source citations with verification markers: `docs/CITATIONS.md`, `docs/research/SOURCES.md`. That honesty is deliberate: the project's credibility rests on measured claims and named gaps.
