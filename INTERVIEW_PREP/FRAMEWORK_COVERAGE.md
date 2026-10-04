# Framework Coverage Dashboard — SecureLLM-Enterprise v4.9.0

One page, eight frameworks, every cell backed by running code or a measured number. Detailed mappings: `docs/frameworks/` (ISO 42001, DPDPA, NIST CSF 2.0, NIST 800-53, MITRE ATLAS) and `docs/OWASP_NIST_Mapping.md`.

| Framework | Coverage | Evidence (clickable, runnable) |
|---|---|---|
| **NIST AI RMF** | **4/4 functions** scored live 1–4 from running-system evidence | `GET /admin/compliance/rmf` — GOVERN/MAP/MEASURE/MANAGE maturity computed from live flags (chain verdict, test status, HITL depth, retention), not prose |
| **OWASP LLM Top 10 (2025)** | **10/10 risks** | `docs/OWASP_NIST_Mapping.md` row per risk + 84-attack corpus (22 categories) hitting them: 0/84 leaks secured vs 100% baseline |
| **MITRE ATLAS** | **16/18 techniques** addressed (14 probe-backed, 2 by-design; 2 partial = registered risks) | `docs/frameworks/MITRE_ATLAS_COVERAGE.md` — row-per-technique matrix with probe category + blocking layer |
| **NIST CSF 2.0** | **6/6 functions** (23/23 categories touched; GOVERN strongest) | `docs/frameworks/NIST_CSF_MAPPING.md` — pipeline + compliance plane mapped per category |
| **NIST SP 800-53 R5** | **34 controls** across the 4 named families (AC 12, AU 9, SI 8, RA 5) + 5 partial families | `docs/frameworks/NIST_800_53_MAPPING.md` — control-by-control with test evidence |
| **ISO/IEC 42001:2023** | Clauses 4–10 covered; **29/38 Annex A controls** fully evidenced (76%), 9 partial, 0 hidden | `docs/frameworks/ISO_42001_MAPPING.md` — clause + Annex A tables with honest gap list |
| **EU AI Act** | **4-tier classifier live** (5 Art.5 prohibited flags, 12 Annex III categories) + Art. 9–17 (+26/50/72) conformity pack generator; May-2026 Digital Omnibus timeline baked in | `POST /admin/compliance/inventory` → auto-classified; `GET /admin/compliance/conformity-pack`; Art.5 registration refused 403 |
| **DPDPA 2023 (India)** | **8/8 duty areas** + Data Principal rights mapped; Rule 7 (72 h Board report) exceeded by design (S1 = 24 h internal SLA) | `docs/frameworks/DPDPA_MAPPING.md`; Output DLP recognises Aadhaar/PAN/+91 shapes; retention purge with chain re-anchoring |

## The numbers an interviewer remembers

- **0/84** red-team leaks with governance on · **100%** leak rate same model, same data, unprotected (`scripts/probe_runner.py`, md5-stamped corpus)
- **489/489** tests · **67/67** live E2E checks on real Ollama · **114** live red-team probes
- **7-layer** enforcement pipeline + **compliance plane** (the plane that *proves* what the pipeline *enforces*)
- **Every governance decision hash-chained** (HMAC-SHA256) — incidents, model selections, compliance writes all inside one tamper-evident chain
- Risk register with **inherent → residual** scoring, residual ≤ inherent enforced at the API
- Incident ledger with **S1–S4 SLA clock** (24 h/48 h/72 h regulatory-assessment design) and a 5-state machine that rejects illegal transitions

## Self-assessment disclaimer

All ISO 42001 / DPDPA / 800-53 / CSF rows are engineering self-assessments with evidence pointers — **not certifications or legal opinions**. That honesty is deliberate: the project's credibility rests on measured claims (leak rates, test counts, chain verdicts) and on naming gaps rather than hiding them.
