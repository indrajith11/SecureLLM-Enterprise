# CITATIONS — in-repo bibliography

Bibliography for SecureLLM-Enterprise v5.0.0: the external sources the governance mappings, attack corpus and incident analyses rely on. Accessed/verified **2026-10-04** at build time. Each entry is tagged with its verification level (footer). Where the repo uses a source, the usage is noted inline. Companion documents: `docs/research/SOURCES.md` (full annotated bibliography) and `docs/research/INCIDENTS.md` (incident detail).

---

## Attack taxonomies

- **OWASP Top 10 for LLM Applications 2025** — OWASP GenAI Security Project — 2025 — https://genai.owasp.org/llm-top-10/ — Accessed 2026-10-04. [V] — Categories LLM01–LLM10 structure `attacks/llm01_prompt_injection.txt` … `llm10_unbounded_consumption.txt`; cited in every `manifest.jsonl` row's `source` field.
- **OWASP Top 10 for Agentic Applications for 2026** — OWASP GenAI Security Project — December 9, 2025 — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ — Accessed 2026-10-04. [V] — Categories ASI01–ASI10 structure `attacks/asi01_goal_hijack.txt` … `asi10_rogue_agents.txt` and the agentic rule families in `config/behavior_rules.yaml`.
- **MITRE ATLAS** — MITRE Corporation — https://atlas.mitre.org/ — Accessed 2026-10-04. [V] — Technique set used across the corpus and registry: AML.T0048/49/50/51/52/53/54/56, AML.T0010, AML.T0020. Per-technique detail in `docs/frameworks/MITRE_ATLAS_COVERAGE.md` and `docs/research/FRAMEWORK_MAPPINGS.md`.

## Governance frameworks

- **NIST AI Risk Management Framework (AI RMF 1.0)** — NIST — January 2023 — https://www.nist.gov/itl/ai-risk-management-framework — Accessed 2026-10-04. [S] — Govern/Map/Measure/Manage function evidence per category in `docs/OWASP_NIST_Mapping.md`; maturity scoring via `assess_rmf_maturity`.
- **NIST Cybersecurity Framework (CSF) 2.0** — NIST — February 2024 — https://www.nist.gov/cyberframework — Accessed 2026-10-04. [S] — 106 sub-categories; mapped subset served live at `/admin/compliance/csf` (`docs/frameworks/NIST_CSF_MAPPING.md`).
- **ISO/IEC 42001:2023 (AI management systems)** — ISO/IEC — December 2023 — https://www.iso.org/standard/81230.html — Accessed 2026-10-04. [S] — Annex A: 38 controls, objective groups A.2–A.10; self-assessed mapping in `docs/frameworks/ISO_42001_MAPPING.md` (Statement of Applicability via `iso42001_soa.py`).
- **Regulation (EU) 2024/1689 (EU AI Act)** — European Parliament — July 2024 — https://eur-lex.europa.eu/eli/reg/2024/1689/oj — Accessed 2026-10-04. [V] — GPAI obligations enforceable from 2 August 2026; the Digital Omnibus provisional deal (May 2026) shifts Annex III high-risk deployer obligations to 2 December 2027. [O] — Classification at registration feeds the conformity pack (`compliance.py`, Art. 9–17 + 26/50/72).
- **Digital Personal Data Protection Act 2023 (India)** — Government of India — August 2023 — https://www.meity.gov.in/data-protection-framework — Accessed 2026-10-04. [V] — DPDP Rules 2025 notified 14 November 2025; Rule 7 requires a detailed breach report to the Data Protection Board within 72 hours. [O] — Obligation mapping incl. the 72 h SLA in `docs/frameworks/DPDPA_MAPPING.md` and `framework_coverage.json`.

## Benchmarks & datasets

Paper-level citations (no URL on file here — see `docs/research/SOURCES.md` for annotated entries). All four inform the attack corpus; three are named in the `manifest.jsonl` `source` field.

- **AdvBench** — Zou et al., 2023 — 520 behaviors. [O]
- **HarmBench** — Mazeika et al., 2024 — 320 behaviors. [O]
- **JailbreakBench** — Chao et al., 2024 — 100 prompts. [O]
- **Do-Not-Answer** — Wang et al., 2023 — 939 questions. [O]

## Tools

- **Garak** — NVIDIA — https://github.com/NVIDIA/garak — Accessed 2026-10-04. [V] — LLM vulnerability scanner; run instructions for real-model verification are referenced from the measurement documentation.
- **PyRIT** — Microsoft — https://github.com/Azure/PyRIT — Accessed 2026-10-04. [V] — Comparable agentic red-teaming framework; used as a design reference for multi-turn automation.
- **Promptfoo** — promptfoo — https://github.com/promptfoo/promptfoo — Accessed 2026-10-04. [V] — Prompt test harness; reference for CI-style probe gating.

## Real-world incidents

Motivating cases for the agentic and output-governance controls; full timelines and control linkages in `docs/research/INCIDENTS.md`.

- **EchoLeak (CVE-2025-32711)** — Microsoft 365 Copilot zero-click prompt-injection data exfiltration — June 2025. [O] — Motivates the L6 injection-residue check and L4 untrusted-content fencing.
- **Replit agent incident** — coding agent deleted a production database during a live session — July 2025. [O] — Motivates the L3.5 HITL agency gate, write-ops Admin-only policy and read-only executor.
- **EmailGPT (CVE-2024-5184)** — prompt injection in a Gmail-integrated assistant enabling service abuse — February 2024. [O] — Motivates L2 instruction-override and delimiter-injection families.

---

## Verification taxonomy

- **[V]** — web-verified at build (2026-10-04): URL fetched and content matched the entry.
- **[O]** — operator research: dates, figures or incident details curated by the project operator from public reporting; re-verify before relying on them in an external audit.
- **[S]** — standard publication metadata (title/date/publisher) taken from the standards body's own listing; the linked pointer is authoritative for the full text.

Entries without a URL (benchmarks) are cited at paper level by author and year; their annotated entries live in `docs/research/SOURCES.md`. This file records *what the repo cites and where it is used*; it does not restate framework content.
