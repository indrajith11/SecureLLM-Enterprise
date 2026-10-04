# SOURCES — SecureLLM-Enterprise v5.0.0

Complete bibliography for the v5.0.0 attack corpus (1,130 OWASP LLM Top 10 attacks and 1,000 OWASP Agentic Top 10 attacks) and for the governance-framework claims made across this repository. Every source carries a verification marker from the legend at the end of this file.

## OWASP Top 10 for LLM Applications (2025)

- **Title:** OWASP Top 10 for LLM Applications 2025
- **Author / Org:** OWASP GenAI Security Project
- **URL:** https://genai.owasp.org/llm-top-10/
- **Date:** 2025 · **Accessed:** 2026-10-04 · **Marker:** [V+O]

Used for: the category skeleton of the LLM corpus — `attacks/llm01_prompt_injection.txt` through `attacks/llm10_unbounded_consumption.txt` (1,130 attacks) follow LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, and LLM10 Unbounded Consumption, as does the detection-rule registry.

## OWASP Top 10 for Agentic Applications (2026)

- **Title:** OWASP Top 10 for Agentic Applications for 2026
- **Author / Org:** OWASP GenAI Security Project
- **URL:** https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- **Date:** December 9, 2025 (operator research) · **Accessed:** 2026-10-04 · **Marker:** [V]

Existence and the ASI01–ASI10 IDs were corroborated on 2026-10-04 via secondary sources: the operos.ai compliance matrix, lucidshark.com (Apr 10, 2026), akto.io (Sep 2, 2026), ammune.ai (Sep 16, 2026), verifywise.ai, and f5.com.

Used for: the agentic corpus skeleton — `attacks/asi01_goal_hijack.txt` through `attacks/asi10_rogue_agents.txt` (1,000 attacks) follow ASI01 Agent Goal Hijack, ASI02 Tool Misuse & Exploitation, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, and ASI10 Rogue Agents.

## MITRE ATLAS

- **Title:** MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- **Author / Org:** MITRE Corporation
- **URL:** https://atlas.mitre.org/
- **Accessed:** 2026-10-04 · **Marker:** [V+O]

Honest note: ATLAS evolves with releases. A published secondary source (docs.365architect.com, Aug 23, 2026) describes "14 tactics, 100+ techniques," but this project does NOT pin a version count. It maps the ten AI-specific techniques exercised by the corpus and registry: AML.T0048 External Harms, AML.T0049 Exploit LLM Toolchain, AML.T0050 Exfiltration via LLM, AML.T0051 LLM Prompt Injection, AML.T0052 LLM Tool Function Injection, AML.T0053 LLM Training Data Poisoning, AML.T0054 LLM Jailbreak, AML.T0056 Extract LLM System Prompt, AML.T0010 ML Supply Chain Compromise, and AML.T0020 ML Model Poisoning. T0056 is corroborated via airiskdeployer.org; T0024 (Exfiltration via AI Inference API) is also referenced in project docs.

Used for: the ATLAS coverage view in `docs/frameworks/MITRE_ATLAS_COVERAGE.md`.

## Governance and Regulatory Frameworks

### NIST AI RMF 1.0

- **Title:** NIST AI RMF 1.0
- **Author / Org:** NIST
- **URL:** https://www.nist.gov/itl/ai-risk-management-framework
- **Date:** January 2023 · **Marker:** [S/V]

Used for: the four-function Govern / Map / Measure / Manage structure behind the compliance console and risk register. Related [V] item: NIST released a concept note on Apr 7, 2026 for an AI RMF Profile on Trustworthy AI in Critical Infrastructure, cited as forward-looking context.

### NIST CSF 2.0

- **Title:** NIST CSF 2.0
- **Author / Org:** NIST
- **URL:** https://www.nist.gov/cyberframework
- **Date:** February 2024 · **Marker:** [S/V]

Used for: the 6-function, 106-sub-category mapping in `src/governance/nist_csf_mapping.py` and `docs/frameworks/NIST_CSF_MAPPING.md`.

### ISO/IEC 42001:2023

- **Title:** ISO/IEC 42001:2023 — AI Management System
- **Author / Org:** ISO/IEC
- **URL:** https://www.iso.org/standard/81230.html
- **Date:** December 2023 · **Marker:** [V]

Corroborated by a clause-by-clause guide dated Jul 9, 2026: clauses 4–10 are mandatory; Annex A provides 38 reference controls under nine objectives (A.2–A.10).

Used for: the Statement of Applicability in `src/governance/iso42001_soa.py` and `docs/frameworks/ISO_42001_MAPPING.md`.

### EU AI Act

- **Title:** Regulation (EU) 2024/1689 (EU AI Act)
- **Author / Org:** European Union
- **URL:** https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- **Date:** July 2024 · **Marker:** [S/V], with the following claims [V]

GPAI obligations apply since 2 Aug 2026, with Article 101 fines up to EUR 15M or 3%; the Digital Omnibus (provisional deal May 2026) shifts Annex III high-risk deployer obligations to 2 Dec 2027; deployer log retention is ≥ 6 months (Articles 12 and 19).

Used for: classification and obligation tracking in the compliance console, including the deployer log-retention check.

### DPDP Act (India)

- **Title:** Digital Personal Data Protection Act, 2023 (DPDPA) and DPDP Rules 2025
- **Author / Org:** MeitY (Ministry of Electronics and IT, India)
- **URL:** https://www.meity.gov.in/data-protection-framework
- **Date:** Act August 2023; Rules notified 14 Nov 2025 · **Marker:** [S/O] for the Act; [V] for the Rules and Rule 7 specifics

Rule 7 requires breach intimation to the Data Protection Board without delay plus a detailed report within 72 hours, and intimation to affected principals without delay (corroborated by dpdpatraining.in, dpdp.llmadvocates.com, and socroom.com, Jun 26, 2026). Full enforcement horizon is ~May 2027 (18-month phase-in).

Used for: breach-notification SLA logic in `src/governance/dpdp_compliance.py` and `docs/frameworks/DPDPA_MAPPING.md`.

## Benchmark Datasets (informed, not redistributed)

- **AdvBench** — Zou et al., 2023; 520 harmful behaviors. [V] (corroborated via OpenReview citing text)
- **HarmBench** — Mazeika et al., 2024; 320 behaviors across 7 categories. [O]
- **JailbreakBench** — Chao et al., 2024; 100 prompts and an evasion taxonomy. [O]
- **Do-Not-Answer** — Wang et al., 2023; 939 questions across 12 risk categories. [O]
- **Overview source (operator-cited):** ar5iv.labs.arxiv.org/html/2602.09629. [O]

Used for: the technique taxonomies that informed curation of the v5.0.0 corpus (adversarial suffixes, payload splitting, encoding bypasses, multiturn escalation, and related families in `attacks/`).

**Honesty note:** the v5 corpus is CURATED by SecureLLM-Enterprise and INFORMED by these benchmarks' technique taxonomies; no benchmark files were redistributed or copied wholesale.

## Red-Team Tooling

- **Garak** — https://github.com/NVIDIA/garak (`pip install -U garak`). [S]
- **PyRIT** — https://github.com/Azure/PyRIT (Python 3.10–3.13). [S]
- **Promptfoo** — https://github.com/promptfoo/promptfoo. [S]

Used for: baseline and secured-state scan reports under `garak_reports/`. In-sandbox status: executed with `SIMULATED=1` (no cloud API keys); live runs occur on the operator machine.

## HuggingFace Datasets (operator-provided references — NOT verified in this environment)

- `scthornton/securecode-aiml` — 747 examples, OWASP LLM Top 10 2025. [O]
- `darkknight25/AI_Agent_Evasion_Dataset` — 1,000 prompts. [O]
- `9mark9/llm-redteam-owasp-prompts` [O]
- `Shomi28/prompt-injection-dataset` [O]
- `Rubyglask/llm-redteam-corpus-taxonomy` [O]

Used for: reference only — operator-provided pointers to related red-team corpora; none were pulled into this repository.

## Verification Taxonomy Legend

- **[V] verified** — confirmed via web search in the v5.0.0 build session (2026-10-04).
- **[O] operator research** — from the project owner's earlier research sessions.
- **[S] standard metadata** — stable publication facts (title / author / year).

**Honesty note:** Citations state what was verifiable at build time; [O] items are carried from operator research and were not independently re-verified in this environment.
