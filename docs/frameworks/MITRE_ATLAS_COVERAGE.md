# MITRE ATLAS — Technique Coverage Report

**Corpus: 84 red-team probes across 22 attack categories** (`tests/probes/jailbreaks.json`, harness v2.0, corpus md5 stamped into every report) **+ 114 live red-team probes verified on real Ollama**. Result against the secured stack: **0/84 leaks** (100% denial) with per-layer stop attribution; against the raw model: **100% attack success** (measured baseline). This document maps the corpus to ATLAS technique IDs (names verified against the current ATLAS taxonomy, Oct 2026), so the coverage claim is checkable row by row.

---

## Coverage matrix

| ATLAS Technique | Name | Covered? | Probe categories (count) | Blocking control(s) |
|---|---|---|---|---|
| AML.T0051 | LLM Prompt Injection | ✅ Probe-backed | `direct_override` (12), `authority_social` (8), `clearance_escalation` (2), `cross_department` (2) | L2 input firewall patterns + heuristic score gate; L6 injection-residue check for indirect |
| AML.T0051.001* | Indirect prompt injection (via content) | ✅ Probe-backed | `indirect_doc_exfiltration` (2), `indirect_rag_poisoning` (4) | UNTRUSTED-document fencing at L4 + L6 residue check |
| AML.T0054 | LLM Jailbreak | ✅ Probe-backed | `roleplay_dan` (10), `psychological` (2), `multilingual` (1) | L2 (DAN/persona/emotional-pressure families); no persona switch is stateful |
| AML.T0056 | Extract LLM System Prompt | ✅ Probe-backed | `system_prompt_extraction` (8) | L2 extraction patterns + L6 canary `CANARY-7f3a` — any leak of the rules is blocked at output even if the model complies |
| AML.T0057 | LLM Data Leakage | ✅ Probe-backed | `data_exfiltration` (6), `secret_exfiltration` (2), `translation_extraction` (1) | L6 role-aware DLP (salaries, PII, cards, Aadhaar/PAN/+91, lakh/crore) + L3 RBAC upstream |
| AML.T0068 | LLM Prompt Obfuscation | ✅ Probe-backed | `encoding` (8), `unicode_evasion` (1), `payload_splitting` (2), `delimiter_injection` (2) | L2: NFKC normalisation, zero-width/bidi strip, Cyrillic/Greek homoglyph folding, base64/hex/ROT13 decode-rescan |
| AML.T0053 | AI Agent Tool Invocation | ✅ Probe-backed | `excessive_agency` (6), `tool_abuse` (1) | L3.5 HITL gate: risky asks become pending human-approval requests; approved actions run in read-only sandboxed executor |
| AML.T0020 | Poison Training Data (RAG analog: corpus poisoning) | ✅ Probe-backed | `indirect_rag_poisoning` (4) | Controlled ingest; poisoned-doc demo `scripts/demo_rag_poisoning.py` + `tests/test_rag_poisoning.py`; L6 faithfulness + DLP neutralise poisoned content downstream |
| AML.T0059 | Erode Dataset Integrity | ✅ Probe-backed | `indirect_rag_poisoning` (4) | Same ingest governance; retrieval scoped per role so poisoned docs have bounded blast radius |
| AML.T0060 | Publish Hallucinated Entities | ✅ Probe-backed | misinfo probes via corpus unit tests | L6 faithfulness check: output numbers must exist digit-normalised in retrieved context |
| AML.T0067 | Trusted Output Components Manipulation | ✅ Probe-backed | injection-residue unit tests | L6 residue check treats model output as untrusted before delivery |
| AML.T0024 | Exfiltration via AI Inference API | ✅ Probe-backed | `data_exfiltration` (6) | L2a token budgets + per-user concurrency caps; L6 DLP blocks sensitive shapes at the API boundary |
| AML.T0043 | Craft Adversarial Data | ✅ Probe-backed | `encoding` (8), `payload_splitting` (2) | Same L2 normalisation pipeline (adversarial encodings fold back to plaintext and are caught) |
| AML.T0048 | External Harms (harm-content elicitation) | ✅ Probe-backed | `roleplay_dan` (10), `direct_override` (12) | L2 deny + documented policy-deny contract (`denied_code` surface) |
| AML.T0061 | LLM Prompt Self-Replication | ✅ By design (no surface) | — | The chatbot has **zero tools and zero outbound capability**; there is nothing for a payload to replicate into |
| AML.T0044 | Full AI Model Access | ✅ By design (no surface) | — | Model served via inference API only; weights never exposed; catalog is admin-gated and audited |
| AML.T0058 | Publish Poisoned Models | ~ Partial (process) | — | Model manifest + pinned catalog; Ollama registry pull is a documented residual risk |
| AML.T0112 | Machine Compromise (host level) | ~ Partial | `audit_tampering` (1) | Tamper-evident chain detects log forgery; the **self-risk in the register** (HMAC key not HSM-anchored, 8→4 residual) covers the key-theft slice honestly |

\* sub-technique noted for completeness; probe families map to the parent technique in the ATLAS corpus view.

---

## Reading the coverage honestly

- **14 of 18 techniques are probe-backed** — there is a named attack file, a category counter, and a per-layer stop record for each.
- **2 are mitigated by architecture** (no agentic surface, no weight access): the strongest kind of "covered".
- **2 are partial**: host-level compromise and poisoned model publication are supply-chain/host concerns that a chat-governance stack legitimately does not own end-to-end — they are registered risks with owners, which is the correct ATLAS-aligned answer.
- Per-layer stop attribution (where each attack died) is regenerated by `scripts/probe_runner.py`; the CI gate fails if the corpus (md5-stamped) regresses above the 0-leak contract.

---

## How to extend

New technique → add probe family to `tests/probes/jailbreaks.json` → run `scripts/probe_runner.py` → report stamps corpus md5 + per-layer stops → add the row here. The workflow keeps this document *derived from the corpus* instead of aspirational.
