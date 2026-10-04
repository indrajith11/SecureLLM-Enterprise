# Gap report - v5.0.0 (honest limitations)

This project's rule: no security theatre. Every limitation below is a scoped, verifiable statement - and most come with the exact command that removes them.

## 1. Mock backend, not a live LLM

The secured/baseline numbers in this run use the deliberately naive mock model (src/model/mock_model.py), which leaks whenever override language reaches it. This makes the LAYER DELTA real and reproducible offline, but absolute live-model leak rates require Ollama: `python -m tests.run_attacks --mode live --model qwen2.5:0.5b`. Every report labels its backend.

## 2. Garak / PyRIT runs are SIMULATED in the sandbox

Without cloud API keys the harness executes garak/PyRIT in SIMULATED=1 mode; on the operator's machine they run live via scripts/run_garak.sh.

## 3. LLM03/LLM04 runtime scope

Supply-chain and poisoning attacks are detected at the input and policy layers; this demo cannot execute model downloads to prove end-to-end artifact-level defence. Rule supply_chain_trust + corpus coverage is the honest scope.

## 4. LLM08 has zero WAF rules - by design

Vector/embedding weaknesses are mitigated at L3/L4 (namespace allowlists, per-namespace RAG) not at the input firewall; the coverage matrix marks the 0 explicitly.

## 5. ISO 42001 / DPDPA are SELF-assessments

The SoA (38 Annex A controls) and DPDPA map are computed from live evidence but are NOT certifications or audits. Refs: iso.org/standard/81230.html; meity.gov.in.

## 6. Framework subset mapping for CSF 2.0

CSF 2.0 defines 106 sub-categories; this project claims a 23-subcategory AI-relevant subset and computes coverage over that subset only (100%). Full enumeration is document-level.

## 7. Baseline leak detection is shape-based

The runner detects money/email/phone/system-prompt/secret/SQL-exec shapes; semantic leaks (paraphrased PII) need the L6 context-faithfulness check, which runs in-pipeline but is not part of the offline scorer.

## 8. Residual self-risk: audit key custody

The HMAC audit signing key lives in config/env, not an HSM - recorded in the risk register (inherent 8 -> residual 4) as a real, tracked risk.

