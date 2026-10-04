# LLM Internals — Attention, GQA, RoPE, and Why They Matter for Security

**Scope**: the serving model this project hardens is `Qwen/Qwen2.5-0.5B` via
Ollama (`model.ollama_model` in `config/app_config.yaml`). Every architectural
number below is read from the published model configuration
(`huggingface.co/Qwen/Qwen2.5-0.5B`, config.json), not from memory. The point
of this document is the one the interview asks for: **a security engineer who
only knows prompts is testing the surface — the real attack surface includes
how the model consumes memory and position.**

| Fact | Value (config.json) | Why a security engineer cares |
|---|---|---|
| Layers | 24 | KV-cache size scales linearly with this |
| Attention heads | 14 | query count per layer |
| KV heads | **2** | **GQA: 7x smaller KV-cache than MHA** |
| Hidden size | 896 | per-token state width |
| RoPE theta | 1,000,000 | ABF-style long-context base |
| Max position embeddings | 32,768 | 32K context = the LLM10 cost ceiling |
| Tied embeddings | true | 0.5B-class efficiency choice |

Papers: *Attention Is All You Need* (Vaswani et al., 2017),
*GQA: Training Generalized Multi-Query Attention from Multi-Head Checkpoints*
(Ainslie et al., 2023), *RoFormer: Enhanced Transformer with Rotary Position
Embedding* (Su et al., 2021), *Qwen2.5 Technical Report* (arXiv:2412.15115).

---

## 1. Attention in one paragraph (and the leak it enables)

Attention computes, for every generated token, a weighted average of "value"
vectors from ALL previous tokens, where the weights come from a softmax over
query-key dot products: `softmax(QK^T/sqrt(d))V`. There is **no provenance
boundary** inside that softmax: system-prompt tokens, retrieved RAG chunks,
and user input are all just positions competing for attention weight. That is
the mechanical reason **prompt injection works** (OWASP LLM01) — an
instruction hidden in a retrieved document can out-attend the system prompt —
and it is why this project does not rely on "the model will ignore it": L2
input governance (48-rule registry), L4 RAG namespace isolation, and L6
output DLP exist precisely because attention itself offers no trust
separation. Multi-turn jailbreaks (the corpus's `multiturn_escalation` file)
work for the same reason: the context window keeps earlier attacker
framing attending strongly across turns.

## 2. GQA — Grouped Query Attention (the KV-cache economics)

Standard MHA keeps a full Key/Value vector for **every** head at **every**
position: KV-cache = `2 x layers x heads x head_dim x seq_len`. Qwen2.5-0.5B
shares **2 KV heads across 14 query heads** (14:2), so its KV-cache is **7x
smaller** than the MHA equivalent (Ainslie et al.: quality ~ MHA, memory ~
MQA). Security read-outs:

- **LLM10 economics.** Session memory cost = KV-cache, and this project's
  `TokenBudgetGuard` (Layer 2c, v5.1.0) caps exactly that resource per
  session: 20,000 tokens per rolling 10-minute window, input + output.
  With GQA the per-token cost is small — which is exactly why a budget is
  needed: cheap-per-token means an attacker must use *many* tokens to DoS
  you, so the defense has to be a *cumulative* window, not a per-request cap.
- **Prefix/KV-cache reuse is a trust boundary.** Serving engines cache KV
  blocks for shared prefixes. A poisoned "shared prefix" is a cross-request
  channel (memory poisoning, ASI06): the cache forgets who contributed a
  block. Project stance: per-session cache pinning assumptions are why the
  budget key is the **JWT session id** (fresh login = fresh budget), and why
  the audit chain records which backend+model served every answer.
- **Why 0.5B is the right lab size.** The defense stack must be model-agnostic
  — the same 48 rules, DLP shapes and budget logic must hold for qwen3:8b or a
  frontier MoE via colibri. Testing on a model with a 7x-reduced KV footprint
  keeps the whole harness runnable on a laptop while the *controls* stay
  invariant across model swaps (documented in `docs/model_manifest.md`).

## 3. RoPE — Rotary Position Embedding (position as a security parameter)

RoPE encodes absolute position as a rotation of the Q/K vectors, so that the
QK dot product depends only on **relative** position (Su et al. 2021); each
head-dimension pair rotates at a different frequency. Qwen2.5 uses an
ABF-style base of `rope_theta = 1,000,000` enabling a native 32,768-token
context. Security read-outs:

- **32K context is a cost weapon (LLM10).** A single request can legally
  carry ~32K tokens; attention is O(n^2) work per layer (24 layers of
  quadratic attention per forward pass). Payload caps
  (`availability.max_prompt_chars`) and the per-minute token limiter (L2a)
  stop request-level abuse; the **session budget (L2c)** stops the aggregate
  that neither per-request cap sees. Mid-stream, the streaming DLP flush cap
  bounds how much unverified text can pile up while a long generation is
  still running.
- **Long-context attacks are position games.** "Lost in the middle":
  instruction-relevant content placed mid-context gets less attention mass —
  attackers exploit this by burying injection between filler so it is read
  by the model but skipped by human review; conversely, defenders can't rely
  on "the model saw the rule" at position 0. The corpus's payload-splitting
  and multi-turn escalation attack files exercise exactly this, and the
  faithfulness check (L6) verifies sensitive output figures against the
  retrieved context regardless of where they sat.
- **RoPE rotation is deterministic — retrieval metadata is not.** Nothing in
  the rotation "knows" a chunk came from `hr_docs` vs a poisoned document;
  provenance must be tracked OUTSIDE the model (namespace isolation, source
  citation in the SSE `meta` event). That is the architectural reason RAG
  security cannot be delegated to the model.

## 4. Where this shows up in the running code

| Concept | Code | Framework hook |
|---|---|---|
| Session KV budget (20k/10min, in+out) | `src/governance/token_budget.py` | OWASP LLM10 · NIST AI RMF MEASURE 2.7 · CSF 2.0 PR.DS/RS |
| Mid-stream cutoff on budget exhaustion | `src/api/main.py` `_chat_stream_impl` | OWASP LLM10 · availability pillar (CIA-A) |
| Streaming DLP scan/flush windows | `src/governance/streaming_dlp.py` | OWASP LLM02 · EU AI Act Art.15 (accuracy/robustness controls) |
| Prompt-injection rules over untrusted content | `config/behavior_rules.yaml` | OWASP LLM01 · MITRE ATLAS LLM Prompt Injection |
| Model identity in audit meta | `docs/model_manifest.md` | ISO/IEC 42001 A.8 (information for interested parties) |

## 5. Deliberate limitations (stated, not hidden)

- Token counts are **estimated** with the same chars/4 ratio as the L2 rate
  limiter for a single consistent estimator; Ollama exposes exact
  `prompt_eval_count` / `eval_count` fields, and swapping the estimator for
  provider-true usage is a drop-in change isolated to `token_budget.py` +
  the two accounting call sites. Estimated counts are conservative for
  enforcement and are labelled `*_estimate` in every API response and audit
  meta.
- The KV-cache discussion here is engineering inference from published
  serving literature (Orca, vLLM PagedAttention, DistServe) applied to
  Ollama/llama.cpp-style serving; this project does not modify the serving
  engine itself — it governs the traffic that shapes the cache.
