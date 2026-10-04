# Disaggregated Serving Security — Mapping the 7-Layer Pipeline to Prefill vs Decode

**Status: design note / future work.** This project runs a single Ollama
(llama.cpp-class) serving process, so prefill and decode happen in one
engine. Production inference at scale increasingly does NOT: it splits
**prefill** (reading the prompt, computing the first token, filling the
KV-cache) and **decode** (autoregressive token generation) onto different
machines — Orca's continuous batching (OSDI 2022), vLLM's PagedAttention,
and DistServe-style prefill/decode disaggregation (OSDI 2024) all move in
this direction. This note documents, honestly and in advance, **where each
governance layer would land in such an architecture** — the answer is not
trivial, and getting it wrong silently disarms the pipeline.

## 1. The two workloads have different trust profiles

| | Prefill plane | Decode plane |
|---|---|---|
| Input | The ENTIRE untrusted request: user text + retrieved RAG chunks + system prompt | The KV-cache produced by prefill + generated-so-far |
| Dominant risk | Prompt injection, poisoned context, oversized payloads (LLM01/LLM04/LLM10) | Mid-stream leakage, runaway generation, cache abuse (LLM02/LLM10) |
| Bounded by | `max_prompt_chars`, 48-rule input registry, RAG namespace isolation, L2a/L2c admission | Streaming DLP windows, session token budget mid-stream cutoff, output DLP |
| Failure style | One big verdict before the first token | Thousands of small verdicts while tokens fly |

The security consequence: **input filtering is a prefill-plane control and
output filtering is a decode-plane control.** If an operator centralizes all
governance on, say, the API gateway only, the decode plane streams tokens to
users with no DLP in the token path — the exact gap v5.1.0's streaming DLP
(`src/governance/streaming_dlp.py`) closes even in the single-engine case.

## 2. Layer-by-layer placement (this project's L1-L7)

| Layer | Control | Prefill | Decode | Notes for disaggregated deployment |
|---|---|---|---|---|
| L1 | JWT authN/Z, session revocation | x | x | Terminates at the API gateway (unchanged); both planes reject unauthenticated traffic, decode-plane nodes never accept connections outside the serving fabric |
| L2a | Rate limit (per-user/min) | x | — | Admission-time only; enforced before dispatch |
| L2c | **Session token budget (v5.1.0)** | x (admission) | x (mid-stream cutoff) | The budget store must be shared/replicated across prefill+decode schedulers so a session's spend is one global view, not two half-views |
| L2 | 48-rule input firewall | x | — | Runs on the assembled prompt BEFORE it enters the prefill node; after prefill, the text is already inside the KV-cache — too late |
| L3 | RBAC + clearance scoping | x | — | Gates retrieval and the built turn; decode sees no user identity unless the gateway forwards signed context |
| L3.5 | HITL action gate | x | — | Approval interrupts before an action executes; unchanged by serving topology |
| L4 | RAG namespace isolation | x | — | Retrieval happens pre-prefill; poisoned namespaces are a prefill-plane problem (LLM04/ASI06) |
| L5 | System prompt + **canary embedding** | x | detect | Canary is planted prefill; the canary tripwire fires in the decode-plane token stream (implemented in `StreamingDLP` via `output_filter.hard_reasons`) |
| L6 | Output DLP (batch) | — | x | Final full-text verdict at stream end (authoritative) |
| L6s | **Streaming DLP (v5.1.0)** | — | x | Per-sentence scan/redact + forced scan/flush windows + budget-aware revoke, in the decode token path |
| L7 | Hash-chained audit | x | x | Every verdict from both planes must append to ONE chain; split-brain audit stores are a tamper surface. Chain-writer role belongs to the gateway/sidecar, not the engine |

## 3. New attack surfaces disaggregation introduces (be able to say these)

1. **KV-cache transfer is a data channel.** Moving KV blocks prefill→decode
   ships the entire conversation state (including anything sensitive the
   prompt contained) across a network hop. Requirements: mTLS between
   planes, integrity-checked cache transfer, no debug endpoints that dump
   cache contents. A stolen KV block IS a data breach (LLM02) even if no
   "output" ever leaked.
2. **Scheduler queue = LLM10 amplifier.** DistServe-style systems size
   prefill and decode pools independently; a client that inflates prefill
   work (32K-token prompts) starves the prefill pool specifically. The
   session token budget must therefore meter PREFILL input tokens and DECODE
   output tokens against one shared per-session window — exactly how
   `TokenBudgetGuard` is shaped (input at admission, output as produced).
3. **Two planes, two failure modes, one audit story.** A prefill crash is a
   4xx/5xx; a decode crash mid-stream is a partial answer already delivered —
   which is why the SSE contract has a `revoked` event and why mid-stream
   revocations are audit-logged (`_deny_sse_body` + `audit.flag_for_review`).
4. **Prefix-cache sharing is cross-tenant by default unless namespaced.**
   If two users share a system prompt, their KV blocks may be shared; a
   poisoned shared prefix becomes ASI06 memory poisoning with persistence.
   Cache keys must include the tenant/session scope that L4 already enforces
   at retrieval time.

## 4. What exists here vs what is future work

- **Exists (v5.1.0)**: the governance *logic* is already split exactly the
  way disaggregated deployment requires — admission (L1/L2a/L2c-check/
  L2-rules/L3/L3.5/L4) before the first token; streaming DLP + mid-stream
  budget cutoff + final batch verdict in the token path. Because both SSE
  and JSON paths share one `_preflight`, moving the planes apart is a
  deployment change, not a policy rewrite.
- **Future work (documented, not claimed as built)**: shared budget store
  across schedulers (today: single in-process store, thread-safe); mTLS
  cache-transfer enforcement (today: one engine, no transfer exists);
  per-plane metrics export (`ai_session_budget_blocks_total` exists;
  prefill/decode labels would be added with the split).

**One-line interview version**: "Prefill sees untrusted input, decode holds
memory state — so input governance lives before prefill, output DLP lives in
the decode token stream, the session token budget must span both planes
against one shared window, and the audit chain has to see verdicts from both.
I documented that mapping in advance, and the single-engine build already
separates the controls along exactly those seams."
