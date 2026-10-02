# colibri backend: frontier MoE models through the same governance pipeline

**Status: shipped in v4.3.0 · extended v4.3.1 (live 1.5-2 GB sweep + routing-leak fix) · no colibri
model can run on the current dev host (honest hardware verdict below).**

[colibri](https://github.com/JustVugg/colibri) (JustVugg, v1.12.1) is a
pure-C inference engine whose trick is treating VRAM + RAM + storage as one
hierarchy: the dense part of a huge Mixture-of-Experts model stays resident
and the routed experts stream from disk on demand. That is how it runs
models like **GLM-5.2 (744B)** or **Kimi K3 (2.8T)** on machines that could
never hold them in memory. Its `coli serve` gateway exposes a standard
**OpenAI-compatible HTTP API** — and that endpoint is exactly what
SecureLLM-Enterprise's model layer now speaks as a second real backend.

The governance property this buys: **the model behind L5 is a routing
decision, not an architecture change.** A colibri-served GLM-5.2 answer
passes through the identical L1–L7 pipeline, lands in the same HMAC audit
chain with `backend + model` attribution in the audit meta, and degrades
visibly to the mock under saturation or outage, like every other backend.

---

## 1. What was actually tried on the dev host (9.2 GB free disk, 3.9 GB RAM, 2 vCPU)

- **Engine:** the prebuilt v1.12.1 Linux x86_64 release (~3.6 MB unpacked,
  9 family engines + the Python `openai_server.py` gateway) downloads,
  unpacks and runs here — `python3 coli info` reports
  `colibri v1.12.1 · 9 model families · MoE experts streamed from disk`.
  The engine itself is a non-issue on any host.
- **Models:** every family is over this host's floor. The planner requires
  the real container to emit a placement plan (a config-only stub is
  refused: `cannot create resource plan: no safetensors shards`), so the
  verdict below uses colibri's official per-family requirements table
  against the measured host.

| Family | Weights on disk | RAM needed | Fits this host? |
|---|---|---|---|
| OLMoE (7B/1B active) — smallest | ~7 GB (int8) | 8 GB | **No** — RAM (3.9 GB total) |
| Qwen3.6-35B-A3B | ~20 GB (int4-gs64) | 24 GB (full residency) | No — RAM + disk |
| DeepSeek V4 Flash (284B) | ~167 GB | 16 GB min | No |
| Qwen3.8-Flash-Next (125B) | ~185.5 GB | 16 GB min | No |
| GLM-5.3-Flash (321B) | ~195 GB | 25 GB | No |
| GLM-5.2 (744B, reference) | ~372 GB | 16 GB min | No |
| GLM-5.3 (744B) | ~419 GB | 16 GB min | No |
| Inkling (975B) | ~469 GB | 25 GB (int4 dense) | No |
| Kimi K3 (2.8T) | ~1.6 TB | 32 GB+ | No |

**Conclusion:** colibri is the *upgrade path*, not a small-host option —
even its smallest family wants 2× our RAM and would eat 3/4 of our disk.
The integration was therefore built and verified at the protocol level
(stub server + cross-implementation proof), so that moving SecureLLM to a
capable box (≥32 GB RAM + NVMe) activates frontier-class reasoning with a
config flip and **zero code change**.

## 2. Verification performed (what "tested" means for this backend)

| Check | Evidence |
|---|---|
| Engine runs on dev host | `python3 coli info` → v1.12.1 ready, 9 families |
| OpenAI JSON contract | 17 tests in `tests/test_colibri_provider.py` against a real-TCP stub of `coli serve` (`/v1/models`, `/v1/chat/completions`) |
| SSE streaming contract | stub streams `data: {...delta.content}` → `data: [DONE]`; adapter yields pieces; empty + mid-stream drop both raise `ProviderUnavailable` |
| Saturation semantics | HTTP 429 (colibri's designed admission-queue signal) maps into the retry → other-model → **visible** mock chain |
| Auth | `Authorization: Bearer` sent only when `colibri_api_key` is configured |
| Thinking routing | `reasoning_effort` rides only when the intent router asked for thinking (GLM contract) |
| Cross-implementation proof | adapter run **unmodified** against Ollama's independent OpenAI-compatible endpoint (`/v1/chat/completions`) with real `qwen2.5:0.5b`: reachable → model listed → grounded answer, exit 0 |
| Fail-closed selection | `MODEL_PROVIDER=bogus` resolves to `mock`; `auto` never picks colibri (explicit opt-in only — no silent brain swap, CHAT-01) |
| Regression | full suite 296/296 green (incl. routing-leak regression test) |
| **Not tested** | a real colibri-served frontier model (no family fits this host); tool calling through GLM-5.2/Kimi K3/DeepSeek V4; `coli`'s Brio endpoint |

## 3. Live sweep: 1.5–2 GB models through the colibri path (v4.3.1)

"No colibri family fits this host" answers the colibri-native question, but
not the user question behind it — *can this box serve a bigger, better-
reasoning model through the colibri integration?* Yes: the adapter speaks
the OpenAI protocol, and Ollama also speaks the OpenAI protocol, so
1.5–2 GB-class models can flow through the identical `colibri` backend path
(`MODEL_PROVIDER=colibri`, `COLIBRI_URL` → Ollama's `/v1`). Real runs,
real SQLite, full L1–L7 pipeline, 6 verifiable reasoning prompts + grounded
policy Q per model:

| Model (q4 size) | Reasoning score | p50 latency | Audit-meta attribution |
|---|---|---|---|
| qwen2.5:0.5b (397 MB) | 1/6 | 10.3 s | `colibri · qwen2.5:0.5b` |
| qwen2.5:1.5b (986 MB) | 3/6 | 17.9 s | `colibri · qwen2.5:1.5b` |
| qwen2.5:3b (1.9 GB) | **5/6** | 33.9 s | `colibri · qwen2.5:3b` |

Governance held at every size: role-scoped CIA-C denial for the analyst
asking an HR question, 5 retrieval sources cited, `meta.backend + meta.model`
correct per run, probe gate re-run after the sweep: **0/84 secured leaks**.
Chart: `docs/screenshots/10_colibri_big_models.png`; raw results:
`scripts/test_results/colibri_big_models.json`.

**Bug the sweep caught (fixed in v4.3.1):** `app_config.yaml` ships
`fast_model` / `reasoner_model: qwen2.5:0.5b` — scoped to the ollama backend,
but `_routing()` let them win on the colibri path too. Result: a colibri
request went out with the *ollama* model-id (audit meta even attributed the
wrong model; a real `coli serve` would 404 every request). `_routing()` now
treats a fast/reasoner value equal to the ollama default as ollama-scoped and
falls back to `model.colibri_model`; any other explicit value is still an
honored override. Regression test:
`test_ollama_scoped_fast_reasoner_do_not_leak_into_colibri`.

## 4. Wiring guide (when you have the hardware)

```bash
# 1) engine + model (example: GLM-5.2 on a 32 GB+ host with NVMe)
#    prebuilt container: mastouri/GLM-5.2-colibri-int4-g64-with-int8-mtp (372 GB)
./coli serve --host 127.0.0.1 --port 8000 \
    --model-id glm-5.2-colibri          # COLI_MODEL=/nvme/glm52_i4

# 2) verify
COLIBRI_URL=http://127.0.0.1:8000 python -m scripts.check_colibri

# 3) run SecureLLM against it
MODEL_PROVIDER=colibri \
COLIBRI_URL=http://127.0.0.1:8000 \
COLIBRI_MODEL=glm-5.2-colibri \
python run.py
```

Config keys (env overrides exist for all three; yaml lives in
`config/app_config.yaml`): `model.colibri_url`, `model.colibri_api_key`,
`model.colibri_model`. The two-model intent router needs no extra config
since v4.3.1: ollama-scoped `fast_model` / `reasoner_model` defaults no
longer leak into the colibri path (see section 3). To run a deliberate
colibri pair, point `model.fast_model` / `model.reasoner_model` at the
`--model-id` the server was started with (a single `coli serve` hosts one
model, so a fast/reasoner pair would need two servers on two ports, or
`routing: single`). Docker compose passes `COLIBRI_URL` /
`COLIBRI_API_KEY` / `COLIBRI_MODEL` through.

## 5. Operations & security notes

- **Auth:** run `coli serve` with `COLI_API_KEY` set and mirror it in
  `colibri_api_key`. colibri's default bind is localhost; keep it that way
  and let the app talk over the loopback (or a private network in compose).
- **Saturation is designed, not exceptional:** the engine serves one
  generation at a time through a bounded FIFO admission queue
  (`--max-queue`, `--queue-timeout`); overflow returns OpenAI-shaped 429s
  before streaming starts. The adapter maps 429 onto
  `ProviderUnavailable`, so a busy 744B engine produces the *same*
  visible-degradation path as a dead Ollama daemon — plus the existing
  L2 per-user/global queue gates in front absorb burst load before it
  ever reaches the engine.
- **Auditability:** every answer's audit meta carries `backend` and
  `model` (shipped with the v4.2 audit-meta work), so colibri-served
  answers are attributable in the tamper-evident chain exactly like
  Ollama ones. `/health` reports `colibri_reachable` (only when the
  backend is in play); `/admin/posture` shows URL + model id.
- **Tool calling:** colibri's OpenAI `tools` support is per-engine
  (GLM-5.2, Kimi K3, DeepSeek V4 yes; OLMoE/Qwen3.8 no) — relevant for a
  future agent wave, out of scope for this integration: the adapter sends
  chat messages only, and the Agency Gate (L3.5) stays the sole path to
  any privileged action.
- **Model identity discipline:** the served model id is operator-declared
  (`--model-id` ↔ `colibri_model`); `scripts/check_colibri.py` refuses to
  pass when the server lists a different id, and
  `scripts/model_manifest.py` remains the copy-paste source for the
  deployment's model manifest rows.
