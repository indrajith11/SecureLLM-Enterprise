# Model Weight Manifest — Supply-Chain Provenance Record

**Pre-deployment security gate, Step 8 (OWASP LLM08 Supply Chain · OWASP LLM05 · ISO 42001 technical documentation · EU AI Act Art. 11 technical documentation).**

Dependencies are pinned and audited in CI (`pip-audit`, `gitleaks`, digest-pinned
Docker base images) — but weights are a supply chain too. This file is the
provenance record for **every model whose weights influence an answer**: the
serving models, the embedding model, and the runtime that executes them.

**Rule:** when a model is updated (re-pulled, re-tagged, swapped in
`config/app_config.yaml`), the corresponding row here is updated **in the same
PR**. Per-request attribution does not live in this file — every successful
answer already records its answering `backend` + `model` in the HMAC-chained
audit `meta` (see `src/governance/audit.py`), so the two layers combine into:
*deployment-level digests* (here) + *per-answer attribution* (audit chain).

## 1. Serving models (the chat brain)

| Role | Model | Source | Digest (sha256) | Size | Pulled | Notes |
|---|---|---|---|---|---|---|
| fast_model (default) | `qwen2.5:0.5b` | Ollama library — https://ollama.com/library/qwen2.5:0.5b | _fill via script ↓_ | ~400 MB | _date_ | default single-model install |
| reasoner_model (default) | `qwen2.5:0.5b` | same as above | same | same | same | point at `qwen3:8b`/`14b` to activate the two-model router |
| runtime | Ollama `0.12.10` | Docker Hub — `ollama/ollama:0.12.10` (tag-pinned) | _registry digest_ | image | _date_ | compose `OLLAMA_NUM_PARALLEL=4`, `KEEP_ALIVE=30m` |

**To fill/refresh the digest rows** (never hand-type — always from the daemon):

```bash
python scripts/model_manifest.py          # prints copy-paste manifest rows
# or against the compose stack:
OLLAMA_URL=http://localhost:11434 python scripts/model_manifest.py
```

The script exits non-zero when the daemon is unreachable — manifest rows are
never guessed. After every `ollama pull`, rerun it and update this file.

## 2. Embedding model (retrieval — Layer 4)

| Setting | Value | Where |
|---|---|---|
| default embedder | `hash` — 256-dim feature hashing (blake2b-based, deterministic, zero-download) | `config/app_config.yaml → retrieval.embedder` |
| opt-in embedder | `sentence-transformers/all-MiniLM-L6-v2` (80 MB, 384-dim) | `retrieval.embedder: st` + `retrieval.st_model` |
| multilingual option | `BAAI/bge-m3` (Hindi/Hinglish, Wave 4.2) | `retrieval.st_model: BAAI/bge-m3` |
| version pin | `sentence-transformers` version is pinned in `requirements.txt` | CI-verified |

Embedder changes are **token-tagged in the vector store**: switching
`embedder`/`st_model` invalidates cached matrices (dimension-safe), and
namespaces rebuild from source texts on first search. To rebuild explicitly:
re-run the ingest container (`docker compose ... up ingest`).

## 3. Degradation path (what answers when the model is down)

| Condition | What answers | Governance |
|---|---|---|
| Ollama unreachable for a request | offline mock model, after retry + model-pair fallback | VISIBLE `[Model notice]` banner in the reply body (CHAT-01 — never silent), `degraded: true` in response meta **and in the audit meta** |
| Operator kill switch | nothing — 503 on all chat routes | `AI_ENABLED=false`, counted in `ai_kill_switch_denials_total` (Step 7) |

## 4. Model change procedure

1. Pull the new weights (`ollama pull <model>`), note the daemon output.
2. Run `python scripts/model_manifest.py` and paste the fresh rows above.
3. Update `model.fast_model` / `model.reasoner_model` in `config/app_config.yaml` if the identifier changed.
4. Re-run the full quality gate: `pytest tests/` (278 tests) **and** `python -m scripts.probe_runner --gate` (0/84 leaks) — a model swap is a behaviour change and must re-prove the 0-leak guarantee.
5. Ship the manifest update, the config change and the green gate evidence in one PR.
6. If the model misbehaves post-deploy: flip `AI_ENABLED=false` (kill switch), then follow `docs/governance/incident_response.md`.
