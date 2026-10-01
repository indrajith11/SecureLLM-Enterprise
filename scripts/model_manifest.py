#!/usr/bin/env python3
"""Model weight provenance helper (pre-deployment security gate, Step 8).

Prints the exact rows an operator copies into docs/model_manifest.md:
model name, Ollama digest, size and pull date - straight from the running
daemon (/api/tags), so the manifest never drifts from what actually serves
traffic. Rerun after every `ollama pull` and update the manifest in the
same PR that changes OLLAMA_MODEL / fast_model / reasoner_model.

Usage:
    python scripts/model_manifest.py                       # default host
    OLLAMA_URL=http://ollama:11434 python scripts/model_manifest.py

The per-ANSWER model identity (backend + model name) is already recorded in
the audit chain meta on every successful /api/chat row - this script covers
the per-DEPLOYMENT half of the provenance record (the immutable digests).

Exit code 1 = daemon unreachable (never fabricate manifest rows).
"""
import json
import os
import sys
import time
import urllib.request

DEFAULT_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
TIMEOUT_S = 5.0


def fetch_models(base_url: str) -> list[dict]:
    with urllib.request.urlopen(f"{base_url}/api/tags", timeout=TIMEOUT_S) \
            as resp:
        return json.load(resp).get("models", [])


def human(n_bytes: int) -> str:
    size = float(n_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def main() -> int:
    base = DEFAULT_URL.rstrip("/")
    try:
        models = fetch_models(base)
    except Exception as exc:                       # noqa: BLE001
        print(f"ERROR: cannot reach Ollama at {base}: {exc}", file=sys.stderr)
        print("Refusing to guess: manifest rows must come from the daemon.",
              file=sys.stderr)
        return 1

    print("# Paste into docs/model_manifest.md (table: Model registry)\n")
    print(f"# Source: {base}/api/tags  |  collected: "
          f"{time.strftime('%Y-%m-%d %H:%M %Z')}\n")
    print("| Model | Digest (sha256, truncated) | Size | Pulled |")
    print("|---|---|---|---|")
    for m in models:
        digest = str(m.get("digest", "")).removeprefix("sha256:")
        pulled = str(m.get("modified_at", ""))[:10]
        print(f"| {m.get('name', '?')} | {digest[:16]}... | "
              f"{human(int(m.get('size', 0)))} | {pulled} |")
    print("\nRemember to also record: embedding model + version "
          "(config/app_config.yaml -> retrieval.embedder / retrieval.st_model) "
          "and the serving runtime (ollama image tag in "
          "deploy/docker-compose.yml).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
