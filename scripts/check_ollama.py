"""Verify the real-model path end to end: Ollama daemon -> qwen2.5:0.5b ->
one governed generation. Run this BEFORE you demo with the real model.

    python -m scripts.check_ollama          # uses config/app_config.yaml
    OLLAMA_URL=http://192.168.x.x:11434 python -m scripts.check_ollama

Exit codes: 0 = real model ready, 1 = daemon/model problem (the app still
works on the mock backend - see the printed instructions).
"""
import sys

import httpx

from src.common.paths import app_config, get_nested
from src.model import ollama_model
from src.model.prompts import SYSTEM_PROMPT, build_user_turn


def main() -> int:
    cfg = app_config()
    url = get_nested(cfg, "model.ollama_url", "http://localhost:11434")
    model = get_nested(cfg, "model.ollama_model", "qwen2.5:0.5b")

    print(f"[1/3] Ollama daemon at {url} ...", end=" ")
    if not ollama_model.healthy():
        print("NOT REACHABLE")
        print("      Start it with:  ollama serve   (or install: https://ollama.com)")
        print("      The app will keep running on the deterministic mock backend.")
        return 1
    print("OK")

    print(f"[2/3] Model '{model}' pulled? ...", end=" ")
    try:
        tags = httpx.get(f"{url}/api/tags", timeout=5).json()
        names = [m.get("name", "") for m in tags.get("models", [])]
    except Exception as exc:
        print(f"ERROR ({exc.__class__.__name__})")
        return 1
    if not any(n.startswith(model) for n in names):
        print("NOT FOUND")
        print(f"      Available: {names or 'none'}")
        print(f"      Pull it with:  ollama pull {model}")
        return 1
    print("OK")

    print(f"[3/3] Governed smoke test ({model}) ...", end=" ", flush=True)
    try:
        ctx = ("KNOWLEDGE BASE CONTEXT (namespace-scoped):\n"
               "POLICY DOCUMENT [tech_docs/wfh_policy]:\n"
               "Engineers may work from home up to 3 days per week.")
        out = ollama_model.generate(SYSTEM_PROMPT,
                                    build_user_turn("What is the WFH policy?",
                                                    ctx))
    except ollama_model.ProviderUnavailable as exc:
        print("FAILED")
        print(f"      {exc}")
        return 1
    print("OK")
    print("\n--- model reply (wrapped by L5 system prompt + L6 DLP in the app) ---")
    print(out.strip()[:400] or "(empty response)")
    print("---------------------------------------------------------------------")
    print("Real-model path is ready:  MODEL_PROVIDER=auto python run.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
