"""Verify the colibri path end to end: OpenAI-compatible server (coli serve,
or any OpenAI-style endpoint such as Ollama's /v1 compatibility layer) ->
one governed-shape generation. Run this BEFORE you point MODEL_PROVIDER at
colibri.

    python -m scripts.check_colibri          # uses config/app_config.yaml
    COLIBRI_URL=http://127.0.0.1:8000 python -m scripts.check_colibri

Typical colibri startup being verified against:
    COLI_MODEL=/nvme/glm52_i4 COLI_API_KEY=local-secret ./coli serve \\
        --host 127.0.0.1 --port 8000 --model-id glm-5.2-colibri
    MODEL_PROVIDER=colibri COLIBRI_URL=http://127.0.0.1:8000 \\
        COLIBRI_API_KEY=local-secret python run.py

Exit codes: 0 = server reachable + model answered, 1 = server/model problem
(the app still works on the ollama/mock backends - see printed instructions).
"""
import sys

import httpx

from src.common.paths import app_config, get_nested
from src.model import colibri_model
from src.model.prompts import SYSTEM_PROMPT, build_user_turn


def main() -> int:
    cfg = app_config()
    url = get_nested(cfg, "model.colibri_url", "http://localhost:8000")
    api_key = get_nested(cfg, "model.colibri_api_key", "") or ""
    model = get_nested(cfg, "model.colibri_model", "glm-5.2-colibri")
    headers = ({"Authorization": f"Bearer {api_key}"} if api_key else {})

    print(f"[1/3] OpenAI-compatible server at {url} ...", end=" ")
    if not colibri_model.healthy():
        print("NOT REACHABLE")
        print("      Start colibri with:  "
              "COLI_MODEL=<model_dir> ./coli serve --host 127.0.0.1 "
              "--port 8000 --model-id " + model)
        print("      The app will keep running on the ollama/mock backend.")
        return 1
    print("OK")

    print(f"[2/3] Model id '{model}' served? ...", end=" ")
    try:
        listing = httpx.get(f"{url}/v1/models", headers=headers,
                            timeout=5).json()
        ids = [str(m.get("id", "")) for m in listing.get("data", [])]
    except Exception as exc:
        print(f"ERROR ({exc.__class__.__name__})")
        return 1
    if ids and model not in ids:
        print("NOT LISTED")
        print(f"      Server serves: {ids}")
        print("      Set COLIBRI_MODEL (or model.colibri_model) to one of "
              "those ids.")
        return 1
    print("OK")

    print(f"[3/3] Governed-shape smoke test ({model}) ...", end=" ",
          flush=True)
    try:
        ctx = ("KNOWLEDGE BASE CONTEXT (namespace-scoped):\n"
               "POLICY DOCUMENT [tech_docs/wfh_policy]:\n"
               "Engineers may work from home up to 3 days per week.")
        out = colibri_model.generate(SYSTEM_PROMPT,
                                     build_user_turn(
                                         "What is the WFH policy?", ctx),
                                     model=model)
    except colibri_model.ProviderUnavailable as exc:
        print("FAILED")
        print(f"      {exc}")
        return 1
    print("OK")
    print("\n--- model reply (in the app this passes through L6 DLP + L7 "
          "audit like every other answer) ---")
    print(out.strip()[:400] or "(empty response)")
    print("\ncolibri backend ready: MODEL_PROVIDER=colibri python run.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
