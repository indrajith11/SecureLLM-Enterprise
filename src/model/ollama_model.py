"""Real-model provider: local Qwen 2.5 0.5B through Ollama.

Enable on your machine:
    ollama pull qwen2.5:0.5b
    MODEL_PROVIDER=ollama python run.py
The app auto-detects Ollama when provider=auto.
"""
import httpx

from src.common.paths import app_config, get_nested


class ProviderUnavailable(Exception):
    pass


def generate(system: str, user_turn: str) -> str:
    cfg = app_config()
    url = get_nested(cfg, "model.ollama_url", "http://localhost:11434")
    model = get_nested(cfg, "model.ollama_model", "qwen2.5:0.5b")
    timeout = float(get_nested(cfg, "model.request_timeout_s", 30))
    try:
        resp = httpx.post(
            f"{url}/api/generate",
            json={"model": model, "system": system, "prompt": user_turn,
                  "stream": False, "keep_alive": "10m",
                  "options": {"temperature": 0.1,
                              "num_predict": int(get_nested(
                                  cfg, "model.max_output_tokens", 512))}},
            timeout=timeout)
        resp.raise_for_status()
        return resp.json().get("response", "")
    except Exception as exc:  # connection refused, timeout, model missing
        raise ProviderUnavailable(
            f"Ollama at {url} unavailable ({exc.__class__.__name__}). "
            "Start Ollama or set MODEL_PROVIDER=mock.") from exc


def healthy(timeout: float = 0.4) -> bool:
    cfg = app_config()
    url = get_nested(cfg, "model.ollama_url", "http://localhost:11434")
    try:
        return httpx.get(f"{url}/api/tags", timeout=timeout).status_code == 200
    except Exception:
        return False
