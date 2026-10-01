"""Real-model provider: local Qwen 2.5 0.5B through Ollama.

Enable on your machine:
    ollama pull qwen2.5:0.5b
    MODEL_PROVIDER=ollama python run.py
The app auto-detects Ollama when provider=auto.

CHAT-02: generate_stream() yields text pieces from Ollama's native NDJSON
stream so /api/chat/stream can forward tokens as they are produced instead
of blocking for the whole generation.
"""
import json
from collections.abc import Iterator

import httpx

from src.common.paths import app_config, get_nested


class ProviderUnavailable(Exception):
    pass


def _cfg():
    cfg = app_config()
    url = get_nested(cfg, "model.ollama_url", "http://localhost:11434")
    model = get_nested(cfg, "model.ollama_model", "qwen2.5:0.5b")
    timeout = float(get_nested(cfg, "model.request_timeout_s", 30))
    max_tokens = int(get_nested(cfg, "model.max_output_tokens", 512))
    return url, model, timeout, max_tokens


def generate(system: str, user_turn: str) -> str:
    url, model, timeout, max_tokens = _cfg()
    try:
        resp = httpx.post(
            f"{url}/api/generate",
            json={"model": model, "system": system, "prompt": user_turn,
                  "stream": False, "keep_alive": "10m",
                  "options": {"temperature": 0.1,
                              "num_predict": max_tokens}},
            timeout=timeout)
        resp.raise_for_status()
        return resp.json().get("response", "")
    except Exception as exc:  # connection refused, timeout, model missing
        raise ProviderUnavailable(
            f"Ollama at {url} unavailable ({exc.__class__.__name__}). "
            "Start Ollama or set MODEL_PROVIDER=mock.") from exc


def generate_stream(system: str, user_turn: str) -> Iterator[str]:
    """Yield incremental text pieces from Ollama's streaming endpoint.
    Raises ProviderUnavailable before the first piece if Ollama is down;
    a mid-stream failure surfaces as ProviderUnavailable too, which the
    SSE layer converts into a visible notice (never a silent swap)."""
    url, model, timeout, max_tokens = _cfg()
    try:
        with httpx.stream(
                "POST", f"{url}/api/generate",
                json={"model": model, "system": system, "prompt": user_turn,
                      "stream": True, "keep_alive": "10m",
                      "options": {"temperature": 0.1,
                                  "num_predict": max_tokens}},
                timeout=timeout) as resp:
            resp.raise_for_status()
            produced = False
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                piece = obj.get("response", "")
                if piece:
                    produced = True
                    yield piece
                if obj.get("done"):
                    break
            if not produced:
                raise ProviderUnavailable(
                    f"Ollama at {url} returned an empty stream.")
    except ProviderUnavailable:
        raise
    except Exception as exc:
        raise ProviderUnavailable(
            f"Ollama at {url} unavailable mid-stream "
            f"({exc.__class__.__name__}).") from exc


def healthy(timeout: float = 0.4) -> bool:
    url, _model, _t, _m = _cfg()
    try:
        return httpx.get(f"{url}/api/tags", timeout=timeout).status_code == 200
    except Exception:
        return False
