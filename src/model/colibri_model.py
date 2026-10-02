"""colibri provider: OpenAI-compatible frontier MoE serving.

colibri (github.com/JustVugg/colibri) is a pure-C inference engine that
streams huge Mixture-of-Experts models (GLM-5.2 744B, Kimi K3 2.8T,
DeepSeek V4 Flash, Qwen3.6 ...) from disk, treating RAM + storage as one
hierarchy. Its ``coli serve`` gateway exposes a standard OpenAI-compatible
HTTP API, which is the exact seam this module speaks:

    COLI_MODEL=/nvme/glm52_i4 COLI_API_KEY=local-secret ./coli serve \\
        --host 127.0.0.1 --port 8000 --model-id glm-5.2-colibri
    MODEL_PROVIDER=colibri COLIBRI_URL=http://127.0.0.1:8000 \\
        COLIBRI_API_KEY=local-secret python run.py

Wire contract implemented here (docs/api.md of colibri v1.12+):
  - GET  /v1/models            -> reachability probe (healthy())
  - POST /v1/chat/completions  -> JSON mode and SSE streaming mode
  - Bearer auth ONLY when an API key is configured (never send an empty
    Authorization header);
  - reasoning_effort is sent only when the router asked for thinking
    (colibri GLM contract: the standard reasoning_effort field enables
    the reasoning block; omitting it keeps the default off);
  - HTTP 429 is colibri's designed saturation signal (its admission queue
    is bounded because the engine serves one generation at a time) - we
    map it to ProviderUnavailable so the existing retry -> other-model ->
    visible-mock chain treats an overloaded 744B engine exactly like an
    unreachable one. No silent degradation, ever (CHAT-01).

Hardware honesty: no colibri family fits a small host (the smallest,
OLMoE 7B, wants ~7 GB disk + 8 GB RAM; GLM-5.2 wants ~372 GB disk +
16 GB RAM). The provider is fail-closed - if the server is not reachable
the request degrades VISIBLY to the mock. See docs/colibri.md for the
full feasibility table and wiring guide.
"""
import json
from collections.abc import Iterator

import httpx

from src.common.paths import app_config, get_nested


class ProviderUnavailable(Exception):
    pass


def _cfg():
    cfg = app_config()
    url = get_nested(cfg, "model.colibri_url", "http://localhost:8000")
    api_key = get_nested(cfg, "model.colibri_api_key", "") or ""
    model = get_nested(cfg, "model.colibri_model", "glm-5.2-colibri")
    timeout = float(get_nested(cfg, "model.request_timeout_s", 30))
    max_tokens = int(get_nested(cfg, "model.max_output_tokens", 512))
    return url, api_key, model, timeout, max_tokens


def _headers(api_key: str) -> dict:
    if not api_key:
        return {"Content-Type": "application/json"}
    return {"Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"}


def _body(system: str, user_turn: str, model: str, max_tokens: int,
          think: bool | None, stream: bool) -> dict:
    body = {"model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user_turn}],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "stream": stream}
    if think is True:
        # colibri GLM contract: a reasoning_effort other than "none"
        # enables the reasoning block. Nothing is sent when the router
        # did not ask for thinking (think False/None -> default off).
        body["reasoning_effort"] = "low"
    return body


def _explain(exc: Exception, url: str, mid_stream: bool = False) -> str:
    where = "mid-stream" if mid_stream else ""
    return (f"colibri at {url} unavailable {where} "
            f"({exc.__class__.__name__}). Start 'coli serve' or set "
            "MODEL_PROVIDER=mock.").replace("  ", " ")


def generate(system: str, user_turn: str, model: str | None = None,
             think: bool | None = None, max_tokens: int | None = None) -> str:
    url, api_key, default_model, timeout, default_max = _cfg()
    model = model or default_model
    max_tokens = int(max_tokens or default_max)
    try:
        resp = httpx.post(
            f"{url}/v1/chat/completions",
            headers=_headers(api_key),
            json=_body(system, user_turn, model, max_tokens, think, False),
            timeout=timeout)
        if resp.status_code == 429:
            # colibri's bounded admission queue is full - designed load
            # shedding, mapped into the same path as unreachability.
            raise ProviderUnavailable(
                f"colibri at {url} queue saturated (HTTP 429). The engine "
                "serves one generation at a time; retry shortly.")
        resp.raise_for_status()
        data = resp.json()
        content = (data.get("choices") or [{}])[0].get("message", {}).get(
            "content", "")
        if not content:
            raise ProviderUnavailable(
                f"colibri at {url} returned an empty completion.")
        return content
    except ProviderUnavailable:
        raise
    except Exception as exc:  # connection refused, timeout, bad status
        raise ProviderUnavailable(_explain(exc, url)) from exc


def generate_stream(system: str, user_turn: str, model: str | None = None,
                    think: bool | None = None,
                    max_tokens: int | None = None) -> Iterator[str]:
    """Yield incremental text pieces from colibri's SSE stream
    (``data: {...choices[0].delta.content...}`` lines, terminated by
    ``data: [DONE]``). Raises ProviderUnavailable before the first piece
    if the server is down or saturated; a mid-stream failure surfaces as
    ProviderUnavailable too, which the SSE layer converts into a visible
    notice (never a silent swap)."""
    url, api_key, default_model, timeout, default_max = _cfg()
    model = model or default_model
    max_tokens = int(max_tokens or default_max)
    try:
        with httpx.stream(
                "POST", f"{url}/v1/chat/completions",
                headers=_headers(api_key),
                json=_body(system, user_turn, model, max_tokens, think, True),
                timeout=timeout) as resp:
            if resp.status_code == 429:
                raise ProviderUnavailable(
                    f"colibri at {url} queue saturated (HTTP 429). The "
                    "engine serves one generation at a time; retry shortly.")
            resp.raise_for_status()
            produced = False
            for line in resp.iter_lines():
                if not line or not line.startswith("data:"):
                    continue
                payload = line[len("data:"):].strip()
                if payload == "[DONE]":
                    break
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                piece = (obj.get("choices") or [{}])[0].get(
                    "delta", {}).get("content", "")
                if piece:
                    produced = True
                    yield piece
            if not produced:
                raise ProviderUnavailable(
                    f"colibri at {url} returned an empty stream.")
    except ProviderUnavailable:
        raise
    except Exception as exc:
        raise ProviderUnavailable(_explain(exc, url, mid_stream=True)) from exc


def healthy(timeout: float = 0.4) -> bool:
    """colibri serves GET /v1/models (OpenAI-compatible) - any OpenAI-style
    server answering there counts as reachable."""
    url, _key, _m, _t, _x = _cfg()
    try:
        return httpx.get(f"{url}/v1/models",
                         timeout=timeout).status_code == 200
    except Exception:
        return False
