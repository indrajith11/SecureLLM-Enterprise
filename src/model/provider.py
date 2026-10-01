"""Provider selection: auto -> ollama if reachable, else mock.

Switch to the real local model (Ollama):
    ollama pull qwen2.5:0.5b
    MODEL_PROVIDER=ollama python run.py     # or leave MODEL_PROVIDER=auto
/scripts/check_ollama.py verifies the daemon, the model, and runs a live
governed smoke test before you demo it.

CHAT-01 remediation (audit Critical): a mid-request Ollama failure used to
silently swap the answer over to the mock model - the user's question was
suddenly answered by a different "brain" with no notice. Now:
  1. the ollama call is retried with a short backoff (transient hiccups);
  2. if it still fails, the fallback to mock HAPPENS but is SURFACED:
     generate() returns a GenerateResult carrying degraded=True + reason,
     and the API prepends a visible banner to the reply body;
  3. the degradation is mirrored in /health and the response meta.

Wave 3.1 (two-model router): every request is classified by the
deterministic route_intent() heuristic (fast lookup vs reason analysis)
and served by fast_model / reasoner_model respectively. The fallback
CHAIN is: primary model (retried) -> the OTHER model of the pair (when
configured differently) -> mock with the visible degraded banner. Which
model actually answered rides in GenerateResult.model, the response meta
and the ai_model_routing_total metric - serving decisions are auditable
like every other governance decision.
"""
import time
from dataclasses import dataclass

import httpx

from src.governance import metrics
from src.model import mock_model, ollama_model
from src.model.prompts import (SYSTEM_PROMPT, build_user_turn,  # noqa: F401
                               route_intent)

_backend: str | None = None
_requested: str = "auto"
_last_fallback_reason: str = ""

_RETRY_ATTEMPTS = 2          # initial try + 2 retries (primary model)
_RETRY_BACKOFF_S = 0.4


@dataclass
class GenerateResult:
    text: str
    backend: str                    # backend that actually produced the text
    degraded: bool = False          # True when we fell back from ollama
    reason: str = ""                # why the fallback happened
    model: str = ""                 # which model of the chain answered
    intent: str = "fast"            # fast | reason (route_intent output)


DEGRADED_BANNER = (
    "[Model notice] The primary model (Ollama) was unreachable for this "
    "request ({reason}). This reply came from the offline mock model, so it "
    "may be lower quality than usual.\n\n")


def resolve_backend(requested: str) -> str:
    global _backend, _requested
    _requested = requested
    if requested == "auto":
        _backend = "ollama" if ollama_model.healthy() else "mock"
    else:
        _backend = requested
    return _backend


def backend_name() -> str:
    return _backend or "unresolved"


def _routing() -> dict:
    """Model-pair configuration (monkeypatch point for tests)."""
    from src.common.paths import app_config, get_nested
    cfg = app_config()
    default_model = get_nested(cfg, "model.ollama_model", "qwen2.5:0.5b")
    fast = get_nested(cfg, "model.fast_model", default_model) or default_model
    reasoner = (get_nested(cfg, "model.reasoner_model", default_model)
                or default_model)
    return {
        "mode": get_nested(cfg, "model.routing", "heuristic"),
        "fast": str(fast),
        "reasoner": str(reasoner),
        "fast_tokens": int(get_nested(cfg, "model.fast_intent_max_tokens", 0)),
        "reason_tokens": int(get_nested(
            cfg, "model.reason_intent_max_tokens", 0)),
    }


def _route(question: str) -> tuple[str, list[str], bool, int | None]:
    """Return (intent, model_chain, think, max_tokens).

    The chain lists models to try in order: the intent's primary first,
    then the OTHER model of the pair when it differs (3.1 fallback).
    routing=single disables the pair and serves model.ollama_model.
    """
    r = _routing()
    if r["mode"] == "single":
        return "fast", [r["fast"]], None, None
    intent = route_intent(question)
    if intent == "reason":
        primary, other = r["reasoner"], r["fast"]
        think, cap = True, r["reason_tokens"] or None
    else:
        primary, other = r["fast"], r["reasoner"]
        think, cap = False, r["fast_tokens"] or None
    chain = [primary] + ([other] if other and other != primary else [])
    return intent, chain, think, cap


def status() -> dict:
    """Everything an operator (or /health) needs about the model layer."""
    r = _routing()
    return {
        "requested_provider": _requested,
        "active_backend": backend_name(),
        "ollama_reachable": ollama_model.healthy(),
        "fallback_reason": _last_fallback_reason or None,
        "routing": r["mode"],
        "fast_model": r["fast"],
        "reasoner_model": r["reasoner"],
    }


def generate(question: str, context: str, user_turn: str) -> GenerateResult:
    """Generate with intent routing, retry-before-fallback and a VISIBLE
    degradation. Never silently swaps the answering backend (CHAT-01)."""
    global _last_fallback_reason
    if _backend == "ollama":
        intent, chain, think, cap = _route(question)
        last_exc: Exception | None = None
        for idx, model in enumerate(chain):
            attempts = _RETRY_ATTEMPTS if idx == 0 else 1
            for attempt in range(attempts):
                try:
                    text = ollama_model.generate(SYSTEM_PROMPT, user_turn,
                                                 model=model, think=think,
                                                 max_tokens=cap)
                    metrics.AI_MODEL_ROUTING.labels(
                        intent=intent, model=model).inc()
                    return GenerateResult(text=text, backend="ollama",
                                          model=model, intent=intent)
                except ollama_model.ProviderUnavailable as exc:
                    last_exc = exc
                    if attempt < attempts - 1:
                        time.sleep(_RETRY_BACKOFF_S * (attempt + 1))
        # The whole chain failed: degrade, but say so - in the reply body,
        # in the response meta, and in /health (CHAT-01).
        _last_fallback_reason = str(last_exc)[:120]
        metrics.AI_MODEL_ROUTING.labels(
            intent=intent, model="mock (fallback)").inc()
        mock_text = mock_model.generate(question, context)
        return GenerateResult(text=mock_text, backend="mock (fallback)",
                              degraded=True, reason=_last_fallback_reason,
                              model="mock", intent=intent)
    return GenerateResult(text=mock_model.generate(question, context),
                          backend="mock", model="mock")
