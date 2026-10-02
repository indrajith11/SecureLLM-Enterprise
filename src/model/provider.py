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

Backend registry (colibri integration): _BACKENDS maps an active backend
name to the wire-level module implementing generate()/generate_stream().
"ollama" stays the auto default; "colibri" (OpenAI-compatible serving of
frontier MoE models streamed from disk, e.g. GLM-5.2 744B) is an explicit
opt-in - it is deliberately NEVER auto-selected, because auto-detecting a
different model stack and silently routing governed traffic to it would
violate the CHAT-01 no-silent-brain-swap rule. Unknown MODEL_PROVIDER
values fail closed to "mock" instead of pretending to be the requested
backend. Both real backends share ONE retry/routing/degradation code path
below; only the wire module differs.
"""
import time
from dataclasses import dataclass

import httpx

from src.governance import metrics
from src.model import colibri_model, mock_model, ollama_model
from src.model.prompts import (SYSTEM_PROMPT, build_user_turn,  # noqa: F401
                               route_intent)

# Active backend name -> wire-level module. Both modules expose
# generate()/generate_stream()/healthy() and their own ProviderUnavailable.
_BACKENDS = {"ollama": ollama_model, "colibri": colibri_model}
_PROVIDER_ERRORS = (ollama_model.ProviderUnavailable,
                    colibri_model.ProviderUnavailable)
_VALID_PROVIDERS = {"auto", "mock"} | set(_BACKENDS)

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
    "[Model notice] The primary model backend was unreachable for this "
    "request ({reason}). This reply came from the offline mock model, so it "
    "may be lower quality than usual.\n\n")


def resolve_backend(requested: str) -> str:
    global _backend, _requested
    _requested = requested
    if requested == "auto":
        _backend = "ollama" if ollama_model.healthy() else "mock"
    elif requested in _VALID_PROVIDERS:
        _backend = requested
    else:
        # Fail closed: an unrecognized provider name must never silently
        # serve from the mock while /health claims the requested backend.
        _backend = "mock"
    return _backend


def backend_name() -> str:
    return _backend or "unresolved"


def _routing(backend: str | None = None) -> dict:
    """Model-pair configuration (monkeypatch point for tests).
    The default single-model id follows the active backend: ollama keeps
    model.ollama_model, colibri keeps model.colibri_model. Explicit
    fast_model/reasoner_model keys always win over these defaults - for a
    colibri install point them at the coli serve --model-id.

    BUGFIX (big-model sweep): fast_model/reasoner_model in app_config.yaml
    are scoped to the ollama backend. When the colibri backend is active,
    a fast/reasoner value equal to the OLLAMA default model-id must not
    leak into colibri requests (the colibri server has no such model-id:
    every request would 404, and audit meta would attribute the wrong
    model). They fall back to the colibri model id instead; any other
    explicit value is still honored as a deliberate override."""
    from src.common.paths import app_config, get_nested
    cfg = app_config()
    backend = backend or _backend or "ollama"
    ollama_default = get_nested(cfg, "model.ollama_model", "qwen2.5:0.5b")
    if backend == "colibri":
        default_model = get_nested(cfg, "model.colibri_model",
                                   "glm-5.2-colibri")
    else:
        default_model = ollama_default

    def _scoped(key: str) -> str:
        val = get_nested(cfg, key, None)
        if backend == "colibri" and val == ollama_default:
            return default_model
        return val or default_model

    fast = _scoped("model.fast_model")
    reasoner = _scoped("model.reasoner_model")
    return {
        "mode": get_nested(cfg, "model.routing", "heuristic"),
        "fast": str(fast),
        "reasoner": str(reasoner),
        "fast_tokens": int(get_nested(cfg, "model.fast_intent_max_tokens", 0)),
        "reason_tokens": int(get_nested(
            cfg, "model.reason_intent_max_tokens", 0)),
    }


def _route(question: str) -> tuple[str, list[str], bool, int | None]:
    """Return (intent, model_chain, think, max_tokens) for the ACTIVE
    backend (module-global _backend - set by resolve_backend or tests).

    The chain lists models to try in order: the intent's primary first,
    then the OTHER model of the pair when it differs (3.1 fallback).
    routing=single disables the pair and serves the backend's default
    model (model.ollama_model for ollama, model.colibri_model for
    colibri).
    """
    r = _routing()   # backend default flows from the module-global _backend
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
    # Probe colibri only when it is actually in play: /health must not pay
    # a second network timeout for a backend nobody requested.
    colibri_in_play = (_requested == "colibri"
                       or backend_name() == "colibri")
    return {
        "requested_provider": _requested,
        "active_backend": backend_name(),
        "ollama_reachable": ollama_model.healthy(),
        "colibri_reachable": (colibri_model.healthy()
                              if colibri_in_play else None),
        "fallback_reason": _last_fallback_reason or None,
        "routing": r["mode"],
        "fast_model": r["fast"],
        "reasoner_model": r["reasoner"],
    }


def generate(question: str, context: str, user_turn: str) -> GenerateResult:
    """Generate with intent routing, retry-before-fallback and a VISIBLE
    degradation. Never silently swaps the answering backend (CHAT-01).
    ollama and colibri share this exact loop - only the wire module
    differs ("one code path" governance principle)."""
    global _last_fallback_reason
    mod = _BACKENDS.get(_backend or "")
    if mod is not None:
        intent, chain, think, cap = _route(question)
        last_exc: Exception | None = None
        for idx, model in enumerate(chain):
            attempts = _RETRY_ATTEMPTS if idx == 0 else 1
            for attempt in range(attempts):
                try:
                    text = mod.generate(SYSTEM_PROMPT, user_turn,
                                        model=model, think=think,
                                        max_tokens=cap)
                    metrics.AI_MODEL_ROUTING.labels(
                        intent=intent, model=model).inc()
                    return GenerateResult(text=text, backend=_backend,
                                          model=model, intent=intent)
                except _PROVIDER_ERRORS as exc:
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
