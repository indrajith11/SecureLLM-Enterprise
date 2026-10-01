"""Provider selection: auto -> ollama if reachable, else mock.

Switch to the real local model (Ollama):
    ollama pull qwen2.5:0.5b
    MODEL_PROVIDER=ollama python run.py     # or leave MODEL_PROVIDER=auto
/scripts/check_ollama.py verifies the daemon, the model, and runs a live
governed smoke test before you demo it.
"""
import httpx

from src.model import mock_model, ollama_model
from src.model.prompts import SYSTEM_PROMPT, build_user_turn  # noqa: F401 (re-export)

_backend: str | None = None
_requested: str = "auto"
_last_fallback_reason: str = ""


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


def status() -> dict:
    """Everything an operator (or /health) needs about the model layer."""
    return {
        "requested_provider": _requested,
        "active_backend": backend_name(),
        "ollama_reachable": ollama_model.healthy(),
        "fallback_reason": _last_fallback_reason or None,
    }


def generate(question: str, context: str, user_turn: str) -> str:
    global _last_fallback_reason
    if _backend == "ollama":
        try:
            return ollama_model.generate(SYSTEM_PROMPT, user_turn)
        except ollama_model.ProviderUnavailable as exc:
            # graceful degradation: continue with mock backend, and SAY so
            _last_fallback_reason = str(exc)[:120]
    return mock_model.generate(question, context)
