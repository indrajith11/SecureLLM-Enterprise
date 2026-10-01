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
"""
import time
from dataclasses import dataclass

import httpx

from src.model import mock_model, ollama_model
from src.model.prompts import SYSTEM_PROMPT, build_user_turn  # noqa: F401 (re-export)

_backend: str | None = None
_requested: str = "auto"
_last_fallback_reason: str = ""

_RETRY_ATTEMPTS = 2          # initial try + 2 retries
_RETRY_BACKOFF_S = 0.4


@dataclass
class GenerateResult:
    text: str
    backend: str                    # backend that actually produced the text
    degraded: bool = False          # True when we fell back from ollama
    reason: str = ""                # why the fallback happened


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


def status() -> dict:
    """Everything an operator (or /health) needs about the model layer."""
    return {
        "requested_provider": _requested,
        "active_backend": backend_name(),
        "ollama_reachable": ollama_model.healthy(),
        "fallback_reason": _last_fallback_reason or None,
    }


def generate(question: str, context: str, user_turn: str) -> GenerateResult:
    """Generate with retry-before-fallback and a VISIBLE degradation.
    Never silently swaps the answering backend again (CHAT-01)."""
    global _last_fallback_reason
    if _backend == "ollama":
        last_exc: Exception | None = None
        for attempt in range(_RETRY_ATTEMPTS):
            try:
                text = ollama_model.generate(SYSTEM_PROMPT, user_turn)
                return GenerateResult(text=text, backend="ollama")
            except ollama_model.ProviderUnavailable as exc:
                last_exc = exc
                if attempt < _RETRY_ATTEMPTS - 1:
                    time.sleep(_RETRY_BACKOFF_S * (attempt + 1))
        # All retries exhausted: degrade, but say so - in the reply body,
        # in the response meta, and in /health (CHAT-01).
        _last_fallback_reason = str(last_exc)[:120]
        mock_text = mock_model.generate(question, context)
        return GenerateResult(text=mock_text, backend="mock (fallback)",
                              degraded=True, reason=_last_fallback_reason)
    return GenerateResult(text=mock_model.generate(question, context),
                          backend="mock")
