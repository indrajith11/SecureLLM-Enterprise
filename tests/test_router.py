"""Waves 3.1 + 1.3 - two-model router, fallback chain, think-routing.

Pinned guarantees:
  - route_intent is deterministic and auditable: why/compare/explain ->
    'reason', everything else -> 'fast';
  - the sync provider walks the chain primary -> other-model -> mock, and
    the answer's meta always names the model that actually produced it;
  - Qwen3 thinking soft switches are applied ONLY to qwen3-family models;
  - per-intent output budgets ride through to the Ollama call.
"""
import pytest

from src.model import ollama_model, provider
from src.model.ollama_model import ProviderUnavailable
from src.model.prompts import route_intent


# ---------- Wave 1.3: intent heuristic --------------------------------------
def test_route_intent_matrix():
    assert route_intent("What is the leave policy?") == "fast"
    assert route_intent("Who is on the Tech team?") == "fast"
    assert route_intent("How many employees are in Finance?") == "fast"
    assert route_intent("Why is the retention rate dropping?") == "reason"
    assert route_intent("Compare the HR and Tech on-call policies") == "reason"
    assert route_intent("Explain the deployment process") == "reason"
    assert route_intent("What is the difference between L3 and L4 "
                        "clearance?") == "reason"
    assert route_intent("") == "fast"
    # reason hints win over lookup hints
    assert route_intent("What are the pros and cons of the two "
                        "plans?") == "reason"


def test_apply_think_only_for_qwen3():
    turn = "USER QUESTION: hi"
    assert ollama_model._apply_think(turn, False, "qwen3:8b") == \
        turn + " /no_think"
    assert ollama_model._apply_think(turn, True, "qwen3:14b") == \
        turn + " /think"
    # non-qwen3 models are never touched (Qwen2.5 sees no switches)
    assert ollama_model._apply_think(turn, False, "qwen2.5:0.5b") == turn
    assert ollama_model._apply_think(turn, True, "llama3:8b") == turn
    # think=None -> no switch even on qwen3
    assert ollama_model._apply_think(turn, None, "qwen3:8b") == turn


# ---------- Wave 3.1: routing chain ------------------------------------------
def test_route_single_model_config_defaults():
    """With the shipped config (both models = qwen2.5:0.5b) the chain is
    exactly one model - behaviour unchanged for single-model installs."""
    intent, chain, think, cap = provider._route("What is the wfh policy?")
    assert intent == "fast" and chain == ["qwen2.5:0.5b"]
    assert think is False and cap == 220
    intent, chain, think, cap = provider._route("Explain the backup strategy")
    assert intent == "reason" and chain == ["qwen2.5:0.5b"]
    assert think is True and cap == 600


def test_route_two_models_builds_fallback_chain(monkeypatch):
    monkeypatch.setattr(provider, "_routing", lambda: {
        "mode": "heuristic", "fast": "qwen3:8b", "reasoner": "qwen3:14b",
        "fast_tokens": 220, "reason_tokens": 600})
    intent, chain, think, cap = provider._route("What is the wfh policy?")
    assert (intent, chain) == ("fast", ["qwen3:8b", "qwen3:14b"])
    intent, chain, think, cap = provider._route("Why did the incident happen?")
    assert (intent, chain) == ("reason", ["qwen3:14b", "qwen3:8b"])


def test_generate_falls_back_to_other_model(monkeypatch):
    """Fast model down -> the reasoner answers, and SAYS which model did."""
    monkeypatch.setattr(provider, "_backend", "ollama")
    monkeypatch.setattr(provider, "_route", lambda q: (
        "fast", ["fast-model-x", "big-model-y"], False, 220))

    calls: list[str] = []

    def fake_generate(system, user_turn, model=None, think=None,
                      max_tokens=None):
        calls.append(model)
        if model == "fast-model-x":
            raise ProviderUnavailable("fast model is down")
        return "Answer: ok"

    monkeypatch.setattr(ollama_model, "generate", fake_generate)
    gen = provider.generate("What is the wfh policy?", "ctx", "turn")
    # primary gets the full retry budget (2 attempts), the secondary model
    # gets one shot, then the mock would follow (not reached here)
    assert calls == ["fast-model-x", "fast-model-x", "big-model-y"]
    assert gen.backend == "ollama"
    assert gen.model == "big-model-y"
    assert gen.degraded is False
    assert gen.intent == "fast"


def test_generate_degrades_visibly_when_chain_dead(monkeypatch):
    monkeypatch.setattr(provider, "_backend", "ollama")
    monkeypatch.setattr(provider, "_route", lambda q: (
        "fast", ["fast-model-x", "big-model-y"], False, 220))

    def always_down(system, user_turn, model=None, think=None,
                    max_tokens=None):
        raise ProviderUnavailable("ollama unreachable")

    monkeypatch.setattr(ollama_model, "generate", always_down)
    monkeypatch.setattr("src.model.mock_model.generate",
                        lambda q, c: "mock answer")
    gen = provider.generate("What is the wfh policy?", "ctx", "turn")
    assert gen.degraded is True
    assert gen.backend == "mock (fallback)"
    assert gen.model == "mock"
    assert "ollama unreachable" in gen.reason
    assert gen.text == "mock answer"


def test_generate_reason_intent_passes_budget(monkeypatch):
    monkeypatch.setattr(provider, "_backend", "ollama")
    captured: dict = {}

    def fake_generate(system, user_turn, model=None, think=None,
                      max_tokens=None):
        captured.update(model=model, think=think, max_tokens=max_tokens)
        return "Answer: analysis"

    monkeypatch.setattr(ollama_model, "generate", fake_generate)
    gen = provider.generate("Explain the failover design", "ctx", "turn")
    assert gen.intent == "reason"
    assert captured["model"] == "qwen2.5:0.5b"
    assert captured["think"] is True
    assert captured["max_tokens"] == 600
