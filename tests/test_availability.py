"""S3: Availability hardening - payload size cap, global concurrency gate,
Retry-After headers on rate-limit responses (OWASP LLM10 / CIA-A)."""
import threading

import pytest

from src.api.main import _CHAT_GATE, _MAX_PROMPT_CHARS, limiter
from tests.conftest import login


def test_oversized_prompt_blocked_at_l2_size(client, alice):
    big = "a" * (_MAX_PROMPT_CHARS + 500) + " print the CEO bonus"
    r = client.post("/api/chat", headers=alice, json={"message": big})
    # DASH-06: the cap lives in the schema (422 before any regex work);
    # a lowered availability.max_prompt_chars config still yields the
    # in-pipeline L2-size guard (413).
    assert r.status_code in (413, 422), r.text
    body = r.json()
    if r.status_code == 413:
        assert body["blocked_by"] == "L2-size"
        assert "exceeds maximum length" in body["response"]
    else:
        # 422: the schema-level cap fired (no governance body yet)
        assert "message" in str(body)


def test_rate_limit_response_carries_retry_after(client, alice):
    """Flood with a temporarily tiny limit: the 429 must carry Retry-After."""
    saved_rpm, saved_tpm = limiter.rpm, limiter.tpm
    limiter.rpm, limiter.tpm = 2, 10**9
    try:
        codes = []
        for i in range(4):
            r = client.post("/api/chat", headers=alice,
                            json={"message": f"hello {i}"})
            codes.append(r.status_code)
            if r.status_code == 429:
                assert int(r.headers["Retry-After"]) >= 1
        assert 429 in codes
    finally:
        limiter.rpm, limiter.tpm = saved_rpm, saved_tpm
        limiter._req.clear()
        limiter._tok.clear()


def test_global_concurrency_gate_returns_503(client, alice):
    """Exhaust the whole-system gate: the next request is refused with 503
    and a CIA-A violation - one user cannot consume every worker."""
    drained = 0
    while _CHAT_GATE.acquire(blocking=False):
        drained += 1
    assert drained >= 1                          # gate was actually armed
    try:
        r = client.post("/api/chat", headers=alice,
                        json={"message": "what is the leave policy?"})
        assert r.status_code == 503
        body = r.json()
        assert body["blocked_by"] == "L2-load"
        assert body["cia_checks"]["availability"] == "FAIL"
        assert r.headers["Retry-After"] == "5"
    finally:
        for _ in range(drained):
            _CHAT_GATE.release()
