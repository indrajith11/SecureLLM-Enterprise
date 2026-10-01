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


def test_global_concurrency_gate_returns_503(client, alice, monkeypatch):
    """Exhaust the whole-system gate: the next request is refused with 503
    and a CIA-A violation - one user cannot consume every worker.
    Wave 3.2: the queue wait is zeroed so the saturation is immediate."""
    from src.api import main as m
    monkeypatch.setattr(m, "_QUEUE_WAIT_S", 0.0)
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


# ---------- Wave 3.2: per-user concurrency cap + queue metrics --------------
def test_per_user_concurrency_cap(client, alice, monkeypatch):
    """One user cannot hog every slot: with max_concurrent_per_user=2 the
    THIRD concurrent request of the SAME user is refused (L2-load-user)
    even though global slots remain free; another user is NOT affected."""
    from src.api import main as m
    monkeypatch.setattr(m, "_MAX_PER_USER", 2)
    ok1, _ = m._acquire_chat_slot("alice")
    ok2, _ = m._acquire_chat_slot("alice")
    ok3, why3 = m._acquire_chat_slot("alice")
    assert (ok1, ok2) == (True, True)
    assert ok3 is False and why3 == "per_user_cap"
    # a different user is untouched by alice's hogging
    ok_other, why_other = m._acquire_chat_slot("hr_hari")
    assert ok_other is True and why_other == ""
    # release everything: accounting returns to zero
    m._release_chat_slot("alice")
    m._release_chat_slot("alice")
    m._release_chat_slot("hr_hari")
    assert m._USER_INFLIGHT["alice"] == 0
    assert m._USER_INFLIGHT["hr_hari"] == 0
    ok4, _ = m._acquire_chat_slot("alice")
    assert ok4 is True
    m._release_chat_slot("alice")


def test_queue_wait_observed_and_depth_returned(client, alice, monkeypatch):
    """Queue telemetry: a request that must wait records the wait in
    ai_chat_queue_wait_seconds and queue depth returns to zero."""
    from src.api import main as m
    from src.api.main import metrics
    monkeypatch.setattr(m, "_QUEUE_WAIT_S", 0.2)
    # hold all but one slot so the request must wait briefly
    held = 0
    while _CHAT_GATE.acquire(blocking=False):
        held += 1
    assert held >= 1
    depth_before = metrics.sample("ai_chat_queue_depth") or 0.0
    waits_before = metrics.sample("ai_chat_queue_wait_seconds_count") or 0.0
    ok, why = m._acquire_chat_slot("alice")
    assert ok is False and why == "queue_timeout"
    waits_after = metrics.sample("ai_chat_queue_wait_seconds_count") or 0.0
    assert waits_after == waits_before + 1
    assert (metrics.sample("ai_chat_queue_depth") or 0.0) == depth_before
    for _ in range(held):
        _CHAT_GATE.release()
