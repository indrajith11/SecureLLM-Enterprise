"""v5.1.0 Layer 2c: per-session token budget (OWASP LLM10 / KV-cache DoS).

Unit tests cover the guard's accounting semantics (rolling window,
conservative admission, output-side recording, expiry). Endpoint tests
cover both enforcement points: the preflight admission check (429 with
blocked_by=L2-budget) and the mid-stream cutoff on the SSE pipeline.
The per-SESSION key semantics are asserted too: a fresh login starts a
fresh budget even for the same user.
"""
import json
import time

import pytest

from src.api import main as m
from src.governance.token_budget import TokenBudgetGuard


# ---- unit tests -------------------------------------------------------------


def test_guard_allows_within_budget_and_records_output():
    g = TokenBudgetGuard(max_tokens=100, window_seconds=60)
    ok, retry, spent, why = g.check('s1', 50)
    assert ok and retry == 0 and spent == 50 and why == ''
    g.record_output('s1', 30)
    assert g.spent('s1') == 80


def test_guard_denies_when_budget_exhausted():
    g = TokenBudgetGuard(max_tokens=100, window_seconds=60)
    assert g.check('s1', 90)[0]
    g.record_output('s1', 20)                      # spent = 110
    ok, retry, spent, why = g.check('s1', 10)
    assert not ok
    assert spent == 110
    assert retry >= 1
    assert 'budget' in why


def test_guard_never_lets_a_request_push_past_the_cap():
    g = TokenBudgetGuard(max_tokens=100, window_seconds=60)
    assert g.check('s1', 99)[0]
    # 99 in window + 5 requested > 100: admission is conservative
    assert not g.check('s1', 5)[0]
    assert g.spent('s1') == 99


def test_guard_rolls_window_by_time(monkeypatch):
    from src.governance import token_budget as tb
    g = tb.TokenBudgetGuard(max_tokens=100, window_seconds=10)
    g.check('s1', 100)
    assert g.spent('s1') == 100

    class _Later:
        @staticmethod
        def time():
            return time.time() + 11        # past the 10s window

    monkeypatch.setattr(tb, 'time', _Later)
    assert g.spent('s1') == 0
    ok, _, _, _ = g.check('s1', 40)
    assert ok


def test_guard_keys_are_independent():
    g = TokenBudgetGuard(max_tokens=100, window_seconds=60)
    assert g.check('session-a', 100)[0]
    # a different session is untouched by session-a's spend
    ok, _, spent, _ = g.check('session-b', 50)
    assert ok and spent == 50


def test_guard_est_uses_shared_ratio():
    g = TokenBudgetGuard(max_tokens=100, window_seconds=60,
                         est_chars_per_token=4)
    assert g.est('x' * 8) == 2
    assert g.est('') == 1                 # minimum 1 token per request


def test_guard_reset():
    g = TokenBudgetGuard(max_tokens=100, window_seconds=60)
    g.check('s1', 50)
    g.reset()
    assert g.spent('s1') == 0


# ---- endpoint integration ----------------------------------------------------

QUESTION = {"message": "What is the wfh policy?"}


def test_chat_429_with_l2_budget_when_session_exhausted(client, alice):
    """Preflight enforcement: once the session's rolling spend crosses the
    configured cap, /api/chat answers 429 with blocked_by=L2-budget."""
    m.BUDGET_ENABLED = True
    m.budget_guard.max_tokens = 900
    m.budget_guard.reset()
    try:
        saw_429 = False
        for _ in range(12):
            r = client.post('/api/chat', headers=alice, json=QUESTION)
            if r.status_code == 429:
                saw_429 = True
                body = r.json()
                assert body['blocked_by'] == 'L2-budget'
                assert 'Retry-After' in r.headers
                assert 'budget' in body['response'].lower()
                break
        assert saw_429, 'session budget never tripped after 12 chats'
    finally:
        m.budget_guard.max_tokens = 10**9
        m.budget_guard.reset()


def test_fresh_session_gets_a_fresh_budget(client, alice):
    """The budget key is the JWT session id: re-login (same user, new
    session) starts a new budget - matching how serving engines pin
    KV-cache state to a session, not to a username."""
    m.BUDGET_ENABLED = True
    m.budget_guard.max_tokens = 900
    m.budget_guard.reset()
    try:
        for _ in range(12):
            r = client.post('/api/chat', headers=alice, json=QUESTION)
            if r.status_code == 429:
                break
        assert r.status_code == 429
        # fresh session, same user -> admitted again
        fresh = client.post('/api/login', json={'username': 'alice',
                                                'password': 'alice123'})
        assert fresh.status_code == 200
        headers = {'Authorization': 'Bearer ' + fresh.json()['access_token']}
        r2 = client.post('/api/chat', headers=headers, json=QUESTION)
        assert r2.status_code == 200
        assert r2.json()['blocked_by'] is None
    finally:
        m.budget_guard.max_tokens = 10**9
        m.budget_guard.reset()


def test_budget_flag_off_disables_enforcement(client, alice):
    m.BUDGET_ENABLED = False
    m.budget_guard.max_tokens = 1     # would deny everything if enforced
    m.budget_guard.reset()
    try:
        r = client.post('/api/chat', headers=alice, json=QUESTION)
        assert r.status_code == 200
        assert r.json()['blocked_by'] is None
        assert all(t['check'] != 'session_token_budget'
                   for t in r.json()['meta']['trace'])
    finally:
        m.BUDGET_ENABLED = True
        m.budget_guard.max_tokens = 10**9
        m.budget_guard.reset()


def test_chat_response_reports_token_usage(client, alice):
    """v5.1.0 telemetry: every governed answer reports its estimated
    input/output tokens and the running session spend."""
    m.budget_guard.reset()
    r = client.post('/api/chat', headers=alice, json=QUESTION)
    assert r.status_code == 200
    usage = r.json()['meta']['token_usage']
    assert usage['input_estimate'] >= 1
    assert usage['output_estimate'] >= 1
    assert usage['session_spent'] >= (usage['input_estimate']
                                      + usage['output_estimate'])
    # the next answer sees the previous spend (session accounting works)
    r2 = client.post('/api/chat', headers=alice, json=QUESTION)
    assert r2.json()['meta']['token_usage']['session_spent'] > \
        usage['session_spent']


def test_sse_stream_revoked_when_budget_exhausted_midstream(client, alice):
    """Mid-stream cutoff: a generation that pushes the session over the
    cap while streaming is revoked immediately - the output side of
    OWASP LLM10 is bounded, not just the admission side."""
    m.BUDGET_ENABLED = True
    m.budget_guard.max_tokens = 70
    m.budget_guard.reset()
    m.budget_guard.record_output(_session_id(alice), 60)   # 60/70 pre-spent
    try:
        events = _stream(client, alice, QUESTION)
        kinds = [e for e, _ in events]
        assert kinds[0] == 'meta'
        assert kinds[-1] == 'revoked'
        body = events[-1][1]
        assert body['blocked_by'] == 'L2-budget'
        assert 'budget' in body['response'].lower()
        # no leak of the answer after the cutoff: deltas are governed text
        assert not any('CANARY' in json.dumps(d)
                       for _, d in events if _ == 'delta')
    finally:
        m.budget_guard.max_tokens = 10**9
        m.budget_guard.reset()


def test_stream_final_reports_token_usage(client, alice):
    m.budget_guard.reset()
    events = _stream(client, alice, QUESTION)
    assert events[-1][0] == 'final'
    usage = events[-1][1]['meta']['token_usage']
    assert usage['input_estimate'] >= 1
    assert usage['output_estimate'] >= 1
    assert usage['session_spent'] >= (usage['input_estimate']
                                      + usage['output_estimate'])


# ---- helpers -------------------------------------------------------------------

def _session_id(headers: dict) -> str:
    from src.governance import auth
    return auth.verify_token(headers['Authorization'].removeprefix(
        'Bearer ')).session_id


def _stream(c, headers, payload):
    """Consume the SSE stream; return [(event, data), ...]."""
    events, buf = [], ''
    with c.stream('POST', '/api/chat/stream', headers=headers,
                  json=payload) as r:
        assert r.status_code == 200
        for chunk in r.iter_text():
            buf += chunk
            while '\n\n' in buf:
                raw, buf = buf.split('\n\n', 1)
                ev, data = None, None
                for line in raw.split('\n'):
                    if line.startswith('event: '):
                        ev = line[7:].strip()
                    elif line.startswith('data: '):
                        data = json.loads(line[6:])
                if ev and data is not None:
                    events.append((ev, data))
    return events
