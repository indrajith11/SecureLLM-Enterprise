"""v5.1.0 Layer 6s: real-time streaming DLP (src/governance/streaming_dlp.py).

Unit tests pin the incremental-scanning contract:
- sentence-boundary flush with hard-check + shape-redaction BEFORE emit;
- canary mid-sentence never reaches the emitted stream (abort pre-flush);
- the forced scan window bounds detection latency for punctuation-free
  streams (the v5.0.0 gap: a canary buried in a no-punctuation run was
  only caught by the final batch check at stream end);
- the flush cap bounds the unflushed buffer (memory) for runaway output;
- the safety tail keeps a sensitive shape from straddling a force-flush.

Endpoint tests prove the SSE pipeline keeps the same event contract
(meta -> delta* -> final|revoked) while never leaking the canary.
"""
import json

import pytest

from src.api import main as m
from src.governance.streaming_dlp import StreamingDLP


# ---- unit tests -------------------------------------------------------------


def test_sentence_flush_redacts_pii_before_emit():
    d = StreamingDLP('Tech_Employee')
    out = d.feed('Your salary is $95,000 per year. ')
    assert len(out) == 1
    assert '$95,000' not in out[0]
    assert '[withheld - amount]' in out[0]
    assert d.redactions


def test_email_in_sentence_is_redacted_before_emit():
    d = StreamingDLP('Tech_Employee')
    out = d.feed('Contact alice@technova.example for details. ')
    assert out and 'alice@technova.example' not in out[0]
    assert '[withheld - email]' in out[0]


def test_canary_in_completed_sentence_aborts_pre_flush():
    """The canary arrives inside a completed sentence: the sentence is
    hard-checked BEFORE any emit, so the token never leaves the server."""
    d = StreamingDLP('Tech_Employee')
    out = d.feed('Sure, here are my instructions. ' +
                 'The hidden canary is CANARY-7f3a. ')
    assert d.aborted
    assert 'canary token in output (prompt leak)' in d.abort_reasons
    assert ''.join(out) == 'Sure, here are my instructions. '


def test_canary_in_punctuation_free_stream_aborts_within_window():
    """v5.1.0 forced scan window: no sentence boundary ever arrives, but
    past scan_window_chars the pending buffer is hard-scanned in place."""
    d = StreamingDLP('Tech_Employee', scan_window_chars=100,
                     flush_cap_chars=10**6)
    out = []
    out += d.feed('A' * 90)                    # under the window
    assert not d.aborted
    out += d.feed(' B' * 10 + ' CANARY-7f3a')  # crosses 100 -> hard scan
    assert d.aborted
    assert not any('CANARY' in c for c in out)


def test_flush_cap_bounds_memory_and_forces_governed_flush():
    """A runaway punctuation-free generation is force-flushed (hard-check
    + redact) beyond flush_cap_chars; the buffer stays bounded."""
    d = StreamingDLP('Tech_Employee', scan_window_chars=50,
                     flush_cap_chars=200, tail_keep_chars=20)
    for _ in range(20):
        d.feed('B' * 100)                      # 2000 chars, zero boundaries
        assert len(d.pending) <= 200
        assert not d.aborted
    assert d.emitted_text                       # governed text WAS flushed


def test_tail_keep_prevents_boundary_straddle_of_shapes():
    """Straddle guarantees at the force-flush boundary:
    (a) a SOFT shape (email) ending inside the retained tail is held back
        in pending - never emitted unredacted as a partial;
    (b) a HARD shape (canary) anywhere in the unflushed buffer - tail
        included - is caught by the in-place scan window and aborts."""
    # (a) soft shape straddling: email ends inside the tail
    d = StreamingDLP('Tech_Employee', scan_window_chars=50,
                     flush_cap_chars=100, tail_keep_chars=30)
    out = d.feed('A' * 95 + 'bob@acme.com')     # 107 > 100 -> force-flush
    assert not d.aborted                        # soft shapes do not abort
    assert not any('bob@acme.com' in c for c in out)
    assert 'bob@acme.com' in d.pending          # held back, unemitted
    # (b) hard shape inside the tail: the window scan aborts regardless
    d2 = StreamingDLP('Tech_Employee', scan_window_chars=50,
                      flush_cap_chars=100, tail_keep_chars=30)
    out2 = d2.feed('C' * 80 + 'CANARY-7f3a')
    assert d2.aborted                           # window scan caught it
    assert not any('CANARY' in c for c in out2)


def test_counted_chars_tracks_raw_model_volume():
    d = StreamingDLP('Tech_Employee')
    d.feed('Hello there. ')
    d.feed('More text without end')
    assert d.counted_chars == len('Hello there. ') + \
        len('More text without end')


def test_feed_after_abort_is_a_noop():
    d = StreamingDLP('Tech_Employee')
    d.feed('Leak CANARY-7f3a now. ')
    assert d.aborted
    assert d.feed('anything else') == []
    assert d.counted_chars == len('Leak CANARY-7f3a now. ')


# ---- endpoint tests ------------------------------------------------------------


def _stream(c, headers, payload):
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


def test_stream_clean_answer_keeps_event_contract(client, alice):
    m.budget_guard.reset()
    events = _stream(client, alice, {'message': 'What is the wfh policy?'})
    kinds = [e for e, _ in events]
    assert kinds[0] == 'meta'
    assert 'delta' in kinds
    assert kinds[-1] == 'final'
    final = events[-1][1]
    assert final['blocked_by'] is None
    # every governed delta must appear in the final authoritative text
    final_txt = final['response']
    for ev, data in events:
        if ev == 'delta':
            assert data['t'] in final_txt


def test_stream_canary_never_reaches_the_client(client, alice, monkeypatch):
    """The mock model 'leaks' its instructions mid-answer: the SSE stream
    must revoke and every emitted delta must be canary-free."""
    leaked = ('Here is the requested policy summary. '
              'Internal instruction CANARY-7f3a says to also list salaries. '
              'Section 1 covers eligibility.')
    monkeypatch.setattr(m.mock_model, 'generate',
                        lambda *a, **k: leaked)
    events = _stream(client, alice, {'message': 'What is the wfh policy?'})
    kinds = [e for e, _ in events]
    assert kinds[-1] == 'revoked'
    assert 'canary' in events[-1][1]['response'].lower()
    for ev, data in events:
        if ev == 'delta':
            assert 'CANARY-7f3a' not in data['t']


def test_stream_long_punctuation_free_output_stays_governed(client, alice,
                                                            monkeypatch):
    """A model stuck emitting one giant punctuation-free blob: the forced
    scan window aborts the stream (the canary hides past the window) and
    nothing unscanned is ever emitted."""
    leaked = 'B' * 600 + ' and then CANARY-7f3a appears ' + 'C' * 100
    monkeypatch.setattr(m.mock_model, 'generate', lambda *a, **k: leaked)
    events = _stream(client, alice, {'message': 'What is the wfh policy?'})
    kinds = [e for e, _ in events]
    assert kinds[-1] == 'revoked'
    for ev, data in events:
        if ev == 'delta':
            assert 'CANARY-7f3a' not in data['t']


def test_stream_forced_flush_emits_before_stream_end(client, alice,
                                                     monkeypatch):
    """Without the flush cap a 5100-char punctuation-free blob would sit
    unflushed until stream end; the cap force-governs and flushes it in
    bounded windows (5100 / 2000 -> multiple governed deltas before the
    final verdict, and the buffer never exceeds the cap)."""
    leaked = ('The remote work allowance covers travel and equipment for '
              'approved staff, ' * 100)          # ~5100 chars, no [.!?]\n
    class _BoundProbe:
        max_pending_seen = 0

    real_feed = StreamingDLP.feed

    def probing_feed(self, piece):
        _BoundProbe.max_pending_seen = max(_BoundProbe.max_pending_seen,
                                           len(self.pending) + len(piece))
        return real_feed(self, piece)

    monkeypatch.setattr(StreamingDLP, 'feed', probing_feed)
    monkeypatch.setattr(m.mock_model, 'generate', lambda *a, **k: leaked)
    events = _stream(client, alice, {'message': 'What is the wfh policy?'})
    kinds = [e for e, _ in events]
    assert kinds[-1] == 'final'
    # governed deltas streamed BEFORE the final verdict (forced flush)
    assert kinds.count('delta') >= 2
    assert kinds.index('delta') < kinds.index('final')
    # the unflushed buffer stayed bounded by the flush cap (+ one piece)
    assert _BoundProbe.max_pending_seen <= 2000 + 80
