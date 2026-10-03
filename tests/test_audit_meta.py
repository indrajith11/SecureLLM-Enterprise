"""Pre-deployment gate, Step 7 - model version tracking in the audit chain.

Pinned guarantees:
  - every successful /api/chat (sync AND SSE) appends an audit row whose
    `meta` JSON records the answering identity: backend, model, intent,
    degraded - "which brain answered" is now part of the tamper-evident log;
  - meta IS covered by the HMAC chain hash when present: editing it breaks
    verification (RAG-04 discipline extended to the new column);
  - BACKWARD COMPATIBILITY: rows written before this column existed (no
    meta) hash exactly as before, so a populated pre-upgrade chain still
    verifies unchanged (upgrade-in-place safety);
  - the JSONL SIEM mirror carries the same meta record.
"""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from src.api.main import audit
from src.common.paths import AUDIT_DB, LOGS_DIR


def _last_row():
    row = audit.conn.execute(
        "SELECT id, ai_response, meta, hash FROM audit "
        "ORDER BY id DESC LIMIT 1").fetchone()
    return row


def _query_as(client, headers):
    r = client.post("/api/chat",
                    json={"message": "What is the deployment process?"},
                    headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def test_chat_audit_row_carries_model_meta(client, alice):
    _query_as(client, alice)
    _id, _resp, meta_raw, _h = _last_row()
    assert meta_raw, "expected a meta record on the newest QUERY row"
    meta = json.loads(meta_raw)
    assert set(meta) == {"backend", "model", "intent", "degraded",
                         "channel", "external_user", "router"}
    assert meta["channel"] == "web"           # default channel unchanged
    assert meta["external_user"] == ""
    assert meta["router"] == "company"        # Wave 6.5: routing in audit
    assert meta["backend"] == "mock"          # test env: mock model answers
    assert meta["model"] == "mock"
    assert meta["degraded"] is False


def test_channel_attribution_lands_in_audit_chain(client, alice):
    # Wave 6: a channel request (telegram/mcp bridge) carries the real
    # human's handle - it must reach BOTH the response meta and the
    # tamper-evident audit chain under the service identity.
    r = client.post("/api/chat",
                    json={"message": "What is the deployment process?",
                          "channel": "telegram", "external_user": "61234567"},
                    headers=alice)
    assert r.status_code == 200, r.text
    assert r.json()["meta"]["channel"] == "telegram"
    assert r.json()["meta"]["external_user"] == "61234567"
    _id, _resp, meta_raw, _h = _last_row()
    meta = json.loads(meta_raw)
    assert meta["channel"] == "telegram"
    assert meta["external_user"] == "61234567"


def test_chain_still_verifies_with_meta_rows(client, alice):
    ok, bad = audit.verify()
    assert ok, bad
    _query_as(client, alice)
    ok, bad = audit.verify()
    assert ok, bad


def test_tampering_with_meta_breaks_the_chain(client, alice):
    """The model-identity record is tamper-evident: swap it in place and the
    full walk must fail - then restore and it must pass again (leaves the
    shared session chain intact for later test modules)."""
    _query_as(client, alice)
    row_id, _resp, meta_raw, _h = _last_row()
    assert meta_raw
    with_audit_lock = __import__("src.governance.audit",
                                 fromlist=["_LOCK"])._LOCK
    with with_audit_lock:
        audit.conn.execute("UPDATE audit SET meta=? WHERE id=?",
                           (json.dumps({"backend": "mock",
                                        "model": "TAMPERED",
                                        "intent": "fast",
                                        "degraded": False}), row_id))
        audit.conn.commit()
    ok, bad = audit.verify()
    assert not ok and bad == row_id
    with with_audit_lock:                      # restore: chain valid again
        audit.conn.execute("UPDATE audit SET meta=? WHERE id=?",
                           (meta_raw, row_id))
        audit.conn.commit()
    ok, bad = audit.verify()
    assert ok, bad


def test_legacy_rows_without_meta_still_verify():
    """Simulate a pre-upgrade row: append WITHOUT meta, then recompute the
    body the way the OLD code did (no meta key at all) - the stored hash
    must match it. Proves upgrade-in-place never bricks chain verification."""
    rid = audit.append(user_id="legacy-probe", role="Tech_Employee",
                       prompt="legacy row", retrieved_context="",
                       ai_response="ok", input_action="allow",
                       output_action="allow", blocked_by="",
                       latency_ms=1.0, action="QUERY")
    ts, uid, role, prompt, rc, ar, ia, oa, bb, lat, action, cia, layer_b, \
        prev_h, h = audit.conn.execute(
            "SELECT ts, user_id, role, prompt, retrieved_context, "
            "ai_response, input_filter_action, output_filter_action, "
            "blocked_by, latency_ms, action, cia_violation, layer_blocked, "
            "prev_hash, hash FROM audit WHERE id=?", (rid,)).fetchone()
    body = {"ts": ts, "user_id": uid, "role": role, "prompt": prompt,
            "input_action": ia, "output_action": oa, "blocked_by": bb,
            "latency_ms": lat, "action": action,
            "cia_violation": cia or "", "layer_blocked": layer_b or "",
            "retrieved_context": rc or "", "ai_response": ar or "",
            "prev_hash": prev_h}
    from src.governance.audit import _canonical, _sign_key
    import hashlib, hmac                        # noqa: E401
    body_hash = hashlib.sha256(_canonical(body).encode()).hexdigest()
    legacy_hash = hmac.new(_sign_key(), body_hash.encode(),
                           hashlib.sha256).hexdigest()
    assert legacy_hash == h                     # old verifier math == stored
    ok, bad = audit.verify()
    assert ok, bad


def test_jsonl_mirror_carries_meta(client, alice):
    _query_as(client, alice)
    path = LOGS_DIR / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    rec = json.loads(lines[-1])
    assert rec.get("meta"), "SIEM mirror must carry the model identity too"
    assert json.loads(rec["meta"])["backend"] == "mock"
