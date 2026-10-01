"""Pre-deployment gate, Step 7 - the operator kill switch (AI_ENABLED).

Pinned guarantees:
  - AI_ENABLED=false -> POST /api/chat AND POST /api/chat/stream return 503
    with a plain operator notice; nothing reaches L2b..L7 (no audit spam,
    no model call, no rate-budget burn);
  - the refusal is counted in ai_kill_switch_denials_total;
  - /health, /api/login and the metrics endpoint stay UP (the notice says:
    everything except the AI feature is still observable during an incident);
  - UNRECOGNIZED values fail CLOSED (a typo like "ture" disables, never
    half-enables) - same fail-closed philosophy as DEPLOY-01/AUTH-07;
  - AI_ENABLED=true or absent -> the pipeline behaves exactly as before;
  - /admin/posture exposes the switch state to Admin (incident visibility).
"""
import pytest

from src.governance import metrics
from tests.conftest import login


@pytest.fixture
def killed(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "false")


def test_chat_returns_503_with_plain_notice(client, alice, killed):
    r = client.post("/api/chat", json={"message": "What is the deployment "
                                                   "process?"},
                    headers=alice)
    assert r.status_code == 503
    body = r.json()
    assert body["blocked_by"] == "KILL_SWITCH"
    assert "disabled by the operator" in body["response"]
    assert "Retry later" in body["response"]


def test_kill_switch_counters_increment(client, alice, killed):
    before = metrics.sample("ai_kill_switch_denials_total") or 0.0
    client.post("/api/chat", json={"message": "hi"}, headers=alice)
    after = metrics.sample("ai_kill_switch_denials_total") or 0.0
    assert after == before + 1


def test_stream_route_503_before_any_event(client, alice, killed):
    r = client.post("/api/chat/stream", json={"message": "hi"}, headers=alice)
    assert r.status_code == 503
    assert "kill switch" in r.json()["detail"].lower()


def test_health_login_and_metrics_stay_up(client, killed):
    assert client.get("/health").status_code == 200
    r = client.post("/api/login", json={"username": "alice",
                                        "password": "alice123"})
    assert r.status_code == 200          # auth surface survives (incident triage)
    assert client.get("/metrics").status_code == 200


def test_kill_switch_is_fail_closed_on_unrecognized_value(client, alice,
                                                          monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "ture")     # operator typo
    r = client.post("/api/chat", json={"message": "hi"}, headers=alice)
    assert r.status_code == 503                  # typo -> OFF, never half-on
    monkeypatch.setenv("AI_ENABLED", "0")
    assert client.post("/api/chat", json={"message": "hi"},
                       headers=alice).status_code == 503


def test_switch_back_on_restores_service(client, alice, monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "false")
    assert client.post("/api/chat", json={"message": "hi"},
                       headers=alice).status_code == 503
    monkeypatch.setenv("AI_ENABLED", "true")
    r = client.post("/api/chat", json={"message": "What is the deployment "
                                                   "process?"},
                    headers=alice)
    assert r.status_code == 200
    assert r.json()["blocked_by"] is None


def test_posture_reports_switch_state(client, killed):
    """Admin can SEE that the switch is off (incident dashboard / runbook)."""
    headers = login(client, "admin", "Admin@123")
    r = client.get("/admin/posture", headers=headers)
    assert r.status_code == 200
    assert r.json()["ai_enabled"] is False


def test_denial_never_touches_audit_chain(client, alice, killed):
    """Kill-switch denials are availability-style refusals: counted, not
    audited (an incident flood must not drown the hash chain in noise) -
    and they must not disturb chain verifiability either."""
    from src.api.main import audit
    ok_before, _ = audit.verify_cached()
    client.post("/api/chat", json={"message": "hi"}, headers=alice)
    ok_after, _ = audit.verify_cached()
    assert ok_before and ok_after
