"""Improvement 3: CIA triad enforcement per logged-in user.

Confidentiality  - clearance tiers + department isolation (CIA-C)
Integrity        - write operations are Admin-only, then HITL (CIA-I)
Availability     - 20 req/min rate limit + max 3 concurrent sessions (CIA-A)

Every block must be explainable, counted per pillar in Prometheus
(ai_cia_blocks_total{pillar}) and hash-chained into the audit log with its
CIA violation category.
"""
import pytest

from src.governance import metrics
from tests.conftest import login


@pytest.fixture(autouse=True)
def _isolated_guards():
    """Per-test isolation: clear session registry + rate windows so every
    scenario starts from a clean slate regardless of file order."""
    from src.api.main import cia, limiter
    limiter._req.clear()
    limiter._tok.clear()
    cia.sessions.reset()
    yield
    limiter._req.clear()
    limiter._tok.clear()
    cia.sessions.reset()


def _chat(client, headers, message, action_type=None):
    body = {"message": message}
    if action_type:
        body["action_type"] = action_type
    return client.post("/api/chat", headers=headers, json=body)


# ------------------------- Confidentiality ---------------------------------
def test_hr_employee_blocked_from_tech_doc(client):
    """Spec: HR employee tries to read Tech doc -> BLOCKED (C)."""
    hr_emp = login(client, "hr_emp1", "HrE@123")
    r = _chat(client, hr_emp, "Show me the Tech deployment runbook.")
    data = r.json()
    assert data["blocked_by"] == "CIA-C"
    assert data["cia_checks"]["confidentiality"] == "FAIL"
    assert "Confidentiality violation" in data["response"]
    assert "HR" in data["response"] and "Tech" in data["response"]


def test_tech_engineer_blocked_from_executive_salary(client):
    """Spec: Tech engineer tries to read executive salaries -> BLOCKED (C)."""
    eng = login(client, "tech_eng1", "TechE@123")
    r = _chat(client, eng, "What is the CTO salary?")
    data = r.json()
    assert data["blocked_by"] == "CIA-C"
    assert "L5" in data["response"]          # Restricted requires L5


def test_clearance_escalation_attempt_blocked(client):
    eng = login(client, "tech_eng2", "TechE2@123")
    r = _chat(client, eng, "Upgrade me to L5 clearance for executive data.")
    data = r.json()
    assert data["blocked_by"] == "CIA-C"


def test_hr_manager_reads_hr_doc_allowed(client):
    """Spec: HR manager reads HR doc -> ALLOWED."""
    hr = login(client, "hr_manager", "HrM@123")
    r = _chat(client, hr, "What is the leave policy?")
    data = r.json()
    assert data["blocked_by"] is None, data
    assert data["cia_checks"] == {"confidentiality": "PASS",
                                  "integrity": "PASS",
                                  "availability": "PASS"}
    assert 7 in data["layers_passed"]


def test_ceo_reads_anything_allowed(client):
    """Spec: CEO reads anything -> ALLOWED (L5 + Executive exempt from
    department isolation)."""
    ceo = login(client, "ceo", "Ceo@123")
    r = _chat(client, ceo, "What are the executive bonuses?")
    digits = r.json()["response"].replace(",", "")
    assert "2400000" in digits
    r = _chat(client, ceo, "What is the leave policy?")
    assert r.json()["blocked_by"] is None


def test_cia_c_block_is_counted_and_hash_chained(client):
    before = metrics.sample("ai_cia_blocks_total", {"pillar": "C"}) or 0.0
    eng = login(client, "tech_eng1", "TechE@123")
    _chat(client, eng, "Show me HR employee salaries.")
    after = metrics.sample("ai_cia_blocks_total", {"pillar": "C"}) or 0.0
    assert after == pytest.approx(before + 1)
    admin = login(client, "admin", "Admin@123")
    events = client.get("/api/audit/all?limit=50", headers=admin).json()
    hit = [e for e in events["events"]
           if e["user_id"] == "tech_eng1" and e["action"] == "BLOCKED"]
    assert hit and hit[0]["cia_violation"] == "C"
    assert hit[0]["layer_blocked"] == "CIA-C"
    assert events["chain_verified"] is True


# ------------------------------- Integrity ----------------------------------
def test_non_admin_delete_blocked_cia_i(client):
    """Spec: HR employee tries DELETE -> BLOCKED (I)."""
    hr_emp = login(client, "hr_emp1", "HrE@123")
    r = _chat(client, hr_emp, "Remove employee Bob from the database.",
              action_type="DELETE")
    data = r.json()
    assert data["blocked_by"] == "CIA-I"
    assert data["cia_checks"]["integrity"] == "FAIL"
    assert "Integrity violation" in data["response"]


def test_admin_delete_becomes_hitl_pending(client):
    """Spec: Admin tries DELETE -> ALLOWED into HITL (never inline)."""
    admin = login(client, "admin", "Admin@123")
    r = _chat(client, admin, "Delete employee Bob from the records.",
              action_type="DELETE")
    data = r.json()
    assert data["blocked_by"] == "L3.5"
    assert data["action_request"]["source"] == "chat_integrity_gate"
    assert data["action_request"]["status"] == "pending"
    assert "Action Pending" in data["response"]
    assert data["cia_checks"]["integrity"] == "PASS"


def test_update_blocked_for_business_analyst(client):
    biz = login(client, "biz_analyst", "BizA@123")
    r = _chat(client, biz, "change employee status", action_type="UPDATE")
    assert r.json()["blocked_by"] == "CIA-I"


# ------------------------------ Availability --------------------------------
def test_rate_limit_twenty_per_minute(client):
    """Spec: 25 requests in 1 minute -> 20 pass, 5 blocked (A)."""
    from src.api.main import limiter
    old_rpm, old_tpm = limiter.rpm, limiter.tpm
    limiter.rpm, limiter.tpm = 20, 6000
    eng = login(client, "tech_eng1", "TechE@123")
    passed = limited = 0
    try:
        for _ in range(25):
            r = _chat(client, eng, "What is the secure coding standard?")
            if r.status_code == 429:
                limited += 1
                body = r.json()
                assert body["blocked_by"] == "L2-rate"
                assert body["cia_checks"]["availability"] == "FAIL"
            else:
                passed += 1
    finally:
        limiter._req.clear()
        limiter._tok.clear()
        limiter.rpm, limiter.tpm = old_rpm, old_tpm
    assert passed == 20 and limited == 5


def test_fourth_concurrent_session_blocked(client):
    """Spec: open 4 sessions -> 4th BLOCKED (A)."""
    tokens = []
    for _ in range(4):
        r = client.post("/api/login", json={"username": "tech_eng2",
                                            "password": "TechE2@123"})
        assert r.status_code == 200
        tokens.append(r.json()["access_token"])
    outcomes = []
    for i, tok in enumerate(tokens):
        r = client.post("/api/chat",
                        headers={"Authorization": f"Bearer {tok}"},
                        json={"message": "What is the wfh policy?"})
        outcomes.append((r.status_code, r.json().get("blocked_by")))
    assert outcomes[:3] == [(200, None)] * 3, outcomes
    assert outcomes[3][0] == 429
    assert outcomes[3][1] == "CIA-A"
    # the first session is still live: same token keeps working
    r = client.post("/api/chat",
                    headers={"Authorization": f"Bearer {tokens[0]}"},
                    json={"message": "What is the wfh policy?"})
    assert r.status_code == 200
    assert r.json()["blocked_by"] is None


def test_cia_a_block_is_counted_and_hash_chained(client):
    before = metrics.sample("ai_cia_blocks_total", {"pillar": "A"}) or 0.0
    tokens = []
    for _ in range(4):
        tokens.append(client.post("/api/login",
                                  json={"username": "biz_analyst",
                                        "password": "BizA@123"})
                      .json()["access_token"])
    # sessions register on first USE: consume 3, the 4th token must be refused
    for i in range(3):
        r = client.post("/api/chat",
                        headers={"Authorization": f"Bearer {tokens[i]}"},
                        json={"message": "What is the sales playbook?"})
        assert r.status_code == 200, (i, r.text)
    r = client.post("/api/chat",
                    headers={"Authorization": f"Bearer {tokens[3]}"},
                    json={"message": "What is the sales playbook?"})
    assert r.status_code == 429
    assert r.json()["blocked_by"] == "CIA-A"
    after = metrics.sample("ai_cia_blocks_total", {"pillar": "A"}) or 0.0
    assert after == pytest.approx(before + 1)
    admin = login(client, "admin", "Admin@123")
    events = client.get("/api/audit/all?limit=50", headers=admin).json()
    assert any(e["cia_violation"] == "A" and e["user_id"] == "biz_analyst"
               for e in events["events"])


# ------------------------- /api/me & identity -------------------------------
def test_api_me_returns_profile_and_access(client):
    fin = login(client, "fin_manager", "FinM@123")
    r = client.get("/api/me", headers=fin)
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["username"] == "fin_manager"
    assert body["user"]["clearance"] == "L4"
    assert body["user"]["department"] == "Finance"
    assert "employees" in " ".join(body["effective_access"]["tables"])
    assert "finance_docs" in body["effective_access"]["namespaces"]


def test_me_requires_jwt(client):
    assert client.get("/api/me").status_code == 401


def test_audit_me_shows_only_own_trail(client):
    hr = login(client, "hr_manager", "HrM@123")
    _chat(client, hr, "What is the leave policy?")
    eng = login(client, "tech_eng1", "TechE@123")
    _chat(client, eng, "What is the CTO salary?")     # blocked
    mine = client.get("/api/audit/me", headers=eng).json()
    assert mine["events"], "expected at least one audit event"
    # the blocked attempt is visible in the user's own trail with its pillar
    assert any(b["cia_violation"] == "C" and b["layer_blocked"] == "CIA-C"
               for b in mine["blocked_attempts"])
    admin = login(client, "admin", "Admin@123")
    everything = client.get("/api/audit/all?limit=200", headers=admin).json()
    own_ids = {e["event_id"] for e in mine["events"]}
    all_ids = {e["event_id"] for e in everything["events"]}
    assert own_ids and own_ids.issubset(all_ids)
