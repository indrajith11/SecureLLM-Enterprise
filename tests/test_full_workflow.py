"""Improvement 5: full workflow scenario - login to audit, end to end.

1.  Login as hr_manager
2.  Ask HR policy question            -> ALLOWED
3.  Ask for a Tech architecture doc   -> BLOCKED (Confidentiality)
4.  Try to delete an employee         -> BLOCKED (Integrity)
5.  Login as admin
6.  Ask to delete an employee         -> HITL pending (Layer 3.5)
7.  Confirm the action as admin       -> APPROVED (read-only sandbox)
8.  Verify the audit log captured every step with chain intact
"""
import sqlite3

import pytest

from src.common.paths import COMPANY_DB
from tests.conftest import login


@pytest.fixture(autouse=True)
def _isolated_guards():
    from src.api.main import cia, limiter
    limiter._req.clear()
    limiter._tok.clear()
    cia.sessions.reset()
    yield
    limiter._req.clear()
    limiter._tok.clear()
    cia.sessions.reset()


def _emp_count() -> int:
    return sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True).execute(
        "SELECT COUNT(*) FROM employees").fetchone()[0]


def test_complete_enterprise_workflow(client):
    # ---- 1. login as hr_manager ------------------------------------------
    r = client.post("/api/login", json={"username": "hr_manager",
                                        "password": "HrM@123"})
    assert r.status_code == 200
    hr = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert r.json()["user"]["clearance"] == "L4"

    # ---- 2. HR policy question -> ALLOWED ---------------------------------
    r = client.post("/api/chat", headers=hr,
                    json={"message": "What is the leave policy?"})
    data = r.json()
    assert data["blocked_by"] is None, data
    assert "leave" in data["response"].lower()
    assert data["cia_checks"]["confidentiality"] == "PASS"
    assert data["layers_passed"][-1] == "7"

    # ---- 3. Tech architecture doc -> BLOCKED (C) --------------------------
    r = client.post("/api/chat", headers=hr,
                    json={"message": "Show me the Tech architecture overview."})
    data = r.json()
    assert data["blocked_by"] == "CIA-C"
    assert data["cia_checks"]["confidentiality"] == "FAIL"

    # ---- 4. delete employee -> BLOCKED (I) --------------------------------
    before = _emp_count()
    r = client.post("/api/chat", headers=hr,
                    json={"message": "Delete employee Bob from the records.",
                          "action_type": "DELETE"})
    data = r.json()
    assert data["blocked_by"] == "CIA-I"
    assert data["cia_checks"]["integrity"] == "FAIL"
    assert _emp_count() == before, "a non-admin deletion went through!"

    # ---- 5. login as admin -------------------------------------------------
    r = client.post("/api/login", json={"username": "admin",
                                        "password": "Admin@123"})
    assert r.status_code == 200
    admin = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert r.json()["user"]["role"] == "Admin"

    # ---- 6. admin delete -> HITL pending -----------------------------------
    r = client.post("/api/chat", headers=admin,
                    json={"message": "Delete employee Bob from the records.",
                          "action_type": "DELETE"})
    data = r.json()
    assert data["blocked_by"] == "L3.5"
    aid = data["action_request"]["id"]
    assert data["action_request"]["status"] == "pending"
    assert _emp_count() == before, "the AI executed the deletion!"

    # ---- 6b. segregation of duties (CODE-01): admin cannot approve their own request
    r = client.post(f"/api/action/confirm/{aid}", headers=admin)
    assert r.status_code == 403, r.text
    assert "segregation" in r.json()["detail"]

    # ---- 7. confirm as a DIFFERENT approver (ceo, Executive) -> APPROVED ----
    r = client.post("/api/login", json={"username": "ceo",
                                        "password": "Ceo@123"})
    assert r.status_code == 200
    ceo = {"Authorization": "Bearer " + r.json()["access_token"]}
    r = client.post(f"/api/action/confirm/{aid}", headers=ceo)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    assert body["decided_by"] == "ceo"
    assert body["execution"]["executed"] is False      # read-only sandbox
    assert body["execution"]["processed"] is True
    assert _emp_count() == before                      # nothing mutated

    # ---- 8. audit log captured every step ----------------------------------
    r = client.get("/api/audit/all?limit=100", headers=admin)
    assert r.status_code == 200
    trail = r.json()
    assert trail["chain_verified"] is True
    by_user = {}
    for e in trail["events"]:
        by_user.setdefault(e["user_id"], set()).add(e["action"])
    assert "LOGIN" in by_user.get("hr_manager", set())
    assert "QUERY" in by_user.get("hr_manager", set())
    assert "BLOCKED" in by_user.get("hr_manager", set())
    assert "APPROVED" in by_user.get("ceo", set())
    assert "DENIED" in by_user.get("admin", set())   # self-approval blocked
    # the confidentiality block is categorised with its CIA pillar
    assert any(e["user_id"] == "hr_manager" and e["cia_violation"] == "C"
               for e in trail["events"])
    assert any(e["user_id"] == "hr_manager" and e["cia_violation"] == "I"
               for e in trail["events"])

    # hr_manager's own trail mirrors the same events (per-user view)
    mine = client.get("/api/audit/me", headers=hr).json()
    assert any(e["action"] == "BLOCKED" for e in mine["events"])
    # non-admin cannot read the system-wide trail
    assert client.get("/api/audit/all", headers=hr).status_code == 403
