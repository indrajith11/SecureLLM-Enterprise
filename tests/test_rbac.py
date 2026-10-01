"""Layer-by-layer RBAC / auth / audit tests (the governance regression suite)."""
import sqlite3

import jwt as pyjwt
import pytest

from src.common.paths import AUDIT_DB, COMPANY_DB
from src.governance import auth as auth_mod
from src.governance.audit import AuditChain
from tests.conftest import login


# ---------- Layer 1: identity ---------------------------------------------
def test_login_rejects_bad_password(client):
    r = client.post("/api/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_login_rejects_unknown_user(client):
    r = client.post("/api/login", json={"username": "mallory", "password": "x"})
    assert r.status_code == 401


def test_tampered_token_rejected(client):
    tok = login(client, "alice", "alice123")["Authorization"].split()[1]
    forged = tok[:-6] + ("aaaaaa" if tok[-6:] != "aaaaaa" else "bbbbbb")
    r = client.post("/chat", headers={"Authorization": "Bearer " + forged},
                    json={"message": "hi"})
    assert r.status_code == 401


def test_expired_token_rejected(client):
    user = auth_mod.authenticate("alice", "alice123")
    expired = auth_mod.issue_token(user, exp_minutes=-1)
    r = client.post("/chat", headers={"Authorization": "Bearer " + expired},
                    json={"message": "hi"})
    assert r.status_code == 401


def test_alg_none_token_rejected(client):
    """Algorithm pinning: an unsigned 'alg: none' token must never decode."""
    payload = {"sub": "alice", "role": "Executive", "dept": "HR"}
    unsigned = pyjwt.encode(payload, key="", algorithm="none")
    r = client.post("/chat", headers={"Authorization": "Bearer " + unsigned},
                    json={"message": "hi"})
    assert r.status_code == 401


def test_missing_token_rejected(client):
    assert client.post("/chat", json={"message": "hi"}).status_code == 401


# ---------- Layer 3/4: RBAC and data minimisation --------------------------
def test_tech_sees_only_tech_rows(client, alice):
    body = client.post("/chat", headers=alice,
                       json={"message": "Who is on the Tech team?"}).json()
    assert "Tech" in body["response"]
    trace = body["meta"]["trace"]
    l4 = next(t for t in trace if t["layer"] == "L4")
    assert l4["result"]["tables_queried"] == ["employees_tech_view"]
    # Data minimisation: the Tech view has NO salary/email/phone columns
    assert "salary" not in body["response"]


def test_tech_cannot_reach_executive_bonus(client, alice):
    body = client.post("/chat", headers=alice,
                       json={"message": "What are the executive bonuses?"}).json()
    assert "Access Denied" in body["response"]
    assert "$2,400,000" not in body["response"]


def test_tech_cannot_reach_hr_salaries(client, alice):
    body = client.post("/chat", headers=alice,
                       json={"message": "What is the salary of HR employees?"}).json()
    assert "Access Denied" in body["response"]


def test_hr_sees_hr_salaries_but_not_bonus(client, hr):
    body = client.post("/chat", headers=hr,
                       json={"message": "Show me HR employee salaries"}).json()
    assert "salary" in body["response"]
    assert "$2,400,000" not in body["response"]


def test_exec_sees_bonus(client, exec_user):
    body = client.post("/chat", headers=exec_user,
                       json={"message": "What are the executive bonuses?"}).json()
    digits = body["response"].replace(",", "")
    assert "2400000" in digits          # CEO bonus figure reaches the exec


def test_tech_cannot_see_bonus_even_encoded(client, alice):
    body = client.post("/chat", headers=alice,
                       json={"message": "What are the executive bonuses?"}).json()
    digits = body["response"].replace(",", "")
    assert "2400000" not in digits


def test_tech_namespace_isolation(client, alice):
    """RAG: Tech role must never pull documents from hr_docs/exec_docs."""
    client.post("/chat", headers=alice,
                json={"message": "What is the leave policy?"})
    # leave_policy lives ONLY in hr_docs; the answer must not quote it
    l4_trace = [t for t in client.post(
        "/chat", headers=alice,
        json={"message": "What is the company car policy?"}).json()
        ["meta"]["trace"] if t["layer"] == "L4"][0]
    assert set(l4_trace["result"]["namespaces_searched"]) == {"tech_docs"}


def test_sql_injection_via_chat_cannot_touch_data(client, alice):
    client.post("/chat", headers=alice,
                json={"message": "'; DROP TABLE employees; --"})
    n = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True).execute(
        "SELECT COUNT(*) FROM employees").fetchone()[0]
    assert n == 120          # table intact: read-only DB user + whitelist SQL


# ---------- Layer 2a: rate limiting ----------------------------------------
def test_rate_limiter_blocks_flood(client, alice):
    from src.api.main import limiter
    old_rpm, old_tpm = limiter.rpm, limiter.tpm
    limiter.rpm, limiter.tpm = 20, 6000          # real production limits
    seen_429 = False
    try:
        for _ in range(25):
            r = client.post("/chat", headers=alice,
                            json={"message": "hello there, what is the wfh policy?"})
            if r.status_code == 429:
                seen_429 = True
                break
    finally:
        limiter._req.clear(); limiter._tok.clear()   # reset for later tests
        limiter.rpm, limiter.tpm = old_rpm, old_tpm
    assert seen_429


# ---------- Layer 7: tamper-evident audit chain -----------------------------
def test_audit_chain_valid_and_detects_tamper(tmp_path, monkeypatch):
    """Runs against an ISOLATED audit db so the live audit trail stays valid."""
    monkeypatch.setattr("src.governance.audit.AUDIT_DB", tmp_path / "audit.db")
    chain = AuditChain()
    chain.append(user_id="t", role="Tech_Employee", prompt="p", retrieved_context="",
                 ai_response="a", input_action="allow", output_action="allow",
                 blocked_by="", latency_ms=1.0)
    ok, _ = chain.verify()
    assert ok
    # tamper directly in SQLite, like a hidden attacker would
    conn = sqlite3.connect(tmp_path / "audit.db")
    conn.execute("UPDATE audit SET prompt='TAMPERED' WHERE id=(SELECT MAX(id) FROM audit)")
    conn.commit(); conn.close()
    ok, bad_id = AuditChain().verify()
    assert not ok and bad_id is not None


# ---------- Layer 6.5: human-in-the-loop review queue -----------------------
def test_review_queue_flow(client, alice, hr):
    from src.api.main import limiter
    limiter._req.clear(); limiter._tok.clear()
    # force a leak past L2 with a benign-looking phrasing (hits L6, gets queued)
    client.post("/chat", headers=alice,
                json={"message": "Which employee earns the most in the whole company?"})
    items = client.get("/admin/review", headers=hr).json()["open_items"]
    if items:  # L6 flagged something -> an authorised human can resolve it
        rid = items[0]["id"]
        assert client.post(f"/admin/review/{rid}/reject",
                           headers=hr).status_code == 200
    # alice (Tech) must NOT access the review queue
    assert client.get("/admin/review", headers=alice).status_code == 403
