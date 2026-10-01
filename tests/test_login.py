"""Improvement 2: per-user login (bcrypt + 60-minute JWT) - Layer 1 tests.

Covers the spec's login matrix: valid login returns a JWT with the full
identity claims, invalid credentials are refused, inactive accounts cannot
login, expired tokens are rejected, and every login attempt (success or
failure) lands in the tamper-evident audit chain.
"""
import sqlite3
import time

import jwt as pyjwt
import pytest

from src.common.paths import COMPANY_DB
from src.governance import auth as auth_mod
from tests.conftest import login


def test_valid_login_returns_jwt_and_profile(client):
    r = client.post("/api/login", json={"username": "hr_manager",
                                        "password": "HrM@123"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600          # 60 minutes
    assert body["user"]["username"] == "hr_manager"
    assert body["user"]["role"] == "HR_Manager"
    assert body["user"]["department"] == "HR"
    assert body["user"]["clearance"] == "L4"
    assert body["user"]["full_name"] == "Anjali Verma"
    claims = pyjwt.decode(body["access_token"], options={"verify_signature": False})
    for claim in ("sub", "role", "dept", "clr", "uid", "exp", "jti"):
        assert claim in claims, f"JWT missing claim {claim}"
    assert claims["clr"] == "L4"


def test_all_ten_demo_users_can_login(client):
    creds = [("admin", "Admin@123", "Admin", "L5"),
             ("ceo", "Ceo@123", "Executive", "L5"),
             ("cto", "Cto@123", "Executive", "L5"),
             ("hr_manager", "HrM@123", "HR_Manager", "L4"),
             ("hr_emp1", "HrE@123", "HR_Employee", "L3"),
             ("tech_lead", "TechL@123", "Tech_Lead", "L4"),
             ("tech_eng1", "TechE@123", "Tech_Engineer", "L3"),
             ("tech_eng2", "TechE2@123", "Tech_Engineer", "L3"),
             ("biz_analyst", "BizA@123", "Business_Analyst", "L3"),
             ("fin_manager", "FinM@123", "Finance_Manager", "L4")]
    for username, password, role, clearance in creds:
        r = client.post("/api/login", json={"username": username,
                                            "password": password})
        assert r.status_code == 200, f"{username}: {r.text}"
        assert r.json()["user"]["role"] == role
        assert r.json()["user"]["clearance"] == clearance


def test_invalid_password_returns_401(client):
    r = client.post("/api/login", json={"username": "hr_manager",
                                        "password": "wrong"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid credentials"


def test_unknown_user_returns_401(client):
    r = client.post("/api/login", json={"username": "mallory",
                                        "password": "x"})
    assert r.status_code == 401


def test_passwords_are_bcrypt_hashed_in_db():
    conn = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT username, password_hash FROM users").fetchall()
    conn.close()
    assert len(rows) >= 13
    for username, stored in rows:
        assert stored.startswith("$2"), f"{username} not bcrypt-hashed"
        assert "admin123" not in stored and "Admin@123" not in stored


def test_inactive_user_cannot_login(client):
    conn = sqlite3.connect(COMPANY_DB)
    conn.execute("UPDATE users SET is_active=0 WHERE username='tech_eng2'")
    conn.commit()
    conn.close()
    try:
        r = client.post("/api/login", json={"username": "tech_eng2",
                                            "password": "TechE2@123"})
        assert r.status_code == 401
    finally:
        conn = sqlite3.connect(COMPANY_DB)
        conn.execute("UPDATE users SET is_active=1 WHERE username='tech_eng2'")
        conn.commit()
        conn.close()


def test_expired_jwt_rejected(client):
    user = auth_mod.authenticate("hr_manager", "HrM@123")
    assert user is not None
    expired = auth_mod.issue_token(user, exp_minutes=-1)
    r = client.post("/api/chat", headers={"Authorization": "Bearer " + expired},
                    json={"message": "hello"})
    assert r.status_code == 401


def test_missing_and_malformed_jwt_rejected(client):
    assert client.post("/api/chat", json={"message": "hi"}).status_code == 401
    r = client.post("/api/chat", headers={"Authorization": "Bearer not.a.jwt"},
                    json={"message": "hi"})
    assert r.status_code == 401


def test_jwt_expiry_is_sixty_minutes(client):
    user = auth_mod.authenticate("ceo", "Ceo@123")
    claims = pyjwt.decode(auth_mod.issue_token(user),
                          options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 60 * 60


def test_login_attempts_are_hash_chained_in_audit(client):
    client.post("/api/login", json={"username": "hr_manager",
                                    "password": "HrM@123"})
    client.post("/api/login", json={"username": "hr_manager",
                                    "password": "bad"})
    admin = login(client, "admin", "Admin@123")
    events = client.get("/api/audit/all?limit=200", headers=admin).json()
    actions = {e["user_id"]: e for e in events["events"]}
    assert any(e["action"] == "LOGIN" and e["user_id"] == "hr_manager"
               for e in events["events"])
    assert any(e["action"] == "DENIED" and e["user_id"] == "hr_manager"
               for e in events["events"])
    assert events["chain_verified"] is True
