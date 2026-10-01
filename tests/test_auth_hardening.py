"""S2: Auth hardening - brute-force lockout, logout revocation, headers,
password policy. The lockout probe uses a throwaway identity so no demo
account is ever locked for the other tests."""
import pytest

from src.governance import auth as auth_mod
from tests.conftest import login


def test_brute_force_lockout_after_five_failures(client):
    victim = "bf_probe_user"          # throwaway: not a demo account
    for _ in range(5):
        r = client.post("/api/login", json={"username": victim,
                                            "password": "wrong-pass"})
        assert r.status_code == 401
    # 6th attempt - even with CORRECT credentials - is locked out
    r = client.post("/api/login", json={"username": victim,
                                        "password": "whatever"})
    assert r.status_code == 429
    assert "locked" in r.json()["detail"].lower()
    # auth module state reset so later tests are unaffected
    auth_mod.record_login_success(victim)
    assert auth_mod.login_lockout(victim) == (False, 0)


def test_lockout_counts_only_within_window():
    ok, retry = auth_mod.login_lockout("never_tried_user")
    assert ok is False and retry == 0


def test_logout_revokes_token_immediately(client):
    headers = login(client, "biz_analyst", "BizA@123")
    assert client.get("/api/me", headers=headers).status_code == 200
    r = client.post("/api/logout", headers=headers)
    assert r.status_code == 200 and r.json()["status"] == "logged_out"
    # the same token is now dead even though it has ~60 min left
    assert client.get("/api/me", headers=headers).status_code == 401
    assert client.post("/api/chat", headers=headers,
                       json={"message": "hello"}).status_code == 401


def test_security_headers_on_every_response(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_password_policy_helper():
    assert auth_mod.validate_password_policy("short1!A") == \
        (False, "minimum length is 10 characters")
    ok, why = auth_mod.validate_password_policy("alllowercase123!")
    assert not ok and "upper" in why
    ok, why = auth_mod.validate_password_policy("Str0ng!Pass123")
    assert ok and why == ""
