"""Wave 5.1 - HttpOnly cookie sessions + CSRF (double-submit pattern).

Pinned guarantees:
  - /api/login issues seac_session (HttpOnly - JS/XSS cannot read it) and
    seac_csrf (readable by the app's own JS) alongside the Bearer token;
  - cookie-authenticated GETs work without any CSRF token;
  - cookie-authenticated STATE-CHANGING requests (POST/PATCH/DELETE) require
    X-CSRF-Token == seac_csrf (constant-time compare) - missing, mismatched
    or forged tokens are 403;
  - the Bearer contract is untouched: header-auth requests never need CSRF;
  - /api/logout clears both cookies and revokes the jti.
"""
import jwt as pyjwt
import pytest

from src.governance import auth as auth_mod
from tests.conftest import login


@pytest.fixture
def cookie_session(client):
    """Login and hand back (client, csrf_token). The TestClient jar now
    carries seac_session + seac_csrf automatically."""
    r = client.post("/api/login", json={"username": "alice",
                                        "password": "alice123"})
    assert r.status_code == 200
    return r.json()["csrf_token"]


def test_login_sets_httponly_session_and_csrf_cookies(client):
    r = client.post("/api/login", json={"username": "alice",
                                        "password": "alice123"})
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert "seac_session=" in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()
    assert "seac_csrf=" in client.cookies.get("seac_csrf", "") or \
        client.cookies.get("seac_csrf")
    body = r.json()
    assert body["csrf_token"]
    # the session cookie value IS the same signed JWT (verifiable)
    cookie_token = client.cookies.get("seac_session")
    payload = pyjwt.decode(cookie_token, options={"verify_signature": False})
    assert payload["sub"] == "alice"


def test_cookie_auth_get_works_without_csrf(client, cookie_session):
    """GET is read-only: cookie-auth is enough, no CSRF needed."""
    r = client.get("/api/me")
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "alice"


def test_cookie_auth_post_without_csrf_forbidden(client, cookie_session):
    r = client.post("/api/chat", json={"message": "What is the deployment "
                                                   "process?"})
    assert r.status_code == 403
    assert "CSRF" in r.json()["detail"]


def test_cookie_auth_post_with_wrong_csrf_forbidden(client, cookie_session):
    r = client.post("/api/chat",
                    headers={"X-CSRF-Token": "forged-token-value"},
                    json={"message": "What is the deployment process?"})
    assert r.status_code == 403


def test_cookie_auth_post_with_valid_csrf_allowed(client, cookie_session):
    r = client.post("/api/chat",
                    headers={"X-CSRF-Token": cookie_session},
                    json={"message": "What is the deployment process?"})
    assert r.status_code == 200, r.text
    assert r.json()["response"]


def test_bearer_contract_untouched_no_csrf_needed(client):
    """Header auth must remain CSRF-free (the double-submit pattern only
    defends cookie-based sessions)."""
    tok = login(client, "alice", "alice123")
    r = client.post("/api/chat", headers=tok,
                    json={"message": "What is the deployment process?"})
    assert r.status_code == 200


def test_logout_clears_cookies_and_revokes(client, cookie_session):
    r = client.post("/api/logout", headers={"X-CSRF-Token": cookie_session})
    assert r.status_code == 200
    # jar still contains the (now revoked) cookie; the request with it fails
    r2 = client.get("/api/me")
    assert r2.status_code == 401


def test_cookie_csrf_uses_constant_time_compare(client, cookie_session,
                                                monkeypatch):
    """Sanity: verification path really uses secrets.compare_digest."""
    import secrets as _secrets
    from src.api import main as m
    called = {"v": False}
    real = _secrets.compare_digest

    def spy(a, b):
        called["v"] = True
        return real(a, b)

    monkeypatch.setattr(m.secrets, "compare_digest", spy)
    client.post("/api/chat", headers={"X-CSRF-Token": "nope"},
                json={"message": "hi"})
    assert called["v"] is True


def test_tampered_session_cookie_rejected(client):
    client.post("/api/login", json={"username": "alice",
                                    "password": "alice123"})
    client.cookies.set("seac_session", "not-a-jwt")
    assert client.get("/api/me").status_code == 401
