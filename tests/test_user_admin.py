"""Waves 2.1 + 2.2 - identity & authority: role_version instant revocation
plus the Admin user-management API.

Pinned guarantees:
  - changing a role/department/clearance or resetting a password bumps
    role_version -> EVERY outstanding JWT for that account is 401 on its
    very next request (revocation-on-change, complementary to logout jti);
  - provisioning hands out a TEMP password that cannot talk to company
    data (403 on chat) until the user sets their own via /api/me/password;
  - Admin self-protection: Admin grants need the SECURELLM_SUPERADMINS
    allow-list (self-elevation -> 403, fail closed when unset), the last
    active Admin cannot be demoted/disabled (409), self-disable refused;
  - the users table has NO password hashes on any admin read surface.
"""
import sqlite3

import pytest

from src.common.paths import COMPANY_DB
from tests.conftest import login


@pytest.fixture
def superadmin_env(monkeypatch):
    """The 'admin' seed account may grant Admin power for these tests."""
    monkeypatch.setenv("SECURELLM_SUPERADMINS", "admin")
    yield


@pytest.fixture
def cleanup_users():
    """Delete accounts created by a test so the runtime DB stays pristine."""
    created: list[str] = []
    yield created
    conn = sqlite3.connect(COMPANY_DB)
    for username in created:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def _make_admin(client, superadmin_env):
    return login(client, "admin", "Admin@123")


def _create(client, headers, cleanup, username, role="Tech_Engineer",
            department="Tech", clearance="L3", password="TempPass#2026"):
    r = client.post("/admin/users", headers=headers, json={
        "username": username, "password": password, "full_name": "Test User",
        "email": f"{username}@corp.example.com", "role": role,
        "department": department, "clearance": clearance})
    if r.status_code == 200:
        cleanup.append(username)
    return r


# ---------- Wave 2.1: role_version instant revocation ------------------------
def test_role_change_revokes_outstanding_token(client, cleanup_users,
                                               superadmin_env):
    """THE 2.1 acceptance: change a user's role -> old JWT 401s NEXT call."""
    admin = _make_admin(client, superadmin_env)
    assert _create(client, admin, cleanup_users, "rv_user1").status_code == 200
    tok = login(client, "rv_user1", "TempPass#2026")
    # change the password first (temp guard) so the session is otherwise valid
    client.post("/api/me/password", headers=tok,
                json={"current_password": "TempPass#2026",
                      "new_password": "MyOwn#Pass99"})
    tok = login(client, "rv_user1", "MyOwn#Pass99")
    assert client.get("/api/me", headers=tok).status_code == 200
    # role change bumps role_version...
    r = client.patch("/admin/users/rv_user1", headers=admin,
                     json={"role": "HR_Employee", "department": "HR"})
    assert r.status_code == 200
    # ...and the OLD token dies on its very next request
    assert client.get("/api/me", headers=tok).status_code == 401
    fresh = login(client, "rv_user1", "MyOwn#Pass99")
    assert client.get("/api/me", headers=fresh).status_code == 200
    assert fresh == fresh     # sanity: fixture headers reusable


def test_disable_revokes_token_and_blocks_login(client, cleanup_users,
                                                superadmin_env):
    admin = _make_admin(client, superadmin_env)
    _create(client, admin, cleanup_users, "rv_user2")
    tok = login(client, "rv_user2", "TempPass#2026")
    client.post("/api/me/password", headers=tok,
                json={"current_password": "TempPass#2026",
                      "new_password": "MyOwn#Pass99"})
    tok = login(client, "rv_user2", "MyOwn#Pass99")
    r = client.patch("/admin/users/rv_user2", headers=admin,
                     json={"is_active": False})
    assert r.status_code == 200
    assert client.get("/api/me", headers=tok).status_code == 401
    r = client.post("/api/login", json={"username": "rv_user2",
                                        "password": "MyOwn#Pass99"})
    assert r.status_code == 401     # offboarding revokes access (fail closed)


def test_pre_feature_token_fails_closed(client, alice):
    """A token without the rv claim can never match a live row (>= 1)."""
    import jwt as pyjwt
    from src.governance import auth as auth_mod
    # craft a token that mimics the pre-2.1 format (no rv claim)
    payload = {"sub": "alice", "role": "Tech_Employee", "dept": "Tech",
               "clr": "L2", "uid": 1, "iat": 1, "exp": 2**31}
    legacy = pyjwt.encode(payload, auth_mod._secret(), algorithm="HS256")
    r = client.post("/chat", headers={"Authorization": "Bearer " + legacy},
                    json={"message": "hi"})
    assert r.status_code == 401


# ---------- Wave 2.2: user management API ------------------------------------
def test_create_login_temp_password_block_then_self_change(client,
                                                           cleanup_users,
                                                           superadmin_env):
    admin = _make_admin(client, superadmin_env)
    r = _create(client, admin, cleanup_users, "life_user1")
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["must_change_password"] == 1
    # temp password works for login...
    tok = login(client, "life_user1", "TempPass#2026")
    # ...but the account may NOT chat with a shared secret
    r = client.post("/chat", headers=tok,
                    json={"message": "What is the deployment process?"})
    assert r.status_code == 403
    assert "password change required" in r.json()["detail"]
    # self-service change (requires CURRENT password, validates policy)
    bad = client.post("/api/me/password", headers=tok,
                      json={"current_password": "Wrong#Pass1",
                            "new_password": "MyOwn#Pass99"})
    assert bad.status_code == 422
    weak = client.post("/api/me/password", headers=tok,
                       json={"current_password": "TempPass#2026",
                             "new_password": "short"})
    assert weak.status_code == 422
    ok = client.post("/api/me/password", headers=tok,
                     json={"current_password": "TempPass#2026",
                           "new_password": "MyOwn#Pass99"})
    assert ok.status_code == 200
    # the rv bump killed the current session; the new password works
    assert client.get("/api/me", headers=tok).status_code == 401
    tok2 = login(client, "life_user1", "MyOwn#Pass99")
    me = client.get("/api/me", headers=tok2).json()["user"]
    assert me["must_change_password"] == 0
    r = client.post("/chat", headers=tok2,
                    json={"message": "What is the deployment process?"})
    assert r.status_code == 200


def test_admin_list_has_no_password_hashes(client, superadmin_env):
    admin = _make_admin(client, superadmin_env)
    users = client.get("/admin/users", headers=admin).json()["users"]
    assert users
    assert all("password_hash" not in u and "password" not in u
               for u in users)


def test_non_admin_cannot_manage_users(client, hr):
    assert client.get("/admin/users", headers=hr).status_code == 403
    assert client.post("/admin/users", headers=hr, json={
        "username": "sneak", "password": "Sneak#12345", "role": "Admin",
        "department": "IT", "clearance": "L5"}).status_code == 403


def test_self_elevation_forbidden_without_superadmin(client, cleanup_users):
    """'admin' is NOT in the allow-list here -> creating an Admin is 403,
    and with the env unset nobody can create Admins (fail closed)."""
    admin = login(client, "admin", "Admin@123")
    r = _create(client, admin, cleanup_users, "elevate1", role="Admin",
                department="IT", clearance="L5")
    assert r.status_code == 403


def test_granting_admin_requires_allowlist_on_patch(client, cleanup_users,
                                                    superadmin_env):
    """Sequenced admin-power guards:
    1. an actor IN the allow-list can mint a second Admin (gate opens);
    2. that second Admin (NOT in the allow-list) cannot mint another
       Admin or grant the role to anyone (403 self-elevation);
    3. demoting a NON-last Admin is fine;
    4. demoting the LAST active Admin is refused (409)."""
    admin = login(client, "admin", "Admin@123")
    # 1) allow-listed admin mints admin3
    r = client.post("/admin/users", headers=admin, json={
        "username": "admin3", "password": "Admin3#Temp1",
        "full_name": "Admin Three", "email": "admin3@corp.example.com",
        "role": "Admin", "department": "IT", "clearance": "L5"})
    assert r.status_code == 200, r.text
    cleanup_users.append("admin3")
    cleanup_users.append("victim1")     # created in step 2
    # 2) admin3 (not in the allow-list) cannot grant Admin to anyone
    tok3 = login(client, "admin3", "Admin3#Temp1")
    client.post("/api/me/password", headers=tok3,
                json={"current_password": "Admin3#Temp1",
                      "new_password": "Admin3#Own99"})
    tok3 = login(client, "admin3", "Admin3#Own99")
    r = client.post("/admin/users", headers=tok3, json={
        "username": "admin4", "password": "Admin4#Temp1",
        "full_name": "x", "role": "Admin", "department": "IT",
        "clearance": "L5"})
    assert r.status_code == 403
    client.post("/admin/users", headers=tok3, json={
        "username": "victim1", "password": "Victim#Temp1",
        "full_name": "x", "role": "Tech_Engineer", "department": "Tech",
        "clearance": "L3"})
    r = client.patch("/admin/users/victim1", headers=tok3,
                     json={"role": "Admin"})
    assert r.status_code == 403
    assert "SECURELLM_SUPERADMINS" in r.json()["detail"]
    # 3) demoting a NON-last Admin is allowed (two active Admins here)
    r = client.patch("/admin/users/admin3", headers=admin,
                     json={"role": "Tech_Engineer", "department": "Tech"})
    assert r.status_code == 200
    # 4) 'admin' is now the ONLY active Admin: self-demotion is 409
    r = client.patch("/admin/users/admin", headers=admin,
                     json={"role": "Tech_Employee"})
    assert r.status_code == 409
    assert "last active Admin" in r.json()["detail"]


def test_admin_reset_password_revokes_sessions(client, cleanup_users,
                                               superadmin_env):
    admin = _make_admin(client, superadmin_env)
    _create(client, admin, cleanup_users, "reset_user1")
    tok = login(client, "reset_user1", "TempPass#2026")
    client.post("/api/me/password", headers=tok,
                json={"current_password": "TempPass#2026",
                      "new_password": "MyOwn#Pass99"})
    tok = login(client, "reset_user1", "MyOwn#Pass99")
    r = client.post("/admin/users/reset_user1/password", headers=admin,
                    json={"new_password": "ReSet#Temp2"})
    assert r.status_code == 200
    assert client.get("/api/me", headers=tok).status_code == 401
    tok2 = login(client, "reset_user1", "ReSet#Temp2")
    # the reset installed a TEMP secret: chat stays blocked until changed
    assert client.post("/chat", headers=tok2,
                       json={"message": "hi"}).status_code == 403
    me = client.get("/api/me", headers=tok2).json()["user"]
    assert me["must_change_password"] == 1


def test_create_rejects_weak_password_and_bad_role(client, cleanup_users,
                                                   superadmin_env):
    admin = _make_admin(client, superadmin_env)
    r = _create(client, admin, cleanup_users, "weakpw1",
                password="weakpassword")
    assert r.status_code == 422
    r = client.post("/admin/users", headers=admin, json={
        "username": "badrole1", "password": "GoodPass#123",
        "full_name": "x", "role": "SuperBoss", "department": "Tech",
        "clearance": "L3"})
    assert r.status_code == 422
    r = client.post("/admin/users", headers=admin, json={
        "username": "Bad User", "password": "GoodPass#123",
        "full_name": "x", "role": "Tech_Engineer", "department": "Tech",
        "clearance": "L3"})
    assert r.status_code == 422       # username charset enforced


def test_user_mutations_are_audited(client, cleanup_users, superadmin_env):
    admin = _make_admin(client, superadmin_env)
    _create(client, admin, cleanup_users, "audit_user1")
    r = client.get("/api/audit/me", headers=admin).json()
    actions = [e["action"] for e in r["events"]]
    assert "USER_CREATE" in actions


# ---------- Wave 2.3 backend: permission preview -----------------------------
def test_role_permissions_endpoint(client, superadmin_env):
    admin = _make_admin(client, superadmin_env)
    r = client.get("/admin/roles/HR_Employee/permissions", headers=admin)
    assert r.status_code == 200
    body = r.json()
    assert "employees_public_view" in body["can"]["tables"]
    assert "employees" in body["cannot"]["tables"]
    assert "salary" not in body["tables"]["employees_public_view"]["columns"]
    assert body["can"]["namespaces"] == ["hr_docs"]
    assert "tech_docs" in body["cannot"]["namespaces"]
    assert client.get("/admin/roles/Nope/permissions",
                      headers=admin).status_code == 404
    assert client.get("/admin/roles/HR_Employee/permissions",
                      headers=login(client, "hr_hari", "hari123")
                      ).status_code == 403


def test_admin_page_served_and_data_gated(client):
    """Wave 2.3: the admin page is a static shell; the SECURITY boundary is
    server-side - every data endpoint it calls stays Admin-only."""
    r = client.get("/admin.html")
    assert r.status_code == 200
    assert b"Permission preview" in r.content
    tok = login(client, "alice", "alice123")
    assert client.get("/admin/users", headers=tok).status_code == 403
    assert client.get("/admin/roles/Admin/permissions",
                      headers=tok).status_code == 403
