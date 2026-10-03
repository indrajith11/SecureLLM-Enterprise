"""Wave 6.1 + 6.6 - Telegram company-bot bridge (per-user login).

Pinned guarantees:
  - fail-closed startup: disabled feature, missing bot token, malformed
    user map ALL refuse to start (service credentials are gone by design:
    every chat rides the LOGGED-IN USER's own identity now);
  - login gate: NO governed API chat call happens without a successful
    company login (/login -> username -> password -> /api/login);
  - chat gate: unauthorized chats never reach the governed API;
  - the governed round trip carries channel="telegram",
    external_user=<tg id> AND the user's OWN bearer token (L1 identity =
    the real human, so RBAC/CIA/audit all bind to them);
  - passwords are never logged or echoed by the bridge;
  - the kill switch is visible: API 503 -> explicit operator message;
  - 401 mid-session -> session dropped -> re-login prompt;
  - per-telegram-user rate limiting still guards the pipeline.

The stubs below are real TCP HTTP servers for BOTH sides - the Telegram
Bot API shapes (getUpdates/sendMessage with bot-token path auth) and the
governed API shapes (/api/login, /api/chat). No HTTP layer is mocked.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.channels import telegram_bot as tb

VALID_USER = {"username": "indra", "password": "Secret@123",
              "role": "Tech_Employee"}


# ---------- governed SecureLLM API stub --------------------------------------
class _StubApi(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    behavior = "ok"                 # ok | 503 | 403
    login_behavior = "ok"           # ok | 401
    last_chat: dict = {}
    last_auth: str | None = None
    logins: list[dict] = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/login":
            _StubApi.logins.append(body)
            if _StubApi.login_behavior == "401" or \
                    body.get("username") != VALID_USER["username"] or \
                    body.get("password") != VALID_USER["password"]:
                code, resp = 401, {"detail": "invalid credentials"}
            else:
                code, resp = 200, {"access_token": "user-jwt-token",
                                   "expires_in": 3600,
                                   "role": VALID_USER["role"]}
        elif self.path == "/api/chat":
            _StubApi.last_chat = {"json": body,
                                  "auth": self.headers.get("Authorization")}
            code = {"ok": 200, "503": 503, "403": 403,
                    "401": 401}[_StubApi.behavior]
            if code == 200:
                resp = {"response": "A governed answer.", "meta": {
                    "backend": "mock", "model": "mock",
                    "channel": "telegram",
                    "external_user": body.get("external_user"),
                    "router": "company"}}
            elif code == 503:
                resp = {"detail": "AI features are temporarily disabled"}
            elif code == 401:
                resp = {"detail": "session expired"}
            else:
                resp = {"detail": "Confidentiality violation"}
        else:
            code, resp = 404, {}
        payload = json.dumps(resp).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


# ---------- telegram Bot API stub --------------------------------------------
class _StubTg(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    sent: list[dict] = []
    token_seen: str = ""

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        parts = self.path.split("/")
        tok = parts[1] if len(parts) > 1 else ""
        _StubTg.token_seen = tok[3:] if tok.startswith("bot") else tok
        method = parts[2] if len(parts) > 2 else ""
        if _StubTg.token_seen != "STUB-TOKEN":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "sendMessage":
            _StubTg.sent.append(body)
        payload = b'{"ok": true, "result": {}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture(scope="module")
def api_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubApi)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def tg_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubTg)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


ENV = {
    "TELEGRAM_BOT_TOKEN": "STUB-TOKEN",
    "TELEGRAM_ALLOWED_CHATS": "-10099",
    "TELEGRAM_USER_MAP": '{"111": "indra", "222": "hr_manager"}',
}


@pytest.fixture()
def bridge(api_server, tg_server, monkeypatch):
    _StubApi.behavior = "ok"
    _StubApi.login_behavior = "ok"
    _StubApi.last_chat = {}
    _StubApi.logins = []
    _StubTg.sent = []
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(
        tb, "app_config",
        lambda: {"telegram": {"enabled": True, "rate_limit_per_min": 5}})
    b = tb.TelegramBridge(api_base=api_server, tg_api=tg_server)
    yield b


def _msg(text, chat=-10099, user=111):
    # the inner telegram message object (what reply_for / run_once consume)
    return {"chat": {"id": chat}, "from": {"id": user}, "text": text}


def _login(bridge, user=111, password=VALID_USER["password"]):
    """Drive the full login conversation; returns the final reply text."""
    r1 = bridge.reply_for(_msg("/login", user=user))[1]
    assert "USERNAME" in r1
    r2 = bridge.reply_for(_msg(VALID_USER["username"], user=user))[1]
    assert "PASSWORD" in r2
    r3 = bridge.reply_for(_msg(password, user=user))[1]
    return r3


# ---------- fail-closed startup ------------------------------------------------
def test_disabled_feature_refuses_to_start(monkeypatch):
    monkeypatch.setattr(tb, "app_config",
                        lambda: {"telegram": {"enabled": False}})
    with pytest.raises(tb.BridgeConfigError, match="disabled"):
        tb.TelegramBridge()


def test_missing_token_refuses_to_start(monkeypatch):
    monkeypatch.setattr(tb, "app_config",
                        lambda: {"telegram": {"enabled": True}})
    with pytest.raises(tb.BridgeConfigError, match="TELEGRAM_BOT_TOKEN"):
        tb.TelegramBridge()


def test_bad_user_map_json_refuses_to_start(bridge, monkeypatch):
    monkeypatch.setenv("TELEGRAM_USER_MAP", "{not json")
    with pytest.raises(tb.BridgeConfigError, match="JSON"):
        tb.TelegramBridge(api_base="http://127.0.0.1:1",
                          tg_api=bridge.tg_api)


def test_no_service_credentials_required(bridge):
    """Wave 6.6: the shared service identity is GONE - sessions are the
    logged-in user's own. No TELEGRAM_SERVICE_* env exists at all."""
    assert not hasattr(bridge, "service_user")
    assert not hasattr(bridge, "service_password")


# ---------- gates (fail closed, bridge-side) -----------------------------------
def test_unauthorized_chat_is_denied_without_api_call(bridge):
    out = bridge.reply_for(_msg("hello", chat=-10042))
    assert out and "not authorized" in out[1]
    assert _StubApi.last_chat == {}          # never reached the pipeline


def test_chat_without_login_is_refused(bridge):
    out = bridge.reply_for(_msg("What is the leave policy?"))
    assert out and "/login" in out[1]
    assert _StubApi.last_chat == {}          # nothing flows unauthenticated


def test_login_gate_is_optional_when_user_map_empty(bridge, monkeypatch):
    monkeypatch.setenv("TELEGRAM_USER_MAP", "")
    b = tb.TelegramBridge(api_base=bridge.api_base, tg_api=bridge.tg_api)
    r = _login(b, user=999)                  # unmapped id CAN login
    assert "Logged in" in r


def test_mapped_gate_blocks_unmapped_login(bridge):
    out = bridge.reply_for(_msg("/login", user=999))
    assert out and "not registered" in out[1]
    assert _StubApi.logins == []             # never reached the API


# ---------- login conversation ---------------------------------------------------
def test_login_flow_ends_in_governed_answer(bridge):
    handled = bridge.run_once(
        [{"update_id": 1, "message": _msg("/login")},
         {"update_id": 2, "message": _msg(VALID_USER["username"])},
         {"update_id": 3, "message": _msg(VALID_USER["password"])},
         {"update_id": 4, "message": _msg("What is the leave policy?")}])
    assert handled == 4
    sent = _StubApi.last_chat
    assert sent["json"]["channel"] == "telegram"      # audit attribution
    assert sent["json"]["external_user"] == "111"     # the real human
    assert sent["auth"] == "Bearer user-jwt-token"    # the USER's identity
    assert any(m["text"] == "A governed answer."
               for m in _StubTg.sent)                 # relayed to telegram


def test_wrong_password_fails_closed(bridge):
    r1 = bridge.reply_for(_msg("/login"))
    assert "USERNAME" in r1[1]
    bridge.reply_for(_msg(VALID_USER["username"]))
    r3 = bridge.reply_for(_msg("wrong-password"))
    assert "Login failed" in r3[1]
    assert bridge._session("111") is None
    out = bridge.reply_for(_msg("any question"))
    assert "/login" in out[1]                 # still gated


def test_bad_username_fails_closed(bridge):
    bridge.reply_for(_msg("/login"))
    bridge.reply_for(_msg("no_such_user"))
    r3 = bridge.reply_for(_msg(VALID_USER["password"]))
    assert "Login failed" in r3[1]
    assert _StubApi.last_chat == {}


def test_cancel_aborts_login(bridge):
    bridge.reply_for(_msg("/login"))
    bridge.reply_for(_msg("someuser"))
    r = bridge.reply_for(_msg("/cancel"))
    assert "cancelled" in r[1]
    r2 = bridge.reply_for(_msg("somepassword"))
    assert "/login" in r2[1]                  # not consumed as a password
    assert _StubApi.logins == []


def test_logout_drops_session(bridge):
    _login(bridge)
    r = bridge.reply_for(_msg("/logout"))
    assert "Logged out" in r[1]
    out = bridge.reply_for(_msg("q"))
    assert "/login" in out[1]


def test_whoami_shows_identity(bridge):
    _login(bridge)
    r = bridge.reply_for(_msg("/whoami"))
    assert "indra" in r[1] and "Tech_Employee" in r[1]


def test_password_is_never_echoed_or_logged(bridge):
    _login(bridge)
    texts = " ".join(m["text"] for m in _StubTg.sent)
    assert VALID_USER["password"] not in texts


def test_expired_session_prompts_relogin(bridge):
    _login(bridge)
    bridge._sessions["111"]["exp"] = 0        # force expiry
    out = bridge.reply_for(_msg("What is the leave policy?"))
    assert "/login" in out[1]
    assert _StubApi.last_chat == {}


def test_api_401_drops_session_visibly(bridge):
    _login(bridge)
    _StubApi.behavior = "401"
    out = bridge.reply_for(_msg("What is the leave policy?"))
    assert "expired" in out[1] or "login" in out[1].lower()
    assert bridge._session("111") is None


def test_general_answer_relayed_without_sources_noise(bridge):
    _login(bridge)
    _StubApi.behavior = "ok"
    import json as _json
    orig = _StubApi.do_POST

    def general_post(self):
        length = int(self.headers.get("Content-Length", 0))
        body = _json.loads(self.rfile.read(length) or b"{}")
        _StubApi.last_chat = {"json": body,
                              "auth": self.headers.get("Authorization")}
        resp = {"response": "Hello! How can I help?",
                "meta": {"router": "general"}}
        payload = _json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    _StubApi.do_POST = general_post
    try:
        out = bridge.reply_for(_msg("hi"))
        assert out and out[1] == "Hello! How can I help?"
    finally:
        _StubApi.do_POST = orig


# ---------- kill switch + denials surface visibly -------------------------------
def test_kill_switch_503_is_visible(bridge):
    _login(bridge)
    _StubApi.behavior = "503"
    out = bridge.reply_for(_msg("hello"))
    assert out and "temporarily disabled" in out[1]


def test_governance_denial_is_relayed(bridge):
    _login(bridge)
    _StubApi.behavior = "403"
    out = bridge.reply_for(_msg("show me salaries"))
    assert out and "denied by governance" in out[1]


# ---------- rate limiting per telegram user -------------------------------------
def test_per_user_rate_limit(bridge):
    _login(bridge)
    bridge.rate_per_min = 2
    bridge._sent["111"].clear()
    assert bridge.reply_for(_msg("q1"))
    assert bridge.reply_for(_msg("q2"))
    out = bridge.reply_for(_msg("q3"))
    assert out and "Rate limit" in out[1]


# ---------- poll loop robustness -------------------------------------------------
def test_run_once_ignores_malformed_and_advances_offset(bridge):
    handled = bridge.run_once([{"update_id": 7, "message": {"chat": {}}},
                               {"update_id": 8},
                               {"update_id": 9, "message": _msg("hi")}])
    assert bridge._offset == 9
    assert handled >= 0                       # no crash on malformed updates


def test_send_message_truncates_to_telegram_cap(bridge):
    bridge.send_message(-10099, "x" * 5000)
    assert len(_StubTg.sent[-1]["text"]) == tb.MSG_LIMIT
