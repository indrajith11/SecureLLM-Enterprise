"""Wave 6.1 - Telegram company-bot bridge.

Pinned guarantees:
  - fail-closed startup: disabled feature, missing bot token, missing
    service credentials or malformed user map ALL refuse to start;
  - the bridge is a CLIENT of the governed API: allowed chat + mapped
    user -> one POST /api/chat carrying channel="telegram" and
    external_user=<tg id> (audit attribution), answer relayed verbatim;
  - authorization denies are bridge-side and fail closed: unmapped users
    and unauthorized chats never reach the governed API;
  - the kill switch is visible: API 503 -> an explicit operator-disabled
    message instead of a stack trace;
  - per-telegram-user rate limiting guards the shared service identity.

The stubs below are real TCP HTTP servers for BOTH sides - the Telegram
Bot API shapes (getUpdates/sendMessage with bot-token path auth) and the
governed API shapes (/api/login, /api/chat). No HTTP layer is mocked.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.channels import telegram_bot as tb


# ---------- governed SecureLLM API stub --------------------------------------
class _StubApi(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    behavior = "ok"                 # ok | 503 | 429 | 403
    last_chat: dict = {}
    last_auth: str | None = None
    logins = 0

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/login":
            _StubApi.logins += 1
            resp = {"access_token": "stub-jwt-token", "expires_in": 3600}
            code = 200
        elif self.path == "/api/chat":
            _StubApi.last_chat = {"json": body,
                                  "auth": self.headers.get("Authorization")}
            code = {"ok": 200, "503": 503, "429": 429, "403": 403}[
                _StubApi.behavior]
            if code == 200:
                resp = {"response": "A governed answer.", "meta": {
                    "backend": "mock", "model": "mock", "channel": "telegram",
                    "external_user": body.get("external_user")}}
            elif code == 503:
                resp = {"detail": "AI features are temporarily disabled"}
            elif code == 429:
                resp = {"detail": "Rate limit exceeded"}
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
    "TELEGRAM_USER_MAP": '{"111": "indra (viewer)", "222": "hr_manager"}',
    "TELEGRAM_SERVICE_USER": "tg_bridge",
    "TELEGRAM_SERVICE_PASSWORD": "pw",
}


@pytest.fixture()
def bridge(api_server, tg_server, monkeypatch):
    _StubApi.behavior = "ok"
    _StubApi.last_chat = {}
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


def test_missing_service_credentials_refuse_to_start(bridge, monkeypatch):
    monkeypatch.delenv("TELEGRAM_SERVICE_PASSWORD")
    with pytest.raises(tb.BridgeConfigError, match="SERVICE"):
        tb.TelegramBridge(api_base="http://127.0.0.1:1",
                          tg_api=bridge.tg_api)


def test_bad_user_map_json_refuses_to_start(bridge, monkeypatch):
    monkeypatch.setenv("TELEGRAM_USER_MAP", "{not json")
    with pytest.raises(tb.BridgeConfigError, match="JSON"):
        tb.TelegramBridge(api_base="http://127.0.0.1:1",
                          tg_api=bridge.tg_api)


# ---------- authorization (fail closed, bridge-side) ---------------------------
def test_unauthorized_chat_is_denied_without_api_call(bridge):
    out = bridge.reply_for(_msg("hello", chat=-10042))
    assert out and "not authorized" in out[1]
    assert _StubApi.last_chat == {}          # never reached the pipeline


def test_unmapped_user_is_denied_without_api_call(bridge):
    out = bridge.reply_for(_msg("hello", user=999))
    assert out and "not registered" in out[1]
    assert _StubApi.last_chat == {}


def test_start_help_does_not_hit_api(bridge):
    out = bridge.reply_for(_msg("/start"))
    assert out and "governance pipeline" in out[1]
    assert _StubApi.last_chat == {}


# ---------- happy path: one governed round trip --------------------------------
def test_mapped_user_gets_governed_answer(bridge):
    handled = bridge.run_once(
        [{"update_id": 1, "message": _msg("What is the leave policy?")}])
    assert handled == 1
    sent = _StubApi.last_chat
    assert sent["json"]["channel"] == "telegram"     # audit attribution
    assert sent["json"]["external_user"] == "111"
    assert sent["auth"] == "Bearer stub-jwt-token"   # L1 as service identity
    assert any(m["text"] == "A governed answer."
               for m in _StubTg.sent)                # relayed to telegram


def test_service_login_caches_token(bridge):
    bridge.ask_governed_api("q1", "111")
    n = _StubApi.logins
    bridge.ask_governed_api("q2", "111")
    assert _StubApi.logins == n              # token reused, no re-login


# ---------- kill switch + denials surface visibly -------------------------------
def test_kill_switch_503_is_visible(bridge):
    _StubApi.behavior = "503"
    out = bridge.reply_for(_msg("hello"))
    assert out and "temporarily disabled" in out[1]


def test_governance_denial_is_relayed(bridge):
    _StubApi.behavior = "403"
    out = bridge.reply_for(_msg("show me salaries"))
    assert out and "denied by governance" in out[1]


# ---------- rate limiting per telegram user -------------------------------------
def test_per_user_rate_limit(bridge):
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
