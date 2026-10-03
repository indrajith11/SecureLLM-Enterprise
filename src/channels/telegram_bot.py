"""Wave 6.1 - Telegram company-bot bridge.

SECURITY MODEL (the bridge is a client of the governed API, never a bypass):
  - Every request goes through the SAME public HTTP API as a web user:
    L1 auth (service identity) -> L2a rate limit -> L2b input firewall ->
    CIA/RBAC -> L5 model -> L6 DLP -> L7 audit chain. Zero pipeline code
    is duplicated here.
  - Identity: the bridge authenticates as ONE configured service user
    (TELEGRAM_SERVICE_USER). The real human behind each request is
    recorded via ChatRequest.external_user (telegram user id) and
    channel="telegram" - both land in the L7 audit chain meta, so a
    Telegram answer is attributable to the person who asked for it.
  - Authorization: fail-closed. Only chats listed in TELEGRAM_ALLOWED_CHATS
    are served; only telegram users mapped in TELEGRAM_USER_MAP (json env:
    {"<tg_user_id>": "display handle"}) may ask. Everyone else gets a
    polite refusal + a bridge-side audit log line.
  - Secrets: TELEGRAM_BOT_TOKEN is env-only (never in yaml). Missing
    token or enabled=false -> the bridge refuses to start.
  - Kill switch: AI_ENABLED=false makes the API return 503 -> the bridge
    says so, visibly, instead of dying silently.

Run:  python -m src.channels.telegram_bot
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict, deque

import httpx

from src.common.paths import app_config, get_nested

TG_API = "https://api.telegram.org"
MSG_LIMIT = 4096          # telegram hard cap per message


class BridgeConfigError(RuntimeError):
    """Fail-closed startup: the bridge refuses to run misconfigured."""


class TelegramBridge:
    def __init__(self, api_base: str = "", tg_api: str = TG_API,
                 http: httpx.Client | None = None):
        cfg = app_config()
        tg = get_nested(cfg, "telegram", {}) or {}
        if not get_nested(tg, "enabled", False):
            raise BridgeConfigError(
                "telegram bridge disabled (telegram.enabled != true) - "
                "enable it explicitly to run a company bot")
        self.bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        if not self.bot_token:
            raise BridgeConfigError(
                "TELEGRAM_BOT_TOKEN missing - fail closed, refusing to start")
        self.api_base = (api_base or get_nested(
            cfg, "telegram.api_url", "http://localhost:8000")).rstrip("/")
        self.tg_api = tg_api.rstrip("/")
        allowed = os.environ.get("TELEGRAM_ALLOWED_CHATS", "") or \
            ",".join(str(c) for c in get_nested(tg, "allowed_chats", []) or [])
        self.allowed_chats = {str(c).strip() for c in allowed.split(",")
                              if str(c).strip()}
        raw_map = os.environ.get("TELEGRAM_USER_MAP", "") or json.dumps(
            get_nested(tg, "user_map", {}) or {})
        try:
            self.user_map = {str(k): str(v)
                             for k, v in json.loads(raw_map).items()}
        except json.JSONDecodeError as e:
            raise BridgeConfigError(
                f"TELEGRAM_USER_MAP is not valid JSON: {e}") from e
        self.service_user = os.environ.get("TELEGRAM_SERVICE_USER", "")
        self.service_password = os.environ.get("TELEGRAM_SERVICE_PASSWORD", "")
        if not (self.service_user and self.service_password):
            raise BridgeConfigError(
                "TELEGRAM_SERVICE_USER / TELEGRAM_SERVICE_PASSWORD missing "
                "- the bridge needs a governed identity to call the API")
        self.rate_per_min = int(get_nested(tg, "rate_limit_per_min", 5))
        self._sent: dict[str, deque] = defaultdict(lambda: deque())
        self._token = ""
        self._token_exp = 0.0
        self.http = http or httpx.Client(timeout=40)
        self._offset = 0

    # -------------------------------------------------- governed API side
    def _login(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        r = self.http.post(f"{self.api_base}/api/login",
                           json={"username": self.service_user,
                                 "password": self.service_password})
        if r.status_code != 200:
            raise BridgeConfigError(
                f"service login failed ({r.status_code}) - check "
                "TELEGRAM_SERVICE_USER/PASSWORD against seeded users")
        body = r.json()
        self._token = body.get("access_token", "")
        exp = body.get("expires_in", 3600)
        self._token_exp = time.time() + float(exp)
        return self._token

    def ask_governed_api(self, question: str,
                         tg_user_id: str) -> tuple[int, dict]:
        """One governed round-trip. Returns (status, body)."""
        tok = self._login()
        r = self.http.post(
            f"{self.api_base}/api/chat",
            headers={"Authorization": f"Bearer {tok}"},
            json={"message": question[:4000], "channel": "telegram",
                  "external_user": tg_user_id[:64]})
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text[:200]}
        return r.status_code, body

    # -------------------------------------------------- rate limiting
    def _allow_rate(self, tg_user_id: str) -> bool:
        now = time.time()
        window = self._sent[tg_user_id]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.rate_per_min:
            return False
        window.append(now)
        return True

    # -------------------------------------------------- telegram side
    def _tg(self, method: str, **payload) -> dict:
        r = self.http.post(f"{self.tg_api}/bot{self.bot_token}/{method}",
                           json=payload)
        if r.status_code != 200:
            raise RuntimeError(f"telegram {method} -> {r.status_code}")
        return r.json()

    def send_message(self, chat_id, text: str) -> None:
        self._tg("sendMessage", chat_id=chat_id, text=text[:MSG_LIMIT])

    def reply_for(self, msg: dict) -> tuple[int, str] | None:
        """Pure decision core: one telegram message -> (chat_id, reply).
        None = ignore the update entirely (non-text, edits, callbacks)."""
        chat_id = msg.get("chat", {}).get("id")
        tg_user = msg.get("from", {}).get("id")
        text = (msg.get("text") or "").strip()
        if chat_id is None:
            return None
        if str(chat_id) not in self.allowed_chats:
            self._deny_audit("chat_not_allowed", chat_id, tg_user, text[:80])
            return (chat_id, "This chat is not authorized to use the "
                             "company assistant.")
        if text.startswith("/start") or text.startswith("/help"):
            return (chat_id,
                    "SecureLLM company assistant. Ask any work question and "
                    "I will answer under the same governance pipeline as the "
                    "web app: role-scoped access, input firewall, output "
                    "DLP, full audit trail.")
        if tg_user is None:
            return (chat_id, "Anonymous messages cannot be attributed - "
                             "denied (fail closed).")
        key = str(tg_user)
        if key not in self.user_map:
            self._deny_audit("user_not_mapped", chat_id, tg_user, text[:80])
            return (chat_id,
                    "You are not registered for the assistant yet. Ask an "
                    "admin to map your telegram id.")
        if not text:
            return None
        if not self._allow_rate(key):
            return (chat_id, "Rate limit reached (try again in a minute).")
        status, body = self.ask_governed_api(text, key)
        if status == 503:
            return (chat_id, "AI features are temporarily disabled by the "
                             "operator. Please try later.")
        if status != 200:
            detail = body.get("detail") or body.get("response") or ""
            if isinstance(detail, str) and detail:
                return (chat_id, f"Request denied by governance: {detail}")
            return (chat_id, "Request could not be completed.")
        answer = body.get("response", "")
        return (chat_id, answer or "(empty answer)")

    def _deny_audit(self, why: str, chat_id, tg_user, snippet: str) -> None:
        # bridge-side audit trail (the governed API never sees these)
        print(f"[telegram] DENY {why} chat={chat_id} user={tg_user} "
              f"text={snippet!r}", file=sys.stderr)

    def run_once(self, updates: list[dict]) -> int:
        """Process one poll batch (also the unit-test seam)."""
        handled = 0
        for upd in updates:
            self._offset = max(self._offset, upd.get("update_id", 0))
            msg = upd.get("message") or upd.get("channel_post") or {}
            try:
                out = self.reply_for(msg)
            except Exception as e:            # never kill the loop
                print(f"[telegram] handler error: {e}", file=sys.stderr)
                chat_id = msg.get("chat", {}).get("id")
                if chat_id is not None:
                    self.send_message(chat_id, "Internal error - the "
                                               "incident has been logged.")
                    handled += 1
                continue
            if out is not None:
                self.send_message(*out)
                handled += 1
        return handled

    def poll_forever(self) -> None:        # pragma: no cover - live loop
        print(f"[telegram] bridge up: "
              f"allowed_chats={sorted(self.allowed_chats)} "
              f"mapped_users={len(self.user_map)} api={self.api_base}",
              file=sys.stderr)
        while True:
            try:
                data = self._tg("getUpdates", offset=self._offset + 1,
                                timeout=30)
                self.run_once(data.get("result", []))
            except Exception as e:
                print(f"[telegram] poll error: {e}", file=sys.stderr)
                time.sleep(3)


def main() -> int:                         # pragma: no cover - live entry
    try:
        bridge = TelegramBridge()
    except BridgeConfigError as e:
        print(f"[telegram] REFUSING TO START: {e}", file=sys.stderr)
        return 2
    bridge.poll_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
