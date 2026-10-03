"""Wave 6.1 + 6.6 - Telegram company-bot bridge with per-user login.

SECURITY MODEL (the bridge is a client of the governed API, never a bypass):
  - Every request goes through the SAME public HTTP API as a web user:
    L1 auth (the LOGGED-IN USER's own identity) -> L2a rate limit ->
    L2b input firewall -> intent router -> CIA/RBAC -> L5 model -> L6 DLP
    -> L7 audit chain. Zero pipeline code is duplicated here.
  - Identity (Wave 6.6): each Telegram user logs in with THEIR OWN company
    credentials (/login -> username -> password). The bot calls /api/login
    and rides that user's JWT: every answer is enforced by the USER's role,
    clearance and department - the same CIA triad as the web app - and the
    audit chain shows the real username (not a shared service account) plus
    channel="telegram" and the telegram user id.
  - Authorization: fail-closed, two gates.
      1. Chat gate: only chats in TELEGRAM_ALLOWED_CHATS are served.
      2. Login gate: no company data flows without a successful company
         login. GENERAL conversation (greetings/small talk/general
         knowledge, routed by the server-side intent router) also requires
         login - it IS still an AI answer governed by L2/L6/L7.
    TELEGRAM_USER_MAP is OPTIONAL extra hardening: when non-empty, only
    mapped telegram ids may even attempt /login; when empty, any member of
    an allowed chat can log in with their own company credentials.
  - Secrets: TELEGRAM_BOT_TOKEN is env-only (never in yaml). Passwords are
    never logged by the bridge and never echoed back. Missing token or
    enabled=false -> the bridge refuses to start.
  - Kill switch: AI_ENABLED=false makes the API return 503 -> the bridge
    says so, visibly, instead of dying silently.

Commands:
  /start   welcome + login instructions
  /help    same
  /login   start the login conversation (username -> password)
  /logout  forget this chat's session
  /whoami  show the logged-in identity and role
  /cancel  abort a pending login prompt

UX (v4.6.0): the user never stares at silence. While their PASSWORD is
being verified the bot first says "checking your details..." and edits
that same message with the verdict; while a governed query runs it says
"Thinking..." (plus a typing indicator) and edits itself into the answer.

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


# conversation states (per telegram user id)
_ASK_USERNAME = "username"
_ASK_PASSWORD = "password"


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
        self.rate_per_min = int(get_nested(tg, "rate_limit_per_min", 5))
        self._sent: dict[str, deque] = defaultdict(lambda: deque())
        # per-telegram-user sessions and login conversation state
        self._sessions: dict[str, dict] = {}     # uid -> {token, username,
        #                                           role, exp}
        self._awaiting: dict[str, str] = {}      # uid -> _ASK_USERNAME |
        #                                           _ASK_PASSWORD
        self._pending_name: dict[str, str] = {}  # uid -> username being
        #                                           authenticated
        self.http = http or httpx.Client(timeout=40)
        self._offset = 0

    # -------------------------------------------------- governed API side
    def _api_login(self, username: str, password: str) -> tuple[int, dict]:
        """One /api/login round-trip with the USER's own credentials.
        Status 0 = the governed API itself is unreachable (connection
        error / timeout) - surfaced as a retry hint, never a crash."""
        try:
            r = self.http.post(f"{self.api_base}/api/login",
                               json={"username": username,
                                     "password": password})
        except httpx.HTTPError:
            return 0, {"detail": "the company directory is unreachable "
                                 "right now"}
        try:
            body = r.json()
        except ValueError:
            body = {"detail": r.text[:200]}
        return r.status_code, body

    def _ask_governed_api(self, question: str, session: dict,
                          tg_user_id: str) -> tuple[int, dict]:
        """One governed round-trip riding the USER's own token.
        Status 0 = backend unreachable - the caller answers with a calm
        retry hint instead of the generic internal-error bubble."""
        try:
            r = self.http.post(
                f"{self.api_base}/api/chat",
                headers={"Authorization": f"Bearer {session['token']}"},
                json={"message": question[:4000], "channel": "telegram",
                      "external_user": tg_user_id[:64]})
        except httpx.HTTPError:
            return 0, {"detail": "assistant backend unreachable"}
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text[:200]}
        return r.status_code, body

    # -------------------------------------------------- session helpers
    def _session(self, tg_user_id: str) -> dict | None:
        s = self._sessions.get(tg_user_id)
        if s and time.time() < float(s.get("exp", 0)) - 30:
            return s
        if s:  # expired -> drop
            self._sessions.pop(tg_user_id, None)
        return None

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

    def send_message(self, chat_id, text: str) -> int | None:
        res = self._tg("sendMessage", chat_id=chat_id,
                       text=text[:MSG_LIMIT]).get("result") or {}
        mid = res.get("message_id")
        try:
            return int(mid) if mid is not None else None
        except (TypeError, ValueError):
            return None

    def edit_message(self, chat_id, message_id: int | None,
                     text: str) -> bool:
        """Edit-in-place for the waiting UX; falls back to a fresh message
        at the caller when the edit is impossible (too old, network...)."""
        if message_id is None:
            return False
        try:
            self._tg("editMessageText", chat_id=chat_id,
                     message_id=message_id, text=text[:MSG_LIMIT])
            return True
        except Exception:                      # noqa: BLE001 - UX fallback
            return False

    def send_typing(self, chat_id) -> None:
        try:
            self._tg("sendChatAction", chat_id=chat_id, action="typing")
        except Exception:                      # noqa: BLE001 - cosmetic only
            pass

    # -------------------------------------------------- decision core
    def reply_for(self, msg: dict) -> tuple[int, str] | None:
        """Pure decision core: one telegram message -> (chat_id, reply).
        None = ignore the update entirely (non-text, edits, callbacks)."""
        chat_id = msg.get("chat", {}).get("id")
        tg_user = msg.get("from", {}).get("id")
        text = (msg.get("text") or "").strip()
        if chat_id is None:
            return None
        if str(chat_id) not in self.allowed_chats:
            self._deny_audit("chat_not_allowed", chat_id, tg_user,
                             text[:80])
            return (chat_id, "This chat is not authorized to use the "
                             "company assistant.")
        if not text:
            return None

        key = str(tg_user) if tg_user is not None else ""
        if tg_user is None:
            return (chat_id, "Anonymous messages cannot be attributed - "
                             "denied (fail closed).")

        # -- commands -------------------------------------------------------
        if text.startswith("/start") or text.startswith("/help"):
            return (chat_id, self._welcome())
        if text.startswith("/cancel"):
            self._awaiting.pop(key, None)
            self._pending_name.pop(key, None)
            return (chat_id, "Login cancelled. Send /login to try again.")
        if text.startswith("/logout"):
            gone = self._sessions.pop(key, None)
            self._awaiting.pop(key, None)
            self._pending_name.pop(key, None)
            return (chat_id, "Logged out - this chat no longer has access "
                             "to company data." if gone else
                    "You were not logged in.")
        if text.startswith("/whoami"):
            s = self._session(key)
            if not s:
                return (chat_id, "Not logged in. Send /login to authenticate "
                                 "with your company credentials.")
            return (chat_id, f"Logged in as {s['username']} "
                             f"(role: {s['role']}). Every answer is enforced "
                             f"by this role and recorded in the audit chain.")
        if text.startswith("/login"):
            if self._session(key):
                s = self._sessions[key]
                return (chat_id, f"Already logged in as {s['username']} "
                                 f"({s['role']}). Use /logout first to "
                                 f"switch accounts.")
            if self.user_map and key not in self.user_map:
                self._deny_audit("user_not_mapped", chat_id, tg_user,
                                 text[:80])
                return (chat_id, "You are not registered for the assistant "
                                 "yet. Ask an admin to map your telegram id.")
            self._awaiting[key] = _ASK_USERNAME
            return (chat_id, "Login: send your company USERNAME.\n"
                             "Send /cancel to abort.")

        # -- login conversation ---------------------------------------------
        state = self._awaiting.get(key)
        if state == _ASK_USERNAME:
            self._pending_name[key] = text[:64]
            self._awaiting[key] = _ASK_PASSWORD
            return (chat_id, "Thanks. Now send your PASSWORD.\n"
                             "Note: Telegram keeps messages in your chat "
                             "history - delete the password message after "
                             "sending (long-press -> delete). I never log "
                             "or store it.\n/cancel to abort.")
        if state == _ASK_PASSWORD:
            username = self._pending_name.pop(key, "")
            self._awaiting.pop(key, None)
            if not username:
                return (chat_id, "Login flow out of sync - send /login to "
                                 "restart.")
            status, body = self._api_login(username, text)
            if status == 200 and body.get("access_token"):
                exp = float(body.get("expires_in", 3600))
                self._sessions[key] = {
                    "token": body["access_token"],
                    "username": username,
                    "role": str(body.get("role", "")),
                    "exp": time.time() + exp}
                return (chat_id, f"Logged in as {username} "
                                 f"({self._sessions[key]['role'] or 'user'})."
                                 f"\nAsk me anything - company data is "
                                 f"enforced by YOUR role and clearance, "
                                 f"general questions are answered directly.")
            detail = body.get("detail", "")
            if isinstance(detail, dict):
                detail = detail.get("message", "")
            why = f" ({detail})" if detail else ""
            return (chat_id, f"Login failed{why}. Send /login to try "
                             f"again. Your account may be locked after "
                             f"repeated failures.")

        # -- normal conversation: requires an active session -----------------
        session = self._session(key)
        if not session:
            return (chat_id, "Please /login with your company credentials "
                             "first - then I can answer under YOUR access "
                             "rights.")
        if not self._allow_rate(key):
            return (chat_id, "Rate limit reached (try again in a minute).")
        status, body = self._ask_governed_api(text, session, key)
        if status == 401:
            self._sessions.pop(key, None)
            return (chat_id, "Your session expired. Send /login to "
                             "authenticate again.")
        if status == 503:
            return (chat_id, "AI features are temporarily disabled by the "
                             "operator. Please try later.")
        if status == 0:
            return (chat_id, "The assistant backend is not reachable "
                             "right now - please try again shortly. Your "
                             "login session is kept.")
        if status != 200:
            detail = body.get("detail") or body.get("response") or ""
            if isinstance(detail, str) and detail:
                return (chat_id, f"Request denied by governance: {detail}")
            return (chat_id, "Request could not be completed.")
        answer = body.get("response", "")
        router = (body.get("meta") or {}).get("router", "company")
        # light provenance: company answers may carry sources; general
        # answers are the model's own (no data was read for this reply).
        if router == "general" and answer:
            return (chat_id, answer)
        return (chat_id, answer or "(empty answer)")

    def _welcome(self) -> str:
        extra = ""
        if self.user_map:
            extra = ("\nThis deployment restricts login to pre-registered "
                     "telegram accounts.")
        return ("SecureLLM company assistant.\n"
                "To use me, log in ONCE with your company credentials:\n"
                "  1. Send /login\n"
                "  2. I ask for your username\n"
                "  3. I ask for your password (never stored, delete the "
                "message after sending)\n"
                "After that, ask anything:\n"
                "  - Company data answers follow YOUR role, clearance and "
                "department (CIA enforced, fully audited).\n"
                "  - Greetings and general questions are answered directly "
                "by the AI.\n"
                "Commands: /login /whoami /logout /cancel /help" + extra)

    def _deny_audit(self, why: str, chat_id, tg_user, snippet: str) -> None:
        # bridge-side audit trail (the governed API never sees these)
        print(f"[telegram] DENY {why} chat={chat_id} user={tg_user} "
              f"text={snippet!r}", file=sys.stderr)

    # -------------------------------------------------- waiting UX
    _LOGIN_WAIT = ("\u23f3 Please wait - checking your details in the "
                   "company directory\u2026")
    _QUERY_WAIT = "\U0001f9e0 Thinking - give me a moment\u2026"

    def _interim_for(self, msg: dict, key: str,
                     text: str) -> tuple[str, str] | None:
        """Which waiting message (if any) this update earns BEFORE the
        slow part runs. Only real conversation earns one - commands and
        empty text reply instantly."""
        if not text or text.startswith("/"):
            return None
        if self._awaiting.get(key) == _ASK_PASSWORD:
            return ("login", self._LOGIN_WAIT)
        if self._session(key):
            return ("query", self._QUERY_WAIT)
        return None

    def run_once(self, updates: list[dict]) -> int:
        """Process one poll batch (also the unit-test seam).
        Waiting UX: send the interim note FIRST, run the (slow) governed
        round trip, then EDIT the note into the verdict/answer - the user
        sees progress instead of silence, and the chat stays one bubble
        per turn."""
        handled = 0
        for upd in updates:
            self._offset = max(self._offset, upd.get("update_id", 0))
            msg = upd.get("message") or upd.get("channel_post") or {}
            chat_id = msg.get("chat", {}).get("id")
            interim_id: int | None = None
            try:
                key = str(msg.get("from", {}).get("id") or "")
                text = (msg.get("text") or "").strip()
                if chat_id is not None:
                    plan = self._interim_for(msg, key, text)
                    if plan:
                        if plan[0] == "query":
                            self.send_typing(chat_id)
                        interim_id = self.send_message(chat_id, plan[1])
                out = self.reply_for(msg)
            except Exception as e:            # never kill the loop
                print(f"[telegram] handler error: {e}", file=sys.stderr)
                if chat_id is not None:
                    err = "Internal error - the incident has been logged."
                    if not self.edit_message(chat_id, interim_id, err):
                        self.send_message(chat_id, err)
                    handled += 1
                continue
            if out is not None:
                cid, reply = out
                if interim_id is not None and \
                        self.edit_message(cid, interim_id, reply):
                    pass
                else:
                    self.send_message(cid, reply)
                handled += 1
            elif interim_id is not None:
                self.edit_message(chat_id, interim_id,
                                  "(nothing to answer for this message.)")
        return handled

    def poll_forever(self) -> None:        # pragma: no cover - live loop
        print(f"[telegram] bridge up: "
              f"allowed_chats={sorted(self.allowed_chats)} "
              f"login_required=True mapped_gate={len(self.user_map)} "
              f"api={self.api_base}", file=sys.stderr)
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
