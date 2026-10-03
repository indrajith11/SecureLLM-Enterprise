# Telegram company bot (Wave 6.1 + 6.6 per-user login + 6.5 routing)

**Status: shipped in v4.5.0 · waiting UX added in v4.6.0 · bridge + login
flow + router + tests complete · off by default, fails closed.** A Telegram bot so anyone in the company
channel can ask the governed assistant — after logging in ONCE with their
OWN company credentials. The bridge is a **client of the governed HTTP API —
never a bypass**: every request crosses the same L1–L7 pipeline as a web
login, enforced by the LOGGED-IN USER's role/clearance/department, and the
real human is recorded in the tamper-evident audit chain (real username +
`channel="telegram"` + `external_user=<tg id>`).

## User experience (like the best bots)

```
you:      /start
bot:      SecureLLM company assistant. To use me, log in once:
          1. /login  2. send username  3. send password
you:      /login
bot:      Login: send your company USERNAME.
you:      indra
bot:      Thanks. Now send your PASSWORD. (delete the message after
          sending - Telegram keeps chat history; the bot never logs it)
you:      ********
bot:      ⏳ Please wait - checking your details in the company
          directory…        <- appears INSTANTLY (v4.6.0 waiting UX)
bot:      Logged in as indra (Tech_Employee). Ask me anything -
          company data is enforced by YOUR role and clearance,
          general questions are answered directly.   <- the SAME bubble
          edited in place once /api/login answers
you:      hi
bot:      Hello! I'm the company assistant. ...
you:      what is the capital of France?
bot:      (direct model answer - no company data touched)
you:      show me the tech employees
bot:      🧠 Thinking - give me a moment…   (+ typing indicator)
bot:      (governed answer - your role decides the rows, fully audited;
          the Thinking bubble is edited into the answer)
```

Commands: `/start` `/help` `/login` `/whoami` `/logout` `/cancel`.

### Waiting UX (v4.6.0)

The user never stares at silence. Commands and instant prompts reply
immediately; anything that triggers a slow network round trip first sends
an interim note, then **edits that same note** into the final reply
(`editMessageText`), so the chat stays one bubble per turn:

| Moment | Interim note | Then |
|---|---|---|
| password being verified | "⏳ Please wait - checking your details in the company directory…" | edited into the login verdict |
| governed query running | "🧠 Thinking - give me a moment…" + `sendChatAction: typing` | edited into the answer / denial |

If the edit is impossible (message too old, network hiccup) the bridge
falls back to a fresh message - the answer always arrives. The pure
decision core (`reply_for`) is unchanged; the waiting UX lives entirely
in `run_once` and is covered by its own tests.

## Security model

| Concern | Control |
|---|---|
| Feature surface | `telegram.enabled: false` by default; bridge refuses to start unless explicitly enabled AND `TELEGRAM_BOT_TOKEN` is set |
| Who can ask | Only chats in `TELEGRAM_ALLOWED_CHATS` are served. Then: NO company answer without a successful company login — the user's own credentials are the authorization |
| Identity | Per-user login (Wave 6.6): `/login` → `/api/login` with THE USER's credentials → every chat rides that user's JWT. No shared service account exists. Audit chain shows the real username + telegram id |
| Extra mapping gate (optional) | `TELEGRAM_USER_MAP` non-empty → only mapped telegram ids may even attempt `/login`; empty → any member of an allowed chat can log in with their own credentials |
| Intent routing (Wave 6.5) | Server-side deterministic router: general chat (greetings/general knowledge) answers WITHOUT company retrieval; company-data questions keep RBAC/CIA/DLP retrieval. Decision is auditable (`meta.router`) and never made bridge-side |
| Rate abuse | Per-telegram-user sliding-window limit (default 5/min); L2a still applies per logged-in user |
| Password hygiene | The bridge never logs or echoes passwords; it asks the user to delete the password message (Telegram keeps chat history client-side) |
| Session expiry | The user's JWT expiry is honoured; 401 mid-session → session dropped → re-login prompt |
| Kill switch | `AI_ENABLED=false` → API 503 → the bot says so, visibly |
| Secrets | Bot token + JWT secret are env-only, never in yaml or git |
| Robustness | Poll loop survives malformed updates; answers truncated to Telegram's 4096-char cap; handler errors answered with a generic incident message |

## Wiring (operator)

```bash
# 1) BotFather -> /newbot -> token
# 2) send any message to the bot, read the chat id from logs, then:
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_ALLOWED_CHATS="-1001234567890"
export TELEGRAM_USER_MAP=''                 # empty = any chat member can /login
# export TELEGRAM_USER_MAP='{"61234567":"indra"}'   # optional extra gate
# config/app_config.yaml -> telegram.enabled: true
python -m src.channels.telegram_bot         # long-poll loop
```

Live-proven on @AIEnterprice_bot (Oct 2026): per-user login conversation,
general/company routing through the real Bot API, ollama backend, chat
allowlist + optional mapping gate; values kept in a gitignored `.env`
(single-quoted so `set -a; . ./.env` is safe).

Backend-down UX (v4.8.0): if the governed API is unreachable the bridge
answers with a calm retry hint - "The assistant backend is not reachable
right now - please try again shortly. Your login session is kept." (query)
/ "Login failed (the company directory is unreachable right now)" (login) -
instead of a generic internal-error bubble. Two tests cover both paths.

Tests: `tests/test_telegram_bridge.py` (30) — fail-closed startup, chat gate
+ login gate without API calls, the full login conversation over real TCP,
wrong password fail-closed, cancel/logout/whoami, password never echoed,
expired session + API-401 re-login prompts, general answer pass-through,
kill-switch visibility, governance-denial relay, per-user rate limit, poll
robustness, 4096 truncation. Router: `tests/test_intent_router.py` (49) +
`tests/test_general_chat.py` (8) — classification matrix, retrieval skip,
CIA-C/field-intent skips for general intent, DLP hard-rules-armed in general
mode, `meta.router` in the audit chain.
