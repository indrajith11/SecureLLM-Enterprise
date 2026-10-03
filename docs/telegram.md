# Telegram company bot (Wave 6.1)

**Status: shipped in v4.4.0 · bridge + tests complete · off by default,
fails closed.** A Telegram bot so anyone in the company channel can ask the
governed assistant. The bridge is a **client of the governed HTTP API —
never a bypass**: every request crosses the same L1–L7 pipeline as a web
login, and the real human behind it is recorded in the tamper-evident
audit chain (`channel="telegram"` + `external_user=<tg id>`).

## Security model

| Concern | Control |
|---|---|
| Feature surface | `telegram.enabled: false` by default; bridge refuses to start unless explicitly enabled AND `TELEGRAM_BOT_TOKEN` is set |
| Who can ask | Only chats in `TELEGRAM_ALLOWED_CHATS` are served; only users mapped in `TELEGRAM_USER_MAP` (`{"<tg_user_id>": "handle"}`) get answers — everyone else is refused bridge-side and logged, the governed API is never touched |
| Identity | The bridge authenticates as ONE service identity (`TELEGRAM_SERVICE_USER`, least privilege); the mapped human rides in `external_user` into the audit chain meta |
| Rate abuse | Per-telegram-user sliding-window limit (default 5/min) in front of the shared service identity (L2a still applies per user) |
| Kill switch | `AI_ENABLED=false` → API 503 → the bot says so, visibly |
| Secrets | Bot token + service password are env-only, never in yaml or git |
| Robustness | Poll loop survives malformed updates; answers truncated to Telegram's 4096-char cap; handler errors answered with a generic incident message |

## Wiring (operator)

```bash
# 1) BotFather -> /newbot -> token
# 2) map your chat: send any message to the bot, read the id from logs,
#    then set the env and enable:
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_ALLOWED_CHATS="-1001234567890"
export TELEGRAM_USER_MAP='{"61234567":"indra","23456789":"hr_manager"}'
export TELEGRAM_SERVICE_USER="tg_bridge"      # seeded, least-privilege user
export TELEGRAM_SERVICE_PASSWORD="..."
# config/app_config.yaml -> telegram.enabled: true
python -m src.channels.telegram_bot            # long-poll loop
```

Tests: `tests/test_telegram_bridge.py` (15) — fail-closed startup, chat/user
deny without API calls, governed round-trip with audit attribution, token
caching, kill-switch visibility, governance-denial relay, per-user rate
limit, poll robustness, 4096 truncation. Both sides are real TCP stubs.
