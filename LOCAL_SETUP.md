# LOCAL SETUP - host SecureLLM-Enterprise on your own machine

Everything runs locally: the governed API, the ChatGPT-style web UI, the
Ollama model and the Telegram company bot. No cloud dependency except the
Telegram API itself (outbound HTTPS long-polling - works behind NAT, no
port forwarding needed) and, optionally, a Cloudflare Tunnel if you want
the web UI reachable from outside your network.

> **One command instead of this whole document:** `./setup.sh` from the repo
> root checks Python, creates the private `.venv`, installs every dependency,
> verifies (or with `--fresh` rebuilds) the entire governed dataset, writes a
> ready `.env` with a fresh JWT secret and boots the stack — flags: `--fresh`
> (regenerate ALL data new) · `--no-run` (install only) · `--telegram` ·
> `--no-ollama`. The steps below are the manual equivalent, kept for operators
> who want full control.

---

## 1. Prerequisites

| Thing        | Version        | Check                  |
|--------------|----------------|------------------------|
| Linux (or macOS/WSL2) | any recent | -              |
| Python       | 3.11+          | `python3 --version`    |
| Ollama       | 0.30+          | `ollama --version`     |
| git          | any            | `git --version`        |

---

## 2. Get the code + dependencies

```bash
git clone git@github.com:indrajith11/SecureLLM-Enterprise.git
cd SecureLLM-Enterprise

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 3. Ollama + model pick (scored wizard)

```bash
# install ollama (if not installed): https://ollama.com/download
ollama pull qwen2.5:0.5b        # small, fast, 397 MB - demo default
# stronger alternatives (pick what your RAM allows):
#   qwen2.5-coder:7b   4.7 GB   best quality, slower on CPU
```

Then run the setup wizard - it detects your installed models, SCORES them
(parameter class, family, instruct/coder bonuses) and recommends the best
one; press Enter to accept:

```bash
python scripts/setup_wizard.py
```

The wizard writes your choice into `config/app_config.yaml`
(`model.ollama_model`). You can switch models later any time - admins get
a one-click, audited model picker in the web UI (AI models panel).

---

## 4. Build the demo database (one command)

The full example enterprise (TechNova Solutions Pvt Ltd, India: 200 staff,
9 departments, 83 policy documents + PDF twins, 12 Excel workbooks, images,
metadata/ACL/retention glue tables) is generated FROM scratch, idempotent:

```bash
python scripts/generate_enterprise_data.py
```

Demo accounts (all seeded automatically, bcrypt):

| username     | password    | role             | clearance |
|--------------|-------------|------------------|-----------|
| admin        | Admin@123   | Admin            | L5        |
| ceo          | Ceo@123     | Executive        | L5        |
| hr_manager   | HrM@123     | HR_Manager       | L4        |
| hr_emp1      | HrE@123     | HR_Employee      | L3        |
| tech_lead    | TechL@123   | Tech_Lead        | L4        |
| tech_eng1    | TechE@123   | Tech_Engineer    | L3        |
| fin_manager  | FinM@123    | Finance_Manager  | L4        |

See per-user authority differences live:

```bash
python scripts/demo_per_user_authority.py     # needs the API running (step 5)
```

---

## 5. Run the stack (one command)

```bash
./scripts/run_local.sh                 # ollama + API + web UI
./scripts/run_local.sh --telegram      # + Telegram company bot
```

- Web UI:   http://localhost:8000/chat  (login with any demo account)
- Health:   http://localhost:8000/health
- Logs:     `logs/api.log`, `logs/telegram.log`, `logs/ollama.log`
- Stop:     Ctrl-C

The same thing as services (optional, survives reboots) - systemd units:

```ini
# /etc/systemd/system/securellm-api.service
[Unit]
Description=SecureLLM governed API
After=network.target ollama.service

[Service]
User=YOUR_USER
WorkingDirectory=/path/to/SecureLLM-Enterprise
ExecStart=/path/to/SecureLLM-Enterprise/.venv/bin/python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/securellm-telegram.service
[Unit]
Description=SecureLLM Telegram bridge
After=securellm-api.service

[Service]
User=YOUR_USER
WorkingDirectory=/path/to/SecureLLM-Enterprise
EnvironmentFile=/path/to/SecureLLM-Enterprise/.env
ExecStart=/path/to/SecureLLM-Enterprise/.venv/bin/python -m src.channels.telegram_bot
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now securellm-api securellm-telegram
```

(If you use systemd for the bridge, set `telegram.enabled: true` in
`config/app_config.yaml` yourself - that IS the operator opt-in.)

---

## 6. Telegram bot wiring

One-time, on <https://t.me/BotFather>: `/newbot` -> keep the token secret.

Create `.env` in the repo root (chmod 600, values single-quoted):

```bash
cat > .env << 'EOF'
TELEGRAM_BOT_TOKEN='123456789:AA...your...token'
TELEGRAM_ALLOWED_CHATS='7617469792'
JWT_SECRET='<python3 -c "import secrets;print(secrets.token_urlsafe(48))">'
EOF
chmod 600 .env
```

- `TELEGRAM_ALLOWED_CHATS` = comma-separated telegram user ids that may
  even talk to the bot (fail-closed chat gate).
- `TELEGRAM_USER_MAP` (optional) = `{"<tg_id>": "handle"}` to additionally
  restrict WHO may attempt `/login`.

Then run with `./scripts/run_local.sh --telegram`. Security model:

1. No login, no answer - the bot refuses everything until you
   `/login` with COMPANY credentials (username -> password, per-chat
   state machine, "checking your details..." interim messages).
2. After login the bot rides YOUR OWN JWT: every answer is enforced by
   YOUR role/clearance/department through the same L1-L7 pipeline as the
   web app, and audited with `channel=telegram`.
3. General questions ("hi", "capital of France?") are answered by the AI
   directly - also audited, also after login.
4. Passwords are never logged; delete your password message afterwards
   (the bot reminds you).
5. `/whoami` `/logout` `/cancel` manage the session.

Your bot is ALREADY wired: @AIEnterprice_bot (token in `.env`).

---

## 7. Expose the web UI with Cloudflare Tunnel (optional)

The Telegram bot does NOT need this (outbound long-polling). Only do this
if you want to open the web chat from outside:

```bash
# install cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
cloudflared tunnel --url http://localhost:8000
# -> prints a temporary https://xxxx.trycloudflare.com URL (quick demo)

# permanent named tunnel (your own domain):
cloudflared tunnel login
cloudflared tunnel create securellm
cloudflared tunnel route dns securellm chat.yourdomain.com
cloudflared tunnel run securellm      # config: ~/.cloudflared/config.yml
```

`~/.cloudflared/config.yml` for the permanent tunnel:

```yaml
tunnel: securellm
credentials-file: /home/YOU/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: chat.yourdomain.com
    service: http://localhost:8000
  - service: http_status:404
```

SECURITY NOTE: a public URL exposes the LOGIN page to the internet. The
pipeline is fail-closed (rate limits, lockouts, input firewall, audit
chain), but keep `secure_mode: true` and treat the tunnel as untrusted
input surface. Telegram does not need the tunnel at all.

---

## 8. Verify everything (60-second checklist)

```bash
curl -s http://localhost:8000/health | grep -o '"status":"[^"]*"'
# -> "status":"healthy"

python3 -m pytest tests/ -q          # 466 tests
# -> 466 passed

# per-user authority in one shot:
python3 scripts/demo_per_user_authority.py
# same salary question: Executive sees it, Tech_Engineer is DENIED@L3,
# Aadhaar questions return nothing even for admin (structural PII blindness)
```

Telegram: open @AIEnterprice_bot -> `/start` -> `/login` -> username ->
password -> ask "what is the HR policy on remote work?" (company path,
audited) and "what is the capital of France?" (general path, audited).

---

## 9. Troubleshooting

| Symptom | Fix |
|---------|-----|
| bridge refuses to start | `telegram.enabled` not true (use `--telegram`) or `.env` missing token |
| bot silent in Telegram | your chat id not in `TELEGRAM_ALLOWED_CHATS`; also check ONLY ONE bridge instance polls (two pollers steal updates from each other) |
| 409 Telegram errors | another machine/process still runs `getUpdates` with the same token - stop it |
| "Internal error" bubble | the governed API was down; `run_local.sh` starts both together; v4.8.0 answers with a retry hint instead |
| model answers are weak | 0.5B is the demo floor - switch to `qwen2.5-coder:7b` in the admin model picker |
| db missing tables | re-run `python scripts/generate_enterprise_data.py` (idempotent) |
