#!/usr/bin/env bash
# setup.sh - ONE command from a fresh clone to a running governed stack.
#
#     git clone https://github.com/indrajith11/SecureLLM-Enterprise.git
#     cd SecureLLM-Enterprise
#     ./setup.sh
#
# What it does, in order (idempotent - safe to re-run any time):
#   1. checks Python (3.11+)
#   2. creates a PRIVATE virtualenv at .venv (isolated from system packages)
#   3. installs every dependency from requirements.txt (pinned)
#   4. verifies the governed dataset - or builds ALL of it new with --fresh
#      (13 users, 200 staff, 9 departments, 83 documents + PDF/Excel twins,
#       vector index; a fresh clone ships the pre-built DBs, so this is a no-op
#       unless you ask for --fresh or deleted db/)
#   5. writes a ready .env with a FRESH per-machine JWT secret (chmod 600)
#      if one does not exist yet
#   6. boots the whole stack via scripts/run_local.sh (web UI on :8000)
#
# Flags:
#   --fresh       wipe db/ + logs/ and regenerate ALL data from scratch
#   --no-run      install + prepare everything, but do not start the stack
#   --telegram    boot with the Telegram company bot (needs a BotFather token
#                 in .env; if the token is empty the flag is dropped with a
#                 warning so the stack still comes up)
#   --no-ollama   boot on the built-in mock model (no Ollama needed)
#
# For the REAL model afterwards: `ollama pull qwen2.5:0.5b` and restart -
# MODEL_PROVIDER=auto picks Ollama up automatically, falls back to mock.
set -euo pipefail

cd "$(dirname "$0")"
PROJ="$(pwd)"

NO_RUN=0; FRESH=0; PASSTHROUGH=()
for arg in "$@"; do
  case "$arg" in
    --no-run) NO_RUN=1 ;;
    --fresh)  FRESH=1 ;;
    --no-ollama) PASSTHROUGH+=("$arg") ;;
    --telegram)
      # decide NOW - a brand-new machine has no .env yet (it is written in
      # step 5/6), and an empty token must never boot a half-up stack
      if [ -f .env ] && grep -q "^TELEGRAM_BOT_TOKEN='[^']" .env 2>/dev/null; then
        PASSTHROUGH+=("--telegram")
      else
        echo "[!!] --telegram requested, but no bot token is wired up yet."
        echo "     The stack will start WITHOUT the bot. To enable it:"
        echo "       1) talk to @BotFather -> /newbot -> copy the token"
        echo "       2) put it in .env (created by this script if missing):"
        echo "          TELEGRAM_BOT_TOKEN='123456:ABC...'"
        echo "          TELEGRAM_ALLOWED_CHATS='-1001234567890'"
        echo "       3) re-run:  ./setup.sh --telegram"
      fi ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg (use --fresh / --no-run / --telegram / --no-ollama)"; exit 2 ;;
  esac
done

step() { printf '\n== [%s] %s ==\n' "$1" "$2"; }

step "1/6" "python check"
PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
  echo "[!!] Python 3.11+ is required (found: $($PY -V 2>&1))."
  echo "     install it (e.g. sudo apt install python3.11 python3.11-venv) or run:"
  echo "     PYTHON=python3.11 ./setup.sh"
  exit 1
fi
echo "   $($PY -V 2>&1) OK"

step "2/6" "private virtualenv (.venv)"
if [ ! -x .venv/bin/python ]; then
  if ! "$PY" -m venv .venv 2>/dev/null; then
    echo "[!!] could not create a venv - on Debian/Ubuntu install the venv module first:"
    echo "     sudo apt install python3-venv python3-full"
    exit 1
  fi
  echo "   created .venv (private, isolated from system Python)"
else
  echo "   .venv already present - reusing it"
fi
VP=.venv/bin/python

step "3/6" "install all dependencies (pinned in requirements.txt)"
if ! "$VP" -m pip install -q --upgrade pip 2>/dev/null; then
  "$VP" -m pip install --upgrade pip
fi
if ! "$VP" -m pip install -q -r requirements.txt 2>/dev/null; then
  echo "   quiet install failed - retrying with full output:"
  "$VP" -m pip install -r requirements.txt
fi
echo "   all dependencies installed"

step "4/6" "governed dataset"
if [ "$FRESH" -eq 1 ]; then
  echo "   --fresh: wiping db/ and logs/ - everything will be rebuilt new"
  rm -rf db logs
fi
if [ ! -f db/company.db ] || [ ! -f db/executives.db ]; then
  echo "   building the full dataset FROM the governed database (one shot):"
  echo "   13 users, 200 staff, 9 departments, 83 documents + PDF twins,"
  echo "   12 Excel workbooks, images, ACL matrix, vector index"
  "$VP" scripts/generate_enterprise_data.py
else
  echo "   pre-built governed database found (committed in the repo) - keeping it."
  echo "   (run ./setup.sh --fresh to regenerate everything new)"
fi

step "5/6" "operator environment (.env)"
if [ ! -f .env ]; then
  FRESH_JWT="$("$VP" -c 'import secrets; print(secrets.token_urlsafe(48))')"
  cat > .env <<EOF
# SecureLLM-Enterprise - operator environment (written by setup.sh)
# KEEP THIS FILE PRIVATE (chmod 600). Values are single-quoted on purpose.

MODEL_PROVIDER=auto
SECURE_MODE=true

# JWT signing secret - FRESH per machine. Regenerate any time:
#   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
JWT_SECRET='${FRESH_JWT}'

OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:0.5b

# --- Telegram company bot (optional) ------------------------------------
# 1) talk to @BotFather -> /newbot -> copy the token
# 2) put it below, add your chat id, then run:  ./setup.sh --telegram
# TELEGRAM_BOT_TOKEN='123456:ABC-from-BotFather'
# TELEGRAM_ALLOWED_CHATS='-1001234567890'
EOF
  chmod 600 .env
  echo "   wrote .env with a FRESH JWT secret (chmod 600)"
else
  echo "   .env already present - keeping it"
fi

if [ "$NO_RUN" -eq 1 ]; then
  step "6/6" "done (not starting - --no-run)"
  echo "
Setup complete. Start the stack any time with:

    ./setup.sh                 # web UI -> http://localhost:8000/chat
    ./setup.sh --telegram      # + Telegram bot (add the token to .env first)
    ./setup.sh --no-ollama     # built-in mock model, no Ollama needed
    ./setup.sh --fresh         # rebuild ALL data new, then start

Real model (optional):  ollama pull qwen2.5:0.5b   (auto-detected on boot)
All logs: ./logs/   ·   one terminal for every log:  ./scripts/logs_tail.sh"
  exit 0
fi

step "6/6" "starting the stack (Ctrl-C stops everything cleanly)"
exec scripts/run_local.sh ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
