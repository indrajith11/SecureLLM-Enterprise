#!/bin/bash
# run_local.sh - ONE command to run the whole SecureLLM-Enterprise stack on
# your own machine (local hosting):
#
#     ./scripts/run_local.sh                 # API + web UI on :8000
#     ./scripts/run_local.sh --telegram      # + Telegram company bot
#     ./scripts/run_local.sh --no-ollama     # API only (mock/AI off host)
#
# Order of startup (each waits until healthy before the next):
#   1. ollama serve              (if the binary exists and --no-ollama unset)
#   2. governed API (uvicorn)    http://localhost:8000  (web UI at /chat)
#   3. telegram bridge           (only with --telegram; needs .env)
#
# Everything logs to ./logs/. Press Ctrl-C to stop the stack cleanly.
# Repo default telegram.enabled=false is flipped true at runtime ONLY when
# --telegram is passed (operator opt-in, never a committed default).
set -u

cd "$(dirname "$0")/.."
PROJ="$(pwd)"
LOGDIR="$PROJ/logs"; mkdir -p "$LOGDIR"

WITH_TG=0; WITH_OLLAMA=1
for arg in "$@"; do
  case "$arg" in
    --telegram)  WITH_TG=1 ;;
    --no-ollama) WITH_OLLAMA=0 ;;
    *) echo "unknown flag: $arg (use --telegram / --no-ollama)"; exit 2 ;;
  esac
done

OLLAMA_BIN="${OLLAMA_BIN:-$(command -v ollama || true)}"
[ -z "$OLLAMA_BIN" ] && [ -x "$HOME/ollama-local/bin/ollama" ] && \
    OLLAMA_BIN="$HOME/ollama-local/bin/ollama"

PIDS=()
cleanup() {
  echo; echo "[run_local] shutting down..."
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  echo "[run_local] stopped."
}
trap cleanup EXIT INT TERM

# telegram operator opt-in (runtime only; repo default stays fail-closed)
if [ "$WITH_TG" = "1" ]; then
  python3 - << 'PYEOF'
import re, pathlib
p = pathlib.Path("config/app_config.yaml"); t = p.read_text()
t2 = re.sub(r"^(telegram:\n\s+enabled:\s)false", r"\1true", t, count=1, flags=re.M)
if t2 != t:
    p.write_text(t2); print("[run_local] operator opt-in: telegram.enabled -> true")
PYEOF
  if [ -f .env ]; then set -a; . ./.env; set +a;
  else echo "[run_local] WARNING: no .env - TELEGRAM_BOT_TOKEN missing,"; \
       echo "           the bridge will refuse to start (fail-closed)."; fi
fi

echo "== [1/3] ollama =="
if [ "$WITH_OLLAMA" = "1" ] && [ -n "$OLLAMA_BIN" ]; then
  if curl -s -m 2 http://localhost:11434/api/version >/dev/null 2>&1; then
    echo "   already running - reusing."
  else
    "$OLLAMA_BIN" serve > "$LOGDIR/ollama.log" 2>&1 &
    PIDS+=($!)
    for i in $(seq 1 30); do
      curl -s -m 2 http://localhost:11434/api/version >/dev/null 2>&1 && break
      sleep 0.5
    done
  fi
  echo "   $(curl -s -m 2 http://localhost:11434/api/version || echo DOWN)"
else
  echo "   skipped (--no-ollama or binary missing) - backend falls back to mock."
fi

echo "== [2/3] governed API on :8000 =="
python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 \
    > "$LOGDIR/api.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 40); do
  curl -s -m 2 http://localhost:8000/health 2>/dev/null | grep -q healthy && break
  sleep 0.5
done
echo "   $(curl -s -m 3 http://localhost:8000/health || echo DOWN)"
echo "   web chat UI:  http://localhost:8000/chat"

if [ "$WITH_TG" = "1" ]; then
  echo "== [3/3] telegram bridge (long polling - works behind NAT) =="
  python3 -m src.channels.telegram_bot > "$LOGDIR/telegram.log" 2>&1 &
  PIDS+=($!)
  sleep 2
  if kill -0 "${PIDS[-1]}" 2>/dev/null; then
    echo "   bridge up - the bot answers only in allowed chats, and only after /login."
  else
    echo "   bridge DIED - check $LOGDIR/telegram.log"
  fi
else
  echo "== [3/3] telegram bridge: skipped (add --telegram to enable) =="
fi

echo
echo "[run_local] stack is UP. Ctrl-C to stop. Logs: $LOGDIR/"
wait
