#!/usr/bin/env bash
# logs_tail.sh - ONE place for every log during a test session.
#
#   ./scripts/logs_tail.sh                    # follow api+telegram+ollama logs
#   ./scripts/logs_tail.sh session.log        # same, but also tee into a file
#   ./scripts/logs_tail.sh --audit            # + live tail of the audit chain
#
# The stack itself (run_local.sh / systemd) writes logs/api.log,
# logs/telegram.log and logs/ollama.log; this helper just merges them with
# per-file headers so a single terminal shows the whole system.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs

FILES=(logs/api.log logs/telegram.log logs/ollama.log)
for f in "${FILES[@]}"; do touch "$f"; done

MODE="plain"
if [ "${1:-}" = "--audit" ]; then
  MODE="audit"
  OUT="${2:-}"
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '2,8p' "$0"; exit 0
else
  OUT="${1:-}"
fi

if [ -n "$OUT" ]; then
  echo "[logs_tail] capturing into $OUT as well"
  if [ "$MODE" = "audit" ] && [ -f db/audit.db ]; then
    tail -F "${FILES[@]}" db/audit_events.jsonl 2>/dev/null | tee "$OUT"
  else
    tail -F "${FILES[@]}" | tee "$OUT"
  fi
else
  if [ "$MODE" = "audit" ] && [ -f db/audit_events.jsonl ]; then
    exec tail -F "${FILES[@]}" db/audit_events.jsonl
  fi
  exec tail -F "${FILES[@]}"
fi
