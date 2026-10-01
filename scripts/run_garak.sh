#!/usr/bin/env bash
# Run the REAL NVIDIA Garak LLM vulnerability scanner against the local
# qwen2.5:0.5b model (requires Ollama running locally).
#
#   pip install garak
#   ollama pull qwen2.5:0.5b
#   bash scripts/run_garak.sh
#
# Results land in garak_reports/ (garak writes its own zlogs/jsonl).

set -euo pipefail

MODEL="${OLLAMA_MODEL:-qwen2.5:0.5b}"
OUTDIR="$(dirname "$0")/../garak_reports"
mkdir -p "$OUTDIR"

echo "[*] Checking Ollama..."
curl -sf http://localhost:11434/api/tags >/dev/null || {
  echo "Ollama is not running. Start it and pull the model first:"; exit 1; }

echo "[*] Running Garak probes: dan, encoding, leakreplay, malwaregen"
garak --model_type ollama --model_name "$MODEL" \
      --probes dan,encoding,leakreplay,malwaregen \
      --report_prefix "$OUTDIR/garak_${MODEL}"

echo "[*] Done. Compare garak output with the local harness baseline:"
echo "    tests/results/jailbreak_report.json"
