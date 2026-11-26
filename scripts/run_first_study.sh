#!/usr/bin/env bash
# First real-agent pilot run for AgentWatch, on your own computer. Free: the model
# runs locally in Ollama, with no paid API.
#
#   bash scripts/run_first_study.sh                 # 20 tasks x 1 run (pilot)
#   MODEL=llama3.1:8b REPEAT=3 bash scripts/run_first_study.sh
#
# Output: private-data/agent-run-<timestamp>/ with the trace, the AgentWatch review,
# and summary.md. Pilot runs check the setup; collect fresh runs for the real study.
set -euo pipefail

cd "$(dirname "$0")/.."
MODEL="${MODEL:-qwen2.5:7b}"
REPEAT="${REPEAT:-1}"
OUT="private-data/agent-run-$(date +%Y%m%d-%H%M%S)"

say() { printf '\n== %s\n' "$*"; }

say "Python environment"
if [ ! -x .venv/bin/python ]; then
  PY="$(command -v python3.12 || command -v python3.13 || command -v python3.11 || command -v python3 || true)"
  [ -n "$PY" ] || { echo "Python 3.11+ not found. Install it (e.g. brew install python@3.12) and rerun."; exit 1; }
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || { echo "$PY is older than 3.11. Install Python 3.12 and rerun."; exit 1; }
  "$PY" -m venv .venv
fi
.venv/bin/python -m pip install -q -c requirements-lock.txt .
echo "OK: $(.venv/bin/python --version)"

say "Ollama"
command -v ollama >/dev/null 2>&1 || {
  echo "Ollama is not installed. Install it from https://ollama.com/download (free), open it once, then rerun."; exit 1; }
curl -s --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null || {
  echo "Ollama is installed but not running. Open the Ollama app (or run 'ollama serve' in another window), then rerun."; exit 1; }
if ! ollama list | awk 'NR>1{print $1}' | grep -qx "$MODEL"; then
  echo "Model $MODEL is not downloaded yet (a few GB of disk; no cost)."
  read -r -p "Download it now? [y/N] " answer
  case "$answer" in y|Y) ollama pull "$MODEL" ;; *) echo "Stopped. Run: ollama pull $MODEL"; exit 1 ;; esac
fi
echo "OK: $MODEL"

say "Running 20 tasks x $REPEAT with $MODEL (this can take a while)"
mkdir -p private-data
.venv/bin/python -m scripts.ollama_agent --model "$MODEL" \
  --tasks examples/study_tasks.json --template examples/study_workspace \
  --allow-host docs.python.org --repeat "$REPEAT" --output "$OUT"

say "AgentWatch review (rules only)"
.venv/bin/agentwatch --rules-only --input "$OUT/activity.jsonl" \
  --allow-domain docs.python.org --output "$OUT/review"

say "Summary"
.venv/bin/python -m scripts.summarize_run "$OUT" examples/study_tasks.json

say "Done"
echo "Open $OUT/review/report.html to see the evidence, and $OUT/summary.md for the overview."
