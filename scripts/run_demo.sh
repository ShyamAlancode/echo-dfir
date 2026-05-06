#!/usr/bin/env bash
# 5-minute demo: install check + tests + run + verify + benchmark.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

echo "================================================"
echo "  ECHO Demo Run — $(date -u +%FT%TZ)"
echo "================================================"

echo ""
echo "==> Phase 1/4: Spoliation tests (architectural guarantees)"
PYTHONPATH="$ROOT" python -m pytest tests/spoliation -v --tb=short

echo ""
echo "==> Phase 2/4: Unit tests (deterministic core)"
PYTHONPATH="$ROOT" python -m pytest tests/unit -v --tb=short

echo ""
echo "==> Phase 3/4: Run case CASE_001_synthetic"
echo "    (requires Ollama running with qwen2.5:7b-instruct-q4_K_M)"
if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    PYTHONPATH="$ROOT" python -m echo_agent.cli run \
        --case-id CASE_001_synthetic \
        --max-iter 6 \
        --budget 40000 \
        --wall-clock 600 || echo "(Run completed; exit code $? captured)"
else
    echo "    Ollama not running — skipping live run."
    echo "    Start with: ollama serve &"
fi

echo ""
echo "==> Phase 4/4: Verify audit chain"
if [ -f "audit/CASE_001_synthetic_iterations.jsonl" ]; then
    PYTHONPATH="$ROOT" python -m echo_agent.cli verify --case-id CASE_001_synthetic
fi

echo ""
echo "================================================"
echo "  Demo complete."
echo "================================================"
