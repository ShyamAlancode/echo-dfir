#!/usr/bin/env bash
# Quick smoke check that everything ECHO needs is available.
set -uo pipefail

ok=true
check() {
    if "$@" >/dev/null 2>&1; then
        printf "  [✓] %s\n" "$*"
    else
        printf "  [✗] %s — MISSING\n" "$*"
        ok=false
    fi
}

echo "== System binaries =="
check command -v python3
check command -v rip.pl
check command -v bulk_extractor
check command -v vol
check command -v ollama

echo "== Python imports =="
check python3 -c "import pydantic, orjson, fastmcp, langgraph, ollama, typer, rich"
check python3 -c "import echo_mcp.tools, echo_agent.graph, validators.cross_source"

echo "== Ollama model =="
if ollama list 2>/dev/null | grep -q "qwen2.5:7b"; then
    echo "  [✓] qwen2.5:7b-instruct loaded"
else
    echo "  [✗] qwen2.5:7b-instruct NOT loaded — run: ollama pull qwen2.5:7b-instruct-q4_K_M"
    ok=false
fi

echo "== Volatility symbols =="
if [ -d "$HOME/.cache/volatility3/symbols/windows" ]; then
    echo "  [✓] Windows symbols present"
else
    echo "  [✗] Windows symbol pack not fetched"
    ok=false
fi

if $ok; then
    echo ""
    echo "All checks passed. ECHO is ready."
    exit 0
fi
echo ""
echo "Some checks failed. Re-run install.sh or fix manually."
exit 1
