#!/usr/bin/env bash
# ECHO — one-command install on SANS SIFT Workstation (Ubuntu 22.04 base).
# Idempotent: safe to re-run.
set -euo pipefail

ECHO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "==> ECHO install starting from $ECHO_DIR"

# 1. System packages SIFT may be missing
echo "==> [1/6] apt: ensuring base packages"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    bulk-extractor \
    git curl jq

# 2. Python venv
echo "==> [2/6] Python venv at $ECHO_DIR/.venv"
if [ ! -d "$ECHO_DIR/.venv" ]; then
    python3 -m venv "$ECHO_DIR/.venv"
fi
# shellcheck disable=SC1091
source "$ECHO_DIR/.venv/bin/activate"
pip install --quiet --upgrade pip

# 3. ECHO + dependencies
echo "==> [3/6] pip install ECHO (editable)"
pip install --quiet -e "$ECHO_DIR"

# 4. Volatility 3 + symbol pack
echo "==> [4/6] Volatility 3"
if ! command -v vol >/dev/null 2>&1; then
    pip install --quiet 'volatility3>=2.7'
fi
SYMBOLS_DIR="$HOME/.cache/volatility3/symbols/windows"
mkdir -p "$SYMBOLS_DIR"
if [ ! -f "$SYMBOLS_DIR/.fetched" ]; then
    echo "    Fetching Windows symbol pack (~250MB)..."
    curl -fSL --retry 3 \
        https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip \
        -o "$SYMBOLS_DIR/windows.zip"
    (cd "$SYMBOLS_DIR" && unzip -q -o windows.zip && rm windows.zip)
    touch "$SYMBOLS_DIR/.fetched"
fi

# 5. RegRipper (rip.pl)
echo "==> [5/6] RegRipper"
if ! command -v rip.pl >/dev/null 2>&1; then
    sudo apt-get install -y -qq libparse-win32registry-perl
    sudo mkdir -p /opt/regripper
    if [ ! -f /opt/regripper/rip.pl ]; then
        sudo git clone --quiet --depth 1 \
            https://github.com/keydet89/RegRipper3.0 /opt/regripper
        sudo ln -sf /opt/regripper/rip.pl /usr/local/bin/rip.pl
        sudo chmod +x /opt/regripper/rip.pl
    fi
fi

# 6. Ollama + model
echo "==> [6/6] Ollama + qwen2.5:7b-instruct-q4_K_M"
if ! command -v ollama >/dev/null 2>&1; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
if ! systemctl is-active --quiet ollama 2>/dev/null; then
    nohup ollama serve >/tmp/ollama.log 2>&1 &
    sleep 3
fi
ollama pull qwen2.5:7b-instruct-q4_K_M

# 7. Case directory mount-point
sudo mkdir -p /mnt/cases
echo "==> Make sure /mnt/cases contains your case_id subdirectories (read-only mount recommended)"

echo ""
echo "============================================================"
echo "  ECHO install complete."
echo "  Activate venv:  source $ECHO_DIR/.venv/bin/activate"
echo "  Smoke test:     pytest tests/unit tests/spoliation -v"
echo "  Run case:       echo run --case-id CASE_001"
echo "  Verify chain:   echo verify --case-id CASE_001"
echo "============================================================"
