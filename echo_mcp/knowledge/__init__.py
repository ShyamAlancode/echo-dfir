"""Load and serve forensic caveats per tool."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from echo_mcp.schemas import CrossCheckHint, Severity, ToolCaveat

CAVEATS_PATH = Path(__file__).parent / "caveats.yaml"


@lru_cache(maxsize=1)
def _load_raw() -> dict:
    if not CAVEATS_PATH.exists():
        return {}
    with CAVEATS_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def caveats_for(tool: str) -> tuple[list[ToolCaveat], list[CrossCheckHint]]:
    """Return (caveats, hints) for a tool. Empty lists if no entry."""
    raw = _load_raw().get(tool, {})
    cav = [
        ToolCaveat(severity=Severity(c["severity"]), text=c["text"])
        for c in raw.get("caveats", [])
    ]
    hints = [
        CrossCheckHint(hint=h["hint"], suggested_tool=h["suggested_tool"])
        for h in raw.get("cross_check_hints", [])
    ]
    return cav, hints
