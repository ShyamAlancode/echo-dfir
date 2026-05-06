"""
Prefetch (.pf) parser.

DFIR background:
    Prefetch is created by Windows the first time an executable runs and
    updated on subsequent runs. The file's existence is strong proof of
    execution; up to 8 last-run timestamps are retained on Win10+.

We invoke `pf.py` from PECmd-compatible parsers shipped with SIFT, or
fall back to the pure-Python `prefetch-parser` library.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from echo_mcp.knowledge import caveats_for
from echo_mcp.schemas import PrefetchEntry, ToolResponse
from echo_mcp.tools._common import (
    DEFAULT_TIMEOUT_S,
    empty_response,
    resolve_evidence_path,
    run_subprocess,
)

PF_NAME_RE = re.compile(r"^(?P<exe>[^.]+)\.EXE-(?P<hash>[A-F0-9]{8})\.pf$", re.IGNORECASE)


def _try_pure_python(pf_file: Path) -> dict[str, Any] | None:
    """Try to use the `prefetch_parser` Python lib if installed."""
    try:
        from prefetch_parser import process_file  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        result = process_file(str(pf_file))  # returns a dict-like
        return dict(result) if result else None
    except Exception:  # noqa: BLE001
        return None


def prefetch_parse(case_id: str, prefetch_dir: str = "Windows/Prefetch") -> ToolResponse:
    """Walk a Prefetch directory and emit PrefetchEntry rows."""
    args = {"case_id": case_id, "prefetch_dir": prefetch_dir}
    cav, hints = caveats_for("prefetch_parse")
    start = time.perf_counter()

    try:
        pf_dir = resolve_evidence_path(case_id, prefetch_dir)
    except Exception as e:  # noqa: BLE001
        return empty_response("prefetch_parse", args, str(e))

    if not pf_dir.is_dir():
        return empty_response(
            "prefetch_parse", args, f"prefetch path not a directory: {pf_dir}",
            time.perf_counter() - start,
        )

    data: list[dict[str, Any]] = []

    for pf_file in sorted(pf_dir.glob("*.pf")):
        m = PF_NAME_RE.match(pf_file.name)
        if not m:
            continue
        exe = m.group("exe") + ".EXE"

        parsed = _try_pure_python(pf_file)

        run_count = None
        last_run_times: list[str] = []
        executable_path = None

        if parsed:
            run_count = parsed.get("run_count") or parsed.get("RunCount")
            lrt = parsed.get("last_run_times") or parsed.get("LastRunTimes") or []
            if isinstance(lrt, list):
                last_run_times = [str(t) for t in lrt[:8]]
            executable_path = parsed.get("executable_path") or parsed.get("ExecutableName")

        try:
            entry = PrefetchEntry(
                executable_name=exe[:260],
                executable_path=str(executable_path)[:1024] if executable_path else None,
                run_count=int(run_count) if run_count is not None else None,
                last_run_times=last_run_times,
            )
            data.append(entry.model_dump())
        except (ValueError, TypeError):
            continue

    return ToolResponse(
        tool="prefetch_parse",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=time.perf_counter() - start,
    )
