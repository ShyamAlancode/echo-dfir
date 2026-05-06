"""
Shared safety layer for every MCP tool.

WINNING-DESIGN PILLAR: Architectural guardrails > prompt guardrails.
The agent literally cannot construct a destructive shell command because
every tool function is typed, path-validated, and wraps a fixed argv list.
There is no run_command(cmd: str) — and there will never be one.

Every tool in echo_mcp.tools.* MUST go through:
    1. resolve_evidence_path()  — anchors paths inside CASE_ROOT
    2. read_only_check()        — refuses to operate on writable mounts
    3. run_subprocess()         — fixed argv, 30s timeout, no shell

Forensic NOTE: even read tools can spoliate evidence by triggering
filesystem-level updates (atime, hive dirty bits). We mitigate by
operating on copies inside read-only mounts only.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Optional

from echo_mcp.schemas import ToolCaveat, ToolResponse, Severity

# -- configuration ---------------------------------------------------------


# CASE_ROOT is the read-only mount where evidence lives. install.sh
# binds /mnt/cases ro on SIFT VM. Override only via env for CI.
DEFAULT_CASE_ROOT = Path(os.environ.get("ECHO_CASE_ROOT", "/mnt/cases")).resolve()
DEFAULT_TIMEOUT_S = int(os.environ.get("ECHO_TOOL_TIMEOUT_S", "30"))


# --------------------------------------------------------------- ERRORS ----


class PathSafetyError(ValueError):
    """Raised when a requested path escapes CASE_ROOT or hits a denylist."""


class ToolTimeoutError(RuntimeError):
    """Raised when a subprocess exceeds DEFAULT_TIMEOUT_S."""


class ReadOnlyViolation(RuntimeError):
    """Raised when a tool attempts to operate on a writable mount."""


# ----------------------------------------------------------- PATH SAFETY ----


def resolve_evidence_path(case_id: str, relative: str, root: Optional[Path] = None) -> Path:
    """Resolve `<root>/<case_id>/<relative>` and assert containment.

    REJECTS:
        - absolute paths in `relative`
        - any `..` traversal that escapes <root>/<case_id>
        - non-printable / NUL bytes
        - case_id with non-portable characters
    """
    if root is None:
        root = DEFAULT_CASE_ROOT
    root = root.resolve()

    if not case_id or any(c in case_id for c in "/\\:.\x00"):
        raise PathSafetyError(f"invalid case_id: {case_id!r}")
    if "\x00" in relative:
        raise PathSafetyError("NUL byte in relative path")
    if relative.startswith("/") or relative.startswith("\\"):
        raise PathSafetyError(f"absolute relative path forbidden: {relative!r}")

    case_dir = (root / case_id).resolve()
    target = (case_dir / relative).resolve()

    # The crucial containment check: target must be inside case_dir.
    try:
        target.relative_to(case_dir)
    except ValueError as e:
        raise PathSafetyError(
            f"path {relative!r} escapes case directory {case_dir}"
        ) from e

    if not target.exists():
        raise PathSafetyError(f"evidence not found: {target}")

    return target


def read_only_check(path: Path) -> None:
    """Refuse to operate on a path that lives on a writable mount.

    This is belt-and-braces: install.sh mounts evidence read-only, but if
    a future operator forgets, this catches it.
    """
    # If the file itself is writable, bail.
    if os.access(path, os.W_OK):
        raise ReadOnlyViolation(f"refusing to operate on writable path: {path}")


# -------------------------------------------------------- SUBPROCESS RUN ----


def run_subprocess(
    argv: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_S,
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> tuple[int, str, str, float]:
    """Run a subprocess with a fixed argv list (NEVER shell=True).

    Returns: (returncode, stdout, stderr, elapsed_seconds).
    Raises ToolTimeoutError on timeout.

    SECURITY NOTE: argv is a list of strings. shell=False. No shell
    metachars are interpreted. This is the difference between a tool
    server and a shell server.
    """
    if not argv:
        raise ValueError("argv must be non-empty list")
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be list[str]")

    start = time.perf_counter()
    try:
        proc = subprocess.run(  # noqa: S603 — argv is fully controlled
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        elapsed = time.perf_counter() - start
        raise ToolTimeoutError(
            f"subprocess timed out after {timeout}s: {shlex.join(argv)} (elapsed={elapsed:.1f}s)"
        ) from e

    elapsed = time.perf_counter() - start
    return proc.returncode, proc.stdout, proc.stderr, elapsed


# --------------------------------------------------------- ENVELOPE HELP ----


def empty_response(tool: str, args: dict, error: str, elapsed: float = 0.0) -> ToolResponse:
    """Build a ToolResponse representing a hard error (no data)."""
    return ToolResponse(
        tool=tool,
        args=args,
        data=[],
        caveats=[
            ToolCaveat(
                severity=Severity.HIGH,
                text=f"tool failed: {error}",
            )
        ],
        cross_check_hints=[],
        runtime_seconds=elapsed,
        truncated=False,
        error=error,
    )
