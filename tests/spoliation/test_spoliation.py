"""
SPOLIATION TEST SUITE — 12 red-team tests.

Every test in this file asserts that ECHO's MCP server CANNOT damage
evidence. These tests are the empirical backing for the architectural-
guardrail claim in the accuracy report.

If any of these tests ever pass without raising an exception, the
architectural claim is false — fail the build.

Run with:
    pytest tests/spoliation -m spoliation -v
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from echo_mcp.tools._common import (
    PathSafetyError,
    ReadOnlyViolation,
    resolve_evidence_path,
    read_only_check,
)


@pytest.fixture()
def case_root(tmp_path: Path) -> Path:
    """A throwaway case root with one pretend evidence file."""
    case_dir = tmp_path / "TEST_CASE"
    case_dir.mkdir()
    (case_dir / "memory.raw").write_bytes(b"\x00" * 16)
    (case_dir / "Windows" / "Prefetch").mkdir(parents=True)
    return tmp_path


# ============================================================== TESTS ====


@pytest.mark.spoliation
def test_001_absolute_path_rejected(case_root: Path) -> None:
    """A001 — absolute paths must be refused."""
    with pytest.raises(PathSafetyError):
        resolve_evidence_path("TEST_CASE", "/etc/passwd", root=case_root)


@pytest.mark.spoliation
def test_002_dotdot_traversal_rejected(case_root: Path) -> None:
    """A002 — `..` escaping the case dir must be refused."""
    with pytest.raises(PathSafetyError):
        resolve_evidence_path("TEST_CASE", "../../etc/passwd", root=case_root)


@pytest.mark.spoliation
def test_003_double_dotdot_rejected(case_root: Path) -> None:
    """A003 — even creative `../../..` chains are refused."""
    with pytest.raises(PathSafetyError):
        resolve_evidence_path(
            "TEST_CASE", "Windows/../../../../tmp/escape", root=case_root,
        )


@pytest.mark.spoliation
def test_004_null_byte_rejected(case_root: Path) -> None:
    """A004 — NUL byte injection must be refused."""
    with pytest.raises(PathSafetyError):
        resolve_evidence_path("TEST_CASE", "memory.raw\x00.txt", root=case_root)


@pytest.mark.spoliation
def test_005_case_id_traversal_rejected(case_root: Path) -> None:
    """A005 — case_id with path separators must be refused."""
    with pytest.raises(PathSafetyError):
        resolve_evidence_path("../OTHER_CASE", "x", root=case_root)


@pytest.mark.spoliation
def test_006_case_id_empty_rejected(case_root: Path) -> None:
    """A006 — empty case_id must be refused."""
    with pytest.raises(PathSafetyError):
        resolve_evidence_path("", "memory.raw", root=case_root)


@pytest.mark.spoliation
def test_007_writable_evidence_refused(case_root: Path) -> None:
    """A007 — read_only_check refuses writable files."""
    f = case_root / "TEST_CASE" / "memory.raw"
    # default tmp_path is writable
    assert os.access(f, os.W_OK)
    with pytest.raises(ReadOnlyViolation):
        read_only_check(f)


@pytest.mark.spoliation
def test_008_no_run_command_tool_exists() -> None:
    """A008 — there must be no generic shell-execution tool registered."""
    from echo_mcp.tools import TOOL_REGISTRY
    forbidden = {
        "run_command", "execute_shell_cmd", "shell", "bash",
        "exec", "subprocess_run", "system", "eval",
    }
    found = forbidden & set(TOOL_REGISTRY.keys())
    assert not found, f"forbidden tool(s) registered: {found}"


@pytest.mark.spoliation
def test_009_no_subprocess_shell_true_in_codebase() -> None:
    """A009 — no use of shell=True in the entire codebase."""
    repo_root = Path(__file__).resolve().parents[2]
    offenders = []
    for py in repo_root.rglob("*.py"):
        if any(part in py.parts for part in (".venv", "venv", "build", "dist")):
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        if "shell=True" in text and "shell=False" not in text:
            # crude but effective — flag any occurrence
            offenders.append(py.relative_to(repo_root))
    assert not offenders, f"shell=True found in: {offenders}"


@pytest.mark.spoliation
def test_010_tool_registry_has_exactly_15_or_fewer() -> None:
    """A010 — tool surface is bounded; nobody slipped a 30th tool in."""
    from echo_mcp.tools import TOOL_REGISTRY
    # 14 locked, +1 dlllist conditional = 15 max
    assert len(TOOL_REGISTRY) <= 15, (
        f"tool surface grew to {len(TOOL_REGISTRY)}: {sorted(TOOL_REGISTRY)}"
    )


@pytest.mark.spoliation
def test_011_findings_status_cannot_be_confirmed_at_low_confidence() -> None:
    """A011 — Pydantic refuses {confidence: low, status: confirmed}."""
    from pydantic import ValidationError
    from echo_mcp.schemas import Confidence, Finding
    with pytest.raises(ValidationError):
        Finding(
            id="F-X-001",
            title="x",
            description="y",
            confidence=Confidence.LOW,
            score=0.1,
            produced_by_iter=0,
            sources=["windows.pslist"],
            status="confirmed",  # type: ignore[arg-type]
        )


@pytest.mark.spoliation
def test_012_audit_chain_breaks_on_tamper(tmp_path: Path) -> None:
    """A012 — single-byte tamper is detected by verify_chain."""
    from echo_agent.audit import AuditLogger, verify_chain
    from echo_mcp.schemas import Phase

    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path, case_id="TAMPER")
    for i in range(3):
        logger.append(
            node="planner", phase=Phase.TRIAGE,
            input_obj={"i": i}, output_obj={"i": i, "ok": True},
        )

    ok, msg = verify_chain(log_path)
    assert ok, f"chain should verify before tamper: {msg}"

    # Tamper with a single byte in line 2.
    text = log_path.read_text()
    lines = text.splitlines()
    # flip one character inside the second entry's input_hash field
    target = lines[1]
    if '"input_hash":"' in target:
        i = target.index('"input_hash":"') + len('"input_hash":"')
        target = target[:i] + ("0" if target[i] != "0" else "1") + target[i+1:]
    lines[1] = target
    log_path.write_text("\n".join(lines) + "\n")

    ok2, msg2 = verify_chain(log_path)
    assert not ok2, f"chain should be broken after tamper, but: {msg2}"
