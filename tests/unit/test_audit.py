"""Tests for SHA-256 Merkle audit chain."""
from __future__ import annotations

from pathlib import Path

import pytest

from echo_agent.audit import (
    GENESIS_PREV_HASH,
    AuditLogger,
    head_hash,
    verify_chain,
)
from echo_mcp.schemas import Phase


def test_genesis_hash_constant() -> None:
    assert GENESIS_PREV_HASH == "0" * 64


def test_empty_log_head_is_genesis(tmp_path: Path) -> None:
    p = tmp_path / "empty.jsonl"
    assert head_hash(p) == GENESIS_PREV_HASH


def test_logger_appends_and_verifies(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path, case_id="UNIT_001")
    e1 = logger.append(
        node="planner", phase=Phase.TRIAGE,
        input_obj={"a": 1}, output_obj={"a": 1, "ok": True},
    )
    e2 = logger.append(
        node="executor", phase=Phase.MEMORY,
        input_obj={"b": 2}, output_obj={"b": 2, "ok": True},
    )

    assert e1.prev_hash == GENESIS_PREV_HASH
    assert e2.prev_hash == e1.this_hash

    ok, msg = verify_chain(log_path)
    assert ok, msg


def test_resume_appends_after_restart(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger1 = AuditLogger(log_path, case_id="UNIT_002")
    logger1.append(node="planner", phase=Phase.TRIAGE,
                   input_obj={}, output_obj={"x": 1})
    head1 = logger1.last_hash

    logger2 = AuditLogger(log_path, case_id="UNIT_002")
    assert logger2.last_hash == head1
    logger2.append(node="executor", phase=Phase.MEMORY,
                   input_obj={}, output_obj={"y": 2})

    ok, _ = verify_chain(log_path)
    assert ok


def test_iter_counter_resumes(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    a = AuditLogger(log_path, case_id="UNIT_003")
    e1 = a.append(node="planner", phase=Phase.TRIAGE, input_obj={}, output_obj={})
    assert e1.iter == 0
    e2 = a.append(node="executor", phase=Phase.MEMORY, input_obj={}, output_obj={})
    assert e2.iter == 1
    a2 = AuditLogger(log_path, case_id="UNIT_003")
    e3 = a2.append(node="validator", phase=Phase.MEMORY, input_obj={}, output_obj={})
    assert e3.iter == 2
