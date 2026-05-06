"""Unit tests for the deterministic core."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from echo_mcp.schemas import (
    Confidence,
    Contradiction,
    Finding,
    IOC,
    IOCType,
    ProcessRecord,
    Severity,
    ToolResponse,
    canonical_json,
    sha256_of,
)
from validators.cross_source import (
    detect_all,
    rule_r01_hidden_process,
    rule_r02_execution_disagreement,
    rule_r03_orphan_network_owner,
)
from validators.score import compute_score, confidence_for, status_for


# ============================================================== SCORER ====


def test_score_high_with_many_sources() -> None:
    s = compute_score(sources_count=4, contradictions_count=0)
    assert s >= 0.75
    label, _ = confidence_for(4, 0)
    assert label == Confidence.HIGH


def test_score_low_with_contradictions() -> None:
    s = compute_score(sources_count=1, contradictions_count=2)
    assert s < 0.45


def test_score_clamped() -> None:
    assert compute_score(sources_count=20, contradictions_count=0) == 1.0
    assert compute_score(sources_count=0, contradictions_count=20) == 0.0


def test_status_for_label() -> None:
    assert status_for(Confidence.LOW) == "low_confidence"
    assert status_for(Confidence.MEDIUM) == "confirmed"
    assert status_for(Confidence.HIGH) == "confirmed"


# ============================================================ SCHEMAS ====


def test_process_record_validates() -> None:
    p = ProcessRecord(pid=4, ppid=0, name="System", source_plugin="pslist")
    assert p.pid == 4


def test_process_record_rejects_negative_pid() -> None:
    with pytest.raises(ValidationError):
        ProcessRecord(pid=-1, ppid=0, name="X", source_plugin="pslist")  # type: ignore[arg-type]


def test_finding_rejects_invalid_mitre() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="F-X-001",
            title="x", description="y",
            confidence=Confidence.HIGH, score=0.9,
            mitre_technique_ids=["BAD"],
            produced_by_iter=0,
            sources=["a"],
            status="confirmed",
        )


def test_finding_rejects_id_format() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="not-a-finding-id",
            title="x", description="y",
            confidence=Confidence.HIGH, score=0.9,
            produced_by_iter=0, sources=["a"],
            status="confirmed",
        )


def test_ioc_strips_whitespace() -> None:
    ioc = IOC(type=IOCType.IPV4, value="  1.2.3.4  ")
    assert ioc.value == "1.2.3.4"


def test_canonical_json_deterministic() -> None:
    a = canonical_json({"b": 2, "a": 1})
    b = canonical_json({"a": 1, "b": 2})
    assert a == b


def test_sha256_of_stable() -> None:
    assert sha256_of({"x": 1}) == sha256_of({"x": 1})
    assert sha256_of({"x": 1}) != sha256_of({"x": 2})


# ============================================================== RULES ====


def _resp(tool: str, data: list[dict]) -> ToolResponse:
    return ToolResponse(
        tool=tool, args={}, data=data, caveats=[], cross_check_hints=[],
        runtime_seconds=0.1,
    )


def test_r01_detects_hidden_process() -> None:
    pslist = _resp("windows.pslist", [
        {"pid": 100, "ppid": 4, "name": "explorer.exe", "source_plugin": "pslist"},
        {"pid": 200, "ppid": 100, "name": "chrome.exe", "source_plugin": "pslist"},
    ])
    psscan = _resp("windows.psscan", [
        {"pid": 100, "ppid": 4, "name": "explorer.exe", "source_plugin": "psscan"},
        {"pid": 200, "ppid": 100, "name": "chrome.exe", "source_plugin": "psscan"},
        {"pid": 666, "ppid": 4, "name": "evil.exe", "source_plugin": "psscan"},
    ])
    c = rule_r01_hidden_process(pslist, psscan, iter_n=1)
    assert c is not None
    assert c.rule_id == "R01"
    assert c.severity == Severity.HIGH
    assert any(a["pid"] == 666 for a in c.artifacts)


def test_r01_no_false_positive_with_exit_time() -> None:
    pslist = _resp("windows.pslist", [
        {"pid": 100, "ppid": 4, "name": "x.exe", "source_plugin": "pslist"},
    ])
    psscan = _resp("windows.psscan", [
        {"pid": 100, "ppid": 4, "name": "x.exe", "source_plugin": "psscan"},
        {
            "pid": 200, "ppid": 100, "name": "exited.exe",
            "source_plugin": "psscan", "exit_time": "2025-01-01 12:00:00",
        },
    ])
    c = rule_r01_hidden_process(pslist, psscan, iter_n=1)
    assert c is None


def test_r02_detects_execution_disagreement() -> None:
    amc = _resp("regripper.amcache", [
        {"path": "C:\\Windows\\System32\\evil.exe", "sha1": "a" * 40},
    ])
    pf = _resp("prefetch_parse", [
        {"executable_name": "BENIGN.EXE", "last_run_times": []},
    ])
    c = rule_r02_execution_disagreement(amc, pf, iter_n=1)
    assert c is not None
    assert c.rule_id == "R02"


def test_r03_detects_orphan_network_owner() -> None:
    netscan = _resp("windows.netscan", [
        {"pid": 999, "owner": "?", "proto": "TCPv4",
         "local_addr": "0.0.0.0", "local_port": 4444,
         "foreign_addr": "1.2.3.4", "foreign_port": 80},
    ])
    pslist = _resp("windows.pslist", [
        {"pid": 100, "ppid": 4, "name": "x.exe", "source_plugin": "pslist"},
    ])
    psscan = _resp("windows.psscan", [
        {"pid": 100, "ppid": 4, "name": "x.exe", "source_plugin": "psscan"},
    ])
    c = rule_r03_orphan_network_owner(netscan, pslist, psscan, iter_n=1)
    assert c is not None
    assert c.rule_id == "R03"
    assert c.severity == Severity.HIGH


def test_detect_all_runs_multiple_rules() -> None:
    cache = {
        "windows.pslist": _resp("windows.pslist", [
            {"pid": 100, "ppid": 4, "name": "a.exe", "source_plugin": "pslist"},
        ]),
        "windows.psscan": _resp("windows.psscan", [
            {"pid": 100, "ppid": 4, "name": "a.exe", "source_plugin": "psscan"},
            {"pid": 666, "ppid": 4, "name": "evil.exe", "source_plugin": "psscan"},
        ]),
        "windows.netscan": _resp("windows.netscan", [
            {"pid": 999, "owner": "?", "proto": "TCPv4",
             "local_addr": "0.0.0.0", "local_port": 4444,
             "foreign_addr": "1.2.3.4", "foreign_port": 80},
        ]),
    }
    results = detect_all(cache, iter_n=3)
    rule_ids = {c.rule_id for c in results}
    assert "R01" in rule_ids
    assert "R03" in rule_ids
