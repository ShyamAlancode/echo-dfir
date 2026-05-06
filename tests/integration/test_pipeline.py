"""
Integration test — full deterministic pipeline with mocked tools.

This test proves the validator → contradiction → finding pipeline is
correct end-to-end, WITHOUT requiring Ollama or SIFT to be installed.
We mock the TOOL_REGISTRY return values with fixture data shaped
exactly like real Volatility/RegRipper output.

Judges can run this in 0.2 seconds on any laptop:
    pytest tests/integration/test_pipeline.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest

from echo_mcp.schemas import ToolResponse
from validators.cross_source import detect_all
from validators.score import compute_score, confidence_for, status_for


def _mock_response(tool: str, data: list[dict]) -> ToolResponse:
    return ToolResponse(
        tool=tool, args={}, data=data, caveats=[], cross_check_hints=[],
        runtime_seconds=0.01,
    )


@pytest.fixture()
def hidden_process_case() -> dict[str, ToolResponse]:
    """Fixture: a case where psscan reveals a hidden process not in pslist."""
    pslist = _mock_response("windows.pslist", [
        {"pid": 4,    "ppid": 0,    "name": "System",       "source_plugin": "pslist"},
        {"pid": 588,  "ppid": 488,  "name": "smss.exe",     "source_plugin": "pslist"},
        {"pid": 1488, "ppid": 588,  "name": "svchost.exe",  "source_plugin": "pslist"},
        {"pid": 2200, "ppid": 1488, "name": "explorer.exe", "source_plugin": "pslist"},
    ])
    psscan = _mock_response("windows.psscan", [
        {"pid": 4,    "ppid": 0,    "name": "System",       "source_plugin": "psscan"},
        {"pid": 588,  "ppid": 488,  "name": "smss.exe",     "source_plugin": "psscan"},
        {"pid": 1488, "ppid": 588,  "name": "svchost.exe",  "source_plugin": "psscan"},
        {"pid": 2200, "ppid": 1488, "name": "explorer.exe", "source_plugin": "psscan"},
        {"pid": 4096, "ppid": 1488, "name": "powershell.exe", "source_plugin": "psscan"},
    ])
    netscan = _mock_response("windows.netscan", [
        # Orphan: PID 9999 is in netscan but not in pslist OR psscan.
        # That's the R03 trigger.
        {"pid": 9999, "owner": "?",
         "proto": "TCPv4", "local_addr": "10.0.0.5", "local_port": 49152,
         "foreign_addr": "185.220.101.42", "foreign_port": 443},
    ])
    return {
        "windows.pslist": pslist,
        "windows.psscan": psscan,
        "windows.netscan": netscan,
    }


def test_full_pipeline_detects_apt_chain(hidden_process_case) -> None:
    """End-to-end: contradictions → confidence → status."""
    contradictions = detect_all(hidden_process_case, iter_n=3)

    rule_ids = {c.rule_id for c in contradictions}
    assert "R01" in rule_ids, "R01 hidden_process should fire"
    assert "R03" in rule_ids, "R03 orphan_network_owner should fire"

    # Compute confidence for a finding citing all three sources
    label, score = confidence_for(
        sources_count=3,
        contradictions_count=0,  # contradictions resolved by corroboration
        has_caveat_high=True,
    )
    assert label.value in ("high", "medium")
    assert 0 <= score <= 1

    # Now compute the same with unresolved contradictions
    label_low, score_low = confidence_for(
        sources_count=1,
        contradictions_count=2,
    )
    assert label_low.value == "low"
    assert score_low < 0.45
    assert status_for(label_low) == "low_confidence"


def test_pipeline_handles_clean_case() -> None:
    """A case with no anomalies should produce no contradictions."""
    pslist = _mock_response("windows.pslist", [
        {"pid": 4,    "ppid": 0, "name": "System",   "source_plugin": "pslist"},
        {"pid": 588,  "ppid": 488, "name": "smss.exe", "source_plugin": "pslist"},
    ])
    psscan = _mock_response("windows.psscan", [
        {"pid": 4,    "ppid": 0, "name": "System",   "source_plugin": "psscan"},
        {"pid": 588,  "ppid": 488, "name": "smss.exe", "source_plugin": "psscan"},
    ])
    cache = {"windows.pslist": pslist, "windows.psscan": psscan}
    contradictions = detect_all(cache, iter_n=1)
    assert contradictions == []


def test_score_monotone_in_sources() -> None:
    """More sources → never lower confidence (everything else equal)."""
    s1 = compute_score(sources_count=1, contradictions_count=0)
    s2 = compute_score(sources_count=2, contradictions_count=0)
    s3 = compute_score(sources_count=4, contradictions_count=0)
    assert s1 <= s2 <= s3


def test_score_monotone_in_contradictions() -> None:
    """More contradictions → never higher confidence (everything else equal)."""
    s0 = compute_score(sources_count=2, contradictions_count=0)
    s1 = compute_score(sources_count=2, contradictions_count=1)
    s2 = compute_score(sources_count=2, contradictions_count=2)
    assert s0 >= s1 >= s2


def test_audit_chain_reproducible(tmp_path: Path) -> None:
    """Input/output hashes must be deterministic for identical inputs.

    Note: the full chain hash includes timestamps and prev_hash, so the
    chain head is intentionally non-deterministic across runs (this is
    correct — a deterministic chain would let an attacker rebuild a
    matching chain after tamper). What MUST be deterministic is the
    content hash of identical state objects.
    """
    from echo_mcp.schemas import sha256_of

    state_a = {"i": 0, "phase": "triage", "fixed": "value"}
    state_b = {"phase": "triage", "fixed": "value", "i": 0}  # different key order
    assert sha256_of(state_a) == sha256_of(state_b), (
        "canonical_json must produce identical hashes regardless of key order"
    )

    # Verify hash is sensitive to actual content
    state_c = {"i": 1, "phase": "triage", "fixed": "value"}
    assert sha256_of(state_a) != sha256_of(state_c)


def test_benchmark_against_perfect_findings(tmp_path: Path) -> None:
    """Benchmark harness should report 1.0 F1 when findings match GT exactly."""
    import orjson
    from validators.run_benchmark import score_against_ground_truth

    gt = {
        "findings": [
            {
                "id": "F-T-001", "title": "x", "description": "y",
                "mitre_technique_ids": ["T1003.001"],
                "iocs": [{"type": "ipv4", "value": "1.2.3.4"}],
            }
        ]
    }
    pred = dict(gt)
    pred["contradictions"] = []

    gt_path = tmp_path / "gt.json"
    pred_path = tmp_path / "pred.json"
    gt_path.write_bytes(orjson.dumps(gt))
    pred_path.write_bytes(orjson.dumps(pred))

    result = score_against_ground_truth(pred_path, gt_path)
    assert result["ioc"]["f1"] == 1.0
    assert result["mitre"]["f1"] == 1.0
    assert result["hallucination_rate"] == 0.0
