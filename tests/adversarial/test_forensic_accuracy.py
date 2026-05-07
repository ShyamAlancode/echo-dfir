"""
Forensic accuracy tests — prove ECHO finds real evil patterns.

These simulate the kinds of artifacts NIST CFReDS and CyberDefenders
cases contain. Until we run against those real images, these fixture-based
tests prove the detection logic is correct.
"""
from __future__ import annotations
import pytest
from echo_mcp.schemas import ToolResponse
from validators.cross_source import (
    detect_all,
    rule_r01_hidden_process,
    rule_r02_execution_disagreement,
    rule_r03_orphan_network_owner,
    rule_r04_event4688_anomaly,
    rule_r05_shimcache_malfind_correlate,
)
from validators.score import compute_score, confidence_for


def _resp(tool: str, data: list) -> ToolResponse:
    return ToolResponse(
        tool=tool, args={}, data=data,
        caveats=[], cross_check_hints=[], runtime_seconds=0.01,
    )


@pytest.mark.adversarial
def test_r01_detects_dkom_hidden_process() -> None:
    """Simulate a rootkit hiding its process via DKOM unlinking."""
    pslist = _resp("windows.pslist", [
        {"pid": 4,    "ppid": 0,    "name": "System",      "source_plugin": "pslist"},
        {"pid": 688,  "ppid": 4,    "name": "lsass.exe",   "source_plugin": "pslist"},
        {"pid": 1488, "ppid": 688,  "name": "svchost.exe", "source_plugin": "pslist"},
    ])
    psscan = _resp("windows.psscan", [
        {"pid": 4,    "ppid": 0,    "name": "System",      "source_plugin": "psscan"},
        {"pid": 688,  "ppid": 4,    "name": "lsass.exe",   "source_plugin": "psscan"},
        {"pid": 1488, "ppid": 688,  "name": "svchost.exe", "source_plugin": "psscan"},
        # Hidden beacon — DKOM unlinked from pslist
        {"pid": 4096, "ppid": 1488, "name": "rundll32.exe","source_plugin": "psscan"},
    ])
    c = rule_r01_hidden_process(pslist, psscan, iter_n=2)
    assert c is not None
    assert c.rule_id == "R01"
    assert any(a["pid"] == 4096 for a in c.artifacts)
    assert c.severity.value == "high"


@pytest.mark.adversarial
def test_r01_zero_false_positives_on_50_clean_processes() -> None:
    """Precision: R01 must produce 0 false positives on clean data.
    
    This is the false-positive rate = 0 requirement for court admissibility.
    """
    processes = [
        {"pid": i * 4 + 8, "ppid": 4, "name": f"svchost_{i}.exe",
         "source_plugin": "pslist"}
        for i in range(50)
    ]
    pslist = _resp("windows.pslist", processes)
    psscan = _resp("windows.psscan",
                   [dict(p, source_plugin="psscan") for p in processes])
    result = rule_r01_hidden_process(pslist, psscan, iter_n=1)
    assert result is None, "R01 must produce zero false positives on clean 50-process list"


@pytest.mark.adversarial
def test_r02_detects_amcache_without_prefetch() -> None:
    """Binary in AmCache with no Prefetch entry = suspicious execution."""
    amcache = _resp("regripper.amcache", [
        {"path": "C:\\Windows\\Temp\\malware.exe", "sha1": "c" * 40},
    ])
    prefetch = _resp("prefetch_parse", [
        {"executable_name": "CHROME.EXE",  "last_run_times": []},
        {"executable_name": "NOTEPAD.EXE", "last_run_times": []},
    ])
    c = rule_r02_execution_disagreement(amcache, prefetch, iter_n=2)
    assert c is not None
    assert c.rule_id == "R02"


@pytest.mark.adversarial
def test_r02_suppressed_when_prefetch_entirely_absent() -> None:
    """If Prefetch is empty (SSD policy), R02 must not fire false positive."""
    amcache = _resp("regripper.amcache", [
        {"path": "C:\\Windows\\Temp\\legitimate.exe", "sha1": "a" * 40},
    ])
    prefetch = _resp("prefetch_parse", [])  # empty = SSD policy
    c = rule_r02_execution_disagreement(amcache, prefetch, iter_n=2)
    assert c is None, "R02 must not fire when Prefetch is entirely absent"


@pytest.mark.adversarial
def test_r03_detects_c2_orphaned_connection() -> None:
    """Hidden process owns outbound C2 connection — classic beacon pattern."""
    netscan = _resp("windows.netscan", [
        {"pid": 4096, "owner": "?", "proto": "TCPv4",
         "local_addr": "10.0.0.5", "local_port": 49200,
         "foreign_addr": "185.220.101.42", "foreign_port": 443},
    ])
    pslist = _resp("windows.pslist", [
        {"pid": 4, "ppid": 0, "name": "System", "source_plugin": "pslist"},
    ])
    psscan = _resp("windows.psscan", [
        {"pid": 4, "ppid": 0, "name": "System", "source_plugin": "psscan"},
    ])
    c = rule_r03_orphan_network_owner(netscan, pslist, psscan, iter_n=2)
    assert c is not None
    assert c.rule_id == "R03"
    assert c.severity.value == "high"
    assert c.artifacts[0]["foreign"] == "185.220.101.42:443"


@pytest.mark.adversarial
def test_r04_detects_single_execution_credential_dumper() -> None:
    """Credential dumper ran once from Temp and exited — single 4688 event."""
    evtx = _resp("evtx_parse", [
        {"event_id": 4688, "channel": "Security",
         "timestamp": "2025-04-12T03:14:22Z",
         "raw": {
             "NewProcessName": "C:\\Windows\\Temp\\mimikatz.exe",
             "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
             "SubjectUserName": "j.morgan",
         }},
    ])
    pslist = _resp("windows.pslist", [
        {"pid": 4,   "ppid": 0, "name": "System",  "source_plugin": "pslist"},
        {"pid": 688, "ppid": 4, "name": "cmd.exe", "source_plugin": "pslist"},
    ])
    c = rule_r04_event4688_anomaly(evtx, pslist, iter_n=3)
    assert c is not None, "R04 must detect single-execution tool from Temp dir"
    assert c.rule_id == "R04"
    assert any("mimikatz" in str(a).lower() for a in c.artifacts)


@pytest.mark.adversarial
def test_r05_detects_shellcode_injection() -> None:
    """Binary in ShimCache + RWX injected region = process injection."""
    shimcache = _resp("regripper.appcompatcache", [
        {"plugin": "appcompatcache",
         "key_path": "SYSTEM\\AppCompatCache",
         "value_name": "entry_0",
         "value_data": "C:\\Windows\\System32\\svchost.exe"},
    ])
    malfind = _resp("windows.malfind", [
        {"pid": 1488, "process": "svchost.exe",
         "protection": "PAGE_EXECUTE_READWRITE",
         "tag": "VadS"},
    ])
    c = rule_r05_shimcache_malfind_correlate(shimcache, malfind, iter_n=4)
    assert c is not None
    assert c.rule_id == "R05"
    assert c.artifacts[0]["pid"] == 1488


@pytest.mark.adversarial
def test_full_apt_chain_r01_and_r03() -> None:
    """Full APT simulation: hidden process + orphaned C2 connection."""
    cache = {
        "windows.pslist": _resp("windows.pslist", [
            {"pid": 4,    "ppid": 0, "name": "System",
             "source_plugin": "pslist"},
            {"pid": 1488, "ppid": 4, "name": "svchost.exe",
             "source_plugin": "pslist"},
        ]),
        "windows.psscan": _resp("windows.psscan", [
            {"pid": 4,    "ppid": 0,    "name": "System",
             "source_plugin": "psscan"},
            {"pid": 1488, "ppid": 4,    "name": "svchost.exe",
             "source_plugin": "psscan"},
            {"pid": 4096, "ppid": 1488, "name": "rundll32.exe",
             "source_plugin": "psscan"},
        ]),
        "windows.netscan": _resp("windows.netscan", [
            {"pid": 9999, "owner": "?", "proto": "TCPv4",
             "local_addr": "10.0.0.5", "local_port": 49200,
             "foreign_addr": "185.220.101.42", "foreign_port": 443},
        ]),
    }
    contradictions = detect_all(cache, iter_n=3)
    rule_ids = {c.rule_id for c in contradictions}
    assert "R01" in rule_ids, "Must detect DKOM-hidden process"
    assert "R03" in rule_ids, "Must detect orphaned C2 connection"
    assert len(contradictions) == 2


@pytest.mark.adversarial
def test_high_confidence_requires_multiple_sources() -> None:
    """Single-source findings cannot be HIGH confidence."""
    label, score = confidence_for(sources_count=1, contradictions_count=0)
    assert label.value == "medium"
    assert score < 0.75


@pytest.mark.adversarial
def test_unresolved_contradiction_prevents_high_confidence() -> None:
    """Unresolved contradiction must not produce HIGH confidence."""
    label, score = confidence_for(
        sources_count=4, contradictions_count=1, has_caveat_high=False
    )
    assert score < 0.75, f"Contradiction should prevent HIGH confidence, got {score}"


@pytest.mark.adversarial
def test_confidence_formula_deterministic_100_times() -> None:
    """Same inputs must produce identical output 100 times in a row."""
    results = [
        compute_score(sources_count=3, contradictions_count=1, has_caveat_high=True)
        for _ in range(100)
    ]
    assert len(set(results)) == 1, "Confidence formula must be deterministic"


@pytest.mark.adversarial
def test_confidence_monotone_in_sources() -> None:
    """More corroborating sources must never decrease confidence."""
    scores = [
        compute_score(sources_count=s, contradictions_count=0)
        for s in range(5)
    ]
    for i in range(1, len(scores)):
        assert scores[i] >= scores[i - 1], (
            f"Score not monotone at sources={i}: {scores[i]} < {scores[i-1]}"
        )


@pytest.mark.adversarial
def test_confidence_monotone_in_contradictions() -> None:
    """More contradictions must never increase confidence."""
    scores = [
        compute_score(sources_count=2, contradictions_count=c)
        for c in range(5)
    ]
    for i in range(1, len(scores)):
        assert scores[i] <= scores[i - 1], (
            f"Score increased at contradictions={i}: {scores[i]} > {scores[i-1]}"
        )