"""
Volatility 3 typed wrappers.

DFIR background for the AI/ML reader:
    Volatility is the canonical memory-forensics framework. Each "plugin"
    answers one question about a memory image:
        - pslist:   live process list (linked-list walk)
        - psscan:   pool-tag scan (finds hidden + recently-exited processes)
        - malfind:  injected/anomalous executable VAD regions
        - netscan:  network connection objects + owning PID
        - cmdline:  process command lines (read from PEB)
        - dlllist:  loaded modules per process
        - mftscan:  in-memory MFT records

Volatility 3 takes --renderer json which produces structured rows we can
deserialize directly into Pydantic models.

ARCHITECTURAL GUARDRAIL: each plugin here is a separate function with a
fixed argv. There is NO `run_volatility(plugin: str)` wildcard.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from echo_mcp.knowledge import caveats_for
from echo_mcp.schemas import ToolResponse, NetworkConnection, ProcessRecord
from echo_mcp.tools._common import (
    DEFAULT_TIMEOUT_S,
    empty_response,
    resolve_evidence_path,
    run_subprocess,
)

# Symbol resolution can be slow on first run; we extend timeout for vol3.
VOL_TIMEOUT_S = max(DEFAULT_TIMEOUT_S, 180)
VOL_BIN = "vol"  # SIFT installs Volatility 3 as `vol`


# --------------------------------------------------------- internal helper --


def _vol_run(
    case_id: str,
    memory_image: str,
    plugin: str,
    extra_args: Optional[list[str]] = None,
) -> tuple[int, list[dict], str, float]:
    """Resolve evidence path, run vol3, parse JSON. Returns (rc, rows, err, elapsed)."""
    image_path = resolve_evidence_path(case_id, memory_image)
    argv = [VOL_BIN, "-q", "-r", "json", "-f", str(image_path), plugin]
    if extra_args:
        argv.extend(extra_args)
    rc, stdout, stderr, elapsed = run_subprocess(argv, timeout=VOL_TIMEOUT_S)
    if rc != 0:
        return rc, [], stderr.strip() or stdout.strip(), elapsed
    try:
        payload = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError as e:
        return rc, [], f"vol3 JSON parse error: {e}", elapsed
    # vol3 -r json returns a list of dicts directly.
    if isinstance(payload, dict):
        # newer vol3 may wrap in {plugin: [...rows...]}; flatten
        for v in payload.values():
            if isinstance(v, list):
                payload = v
                break
        else:
            payload = []
    return rc, payload, "", elapsed


# ------------------------------------------------------------- pslist -----


def pslist(case_id: str, memory_image: str) -> ToolResponse:
    """windows.pslist — active process list via EPROCESS linked-list walk."""
    args = {"case_id": case_id, "memory_image": memory_image}
    rc, rows, err, elapsed = _vol_run(case_id, memory_image, "windows.pslist")
    cav, hints = caveats_for("windows.pslist")
    if rc != 0:
        return empty_response("windows.pslist", args, err, elapsed)

    data: list[dict[str, Any]] = []
    for r in rows:
        try:
            rec = ProcessRecord(
                pid=int(r.get("PID", 0)),
                ppid=int(r.get("PPID", 0)),
                name=str(r.get("ImageFileName") or r.get("ImageFile") or "unknown"),
                create_time=str(r.get("CreateTime")) if r.get("CreateTime") else None,
                exit_time=str(r.get("ExitTime")) if r.get("ExitTime") else None,
                threads=int(r["Threads"]) if "Threads" in r and r["Threads"] is not None else None,
                handles=int(r["Handles"]) if r.get("Handles") not in (None, "") else None,
                source_plugin="pslist",
            )
            data.append(rec.model_dump())
        except (ValueError, TypeError, KeyError):
            continue  # one bad row should not kill the response

    return ToolResponse(
        tool="windows.pslist",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ------------------------------------------------------------- psscan -----


def psscan(case_id: str, memory_image: str) -> ToolResponse:
    """windows.psscan — pool-tag scan, finds hidden/exited processes."""
    args = {"case_id": case_id, "memory_image": memory_image}
    rc, rows, err, elapsed = _vol_run(case_id, memory_image, "windows.psscan")
    cav, hints = caveats_for("windows.psscan")
    if rc != 0:
        return empty_response("windows.psscan", args, err, elapsed)

    data: list[dict[str, Any]] = []
    for r in rows:
        try:
            rec = ProcessRecord(
                pid=int(r.get("PID", 0)),
                ppid=int(r.get("PPID", 0)),
                name=str(r.get("ImageFileName") or r.get("ImageFile") or "unknown"),
                create_time=str(r.get("CreateTime")) if r.get("CreateTime") else None,
                exit_time=str(r.get("ExitTime")) if r.get("ExitTime") else None,
                source_plugin="psscan",
            )
            data.append(rec.model_dump())
        except (ValueError, TypeError, KeyError):
            continue

    return ToolResponse(
        tool="windows.psscan",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ------------------------------------------------------------- malfind -----


def malfind(case_id: str, memory_image: str) -> ToolResponse:
    """windows.malfind — flags suspicious executable+writable VAD regions."""
    args = {"case_id": case_id, "memory_image": memory_image}
    rc, rows, err, elapsed = _vol_run(case_id, memory_image, "windows.malfind")
    cav, hints = caveats_for("windows.malfind")
    if rc != 0:
        return empty_response("windows.malfind", args, err, elapsed)
    # malfind returns rich rows; pass through the relevant fields.
    data = [
        {
            "pid": int(r.get("PID", 0)),
            "process": str(r.get("Process") or r.get("ImageFileName") or "unknown"),
            "start_vpn": r.get("Start VPN") or r.get("Start"),
            "end_vpn": r.get("End VPN") or r.get("End"),
            "tag": r.get("Tag"),
            "protection": r.get("Protection"),
            "commit_charge": r.get("CommitCharge"),
            "private_memory": r.get("PrivateMemory"),
            "hexdump_first16": (r.get("Hexdump") or "")[:48],
        }
        for r in rows
    ]
    return ToolResponse(
        tool="windows.malfind",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ------------------------------------------------------------- netscan -----


def netscan(case_id: str, memory_image: str) -> ToolResponse:
    """windows.netscan — TCP/UDP connection objects + owning PID."""
    args = {"case_id": case_id, "memory_image": memory_image}
    rc, rows, err, elapsed = _vol_run(case_id, memory_image, "windows.netscan")
    cav, hints = caveats_for("windows.netscan")
    if rc != 0:
        return empty_response("windows.netscan", args, err, elapsed)

    data: list[dict[str, Any]] = []
    for r in rows:
        try:
            proto = str(r.get("Proto") or "TCPv4")
            if proto not in {"TCPv4", "TCPv6", "UDPv4", "UDPv6"}:
                continue
            local_port = int(r.get("LocalPort") or 0)
            foreign_port = r.get("ForeignPort")
            rec = NetworkConnection(
                pid=int(r.get("PID", 0)),
                owner=str(r.get("Owner")) if r.get("Owner") else None,
                proto=proto,  # type: ignore[arg-type]
                local_addr=str(r.get("LocalAddr") or "0.0.0.0"),
                local_port=local_port,
                foreign_addr=str(r.get("ForeignAddr")) if r.get("ForeignAddr") else None,
                foreign_port=int(foreign_port) if foreign_port not in (None, "") else None,
                state=str(r.get("State")) if r.get("State") else None,
                created=str(r.get("Created")) if r.get("Created") else None,
            )
            data.append(rec.model_dump())
        except (ValueError, TypeError, KeyError):
            continue

    return ToolResponse(
        tool="windows.netscan",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ------------------------------------------------------------- cmdline -----


def cmdline(case_id: str, memory_image: str) -> ToolResponse:
    """windows.cmdline — process command lines from PEB."""
    args = {"case_id": case_id, "memory_image": memory_image}
    rc, rows, err, elapsed = _vol_run(case_id, memory_image, "windows.cmdline")
    cav, hints = caveats_for("windows.cmdline")
    if rc != 0:
        return empty_response("windows.cmdline", args, err, elapsed)
    data = [
        {
            "pid": int(r.get("PID", 0)),
            "process": str(r.get("Process") or r.get("ImageFileName") or "unknown"),
            "args": (r.get("Args") or "")[:8192],
        }
        for r in rows
    ]
    return ToolResponse(
        tool="windows.cmdline",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ------------------------------------------------------------- dlllist -----


def dlllist(case_id: str, memory_image: str, pid: Optional[int] = None) -> ToolResponse:
    """windows.dlllist — loaded modules per process. Optionally filter by PID."""
    args: dict[str, Any] = {"case_id": case_id, "memory_image": memory_image, "pid": pid}
    extra = ["--pid", str(pid)] if pid is not None else None
    rc, rows, err, elapsed = _vol_run(case_id, memory_image, "windows.dlllist", extra)
    cav, hints = caveats_for("windows.dlllist")
    if rc != 0:
        return empty_response("windows.dlllist", args, err, elapsed)
    data = [
        {
            "pid": int(r.get("PID", 0)),
            "process": str(r.get("Process") or "unknown"),
            "base": r.get("Base"),
            "size": r.get("Size"),
            "name": r.get("Name"),
            "path": r.get("Path"),
        }
        for r in rows
    ]
    return ToolResponse(
        tool="windows.dlllist",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ------------------------------------------------------------- mftscan -----


def mftscan(case_id: str, memory_image: str) -> ToolResponse:
    """windows.mftscan — in-memory MFT records."""
    args = {"case_id": case_id, "memory_image": memory_image}
    rc, rows, err, elapsed = _vol_run(case_id, memory_image, "windows.mftscan")
    cav, hints = caveats_for("windows.mftscan")
    if rc != 0:
        return empty_response("windows.mftscan", args, err, elapsed)
    data = [
        {
            "record_number": int(r.get("RecordNumber", 0)),
            "name": r.get("Name") or r.get("Filename"),
            "type": r.get("Type"),
            "created": r.get("Created"),
            "modified": r.get("Modified"),
            "accessed": r.get("Accessed"),
        }
        for r in rows
    ]
    return ToolResponse(
        tool="windows.mftscan",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )
