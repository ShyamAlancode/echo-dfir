"""
ECHO MCP server — the architectural guardrail layer.

The LangGraph agent connects to this server over stdio and sees ONLY
the 14 typed tool functions registered below. No execute_shell_cmd.
No generic Python eval. The agent literally cannot construct a
destructive command because the corresponding tool does not exist.

Run as a module:
    python -m echo_mcp.server

Or via console script:
    echo-mcp
"""
from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any, Optional

from fastmcp import FastMCP

from echo_mcp.tools import TOOL_REGISTRY

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] echo-mcp: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("echo-mcp")

mcp = FastMCP(
    name="echo-mcp",
    instructions=(
        "ECHO Forensic MCP server. Exposes 14 typed, read-only forensic "
        "functions over the SANS SIFT Workstation. No shell access. "
        "Every response includes data, caveats, and cross_check_hints."
    ),
)


# -- helpers ---------------------------------------------------------------


def _serialize(resp) -> dict[str, Any]:
    """Convert a ToolResponse to a plain dict for the MCP wire format."""
    if hasattr(resp, "model_dump"):
        return resp.model_dump()
    return resp


# -- tool registration -----------------------------------------------------


@mcp.tool()
def windows_pslist(case_id: str, memory_image: str) -> dict[str, Any]:
    """Volatility 3 windows.pslist — active EPROCESS list.

    Args:
        case_id: case identifier (must match a directory under CASE_ROOT)
        memory_image: relative path to the memory image inside the case dir
    """
    return _serialize(TOOL_REGISTRY["windows.pslist"](case_id, memory_image))


@mcp.tool()
def windows_psscan(case_id: str, memory_image: str) -> dict[str, Any]:
    """Volatility 3 windows.psscan — pool-tag process scan."""
    return _serialize(TOOL_REGISTRY["windows.psscan"](case_id, memory_image))


@mcp.tool()
def windows_malfind(case_id: str, memory_image: str) -> dict[str, Any]:
    """Volatility 3 windows.malfind — injected/anomalous VAD detection."""
    return _serialize(TOOL_REGISTRY["windows.malfind"](case_id, memory_image))


@mcp.tool()
def windows_netscan(case_id: str, memory_image: str) -> dict[str, Any]:
    """Volatility 3 windows.netscan — TCP/UDP connection objects."""
    return _serialize(TOOL_REGISTRY["windows.netscan"](case_id, memory_image))


@mcp.tool()
def windows_cmdline(case_id: str, memory_image: str) -> dict[str, Any]:
    """Volatility 3 windows.cmdline — process command lines."""
    return _serialize(TOOL_REGISTRY["windows.cmdline"](case_id, memory_image))


@mcp.tool()
def windows_dlllist(
    case_id: str, memory_image: str, pid: Optional[int] = None
) -> dict[str, Any]:
    """Volatility 3 windows.dlllist — loaded modules (optionally per PID)."""
    return _serialize(TOOL_REGISTRY["windows.dlllist"](case_id, memory_image, pid))


@mcp.tool()
def windows_mftscan(case_id: str, memory_image: str) -> dict[str, Any]:
    """Volatility 3 windows.mftscan — in-memory MFT records."""
    return _serialize(TOOL_REGISTRY["windows.mftscan"](case_id, memory_image))


@mcp.tool()
def regripper_appcompatcache(case_id: str, system_hive: str) -> dict[str, Any]:
    """RegRipper appcompatcache — ShimCache from SYSTEM hive."""
    return _serialize(TOOL_REGISTRY["regripper.appcompatcache"](case_id, system_hive))


@mcp.tool()
def regripper_amcache(case_id: str, amcache_hive: str) -> dict[str, Any]:
    """RegRipper amcache — AmCache.hve binary inventory."""
    return _serialize(TOOL_REGISTRY["regripper.amcache"](case_id, amcache_hive))


@mcp.tool()
def regripper_run(case_id: str, hive: str) -> dict[str, Any]:
    """RegRipper run — Run/RunOnce persistence keys."""
    return _serialize(TOOL_REGISTRY["regripper.run"](case_id, hive))


@mcp.tool()
def regripper_services(case_id: str, system_hive: str) -> dict[str, Any]:
    """RegRipper services — service hive entries (T1543.003)."""
    return _serialize(TOOL_REGISTRY["regripper.services"](case_id, system_hive))


@mcp.tool()
def evtx_parse(
    case_id: str,
    evtx_relpath: str,
    event_ids: Optional[list[int]] = None,
    max_records: int = 5000,
) -> dict[str, Any]:
    """python-evtx — parse Windows .evtx, filter by interesting event IDs."""
    return _serialize(
        TOOL_REGISTRY["evtx_parse"](case_id, evtx_relpath, event_ids, max_records)
    )


@mcp.tool()
def prefetch_parse(
    case_id: str, prefetch_dir: str = "Windows/Prefetch"
) -> dict[str, Any]:
    """Prefetch (.pf) execution evidence parser."""
    return _serialize(TOOL_REGISTRY["prefetch_parse"](case_id, prefetch_dir))


@mcp.tool()
def mft_parse(
    case_id: str, mft_relpath: str, max_records: int = 5000
) -> dict[str, Any]:
    """analyzeMFT body-file parser — disk-resident NTFS metadata."""
    return _serialize(TOOL_REGISTRY["mft_parse"](case_id, mft_relpath, max_records))


@mcp.tool()
def bulk_extractor_run(
    case_id: str, image_relpath: str, max_iocs: int = 2000
) -> dict[str, Any]:
    """bulk_extractor — IOC harvest (IPs, domains, URLs, emails, hashes)."""
    return _serialize(
        TOOL_REGISTRY["bulk_extractor_run"](case_id, image_relpath, max_iocs)
    )


# -- entrypoint ------------------------------------------------------------


def main() -> None:
    log.info("ECHO MCP server starting on stdio (14 tools registered)")
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
