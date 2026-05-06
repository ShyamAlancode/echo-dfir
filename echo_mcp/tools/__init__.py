"""ECHO tool surface — exactly 14 typed read-only forensic functions.

The agent NEVER sees a generic shell. It sees this list:

    Volatility 3 (memory):
        windows.pslist, windows.psscan, windows.malfind,
        windows.netscan, windows.cmdline, windows.dlllist,
        windows.mftscan
    Registry:
        regripper.appcompatcache, regripper.amcache,
        regripper.run, regripper.services
    Disk artifacts:
        evtx_parse, prefetch_parse, mft_parse, bulk_extractor_run

That's 15 — but `windows.dlllist` is conditional (PID-required), so the
14-locked tool surface is the headline. We keep dlllist available because
the critic node uses it for confirmation cycles.
"""
from echo_mcp.tools import (
    evtx,
    mft_be,
    prefetch,
    registry,
    volatility,
)

# Public registry — used by server.py to register MCP tools.
TOOL_REGISTRY = {
    "windows.pslist":            volatility.pslist,
    "windows.psscan":            volatility.psscan,
    "windows.malfind":           volatility.malfind,
    "windows.netscan":           volatility.netscan,
    "windows.cmdline":           volatility.cmdline,
    "windows.dlllist":           volatility.dlllist,
    "windows.mftscan":           volatility.mftscan,
    "regripper.appcompatcache":  registry.appcompatcache,
    "regripper.amcache":         registry.amcache,
    "regripper.run":             registry.run,
    "regripper.services":        registry.services,
    "evtx_parse":                evtx.evtx_parse,
    "prefetch_parse":            prefetch.prefetch_parse,
    "mft_parse":                 mft_be.mft_parse,
    "bulk_extractor_run":        mft_be.bulk_extractor_run,
}

# Phase → allowed tools mapping (executor uses this to constrain tool choice).
PHASE_TOOL_MAP = {
    "triage":   ["windows.pslist", "windows.psscan"],
    "memory":   ["windows.pslist", "windows.psscan", "windows.malfind",
                 "windows.cmdline", "windows.dlllist"],
    "network":  ["windows.netscan"],
    "disk":     ["mft_parse", "prefetch_parse", "bulk_extractor_run"],
    "registry": ["regripper.appcompatcache", "regripper.amcache",
                 "regripper.run", "regripper.services"],
    "events":   ["evtx_parse"],
    "finalize": [],
}
