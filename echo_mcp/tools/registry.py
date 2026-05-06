"""
RegRipper wrappers — Windows Registry forensic plugins.

DFIR background:
    The Registry is a hierarchical database where Windows stores
    configuration AND inadvertently records execution history. RegRipper
    is a Perl tool installed on SIFT that runs targeted plugins against
    a hive (SYSTEM, SOFTWARE, NTUSER.DAT, AmCache.hve).

We expose four plugins:
    - appcompatcache : ShimCache execution-adjacent paths
    - amcache        : AmCache.hve binary inventory + SHA1 + first-run
    - run            : Run / RunOnce persistence keys
    - services       : Services hive (T1543.003 persistence)

Each is a fixed-argv typed function. No generic 'rip with arbitrary plugin'.
"""
from __future__ import annotations

import re
from typing import Any

from echo_mcp.knowledge import caveats_for
from echo_mcp.schemas import AmcacheEntry, RegistryEntry, ToolResponse
from echo_mcp.tools._common import (
    DEFAULT_TIMEOUT_S,
    empty_response,
    resolve_evidence_path,
    run_subprocess,
)

RIP_BIN = "rip.pl"  # SIFT default
RIP_TIMEOUT_S = max(DEFAULT_TIMEOUT_S, 60)


def _rip(case_id: str, hive_relpath: str, plugin: str) -> tuple[int, str, str, float]:
    hive_path = resolve_evidence_path(case_id, hive_relpath)
    argv = [RIP_BIN, "-r", str(hive_path), "-p", plugin]
    return run_subprocess(argv, timeout=RIP_TIMEOUT_S)


# ------------------------------------------------------- appcompatcache --


_SHIM_LINE = re.compile(r"^(?P<ts>\S+\s+\S+)\s+(?P<path>.+)$")


def appcompatcache(case_id: str, system_hive: str) -> ToolResponse:
    """Parse ShimCache (AppCompatCache) entries from SYSTEM hive."""
    args = {"case_id": case_id, "system_hive": system_hive}
    rc, stdout, stderr, elapsed = _rip(case_id, system_hive, "appcompatcache")
    cav, hints = caveats_for("regripper.appcompatcache")
    if rc != 0:
        return empty_response("regripper.appcompatcache", args, stderr.strip(), elapsed)

    data: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("Launching", "appcompatcache", "ControlSet", "**")):
            continue
        m = _SHIM_LINE.match(line)
        if not m:
            continue
        try:
            entry = RegistryEntry(
                plugin="appcompatcache",
                key_path=r"SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache",
                value_name=m.group("path")[:256],
                value_data=m.group("path")[:8192],
                last_write=m.group("ts"),
            )
            data.append(entry.model_dump())
        except (ValueError, TypeError):
            continue

    return ToolResponse(
        tool="regripper.appcompatcache",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ----------------------------------------------------------- amcache ----


_AMCACHE_PATH = re.compile(r"^Path\s*:\s*(.+)$", re.IGNORECASE)
_AMCACHE_SHA1 = re.compile(r"^SHA1\s*:\s*([a-fA-F0-9]{40})$", re.IGNORECASE)
_AMCACHE_LASTMOD = re.compile(r"^LastMod(?:ified)?\s*:\s*(.+)$", re.IGNORECASE)
_AMCACHE_PUB = re.compile(r"^Publisher\s*:\s*(.+)$", re.IGNORECASE)
_AMCACHE_PROD = re.compile(r"^Product(?:Name)?\s*:\s*(.+)$", re.IGNORECASE)


def amcache(case_id: str, amcache_hive: str) -> ToolResponse:
    """Parse AmCache.hve binary inventory."""
    args = {"case_id": case_id, "amcache_hive": amcache_hive}
    rc, stdout, stderr, elapsed = _rip(case_id, amcache_hive, "amcache")
    cav, hints = caveats_for("regripper.amcache")
    if rc != 0:
        return empty_response("regripper.amcache", args, stderr.strip(), elapsed)

    data: list[dict[str, Any]] = []
    block: dict[str, Any] = {}

    def _flush() -> None:
        if not block.get("path"):
            return
        try:
            entry = AmcacheEntry(
                path=block["path"][:1024],
                sha1=block.get("sha1"),
                first_run=block.get("first_run"),
                publisher=(block.get("publisher") or "")[:512] or None,
                product_name=(block.get("product_name") or "")[:512] or None,
            )
            data.append(entry.model_dump())
        except (ValueError, TypeError):
            pass

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            _flush()
            block = {}
            continue
        if (m := _AMCACHE_PATH.match(line)):
            _flush()
            block = {"path": m.group(1).strip()}
        elif (m := _AMCACHE_SHA1.match(line)):
            block["sha1"] = m.group(1).lower()
        elif (m := _AMCACHE_LASTMOD.match(line)):
            block["first_run"] = m.group(1).strip()
        elif (m := _AMCACHE_PUB.match(line)):
            block["publisher"] = m.group(1).strip()
        elif (m := _AMCACHE_PROD.match(line)):
            block["product_name"] = m.group(1).strip()
    _flush()

    return ToolResponse(
        tool="regripper.amcache",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ----------------------------------------------------------------- run --


def run(case_id: str, ntuser_or_software_hive: str) -> ToolResponse:
    """Parse Run/RunOnce persistence keys."""
    args = {"case_id": case_id, "hive": ntuser_or_software_hive}
    rc, stdout, stderr, elapsed = _rip(case_id, ntuser_or_software_hive, "run")
    cav, hints = caveats_for("regripper.run")
    if rc != 0:
        return empty_response("regripper.run", args, stderr.strip(), elapsed)

    data: list[dict[str, Any]] = []
    current_key = ""
    last_write = None
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("Microsoft\\Windows\\CurrentVersion\\Run") or "Run" in line and "->" not in line and ":" not in line:
            current_key = line.strip()
            continue
        if "LastWrite" in line:
            last_write = line.split("LastWrite", 1)[1].strip(" :;-")
            continue
        if " -> " in line:
            name, _, value = line.partition(" -> ")
            try:
                entry = RegistryEntry(
                    plugin="run",
                    key_path=current_key or "Run",
                    value_name=name.strip()[:256],
                    value_data=value.strip()[:8192],
                    last_write=last_write,
                )
                data.append(entry.model_dump())
            except (ValueError, TypeError):
                continue

    return ToolResponse(
        tool="regripper.run",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )


# ------------------------------------------------------------- services --


def services(case_id: str, system_hive: str) -> ToolResponse:
    """Parse Services persistence (T1543.003)."""
    args = {"case_id": case_id, "system_hive": system_hive}
    rc, stdout, stderr, elapsed = _rip(case_id, system_hive, "services")
    cav, hints = caveats_for("regripper.services")
    if rc != 0:
        return empty_response("regripper.services", args, stderr.strip(), elapsed)

    data: list[dict[str, Any]] = []
    block: dict[str, Any] = {}

    def _flush() -> None:
        if not block.get("name"):
            return
        try:
            entry = RegistryEntry(
                plugin="services",
                key_path=fr"SYSTEM\ControlSet001\Services\{block['name']}",
                value_name=block.get("display_name") or block["name"],
                value_data=(block.get("image_path") or "")[:8192],
                last_write=block.get("last_write"),
            )
            data.append(entry.model_dump())
        except (ValueError, TypeError):
            pass

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            _flush()
            block = {}
            continue
        if line.lower().startswith("name"):
            _flush()
            block = {"name": line.split(":", 1)[-1].strip()}
        elif line.lower().startswith("display"):
            block["display_name"] = line.split(":", 1)[-1].strip()
        elif line.lower().startswith("imagepath") or line.lower().startswith("image path"):
            block["image_path"] = line.split(":", 1)[-1].strip()
        elif line.lower().startswith("lastwrite") or "last write" in line.lower():
            block["last_write"] = line.split(":", 1)[-1].strip()
    _flush()

    return ToolResponse(
        tool="regripper.services",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
    )
