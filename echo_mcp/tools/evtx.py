"""
Windows Event Log parser using python-evtx.

DFIR background:
    Windows event logs (.evtx) are the canonical record of OS-level
    activity. The IDs ECHO cares about (and why):
        4624 — Successful logon (lateral movement evidence)
        4625 — Failed logon (brute-force / spray)
        4648 — Logon with explicit credentials (runas / pass-the-hash)
        4672 — Special privileges assigned (admin equivalent)
        4688 — Process creation (with cmdline if auditing enabled)
        4697 — Service installed via SCM
        4698 — Scheduled task created
        7045 — System service installed (T1543.003)
        1102 — Audit log cleared (T1070.001)
        4104 — PowerShell ScriptBlock logging
        5861 — WMI permanent event subscription (T1546.003)

We use python-evtx (pure Python) because EvtxECmd is .NET-only and may
not be present on every SIFT image.
"""
from __future__ import annotations

import re
from typing import Optional
from xml.etree import ElementTree as ET

from echo_mcp.knowledge import caveats_for
from echo_mcp.schemas import EventLogEntry, ToolResponse
from echo_mcp.tools._common import empty_response, resolve_evidence_path

INTERESTING_IDS = {
    1102, 4104, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 5861, 7045,
}

# python-evtx XML uses this namespace.
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _strip_ns(elem: ET.Element) -> ET.Element:
    """Remove namespace prefixes for easier XPath."""
    for el in elem.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return elem


def evtx_parse(
    case_id: str,
    evtx_relpath: str,
    event_ids: Optional[list[int]] = None,
    max_records: int = 5000,
) -> ToolResponse:
    """Stream-parse an .evtx file and emit EventLogEntry rows."""
    args = {
        "case_id": case_id,
        "evtx_relpath": evtx_relpath,
        "event_ids": event_ids,
        "max_records": max_records,
    }
    cav, hints = caveats_for("evtx_parse")

    try:
        path = resolve_evidence_path(case_id, evtx_relpath)
    except Exception as e:  # noqa: BLE001 — we want this in the response
        return empty_response("evtx_parse", args, str(e))

    try:
        # Lazy import — python-evtx is a heavy module.
        from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
    except ImportError:
        return empty_response(
            "evtx_parse", args,
            "python-evtx not installed. Run: pip install python-evtx",
        )

    wanted = set(event_ids) if event_ids else INTERESTING_IDS
    data: list[dict] = []
    truncated = False

    import time
    start = time.perf_counter()

    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                if len(data) >= max_records:
                    truncated = True
                    break
                try:
                    xml = record.xml()
                    root = _strip_ns(ET.fromstring(xml))
                    sys_el = root.find("System")
                    if sys_el is None:
                        continue
                    eid_el = sys_el.find("EventID")
                    if eid_el is None or eid_el.text is None:
                        continue
                    eid = int(eid_el.text.strip())
                    if eid not in wanted:
                        continue

                    chan_el = sys_el.find("Channel")
                    prov_el = sys_el.find("Provider")
                    tc_el = sys_el.find("TimeCreated")
                    rec_id_el = sys_el.find("EventRecordID")
                    comp_el = sys_el.find("Computer")

                    # message: collect EventData/Data values
                    data_el = root.find("EventData")
                    raw: dict[str, str] = {}
                    if data_el is not None:
                        for d in data_el.findall("Data"):
                            name = d.get("Name", "Data")
                            raw[name] = (d.text or "")[:2048]

                    user = raw.get("TargetUserName") or raw.get("SubjectUserName")
                    msg_parts = [f"{k}={v}" for k, v in list(raw.items())[:8]]
                    message = "; ".join(msg_parts)[:8192] or None

                    entry = EventLogEntry(
                        event_id=eid,
                        channel=(chan_el.text or "Unknown")[:128] if chan_el is not None else "Unknown",
                        timestamp=(tc_el.get("SystemTime", "") if tc_el is not None else "")[:64],
                        provider=(prov_el.get("Name") if prov_el is not None else None),
                        record_id=int(rec_id_el.text) if rec_id_el is not None and rec_id_el.text else None,
                        user=user,
                        computer=(comp_el.text if comp_el is not None else None),
                        message=message,
                        raw=raw or None,
                    )
                    data.append(entry.model_dump())
                except (ET.ParseError, ValueError, TypeError):
                    continue
    except Exception as e:  # noqa: BLE001
        return empty_response("evtx_parse", args, f"evtx parse error: {e}", time.perf_counter() - start)

    elapsed = time.perf_counter() - start
    return ToolResponse(
        tool="evtx_parse",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=elapsed,
        truncated=truncated,
    )
