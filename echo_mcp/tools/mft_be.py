"""
MFT parsing + bulk_extractor IOC extraction.

DFIR background:
    The Master File Table (MFT) is NTFS's record of every file on disk,
    including deleted ones. Each record carries TWO sets of timestamps:
    Standard Information ($SI, user-modifiable, used by Windows Explorer)
    and Filename ($FN, kernel-controlled, harder to forge). Discrepancies
    between $SI and $FN are timestomping evidence (T1070.006).

    bulk_extractor is a high-throughput tool that scans raw bytes for
    candidate IOCs (IPs, emails, URLs, hashes, credit cards) without
    touching filesystem metadata.
"""
from __future__ import annotations

import csv
import re
import time
from pathlib import Path
from typing import Any

from echo_mcp.knowledge import caveats_for
from echo_mcp.schemas import IOC, IOCType, MFTRecord, ToolResponse
from echo_mcp.tools._common import (
    DEFAULT_TIMEOUT_S,
    empty_response,
    resolve_evidence_path,
    run_subprocess,
)

MFT_TIMEOUT_S = max(DEFAULT_TIMEOUT_S, 300)
BE_TIMEOUT_S = max(DEFAULT_TIMEOUT_S, 600)


# ----------------------------------------------------------- mft_parse --


def mft_parse(case_id: str, mft_relpath: str, max_records: int = 5000) -> ToolResponse:
    """Parse $MFT using analyzeMFT.py (SIFT default).

    Output is CSV; we map the rows we care about into MFTRecord objects.
    """
    args = {"case_id": case_id, "mft_relpath": mft_relpath, "max_records": max_records}
    cav, hints = caveats_for("mft_parse")
    start = time.perf_counter()

    try:
        mft_path = resolve_evidence_path(case_id, mft_relpath)
    except Exception as e:  # noqa: BLE001
        return empty_response("mft_parse", args, str(e))

    out_csv = Path("/tmp") / f"echo_mft_{case_id}_{int(time.time())}.csv"
    argv = ["analyzeMFT.py", "-f", str(mft_path), "-o", str(out_csv)]

    try:
        rc, _stdout, stderr, elapsed = run_subprocess(argv, timeout=MFT_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001
        return empty_response("mft_parse", args, f"analyzeMFT failed to start: {e}")

    if rc != 0 or not out_csv.exists():
        return empty_response("mft_parse", args, stderr.strip() or "analyzeMFT produced no output", elapsed)

    data: list[dict[str, Any]] = []
    truncated = False

    try:
        with out_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if len(data) >= max_records:
                    truncated = True
                    break
                try:
                    rec = MFTRecord(
                        record_number=int(row.get("Record Number") or row.get("RecordNum") or 0),
                        flags=[s.strip() for s in (row.get("Flags") or "").split("|") if s.strip()][:8],
                        full_path=(row.get("Filename #1") or row.get("Path") or "")[:2048] or None,
                        file_size=int(row["FileSize"]) if row.get("FileSize", "").isdigit() else None,
                        created=row.get("Std Info Creation date") or row.get("Created") or None,
                        modified=row.get("Std Info Modification date") or row.get("Modified") or None,
                        accessed=row.get("Std Info Access date") or row.get("Accessed") or None,
                        mft_modified=row.get("Std Info Entry date") or None,
                    )
                    data.append(rec.model_dump())
                except (ValueError, TypeError, KeyError):
                    continue
    finally:
        try:
            out_csv.unlink(missing_ok=True)
        except OSError:
            pass

    return ToolResponse(
        tool="mft_parse",
        args=args,
        data=data,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=time.perf_counter() - start,
        truncated=truncated,
    )


# ----------------------------------------------------- bulk_extractor_run --


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")


def _classify_ioc(value: str) -> IOCType | None:
    if _IPV4_RE.match(value):
        return IOCType.IPV4
    if ":" in value and value.count(":") >= 2:
        return IOCType.IPV6
    if _SHA256_RE.match(value):
        return IOCType.SHA256
    if _SHA1_RE.match(value):
        return IOCType.SHA1
    if _MD5_RE.match(value):
        return IOCType.MD5
    if _DOMAIN_RE.match(value):
        return IOCType.DOMAIN
    if value.startswith(("http://", "https://")):
        return IOCType.URL
    if "@" in value and "." in value.split("@", 1)[-1]:
        return IOCType.EMAIL
    return None


def bulk_extractor_run(
    case_id: str,
    image_relpath: str,
    max_iocs: int = 2000,
) -> ToolResponse:
    """Run bulk_extractor on a disk/memory image and harvest IOC candidates."""
    args = {"case_id": case_id, "image_relpath": image_relpath, "max_iocs": max_iocs}
    cav, hints = caveats_for("bulk_extractor_run")
    start = time.perf_counter()

    try:
        img = resolve_evidence_path(case_id, image_relpath)
    except Exception as e:  # noqa: BLE001
        return empty_response("bulk_extractor_run", args, str(e))

    out_dir = Path("/tmp") / f"echo_be_{case_id}_{int(time.time())}"
    out_dir.mkdir(parents=True, exist_ok=True)

    argv = ["bulk_extractor", "-q", "-o", str(out_dir), str(img)]
    try:
        rc, _stdout, stderr, elapsed = run_subprocess(argv, timeout=BE_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001
        return empty_response("bulk_extractor_run", args, f"bulk_extractor failed: {e}")

    if rc != 0:
        return empty_response("bulk_extractor_run", args, stderr.strip() or "bulk_extractor returned non-zero", elapsed)

    iocs: list[dict[str, Any]] = []
    sources_to_scan = {
        "ip.txt": IOCType.IPV4,
        "domain.txt": IOCType.DOMAIN,
        "url.txt": IOCType.URL,
        "email.txt": IOCType.EMAIL,
    }

    for fname, default_type in sources_to_scan.items():
        f = out_dir / fname
        if not f.exists():
            continue
        with f.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if len(iocs) >= max_iocs:
                    break
                # bulk_extractor format: "offset\tvalue\t..."
                parts = line.strip().split("\t")
                if len(parts) < 2:
                    continue
                value = parts[1].strip()
                if not value or value.startswith("#"):
                    continue
                t = _classify_ioc(value) or default_type
                try:
                    ioc = IOC(
                        type=t,
                        value=value,
                        first_seen_in="bulk_extractor",
                        context=f"offset={parts[0]}",
                    )
                    iocs.append(ioc.model_dump())
                except (ValueError, TypeError):
                    continue
        if len(iocs) >= max_iocs:
            break

    # cleanup output dir
    try:
        for f in out_dir.iterdir():
            f.unlink(missing_ok=True)
        out_dir.rmdir()
    except OSError:
        pass

    return ToolResponse(
        tool="bulk_extractor_run",
        args=args,
        data=iocs,
        caveats=cav,
        cross_check_hints=hints,
        runtime_seconds=time.perf_counter() - start,
        truncated=len(iocs) >= max_iocs,
    )
