"""
SHA-256 Merkle-chained append-only audit log.

Every finding ECHO produces must trace back to the exact tool call that
produced it. The hackathon judges this directly (Audit Trail Quality).
A flat log is not enough — without chaining, a tampered entry is invisible.

DESIGN:
- iterations.jsonl is append-only, one ChainEntry per line.
- this_hash = sha256(canonical_json(entry without this_hash) || prev_hash)
- prev_hash of entry N = this_hash of entry N-1.
- Genesis entry uses GENESIS_PREV_HASH (all zeros).
- verify_chain() walks the file and recomputes every hash. One byte
  changed = chain breaks = tampering detected.

This pattern is lifted directly from GhostByte V2's cryptographic sandbox.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import orjson

from echo_mcp.schemas import ChainEntry, Phase, canonical_json

GENESIS_PREV_HASH = "0" * 64


def _hash_for_chain(entry_dict: dict[str, Any], prev_hash: str) -> str:
    """Compute this_hash for an entry whose this_hash field is not yet set."""
    payload = canonical_json(entry_dict) + prev_hash.encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class AuditLogger:
    """Append-only, hash-chained iteration logger.

    OOP TEACHING NOTE:
    This is a class because each agent run owns one logger that holds
    state (the path of the active log + the latest hash in memory). A
    plain function would have to re-read the last line on every append.

    Usage:
        logger = AuditLogger(Path("audit/iterations.jsonl"), case_id="CASE_001")
        logger.append(node="planner", phase=Phase.TRIAGE, ...)
    """

    def __init__(self, log_path: Path, case_id: str) -> None:
        self.log_path = log_path
        self.case_id = case_id
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str = self._load_last_hash()
        self._iter_counter: int = self._load_last_iter() + 1

    def append(
        self,
        node: str,
        phase: Phase,
        input_obj: Any,
        output_obj: Any,
        tool_call: Optional[dict[str, Any]] = None,
        tool_result_summary: Optional[dict[str, Any]] = None,
        validator_result: Optional[dict[str, Any]] = None,
        tokens_used: int = 0,
        produced_finding_id: Optional[str] = None,
    ) -> ChainEntry:
        """Append one entry. Returns the validated ChainEntry."""
        ts = datetime.now(timezone.utc).isoformat()
        input_hash = hashlib.sha256(canonical_json(input_obj)).hexdigest()
        output_hash = hashlib.sha256(canonical_json(output_obj)).hexdigest()

        entry_dict = {
            "iter": self._iter_counter,
            "ts": ts,
            "case_id": self.case_id,
            "node": node,
            "phase": phase.value if isinstance(phase, Phase) else phase,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "tool_call": tool_call,
            "tool_result_summary": tool_result_summary,
            "validator_result": validator_result,
            "tokens_used": tokens_used,
            "produced_finding_id": produced_finding_id,
            "prev_hash": self._last_hash,
        }
        this_hash = _hash_for_chain(entry_dict, self._last_hash)
        entry_dict["this_hash"] = this_hash

        entry = ChainEntry(**entry_dict)

        with self.log_path.open("ab") as f:
            f.write(orjson.dumps(entry.model_dump()) + b"\n")
            f.flush()
            os.fsync(f.fileno())

        self._last_hash = this_hash
        self._iter_counter += 1
        return entry

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def next_iter(self) -> int:
        return self._iter_counter

    def _load_last_hash(self) -> str:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return GENESIS_PREV_HASH
        with self.log_path.open("rb") as f:
            last = b""
            for line in f:
                if line.strip():
                    last = line
            if not last:
                return GENESIS_PREV_HASH
            return orjson.loads(last)["this_hash"]

    def _load_last_iter(self) -> int:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return -1
        with self.log_path.open("rb") as f:
            last = b""
            for line in f:
                if line.strip():
                    last = line
            if not last:
                return -1
            return int(orjson.loads(last)["iter"])


class ChainVerificationError(Exception):
    """Raised when the Merkle chain does not verify."""


def verify_chain(log_path: Path) -> tuple[bool, str]:
    """Walk the chain and verify every hash. Return (ok, message)."""
    if not log_path.exists():
        return False, f"audit log not found at {log_path}"

    prev_hash = GENESIS_PREV_HASH
    line_no = 0

    with log_path.open("rb") as f:
        for raw in f:
            line_no += 1
            if not raw.strip():
                continue
            try:
                entry = orjson.loads(raw)
            except orjson.JSONDecodeError as e:
                return False, f"line {line_no}: malformed JSON ({e})"

            stored_this_hash = entry.get("this_hash")
            stored_prev_hash = entry.get("prev_hash")

            if stored_prev_hash != prev_hash:
                return (
                    False,
                    f"line {line_no}: prev_hash mismatch "
                    f"(expected {prev_hash[:12]}..., got {(stored_prev_hash or '')[:12]}...)",
                )

            entry_no_this = {k: v for k, v in entry.items() if k != "this_hash"}
            recomputed = _hash_for_chain(entry_no_this, prev_hash)

            if recomputed != stored_this_hash:
                return (
                    False,
                    f"line {line_no}: this_hash recomputation failed "
                    f"(stored {stored_this_hash[:12]}..., recomputed {recomputed[:12]}...)",
                )

            prev_hash = stored_this_hash

    return True, f"chain verified ({line_no} entries, head={prev_hash[:12]}...)"


def head_hash(log_path: Path) -> str:
    """Return the latest this_hash in the log, or GENESIS if empty."""
    if not log_path.exists() or log_path.stat().st_size == 0:
        return GENESIS_PREV_HASH
    with log_path.open("rb") as f:
        last = b""
        for line in f:
            if line.strip():
                last = line
        if not last:
            return GENESIS_PREV_HASH
        return orjson.loads(last)["this_hash"]
