"""
ECHO core schemas — Pydantic v2 data contracts.

WHY THIS FILE MATTERS (read before editing):
Every tool output, every finding, every audit-chain entry passes through these
models. They are the wall between the LLM (which can hallucinate strings) and
the rest of the system (which must trust its inputs). Pydantic validates types
and ranges at every boundary, so a malformed LLM response never leaks past the
executor node.

Pydantic v2 syntax only: model_validator / field_validator / ConfigDict.
DO NOT use v1 root_validator/validator — they silently break on v2.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# -------------------------------------------------------------------- ENUMS --


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence labels — DETERMINISTIC, computed from score, never LLM-assigned."""

    HIGH = "high"        # score >= 0.75
    MEDIUM = "medium"    # 0.45 <= score < 0.75
    LOW = "low"          # score < 0.45


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    EMAIL = "email"
    USER_ACCOUNT = "user_account"


class Phase(str, Enum):
    TRIAGE = "triage"
    MEMORY = "memory"
    DISK = "disk"
    REGISTRY = "registry"
    NETWORK = "network"
    EVENTS = "events"
    FINALIZE = "finalize"


# ---------------------------------------------------------- FORENSIC RECORDS --


class ProcessRecord(BaseModel):
    """One process row from Volatility 3 windows.pslist or windows.psscan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(ge=0, le=2**31 - 1)
    ppid: int = Field(ge=0, le=2**31 - 1)
    name: str = Field(min_length=1, max_length=260)
    create_time: Optional[str] = None
    exit_time: Optional[str] = None
    threads: Optional[int] = Field(default=None, ge=0)
    handles: Optional[int] = Field(default=None, ge=0)
    image_path: Optional[str] = Field(default=None, max_length=1024)
    cmdline: Optional[str] = Field(default=None, max_length=8192)
    source_plugin: Literal["pslist", "psscan", "pstree"]


class NetworkConnection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(ge=0)
    owner: Optional[str] = None
    proto: Literal["TCPv4", "TCPv6", "UDPv4", "UDPv6"]
    local_addr: str = Field(max_length=64)
    local_port: int = Field(ge=0, le=65535)
    foreign_addr: Optional[str] = Field(default=None, max_length=64)
    foreign_port: Optional[int] = Field(default=None, ge=0, le=65535)
    state: Optional[str] = Field(default=None, max_length=32)
    created: Optional[str] = None


class EventLogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: int = Field(ge=0, le=65535)
    channel: str = Field(max_length=128)
    timestamp: str
    provider: Optional[str] = Field(default=None, max_length=256)
    record_id: Optional[int] = Field(default=None, ge=0)
    user: Optional[str] = Field(default=None, max_length=256)
    computer: Optional[str] = Field(default=None, max_length=256)
    message: Optional[str] = Field(default=None, max_length=16384)
    raw: Optional[dict[str, Any]] = None


class AmcacheEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=1024)
    sha1: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{40}$")
    file_size: Optional[int] = Field(default=None, ge=0)
    first_run: Optional[str] = None
    publisher: Optional[str] = Field(default=None, max_length=512)
    product_name: Optional[str] = Field(default=None, max_length=512)


class PrefetchEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    executable_name: str = Field(min_length=1, max_length=260)
    executable_path: Optional[str] = Field(default=None, max_length=1024)
    run_count: Optional[int] = Field(default=None, ge=0)
    last_run_times: list[str] = Field(default_factory=list, max_length=8)
    sha256: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


class MFTRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_number: int = Field(ge=0)
    flags: list[str] = Field(default_factory=list)
    full_path: Optional[str] = Field(default=None, max_length=2048)
    file_size: Optional[int] = Field(default=None, ge=0)
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    mft_modified: Optional[str] = None


class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plugin: str = Field(min_length=1, max_length=64)
    key_path: str = Field(min_length=1, max_length=1024)
    value_name: Optional[str] = Field(default=None, max_length=256)
    value_data: Optional[str] = Field(default=None, max_length=8192)
    last_write: Optional[str] = None


class IOC(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: IOCType
    value: str = Field(min_length=1, max_length=2048)
    context: Optional[str] = Field(default=None, max_length=1024)
    first_seen_in: Optional[str] = Field(default=None, max_length=64)

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip()


# ----------------------------------------------------------- TOOL ENVELOPES --


class ToolCaveat(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Severity
    text: str = Field(min_length=1, max_length=2048)


class CrossCheckHint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hint: str = Field(min_length=1, max_length=512)
    suggested_tool: str = Field(min_length=1, max_length=64)


class ToolResponse(BaseModel):
    """The standard envelope every MCP tool returns."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    data: list[dict[str, Any]] = Field(default_factory=list)
    caveats: list[ToolCaveat] = Field(default_factory=list)
    cross_check_hints: list[CrossCheckHint] = Field(default_factory=list)
    runtime_seconds: float = Field(ge=0)
    truncated: bool = False
    error: Optional[str] = Field(default=None, max_length=2048)


# ------------------------------------------------------ FINDINGS / FINALIZER --


class Contradiction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=r"^R\d{2}$")
    rule_name: str = Field(min_length=1, max_length=128)
    severity: Severity
    description: str = Field(min_length=1, max_length=2048)
    sources: list[str] = Field(min_length=2, max_length=8)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    detected_at_iter: int = Field(ge=0)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^F-[A-Z0-9_]{1,32}-\d{3}$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=8192)
    confidence: Confidence
    score: float = Field(ge=0.0, le=1.0)
    mitre_technique_ids: list[str] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    produced_by_iter: int = Field(ge=0)
    tool_calls_used: list[str] = Field(default_factory=list, max_length=64)
    sources: list[str] = Field(default_factory=list, max_length=16)
    status: Literal["confirmed", "low_confidence", "requires_human_review"]
    contradictions_resolved: list[str] = Field(default_factory=list)
    audit_chain_refs: list[str] = Field(default_factory=list)

    @field_validator("mitre_technique_ids")
    @classmethod
    def validate_mitre(cls, v: list[str]) -> list[str]:
        for tid in v:
            if not (tid.startswith("T") and len(tid) >= 5 and tid[1:5].isdigit()):
                raise ValueError(f"Invalid MITRE technique id: {tid}")
        return v

    @model_validator(mode="after")
    def status_matches_confidence(self) -> "Finding":
        if self.confidence == Confidence.LOW and self.status == "confirmed":
            raise ValueError("Cannot mark low-confidence finding as confirmed.")
        return self


# ---------------------------------------------------------- AGENT STATE LOG --


class ChainEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iter: int = Field(ge=0)
    ts: str
    case_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    node: Literal["planner", "executor", "validator", "critic", "reflector", "finalizer"]
    phase: Phase
    input_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool_call: Optional[dict[str, Any]] = None
    tool_result_summary: Optional[dict[str, Any]] = None
    validator_result: Optional[dict[str, Any]] = None
    tokens_used: int = Field(default=0, ge=0)
    produced_finding_id: Optional[str] = None
    prev_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    this_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReflectionEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    iter: int = Field(ge=0)
    ts: str
    trigger: str = Field(min_length=1, max_length=512)
    lesson: str = Field(min_length=1, max_length=2048)
    next_hint: str = Field(min_length=1, max_length=2048)


class EchoState(BaseModel):
    model_config = ConfigDict()

    case_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    phase: Phase = Phase.TRIAGE
    iter: int = 0
    max_iter: int = Field(default=8, ge=1, le=32)
    budget_tokens: int = Field(default=60_000, ge=1_000)
    tokens_used: int = 0
    wall_clock_max_seconds: int = Field(default=900, ge=30)
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    plan: list[str] = Field(default_factory=list)
    last_tool_call: Optional[dict[str, Any]] = None
    last_tool_output: Optional[ToolResponse] = None
    findings: list[Finding] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    reflection_memory: list[ReflectionEntry] = Field(default_factory=list)
    needs_revision: bool = False
    halt_reason: Optional[str] = None

    def budget_exhausted(self) -> bool:
        return self.tokens_used >= self.budget_tokens or self.iter >= self.max_iter


# --------------------------------------------------------------- HELPERS ----


def canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON for hashing.
    Floats are rounded to 6 decimal places to ensure cross-platform
    reproducibility — orjson uses shortest-round-trip representation
    which can differ across Python versions and CPU architectures.
    """
    import orjson

    def _normalize(o: Any) -> Any:
        if isinstance(o, float):
            return round(o, 6)
        if isinstance(o, dict):
            return {k: _normalize(v) for k, v in o.items()}
        if isinstance(o, list):
            return [_normalize(i) for i in o]
        return o

    return orjson.dumps(_normalize(obj), option=orjson.OPT_SORT_KEYS)


def sha256_of(obj: Any) -> str:
    """SHA-256 hex of the canonical JSON encoding of an object."""
    return hashlib.sha256(canonical_json(obj)).hexdigest()
