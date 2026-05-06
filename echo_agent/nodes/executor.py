"""
Executor node — picks ONE tool from the phase-allowed subset and runs it.

The LLM here is constrained two ways:
    1. The schema only allows a tool name from the phase's allowlist.
    2. The args dict is validated against the tool's expected keys.

If the LLM picks an out-of-phase tool, we override and pick the
phase-default. We never let the agent freely roam the tool space.
"""
from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from echo_agent.llm import chat_json
from echo_mcp.schemas import EchoState, Phase, ToolResponse
from echo_mcp.tools import PHASE_TOOL_MAP, TOOL_REGISTRY

log = logging.getLogger("echo.executor")


class ExecutorOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=1, max_length=512)


EXECUTOR_SYSTEM = """\
You are the tool-selection node inside ECHO, an autonomous DFIR agent.
For the current investigation phase, choose EXACTLY ONE forensic tool
to execute. Provide its arguments.

CONSTRAINTS:
- You may pick ONLY from the allowed tool list provided.
- args must use the exact parameter names listed for that tool.
- All paths in args are RELATIVE to the case directory; no leading slash.
- Defaults you may use:
    case_id        — provided in the prompt; copy it exactly
    memory_image   — "memory.raw"        (unless prompt overrides)
    system_hive    — "Windows/System32/config/SYSTEM"
    amcache_hive   — "Windows/AppCompat/Programs/Amcache.hve"
    hive (run)     — "Users/Default/NTUSER.DAT" or
                     "Windows/System32/config/SOFTWARE"
    evtx_relpath   — "Windows/System32/winevt/Logs/Security.evtx"
    mft_relpath    — "$MFT"
    prefetch_dir   — "Windows/Prefetch"
    image_relpath  — "memory.raw"

OUTPUT: ONE JSON object: {tool, args, rationale}. No prose.
"""


def _allowed_for_phase(phase: Phase) -> list[str]:
    return PHASE_TOOL_MAP.get(phase.value, [])


def _phase_default(phase: Phase, case_id: str) -> tuple[str, dict[str, Any]]:
    """Return a sensible default tool+args for a phase if the LLM misfires."""
    defaults: dict[Phase, tuple[str, dict[str, Any]]] = {
        Phase.TRIAGE:   ("windows.pslist", {"case_id": case_id, "memory_image": "memory.raw"}),
        Phase.MEMORY:   ("windows.malfind", {"case_id": case_id, "memory_image": "memory.raw"}),
        Phase.NETWORK:  ("windows.netscan", {"case_id": case_id, "memory_image": "memory.raw"}),
        Phase.REGISTRY: ("regripper.amcache",
                         {"case_id": case_id,
                          "amcache_hive": "Windows/AppCompat/Programs/Amcache.hve"}),
        Phase.EVENTS:   ("evtx_parse",
                         {"case_id": case_id,
                          "evtx_relpath": "Windows/System32/winevt/Logs/Security.evtx"}),
        Phase.DISK:     ("prefetch_parse",
                         {"case_id": case_id, "prefetch_dir": "Windows/Prefetch"}),
        Phase.FINALIZE: ("", {}),
    }
    return defaults.get(phase, ("", {}))


def executor_node(state: EchoState, tool_cache: dict[str, ToolResponse]) -> EchoState:
    """Pick + run one tool. Mutates state.last_tool_call, state.last_tool_output."""
    phase = state.phase
    if phase == Phase.FINALIZE:
        return state

    allowed = _allowed_for_phase(phase)
    if not allowed:
        log.warning("executor: phase %s has no allowed tools, skipping", phase.value)
        return state

    user_msg = (
        f"case_id: {state.case_id}\n"
        f"phase: {phase.value}\n"
        f"iter: {state.iter}\n"
        f"allowed_tools: {allowed}\n"
        "Pick exactly one tool and provide args."
    )

    chosen_tool = ""
    chosen_args: dict[str, Any] = {}
    try:
        out, tokens = chat_json(
            schema=ExecutorOutput,
            system=EXECUTOR_SYSTEM,
            user=user_msg,
            num_predict=384,
        )
        state.tokens_used += tokens
        if out.tool in allowed:
            chosen_tool, chosen_args = out.tool, out.args
        else:
            log.warning("executor: LLM picked %r outside allowlist; using default", out.tool)
    except Exception as e:  # noqa: BLE001
        log.warning("executor: LLM failure (%s); using default", e)

    if not chosen_tool:
        chosen_tool, chosen_args = _phase_default(phase, state.case_id)

    if not chosen_tool:
        return state

    # Always inject case_id (LLM sometimes forgets)
    chosen_args.setdefault("case_id", state.case_id)

    log.info("executor: → %s args=%s", chosen_tool, chosen_args)
    fn = TOOL_REGISTRY[chosen_tool]
    try:
        resp: ToolResponse = fn(**chosen_args)
    except TypeError as e:
        # signature mismatch — fall back to default
        log.warning("executor: arg mismatch for %s (%s); falling back", chosen_tool, e)
        chosen_tool, chosen_args = _phase_default(phase, state.case_id)
        if chosen_tool:
            resp = TOOL_REGISTRY[chosen_tool](**chosen_args)
        else:
            return state
    except Exception as e:  # noqa: BLE001
        log.error("executor: tool %s raised: %s", chosen_tool, e)
        return state

    state.last_tool_call = {"tool": chosen_tool, "args": chosen_args}
    state.last_tool_output = resp
    tool_cache[chosen_tool] = resp
    return state
