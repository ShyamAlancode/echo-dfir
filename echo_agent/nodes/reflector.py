"""
Reflector node — writes a one-line lesson to reflection_memory.

This is the GhostByte V2 Reflection Memory pattern, ported. After every
non-trivial iteration, the reflector summarises:
    trigger    — what surprised us this iter
    lesson     — what we learned
    next_hint  — what the planner should consider next iter

Reflection memory persists for the duration of THIS case and is fed
back into the planner. Across cases it is reset.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from echo_agent.llm import chat_json
from echo_mcp.schemas import EchoState, ReflectionEntry

log = logging.getLogger("echo.reflector")


class ReflectorOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger: str = Field(min_length=1, max_length=512)
    lesson: str = Field(min_length=1, max_length=1024)
    next_hint: str = Field(min_length=1, max_length=1024)


REFLECTOR_SYSTEM = """\
You are the reflector node inside ECHO. Your job is to write ONE
short structured lesson capturing what just happened. Future planner
iterations will read your output. Be concise and specific.

trigger:   what artifact or contradiction caused this reflection
lesson:    one sentence; what worked, what failed, what the data showed
next_hint: one sentence; concrete suggestion for next iteration

Output ONE JSON object. No prose.
"""


def reflector_node(state: EchoState) -> EchoState:
    """Append a reflection entry to state.reflection_memory."""
    if state.iter == 0:
        return state  # nothing to reflect on at iter 0

    last_call = state.last_tool_call or {}
    last_out = state.last_tool_output

    summary = (
        f"iter: {state.iter}\n"
        f"phase: {state.phase.value}\n"
        f"last_tool: {last_call.get('tool')}\n"
        f"last_output_size: {len(last_out.data) if last_out else 0} rows\n"
        f"contradictions_so_far: "
        f"{[c.rule_id for c in state.contradictions]}\n"
    )

    try:
        out, tokens = chat_json(
            schema=ReflectorOutput,
            system=REFLECTOR_SYSTEM,
            user=summary,
            num_predict=384,
            temperature=0.3,
        )
        state.tokens_used += tokens
    except Exception as e:  # noqa: BLE001
        log.warning("reflector LLM failure: %s", e)
        return state

    entry = ReflectionEntry(
        iter=state.iter,
        ts=datetime.now(timezone.utc).isoformat(),
        trigger=out.trigger,
        lesson=out.lesson,
        next_hint=out.next_hint,
    )
    state.reflection_memory.append(entry)
    log.info("reflector: lesson=%s | next_hint=%s", out.lesson[:80], out.next_hint[:80])
    return state
