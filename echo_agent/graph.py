"""
LangGraph V2 — full cyclic graph with critic + reflector + finalizer.

GRAPH SHAPE:

    [start] → planner → executor → validator
                                       │
                          ┌────────────┴────────────┐
                          ▼                         ▼
                    needs_revision?            no contradictions
                          │                         │
                          ▼                         ▼
                       critic                   reflector
                          │                         │
                          ▼                         ▼
                       reflector                 next_or_finalize?
                          │                         │
                          ▼                         ▼
                    next_or_finalize?           planner / finalizer
                          │
                          ▼
                  planner (loop) / finalizer / END

Termination is enforced by THREE caps (any one trips → finalize):
    - state.iter >= state.max_iter
    - state.tokens_used >= state.budget_tokens
    - wall-clock seconds since start > state.wall_clock_max_seconds

Plus an absolute graph-level recursion_limit on the LangGraph compile()
for last-resort guard.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langgraph.graph import END, StateGraph

from echo_agent.audit import AuditLogger
from echo_agent.nodes import (
    critic_node,
    executor_node,
    finalizer_node,
    planner_node,
    reflector_node,
    validator_node,
)
from echo_mcp.schemas import EchoState, Phase, ToolResponse

log = logging.getLogger("echo.graph")


def build_graph(
    case_outdir: Path,
    audit_log_path: Path,
    tool_cache: dict[str, ToolResponse] | None = None,
):
    """Build and compile the ECHO LangGraph.

    `tool_cache` is shared across nodes by closure — LangGraph state must
    be Pydantic-serialisable, and ToolResponse with its data list isn't a
    great fit to round-trip in state on every transition. We keep it
    in-process.
    """
    cache: dict[str, ToolResponse] = tool_cache if tool_cache is not None else {}
    audit = AuditLogger(audit_log_path, case_id="placeholder")
    started_wall = time.perf_counter()

    g: StateGraph = StateGraph(EchoState)

    # ----- node wrappers that update the audit chain on entry/exit ---------

    def _logged_planner(state: EchoState) -> EchoState:
        audit.case_id = state.case_id
        before = state.model_dump()
        state = planner_node(state)
        audit.append(
            node="planner", phase=state.phase,
            input_obj=before, output_obj=state.model_dump(),
            tokens_used=state.tokens_used,
        )
        state.iter += 1  # iter counts each planner invocation
        return state

    def _logged_executor(state: EchoState) -> EchoState:
        before = state.model_dump()
        state = executor_node(state, cache)
        audit.append(
            node="executor", phase=state.phase,
            input_obj=before, output_obj=state.model_dump(),
            tool_call=state.last_tool_call,
            tool_result_summary=(
                {"rows": len(state.last_tool_output.data),
                 "tool": state.last_tool_output.tool,
                 "error": state.last_tool_output.error}
                if state.last_tool_output else None
            ),
            tokens_used=state.tokens_used,
        )
        return state

    def _logged_validator(state: EchoState) -> EchoState:
        before = state.model_dump()
        state = validator_node(state, cache)
        audit.append(
            node="validator", phase=state.phase,
            input_obj=before, output_obj=state.model_dump(),
            validator_result={
                "contradictions": [c.rule_id for c in state.contradictions],
                "needs_revision": state.needs_revision,
            },
        )
        return state

    def _logged_critic(state: EchoState) -> EchoState:
        before = state.model_dump()
        state = critic_node(state, cache)
        audit.append(
            node="critic", phase=state.phase,
            input_obj=before, output_obj=state.model_dump(),
            tool_call=state.last_tool_call,
            tokens_used=state.tokens_used,
        )
        return state

    def _logged_reflector(state: EchoState) -> EchoState:
        before = state.model_dump()
        state = reflector_node(state)
        audit.append(
            node="reflector", phase=state.phase,
            input_obj=before, output_obj=state.model_dump(),
            tokens_used=state.tokens_used,
        )
        return state

    def _logged_finalizer(state: EchoState) -> EchoState:
        before = state.model_dump()
        state = finalizer_node(state, cache, case_outdir, audit_log_path)
        produced_ids = ",".join(f.id for f in state.findings) or None
        audit.append(
            node="finalizer", phase=Phase.FINALIZE,
            input_obj=before, output_obj=state.model_dump(),
            tokens_used=state.tokens_used,
            produced_finding_id=produced_ids,
        )
        return state

    # ---- nodes ----
    g.add_node("planner", _logged_planner)
    g.add_node("executor", _logged_executor)
    g.add_node("validator", _logged_validator)
    g.add_node("critic", _logged_critic)
    g.add_node("reflector", _logged_reflector)
    g.add_node("finalizer", _logged_finalizer)

    g.set_entry_point("planner")

    # ---- conditional routing ----
    def _after_planner(state: EchoState) -> str:
        if state.phase == Phase.FINALIZE:
            return "finalizer"
        if _budget_tripped(state, started_wall):
            state.halt_reason = "budget_or_wallclock_exceeded"
            return "finalizer"
        return "executor"

    def _after_validator(state: EchoState) -> str:
        if _budget_tripped(state, started_wall):
            state.halt_reason = "budget_or_wallclock_exceeded"
            return "finalizer"
        if state.needs_revision:
            return "critic"
        return "reflector"

    def _after_reflector(state: EchoState) -> str:
        if state.iter >= state.max_iter or _budget_tripped(state, started_wall):
            return "finalizer"
        return "planner"

    g.add_conditional_edges("planner", _after_planner,
                            {"executor": "executor", "finalizer": "finalizer"})
    g.add_edge("executor", "validator")
    g.add_conditional_edges("validator", _after_validator,
                            {"critic": "critic", "reflector": "reflector",
                             "finalizer": "finalizer"})
    g.add_edge("critic", "reflector")
    g.add_conditional_edges("reflector", _after_reflector,
                            {"planner": "planner", "finalizer": "finalizer"})
    g.add_edge("finalizer", END)

    # 6 nodes × max_iter + slack = safe upper bound
    return g.compile()


def _budget_tripped(state: EchoState, started_wall: float) -> bool:
    if state.tokens_used >= state.budget_tokens:
        log.warning("budget: tokens exhausted (%d/%d)", state.tokens_used, state.budget_tokens)
        return True
    elapsed = time.perf_counter() - started_wall
    if elapsed >= state.wall_clock_max_seconds:
        log.warning("budget: wall-clock exceeded (%.1fs / %ds)",
                    elapsed, state.wall_clock_max_seconds)
        return True
    return False


def run_case(
    case_id: str,
    case_outdir: Path,
    audit_log_path: Path,
    *,
    max_iter: int = 8,
    budget_tokens: int = 60_000,
    wall_clock_max_seconds: int = 900,
) -> EchoState:
    """End-to-end driver. Build graph, run case, return final state."""
    init_state = EchoState(
        case_id=case_id,
        max_iter=max_iter,
        budget_tokens=budget_tokens,
        wall_clock_max_seconds=wall_clock_max_seconds,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    graph = build_graph(case_outdir=case_outdir, audit_log_path=audit_log_path)
    final = graph.invoke(init_state, config={"recursion_limit": max_iter * 8 + 10})
    if isinstance(final, dict):
        final = EchoState(**final)
    return final
