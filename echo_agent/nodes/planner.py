"""
Planner node — decides which investigation phase to run next.

The planner has THREE inputs:
    - Current EchoState (phase, iter, findings so far, contradictions)
    - The reflection memory (lessons learned this case)
    - A fixed phase-progression policy

It outputs: PlannerOutput (next phase + rationale + budget hint).
"""
from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from echo_agent.llm import chat_json
from echo_mcp.schemas import EchoState, Phase

log = logging.getLogger("echo.planner")


class PlannerOutput(BaseModel):
    """Schema-constrained output of the planner LLM call."""

    model_config = ConfigDict(extra="forbid")

    next_phase: Literal["triage", "memory", "disk", "registry", "network", "events", "finalize"]
    rationale: str = Field(min_length=1, max_length=1024)
    expected_signal: str = Field(min_length=1, max_length=1024)


PLANNER_SYSTEM = """\
You are the planner inside ECHO, an autonomous DFIR agent investigating a Windows
host compromise. Your job is to choose the NEXT investigation phase from this set:

    triage    — initial process listing, get the lay of the land
    memory    — deeper memory analysis (malfind, cmdline, dlllist)
    network   — netscan, foreign connections
    registry  — persistence keys, services, AmCache
    disk      — MFT, prefetch, IOC sweep
    events    — Windows event log analysis
    finalize  — produce findings.json + report.md

GUIDANCE:
- Always start with "triage" on iter 0.
- After triage, choose phases based on what the validator already saw.
- If contradictions list is non-empty, prefer the phase that produces
  a corroborating data source.
- If iter >= max_iter - 1, choose "finalize".
- Reflection memory entries are lessons from previous iterations of THIS
  case — treat them as authoritative.

Respond as ONE JSON object matching the requested schema. No prose.
"""


def _state_summary(s: EchoState) -> str:
    contras = "\n".join(
        f"  - {c.rule_id} {c.rule_name} ({c.severity.value}): {c.description}"
        for c in s.contradictions
    ) or "  (none yet)"
    refl = "\n".join(
        f"  - iter {r.iter}: {r.lesson} → next: {r.next_hint}"
        for r in s.reflection_memory
    ) or "  (none yet)"
    findings = "\n".join(
        f"  - {f.id} {f.title} ({f.confidence.value})"
        for f in s.findings
    ) or "  (none yet)"

    return (
        f"case_id: {s.case_id}\n"
        f"iter: {s.iter}/{s.max_iter}\n"
        f"phase: {s.phase.value}\n"
        f"tokens_used: {s.tokens_used}/{s.budget_tokens}\n"
        f"contradictions:\n{contras}\n"
        f"findings_so_far:\n{findings}\n"
        f"reflection_memory:\n{refl}\n"
    )


def planner_node(state: EchoState) -> EchoState:
    """Decide next phase. Mutates state.phase, state.plan."""
    if state.iter == 0:
        state.phase = Phase.TRIAGE
        state.plan.append("iter=0: triage (always)")
        log.info("planner: iter=0 → triage (default)")
        return state

    if state.iter >= state.max_iter - 1:
        state.phase = Phase.FINALIZE
        state.plan.append(f"iter={state.iter}: finalize (max_iter)")
        log.info("planner: forced finalize at iter=%d", state.iter)
        return state

    user_msg = (
        "STATE SUMMARY:\n"
        f"{_state_summary(state)}\n"
        "Pick the next phase. If contradictions exist, prefer a phase that "
        "produces a tool likely to corroborate or refute them."
    )

    try:
        out, tokens = chat_json(
            schema=PlannerOutput,
            system=PLANNER_SYSTEM,
            user=user_msg,
            num_predict=512,
        )
    except Exception as e:  # noqa: BLE001
        log.warning("planner LLM failure (%s); defaulting to next phase by policy", e)
        state.phase = _next_phase_default(state.phase)
        state.plan.append(f"iter={state.iter}: {state.phase.value} (LLM-fallback)")
        return state

    state.phase = Phase(out.next_phase)
    state.tokens_used += tokens
    state.plan.append(
        f"iter={state.iter}: {state.phase.value} — {out.rationale[:120]}"
    )
    log.info("planner: → %s (rationale: %s)", state.phase.value, out.rationale[:100])
    return state


_DEFAULT_PROGRESSION: list[Phase] = [
    Phase.TRIAGE, Phase.MEMORY, Phase.NETWORK,
    Phase.REGISTRY, Phase.EVENTS, Phase.DISK, Phase.FINALIZE,
]


def _next_phase_default(current: Phase) -> Phase:
    try:
        idx = _DEFAULT_PROGRESSION.index(current)
        return _DEFAULT_PROGRESSION[min(idx + 1, len(_DEFAULT_PROGRESSION) - 1)]
    except ValueError:
        return Phase.MEMORY
