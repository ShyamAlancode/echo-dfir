"""
Validator node — DETERMINISTIC contradiction detection.

This node is pure Python. It does NOT call the LLM. It runs the rule
engine in validators.cross_source.detect_all() against the tool cache
and updates state.contradictions.

If new contradictions appear, state.needs_revision = True, which routes
the graph through the critic node. Otherwise the graph continues to the
reflector / planner.
"""
from __future__ import annotations

import logging

from echo_mcp.schemas import EchoState, ToolResponse
from validators.cross_source import detect_all

log = logging.getLogger("echo.validator")


def validator_node(state: EchoState, tool_cache: dict[str, ToolResponse]) -> EchoState:
    """Run all applicable contradiction rules. Pure Python — no LLM."""
    new_contradictions = detect_all(tool_cache, state.iter)

    seen_ids = {(c.rule_id, tuple(sorted(c.sources))) for c in state.contradictions}
    truly_new = [
        c for c in new_contradictions
        if (c.rule_id, tuple(sorted(c.sources))) not in seen_ids
    ]

    if truly_new:
        state.contradictions.extend(truly_new)
        state.needs_revision = True
        log.info(
            "validator: %d new contradiction(s) detected: %s",
            len(truly_new),
            [c.rule_id for c in truly_new],
        )
    else:
        state.needs_revision = False
        log.info("validator: no new contradictions (cache=%d tools)", len(tool_cache))

    return state
