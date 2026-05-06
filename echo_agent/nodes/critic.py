"""
Critic node — when the validator flags a contradiction, the critic
decides what to DO about it.

The critic LLM is constrained to pick ONE of three actions:
    rerun           — re-execute the tool that produced the suspect output
    accept_low_conf — accept the finding but mark it low_confidence
    escalate        — request a different tool that would resolve the issue

This is structured-output: the LLM never writes free-form remediation.
It picks a discrete action and (if escalating) a tool from the allowlist.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from echo_agent.llm import ECHO_CRITIC_MODEL, chat_json
from echo_mcp.schemas import Contradiction, EchoState, ToolResponse
from echo_mcp.tools import TOOL_REGISTRY

log = logging.getLogger("echo.critic")


class CriticOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["rerun", "accept_low_conf", "escalate"]
    tool: Optional[str] = Field(default=None, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=1, max_length=1024)


CRITIC_SYSTEM = """\
You are the critic node inside ECHO. The deterministic validator just
flagged a CONTRADICTION between forensic data sources. You must choose
ONE action:

    rerun           — re-execute the most recent tool (transient kernel state)
    accept_low_conf — accept the finding but tag it low_confidence
    escalate        — call a DIFFERENT tool that should resolve the discrepancy

GUIDANCE:
- For R01 hidden_process: escalate to windows.cmdline or windows.dlllist
  for the suspect PID.
- For R02 execution_disagreement: escalate to evtx_parse for Event 4688.
- For R03 orphan_network_owner: rerun windows.psscan (transient state)
  or escalate to windows.malfind.
- For R04 event4688_anomaly: escalate to regripper.amcache.
- For R05 shimcache_malfind_correlate: escalate to windows.dlllist for the PID.

Output ONE JSON object. No prose.
"""


def critic_node(state: EchoState, tool_cache: dict[str, ToolResponse]) -> EchoState:
    """Decide remediation for the most recent contradiction(s)."""
    if not state.contradictions:
        return state

    # Most recent unresolved contradiction:
    contra = state.contradictions[-1]

    user_msg = (
        f"contradiction:\n"
        f"  rule_id: {contra.rule_id}\n"
        f"  rule_name: {contra.rule_name}\n"
        f"  severity: {contra.severity.value}\n"
        f"  description: {contra.description}\n"
        f"  sources: {contra.sources}\n"
        f"  artifacts (truncated): {str(contra.artifacts)[:1000]}\n\n"
        f"recent tool call: {state.last_tool_call}\n"
        f"available tools: {list(TOOL_REGISTRY.keys())}\n\n"
        "Choose action."
    )

    try:
        out, tokens = chat_json(
            schema=CriticOutput,
            system=CRITIC_SYSTEM,
            user=user_msg,
            model=ECHO_CRITIC_MODEL,
            num_predict=512,
            temperature=0.2,
        )
        state.tokens_used += tokens
    except Exception as e:  # noqa: BLE001
        log.warning("critic LLM failure (%s); defaulting to accept_low_conf", e)
        state.needs_revision = False
        return state

    log.info("critic: action=%s tool=%s rationale=%s", out.action, out.tool, out.rationale[:120])

    if out.action == "rerun" and state.last_tool_call:
        last = state.last_tool_call
        try:
            resp = TOOL_REGISTRY[last["tool"]](**last["args"])
            tool_cache[last["tool"]] = resp
            state.last_tool_output = resp
        except Exception as e:  # noqa: BLE001
            log.warning("critic rerun failed: %s", e)

    elif out.action == "escalate" and out.tool and out.tool in TOOL_REGISTRY:
        args = out.args or {}
        args.setdefault("case_id", state.case_id)
        try:
            resp = TOOL_REGISTRY[out.tool](**args)
            tool_cache[out.tool] = resp
            state.last_tool_call = {"tool": out.tool, "args": args}
            state.last_tool_output = resp
        except Exception as e:  # noqa: BLE001
            log.warning("critic escalate failed: %s", e)

    # accept_low_conf: do nothing here; the finalizer will compute a low score
    # because contradictions_count > 0.

    state.needs_revision = False  # critic has dealt with it; let the loop continue
    return state
