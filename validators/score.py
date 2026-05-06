"""
Deterministic confidence scoring.

The hackathon explicitly rewards "Confirmed findings distinguished from
inferences." We compute confidence as a closed-form function of:
    sources_count       — how many tools corroborate the claim
    contradictions_count — how many R0X rules flagged this finding
    has_caveat_high     — was a HIGH severity caveat attached?

Formula:
    score = clamp(
        0.30
      + 0.20 * min(sources_count, 4)
      - 0.30 * contradictions_count
      - 0.10 * (1 if has_caveat_high else 0),
        0.0, 1.0,
    )

Labels:
    score >= 0.75 → HIGH    → status: confirmed
    0.45 ≤ score < 0.75 → MEDIUM  → status: confirmed
    score < 0.45 → LOW     → status: low_confidence

The agent NEVER picks a confidence label. It computes a score, and the
label drops out of this module. That makes "I'm 95% sure" hallucinations
impossible.
"""
from __future__ import annotations

from echo_mcp.schemas import Confidence


def compute_score(
    sources_count: int,
    contradictions_count: int,
    has_caveat_high: bool = False,
) -> float:
    """Return a clamped score in [0.0, 1.0]."""
    score = (
        0.30
        + 0.20 * min(sources_count, 4)
        - 0.30 * contradictions_count
        - 0.10 * (1 if has_caveat_high else 0)
    )
    return max(0.0, min(1.0, score))


def confidence_for(
    sources_count: int,
    contradictions_count: int,
    has_caveat_high: bool = False,
) -> tuple[Confidence, float]:
    """Return (label, score)."""
    score = compute_score(sources_count, contradictions_count, has_caveat_high)
    if score >= 0.75:
        return Confidence.HIGH, score
    if score >= 0.45:
        return Confidence.MEDIUM, score
    return Confidence.LOW, score


def status_for(label: Confidence) -> str:
    if label == Confidence.LOW:
        return "low_confidence"
    return "confirmed"
