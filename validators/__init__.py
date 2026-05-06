"""ECHO deterministic validators — pure-Python contradiction + scoring."""
from validators.cross_source import detect_all
from validators.score import compute_score, confidence_for, status_for

__all__ = ["detect_all", "compute_score", "confidence_for", "status_for"]
