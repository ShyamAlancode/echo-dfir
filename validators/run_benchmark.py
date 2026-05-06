"""
Accuracy benchmark harness — Precision / Recall / F1.

Two scoring axes:
    1. IOC-level matching: predicted IOC values vs ground-truth IOC values.
    2. MITRE technique matching: predicted technique IDs vs ground-truth.

We also record:
    - hallucination_rate = (predicted - tp) / max(predicted, 1)
    - self_correction_success = contradictions whose rule_id appears in
      Finding.contradictions_resolved divided by total contradictions.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import orjson


def _set_of_iocs(findings: list[dict[str, Any]]) -> set[tuple[str, str]]:
    out = set()
    for f in findings:
        for ioc in f.get("iocs", []):
            t = (ioc.get("type") or "").lower()
            v = (ioc.get("value") or "").strip().lower()
            if t and v:
                out.add((t, v))
    return out


def _set_of_techniques(findings: list[dict[str, Any]]) -> set[str]:
    out = set()
    for f in findings:
        for t in f.get("mitre_technique_ids", []) or []:
            out.add(t.strip().upper())
    return out


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return round(p, 3), round(r, 3), round(f1, 3)


def score_against_ground_truth(
    findings_path: Path, ground_truth_path: Path,
) -> dict[str, Any]:
    """Score predicted findings against ground truth.

    findings.json structure: {findings: [...], contradictions: [...]}
    ground_truth.json structure: {findings: [...]}  (same Finding shape)
    """
    pred = orjson.loads(findings_path.read_bytes())
    gt = orjson.loads(ground_truth_path.read_bytes())

    pred_findings = pred.get("findings", [])
    gt_findings = gt.get("findings", [])

    # IOC-level
    pred_iocs = _set_of_iocs(pred_findings)
    gt_iocs = _set_of_iocs(gt_findings)
    tp_i = len(pred_iocs & gt_iocs)
    fp_i = len(pred_iocs - gt_iocs)
    fn_i = len(gt_iocs - pred_iocs)
    p_i, r_i, f1_i = _prf(tp_i, fp_i, fn_i)

    # MITRE-level
    pred_t = _set_of_techniques(pred_findings)
    gt_t = _set_of_techniques(gt_findings)
    tp_t = len(pred_t & gt_t)
    fp_t = len(pred_t - gt_t)
    fn_t = len(gt_t - pred_t)
    p_t, r_t, f1_t = _prf(tp_t, fp_t, fn_t)

    # Hallucination rate (over IOCs and techniques combined)
    total_pred = len(pred_iocs) + len(pred_t)
    total_tp = tp_i + tp_t
    hallucination_rate = (
        round(1 - (total_tp / total_pred), 3) if total_pred else 0.0
    )

    # Self-correction success
    contras = pred.get("contradictions", [])
    resolved_ids: set[str] = set()
    for f in pred_findings:
        for rid in f.get("contradictions_resolved", []) or []:
            resolved_ids.add(rid)
    sc_success = (
        round(len(resolved_ids) / max(len(contras), 1), 3) if contras else 1.0
    )

    return {
        "ioc": {
            "precision": p_i, "recall": r_i, "f1": f1_i,
            "tp": tp_i, "fp": fp_i, "fn": fn_i,
        },
        "mitre": {
            "precision": p_t, "recall": r_t, "f1": f1_t,
            "tp": tp_t, "fp": fp_t, "fn": fn_t,
        },
        "hallucination_rate": hallucination_rate,
        "self_correction_success_rate": sc_success,
        "predicted_findings": len(pred_findings),
        "ground_truth_findings": len(gt_findings),
        "contradictions_detected": len(contras),
    }
