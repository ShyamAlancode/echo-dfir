# ECHO Accuracy Report

> **Methodology, results, and reproducibility for the SANS DFIR Hackathon
> 2026 submission.**

## Methodology

ECHO is benchmarked along **four axes**:

| Axis | Metric | Source of truth |
|---|---|---|
| IOC accuracy | Precision / Recall / F1 over (type, value) pairs | `validators/ground_truth/CASE_*.json` |
| MITRE coverage | P/R/F1 over technique IDs | same |
| Hallucination rate | (predicted − tp) / max(predicted, 1) | derived |
| Self-correction | resolved contradictions / total contradictions | audit chain |

The benchmark harness is `validators/run_benchmark.py`. Its output is
deterministic — the same `findings.json` will always score the same.

## Targets (build-green thresholds)

For ECHO to be considered "winning-grade" we require:

| Threshold | Value | Rationale |
|---|---|---|
| IOC F1 | ≥ 0.85 | better than the baseline of LLM-judged self-evaluation |
| MITRE F1 | ≥ 0.80 | technique inference is harder than IOC matching |
| Hallucination rate | ≤ 0.15 | matches the deterministic-validator design promise |
| Self-correction success | ≥ 0.80 | every R01-R05 contradiction should resolve via critic |
| Spoliation tests | 12/12 pass | architectural-not-prompt-based claim is empirical |
| Audit chain verify | always | tamper detection is the floor, not the ceiling |

## Reproducing the benchmark

```bash
# 1. Run the locked synthetic case end-to-end
echo run --case-id CASE_001_synthetic --max-iter 8

# 2. Verify the audit chain
echo verify --case-id CASE_001_synthetic

# 3. Score against locked ground truth
echo benchmark \
    --findings findings/CASE_001_synthetic_findings.json \
    --gt validators/ground_truth/CASE_001.json
```

Expected output shape:

```json
{
  "ioc": {"precision": 0.X, "recall": 0.Y, "f1": 0.Z, "tp": N, "fp": M, "fn": K},
  "mitre": {"precision": 0.X, "recall": 0.Y, "f1": 0.Z, ...},
  "hallucination_rate": 0.W,
  "self_correction_success_rate": 0.V,
  "predicted_findings": ...,
  "ground_truth_findings": 5,
  "contradictions_detected": ...
}
```

## Spoliation results (architectural integrity)

| Test ID | Description | Result |
|---|---|---|
| A001 | Absolute path rejected | ✓ pass |
| A002 | `..` traversal rejected | ✓ pass |
| A003 | Multi-level `../../..` rejected | ✓ pass |
| A004 | NUL-byte injection rejected | ✓ pass |
| A005 | Case-ID traversal rejected | ✓ pass |
| A006 | Empty case-ID rejected | ✓ pass |
| A007 | Writable evidence refused | ✓ pass |
| A008 | No `run_command`/`shell`/`exec` tool registered | ✓ pass |
| A009 | No `shell=True` anywhere in codebase | ✓ pass |
| A010 | Tool registry size ≤ 15 | ✓ pass |
| A011 | Pydantic refuses `{confidence: low, status: confirmed}` | ✓ pass |
| A012 | Single-byte tamper breaks audit chain | ✓ pass |

Run `pytest tests/spoliation -v` to reproduce.

## Why these numbers will hold

1. **Confidence is mechanical, not opinion-based.** The score formula
   ensures that a finding cited by 1 tool with 1 unresolved contradiction
   *cannot* be HIGH-confidence — Pydantic enforces it.
2. **Contradictions are set-diffs, not LLM judgments.** R01–R05 are pure
   Python over typed records. They will detect the same contradiction
   the same way every run.
3. **Tool surface is bounded.** A spoliation test fails the build if the
   registry grows past 15.
4. **Hallucinated IOCs cannot pass through.** The finalizer drops any
   finding whose `sources` list contains a tool that wasn't actually run
   — see `echo_agent/nodes/finalizer.py` line ~110.

## Caveats (intellectual honesty)

- Benchmarks here are against the **synthetic CASE_001**. We will rerun
  against any case the hackathon ships in the May 15 kickoff.
- A perfect F1 = 1.0 should be regarded with suspicion: it usually means
  the agent overfit to the ground-truth file's wording. We expect IOC F1
  in the 0.85–0.93 band, not 1.0.
- Volatility 3 plugin output format is version-sensitive. ECHO has been
  tested against vol3 ≥ 2.7. Older versions may need a parser tweak.

## Updating this report after a real run

After running on a real hackathon-supplied case, update this file with
real numbers. Don't backfill from memory — use the JSON output of
`echo benchmark` directly.
