# CASE_001 — Synthetic Reproducible Demo

This is a **synthetic** case for judges to verify ECHO end-to-end without
needing a real disk image. It is NOT a triaged production sample.

## What this case represents

A simulated incident on `WIN10-FINANCE-04`:
- Initial access: spear-phishing attachment (`Q4_Invoice.docm`) executed by user `j.morgan`
- Persistence: malicious service `EvtSysSvc` registered via `sc.exe`
- Defense evasion: process injection from `powershell.exe` into `svchost.exe`
- Execution: `mimikatz_x64.exe` dropped to `C:\Windows\Temp\` and run
- Impact: lateral movement RDP attempt to `10.10.20.5`

## Files in this case

```
samples/CASE_001_synthetic/
├── memory.raw                     # placeholder — see fixture script
├── $MFT                           # placeholder
├── Windows/
│   ├── Prefetch/                  # synthetic .pf names
│   ├── System32/
│   │   ├── config/SYSTEM, SOFTWARE  # placeholder hives
│   │   └── winevt/Logs/Security.evtx  # placeholder
│   └── AppCompat/Programs/Amcache.hve  # placeholder
└── README.md                      # this file
```

## Why placeholders?

A real memory image is ~8 GB and copyrighted. For the demo we ship
**deterministic fixtures** in `tests/integration/` that mock the
TOOL_REGISTRY responses with the same data shapes ECHO would see in
production. The agent runs the same code path; only the data source
differs.

## How to verify

```bash
# 1. With Ollama running locally:
echo run --case-id CASE_001_synthetic

# 2. Score against locked ground truth:
echo benchmark \
    --findings findings/CASE_001_synthetic_findings.json \
    --gt validators/ground_truth/CASE_001.json
```

Ground-truth findings are locked in `validators/ground_truth/CASE_001.json`.
ECHO must achieve **F1 ≥ 0.85** on this case for the build to be considered
green (see `ACCURACY_REPORT.md` for the full benchmark methodology).
