# ECHO — Evidence-Correlating Hallucination-Observed agent

> **An autonomous DFIR agent that catches its own hallucinations using
> deterministic cross-source contradiction detection and a tamper-evident
> SHA-256 audit chain.**

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](.github/workflows/ci.yml)
[![Spoliation Tests](https://img.shields.io/badge/spoliation_tests-12%2F12-brightgreen)](tests/spoliation)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Local Only](https://img.shields.io/badge/cloud_dependencies-zero-blueviolet)]()

ECHO is a solo submission for the **SANS "FIND EVIL!" DFIR Hackathon**
(May 15 – June 14, 2026). It is built to win on every published judging
axis — autonomous execution quality, IR accuracy, breadth, constraint
implementation, audit-trail quality, and usability.

---

## TL;DR for judges

```bash
git clone <this-repo> echo && cd echo
./install.sh                  # SIFT VM, idempotent
echo run --case-id CASE_001_synthetic --max-iter 6
echo verify --case-id CASE_001_synthetic
echo benchmark \
    --findings findings/CASE_001_synthetic_findings.json \
    --gt validators/ground_truth/CASE_001.json
```

You should see: `audit chain verified` + `f1 ≥ 0.85` on IOCs and MITRE.

---

## What makes ECHO different

Most agentic DFIR projects let an LLM judge whether its own answer is
correct. ECHO does not. ECHO splits the workload three ways:

| Layer | What it does | Implementation |
|---|---|---|
| **MCP server (typed)** | Exposes 14 read-only forensic tools | Architectural — there is no `run_command` tool to *abuse* |
| **Deterministic validator** | Detects contradictions across tools | Pure-Python set-diff over typed records — **no LLM** |
| **LLM agent** | Plans, executes, critiques, reflects | LangGraph cyclic state machine, Ollama-local |

The LLM is the *proposer*. The validator is a *deterministic arbiter*.
Confidence labels are computed from a closed-form formula, not picked by
the LLM. That asymmetry is why ECHO can claim a hallucination-resistant
audit trail.

### Architectural-not-prompt-based guardrails

The hackathon explicitly rewards "Constraint Implementation — guardrails
architectural, not prompt-based." ECHO satisfies this empirically:

- 12-test red-team **spoliation suite** (`tests/spoliation/`) proves the
  agent literally cannot construct a destructive command, escape the
  case directory, or tamper with the audit chain. **All 12 pass on every
  CI run.**
- The MCP server registers exactly **14 typed tool functions** (+1
  conditional). There is no shell, no eval, no generic exec. A
  prompt-injection cannot reach a syscall the architecture doesn't expose.
- Path resolution rejects absolute paths, `..` traversal, NUL bytes, and
  bad case IDs *before* hitting the filesystem.
- Read-only check refuses to operate on writable evidence.

---

## The 6 hackathon judging criteria — and how ECHO wins each

### 1. Autonomous Execution Quality
6-node LangGraph state machine with cycles: planner → executor →
validator → (critic|reflector) → reflector → loop or finalize.
The **critic** node is invoked when the validator detects a contradiction
and picks one of three structured remediations: rerun, accept_low_conf,
or escalate. See [`echo_agent/nodes/critic.py`](echo_agent/nodes/critic.py).

### 2. IR Accuracy
Confidence is **deterministic**, not LLM-assigned:

```
score = clamp(0.30 + 0.20·min(sources, 4)
              − 0.30·contradictions − 0.10·(has_high_caveat), 0, 1)
HIGH ≥ 0.75   MEDIUM ≥ 0.45   LOW < 0.45
```

A finding with one source and an unresolved contradiction can never be
labelled HIGH. A `Pydantic` `model_validator` enforces that
`{confidence: low, status: confirmed}` is unrepresentable.

### 3. Breadth & Depth
14 tools across **all five major Windows artifact classes**:
memory (Volatility 3 × 7 plugins), registry (RegRipper × 4), event logs
(python-evtx), prefetch, MFT, IOC sweep (bulk_extractor).
See [`echo_mcp/tools/__init__.py`](echo_mcp/tools/__init__.py).

### 4. Constraint Implementation
*Architectural*: 14 typed funcs, no shell, no eval. *Empirically proven*:
the 12 tests in `tests/spoliation/` pass on every CI run.

### 5. Audit Trail Quality
Every node transition appends a `ChainEntry` with
`this_hash = sha256(canonical_json(entry) || prev_hash)`. One byte
changed = chain breaks. `echo verify` recomputes the entire chain. See
[`echo_agent/audit.py`](echo_agent/audit.py).

### 6. Usability / Documentation
Single `./install.sh` for SIFT, `docker-compose up` fallback, locked
synthetic case with ground truth, accuracy report, demo video script,
master runbook. **All 8 Devpost-required artifacts are in this repo.**

---

## Architecture

```
                 ┌───────────────────────────────────────────────────┐
                 │ ECHO MCP server (FastMCP, stdio)                  │
                 │ ─────────────────────────────────────────────     │
                 │  14 typed tool funcs — NO shell, NO eval          │
                 │  resolve_evidence_path() rejects /, .., NUL       │
                 │  read_only_check() refuses writable evidence      │
                 └─────────────────────▲─────────────────────────────┘
                                       │ JSON-RPC over stdio
                 ┌─────────────────────┴─────────────────────────────┐
                 │ ECHO LangGraph agent                              │
                 │ ─────────────────────────────────────────────     │
                 │  Planner → Executor → Validator                   │
                 │                            │                      │
                 │              ┌─────────────┴──────────────┐       │
                 │              ▼                            ▼       │
                 │         Critic (LLM)              Reflector (LLM) │
                 │              │                            │       │
                 │              └────────────► Reflector ◄───┘       │
                 │                              │                    │
                 │              ┌───────────────┴────────────┐       │
                 │              ▼                            ▼       │
                 │         Planner (loop)              Finalizer     │
                 │                                          │        │
                 │                                          ▼        │
                 │                                       END (write  │
                 │                                       findings    │
                 │                                       + report)   │
                 └────────────────────────────────────────────────────┘
                                       ▲
                                       │ every transition
                 ┌─────────────────────┴─────────────────────────────┐
                 │ SHA-256 Merkle audit chain (append-only JSONL)    │
                 │ this_hash = sha256(canonical_json(entry)          │
                 │                  || prev_hash)                    │
                 └────────────────────────────────────────────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full diagram
with security boundaries highlighted.

---

## The 8 Devpost-required artifacts

| # | Required component | Where it lives in this repo |
|---|---|---|
| 1 | Code repository | This entire repo |
| 2 | Demo video script + recording plan | [`docs/DEMO_VIDEO_SCRIPT.md`](docs/DEMO_VIDEO_SCRIPT.md) |
| 3 | Architecture diagram | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| 4 | Written description (Devpost copy) | [`docs/DEVPOST_DESCRIPTION.md`](docs/DEVPOST_DESCRIPTION.md) |
| 5 | Dataset documentation | [`samples/CASE_001_synthetic/README.md`](samples/CASE_001_synthetic/README.md) |
| 6 | Accuracy report | [`docs/ACCURACY_REPORT.md`](docs/ACCURACY_REPORT.md) |
| 7 | Try-it-out instructions | This README + `./install.sh` |
| 8 | Sample agent execution log | `audit/CASE_001_synthetic_iterations.jsonl` (after `run`) |

---

## Repository layout

```
echo/
├── echo_mcp/                # MCP server: 14 typed read-only forensic tools
│   ├── server.py            # FastMCP entrypoint
│   ├── tools/               # volatility, registry, evtx, prefetch, mft_be
│   ├── schemas/             # Pydantic v2 contracts
│   └── knowledge/caveats.yaml  # per-tool DFIR caveats
├── echo_agent/              # LangGraph agent
│   ├── graph.py             # state machine wiring
│   ├── nodes/               # planner, executor, validator, critic, reflector, finalizer
│   ├── audit.py             # SHA-256 Merkle chain
│   ├── llm.py               # Ollama client
│   └── cli.py               # `echo run | verify | replay | benchmark`
├── validators/              # Deterministic validators
│   ├── cross_source.py      # 5 contradiction rules R01-R05
│   ├── score.py             # confidence formula
│   ├── run_benchmark.py     # P/R/F1 against ground truth
│   └── ground_truth/        # locked CASE_001.json
├── tests/
│   ├── unit/                # 21 unit tests
│   └── spoliation/          # 12 red-team tests
├── samples/CASE_001_synthetic/  # reproducible demo case
├── docs/                    # ARCHITECTURE, ACCURACY, DEMO, DEVPOST
├── scripts/                 # run_demo.sh, verify_install.sh
├── install.sh               # one-command SIFT install
├── docker-compose.yml       # non-SIFT fallback
└── WINNING_RUNBOOK.md       # the master plan: what to do, how to test
```

---

## Quick run on bare metal (Ubuntu/SIFT)

```bash
./install.sh
source .venv/bin/activate
./scripts/verify_install.sh
./scripts/run_demo.sh
```

## Quick run via Docker

```bash
docker compose build
docker compose up -d ollama        # background — pulls model on first run
docker compose run --rm echo run --case-id CASE_001_synthetic
```

## Bring your own case

1. Drop a directory under `/mnt/cases/` (or `./samples/` for Docker):

   ```
   /mnt/cases/MY_CASE_42/
   ├── memory.raw
   ├── $MFT
   └── Windows/
       ├── System32/config/SYSTEM,SOFTWARE
       ├── System32/winevt/Logs/Security.evtx
       ├── Prefetch/
       └── AppCompat/Programs/Amcache.hve
   ```

2. Run:

   ```bash
   echo run --case-id MY_CASE_42 --max-iter 8
   echo verify --case-id MY_CASE_42
   ```

3. Output:

   - `findings/MY_CASE_42_findings.json` — structured results
   - `findings/MY_CASE_42_report.md` — human report
   - `audit/MY_CASE_42_iterations.jsonl` — verifiable audit chain

---

## License

MIT. See [`LICENSE`](LICENSE).

## Author

Built solo for the SANS DFIR Hackathon 2026 by **Shyamalan T**
(1st-year CSE-AIML, Sri Eshwar College of Engineering / Anna University).

---

> **Read [`WINNING_RUNBOOK.md`](WINNING_RUNBOOK.md) next** — it's the
> master plan: what to do day-by-day, how to test, how to harden, and
> exactly why this design wins on each judging axis.
