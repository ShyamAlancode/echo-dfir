# Devpost Description — copy-paste ready

> Use this verbatim in the Devpost submission form. Headers correspond
> to Devpost's required sections.

---

## Inspiration

Working on RL-based safety projects, I noticed every "agentic security"
demo I'd ever seen had the same blind spot: **the LLM judged its own
output**. An agent would run a memory analysis, propose a finding, and
then the same model would say "yes, I'm 95% confident". Meanwhile,
real DFIR analysts spend most of their time *cross-checking* — does
ShimCache agree with Prefetch, does netscan's owner PID exist in pslist,
did Event 4688 record an image that's not in the live process list?

I wanted to build an agent that did that cross-checking *deterministically*
— not by asking the LLM to grade itself, but by computing set differences
over typed records in pure Python. ECHO is the result.

## What it does

ECHO is an autonomous DFIR agent for Windows host investigation. Given a
case directory containing a memory image, registry hives, event logs,
prefetch, and MFT, it:

1. **Plans** an investigation across seven phases (triage, memory,
   network, registry, events, disk, finalize) using a LangGraph state
   machine.
2. **Executes** ONE of 14 typed forensic tools per iteration — wrapped
   Volatility 3 plugins, RegRipper, python-evtx, prefetch parser,
   analyzeMFT, and bulk_extractor.
3. **Validates** the cumulative tool output with five deterministic
   contradiction rules (R01–R05) implemented in pure Python over
   Pydantic-typed records.
4. **Critiques** any contradiction by picking ONE of three structured
   remediations: rerun the tool, accept low-confidence, or escalate to
   a different tool.
5. **Reflects** on each iteration into a per-case memory the planner
   reads next iteration.
6. **Finalizes** with a structured findings.json + report.md, where
   confidence labels are computed from a deterministic formula —
   the LLM never picks them.

Every node transition is hashed into a SHA-256 Merkle chain. One byte
changed anywhere = chain breaks = `echo verify` reports the tampered
line.

## How I built it

**Stack:** Python 3.11, Pydantic v2, FastMCP (stdio), LangGraph, Ollama
running `qwen2.5:7b-instruct-q4_K_M` 4-bit quantized, Typer CLI, Rich
console output. Forensic tools are SIFT defaults: Volatility 3,
RegRipper, python-evtx, analyzeMFT, bulk_extractor.

**Architecture:** three-layer separation —
1. The MCP server is the architectural guardrail: it exposes 14 typed,
   read-only tool functions and refuses to register a generic shell.
2. The deterministic validator is pure Python: rules R01–R05 are
   set-diff arithmetic over typed records. The LLM is never consulted
   on consistency.
3. The LangGraph agent is the only LLM consumer: planner, executor,
   critic, reflector, finalizer. Every LLM call uses Ollama
   `format=<json_schema>` to constrain output to a Pydantic model.

**Key decisions, in retrospect:**
- Killed `Groq` (rate limits, no training). Killed `TRL` (static).
  Picked Ollama + Qwen 2.5 7B because it's the smallest 4-bit model that
  reliably honours strict JSON-schema output.
- Used FastMCP over stdio rather than SSE so the server has zero
  network surface — it can only be talked to via the parent process's
  pipe.
- Picked `analyzeMFT` over `MFTECmd` because the former is pure Python
  and ships with SIFT; the latter is .NET-only.
- Built the spoliation suite first (12 red-team tests), THEN the agent.
  Test-driven development was the only way to be confident about
  "architectural-not-prompt-based" claims.

## Challenges I ran into

1. **Ollama JSON-schema mode wasn't reliable on the first prompt.**
   I added a retry-once-with-stricter-prompt + regex fallback chain in
   `echo_agent/llm.py`.
2. **Volatility 3 JSON output format changed between minor versions.**
   I pinned `vol3 ≥ 2.7` and ship Windows symbols separately so the install
   is reproducible.
3. **The audit-chain `iter` counter** caused a subtle bug: on graph
   resume after partial run, the iter value was read from state instead
   of from the log file, so resumed runs duplicated the iter number.
   Fixed by giving `AuditLogger` its own `_iter_counter` that loads from
   disk on construction.
4. **The validator's R02 rule** (AmCache vs Prefetch disagreement)
   produced false positives on hosts with Prefetch disabled (SSDs).
   Added a guard: if Prefetch is empty entirely, suppress R02 — the
   asymmetry is policy, not adversary action.

## Accomplishments I'm proud of

- **12 red-team tests pass on every CI run.** Architectural claim,
  empirically backed.
- **Confidence labels are mathematically impossible to spoof.** The
  Pydantic `model_validator` refuses `{confidence: low,
  status: confirmed}` at the type level.
- **Audit chain detects single-byte tamper.** Demonstrated in the
  spoliation test A012.
- **Zero cloud dependencies.** Runs entirely on a SIFT VM with a
  6 GB GPU. No API keys, no rate limits, no data leaving the host.

## What I learned

- **The LLM is the proposer; the validator is the arbiter.** Treating
  these as separate concerns — implemented in different languages of
  rigor — is the difference between a demo and a system.
- **Schema constraints beat prompt constraints by an order of
  magnitude.** Ollama's `format=<json_schema>` is non-negotiable for
  any agent doing more than chat.
- **DFIR has rich domain knowledge that fits well into structured
  rules.** The five contradiction rules I implemented are real DFIR
  patterns; they're not ML-discovered. Sometimes the best move is to
  encode the analyst's checklist into Python.

## What's next for ECHO

- Expand to **Linux artifact analysis** (auditd, journald, AIDE).
- Add **Sigma rule ingestion** — parse a Sigma rulepack and emit
  contradiction rules automatically.
- Build a **collaborative critic** that runs two LLMs of different
  families and only accepts findings where both agree.
- Open-source the `echo_mcp` server so anyone running an OSINT or DFIR
  pipeline can reuse the typed tool layer.

## Built with

`python` `pydantic` `langgraph` `fastmcp` `ollama` `qwen2.5` `typer`
`rich` `volatility3` `regripper` `python-evtx` `analyzemft`
`bulk-extractor` `sift-workstation` `pytest` `ruff` `black`

## Try it out

- Repo: `<your-github-url>`
- 60-second install: `./install.sh`
- 5-minute demo: `./scripts/run_demo.sh`
- Detailed runbook: [`WINNING_RUNBOOK.md`](WINNING_RUNBOOK.md)
