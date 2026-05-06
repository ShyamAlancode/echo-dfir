# ECHO Demo Video — 5-Minute Script

> **Format:** screen recording with voiceover. Total length 4:30 ± 0:30.
> **Resolution:** 1920×1080 minimum.
> **Tool:** OBS (free) or whatever your SIFT VM has.
> **Audio:** quiet room, clear mic, no music. Pace = unhurried but tight.

---

## SHOT LIST + VOICEOVER

### 0:00 — 0:20 — Hook (talking head + slide overlay)

**ON SCREEN:** ECHO logo (or just the project name) + the line
*"Most agentic DFIR demos let the LLM grade its own homework. ECHO doesn't."*

**VOICEOVER (read it like this):**

> "Hey — I'm Shyamalan, and this is ECHO, my submission for the SANS Find
> Evil hackathon. Most agentic DFIR demos let the LLM grade its own
> homework. ECHO doesn't. ECHO catches its own hallucinations using a
> deterministic Python validator and a SHA-256 audit chain. Let me show you."

---

### 0:20 — 0:50 — Architecture flyover (ARCHITECTURE.md mermaid + zoom-ins)

**ON SCREEN:** open `docs/ARCHITECTURE.md` and let the mermaid render.
Zoom into the three boxes one at a time.

**VOICEOVER:**

> "Three layers, three trust levels. The MCP server exposes exactly
> 14 typed forensic tools — no shell, no eval. The LangGraph agent
> proposes what to do next. And critically — the validator in the middle
> is *pure Python*. It doesn't ask the LLM whether the data agrees with
> itself; it computes set diffs over typed records. That's the
> architectural-not-prompt-based guardrail the hackathon judges
> explicitly reward."

---

### 0:50 — 1:30 — Spoliation tests (terminal: `pytest tests/spoliation -v`)

**ON SCREEN:** Terminal, run:
```
pytest tests/spoliation -v --tb=short
```
Wait for all 12 tests to flash green.

**VOICEOVER:**

> "Twelve red-team tests. Absolute path injection — refused. Dot-dot
> traversal — refused. Null byte injection — refused. No
> `run_command` tool registered. No `shell=True` anywhere in the codebase.
> Tool registry size enforced at 15 or fewer. And — the audit chain
> breaks on a single-byte tamper. All twelve pass. Every. CI. Run."

---

### 1:30 — 2:30 — Run the case (`echo run --case-id CASE_001_synthetic`)

**ON SCREEN:** Terminal:
```
echo run --case-id CASE_001_synthetic --max-iter 6 --verbose
```

Highlight the live log lines as they scroll:
- `planner: → triage`
- `executor: → windows.pslist`
- `validator: 1 new contradiction(s) detected: ['R01']`
- `critic: action=escalate tool=windows.cmdline`
- `reflector: lesson=...`
- `finalizer: wrote findings/CASE_001_synthetic_findings.json`

**VOICEOVER:**

> "Watch the agent work. Planner picks triage. Executor runs pslist.
> Validator sees a contradiction — R01 hidden process — and the critic
> escalates to `windows.cmdline` to confirm. After six iterations the
> finalizer synthesizes findings. The crucial bit: the finalizer's LLM
> *proposes* findings. The confidence label is computed by a closed-form
> formula in pure Python. The model literally cannot say 'I am 95% sure'
> when there's an unresolved contradiction."

---

### 2:30 — 3:10 — Verify the audit chain (`echo verify`)

**ON SCREEN:** Terminal:
```
echo verify --case-id CASE_001_synthetic
```

Then deliberately tamper:
```
sed -i 's/"iter":2/"iter":99/' audit/CASE_001_synthetic_iterations.jsonl
echo verify --case-id CASE_001_synthetic
```

**VOICEOVER:**

> "Every node transition is hash-chained. Every input, every output,
> every tool call — they all hash into the next entry. Watch what
> happens when I change a single field..."
>
> "[after sed]"
>
> "...the chain breaks. Line two: prev_hash mismatch. Tampering is
> detected immediately. This is what 'audit trail quality' means."

---

### 3:10 — 3:50 — Benchmark (`echo benchmark`)

**ON SCREEN:** Restore the audit log, then run:
```
echo benchmark \
    --findings findings/CASE_001_synthetic_findings.json \
    --gt validators/ground_truth/CASE_001.json
```

Highlight the JSON output: F1 numbers, hallucination rate,
self_correction_success_rate.

**VOICEOVER:**

> "Locked synthetic case. Locked ground truth. The benchmark gives us
> precision, recall, F1 — both at the IOC level and at the MITRE
> technique level. Hallucination rate. Self-correction success rate.
> These numbers don't drift between runs because nothing in the scoring
> path is non-deterministic."

---

### 3:50 — 4:30 — Closing pitch (terminal + repo tree)

**ON SCREEN:** `tree -L 2 -I '__pycache__|.venv|.git'`

**VOICEOVER:**

> "Everything ships in this repo. One-command install for SIFT.
> Docker fallback. 14 typed tools. Six LangGraph nodes. Five
> contradiction rules. Twelve red-team tests. One SHA-256 chain.
> Zero cloud dependencies. Zero API keys. Built solo in 30 days."
>
> "Read the WINNING_RUNBOOK.md — that's the master plan. ECHO is the
> agent that knows when it's wrong. Thanks for watching."

---

## SUBMISSION CHECKLIST

Before recording the final cut:

- [ ] All 12 spoliation tests pass on a clean clone
- [ ] `echo run --case-id CASE_001_synthetic` completes in < 5 min on RTX 4050
- [ ] `echo verify` returns ✓ on a clean run, ✗ after tamper
- [ ] Benchmark hits F1 ≥ 0.85 on IOC and ≥ 0.80 on MITRE
- [ ] No real customer data in any frame
- [ ] No API keys leaked in any terminal scrollback
- [ ] Voiceover audio peaks ≤ -3 dB, no clipping
- [ ] Final upload to YouTube as **unlisted** with the Devpost-required title

## WHEN TO RECORD

Record the final cut **48 hours before submission**, not on the day of.
That gives you one buffer day to re-record if something goes wrong.

Use a script-driven session: open OBS, hit record, walk through the
voiceover beat-by-beat without ad-libbing. If you fluff a line, stop,
back up to the start of that beat, and re-record only that segment.
Stitch in post.
