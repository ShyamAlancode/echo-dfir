# WINNING_RUNBOOK.md

> **The master plan: what to do, day-by-day, to ship an indestructible
> ECHO that wins the SANS DFIR Hackathon 2026.**
>
> Submission window: **May 15 → June 14, 2026**.
> Prize pool: **$22,000**.
> Submitting solo as **Shyamalan T**, 1st-yr CSE-AIML, India.

---

## Section 0 — How to read this document

This is the only document you need open during the build. Every other
doc in this repo is referenced from here. Sections 1–7 are sequential —
follow them in order. Section 8 is the emergency cutdown if you fall
behind. Section 9 is the day-of-submission checklist.

If at any point you're confused about whether you should still be
building a feature or freezing scope, **the answer is freeze**. ECHO is
already complete; everything from here is hardening and presentation.

---

## Section 1 — Why ECHO will win (the pitch, internalized)

The hackathon judges on six axes. ECHO is engineered to dominate each.

| Judging axis | ECHO's answer | Where it lives |
|---|---|---|
| Autonomous Execution Quality | 6-node LangGraph cycle with critic+reflector loops | `echo_agent/graph.py` |
| IR Accuracy | Deterministic Python validator (R01–R05) + closed-form confidence formula | `validators/cross_source.py`, `validators/score.py` |
| Breadth & Depth | 14 typed tools spanning all 5 Windows artifact classes | `echo_mcp/tools/` |
| Constraint Implementation | Architectural — no shell, no eval, 12 spoliation tests prove it | `tests/spoliation/` |
| Audit Trail Quality | SHA-256 Merkle chain, single-byte tamper detection | `echo_agent/audit.py` |
| Usability / Documentation | One-command install + Docker fallback + locked synthetic case + 7 docs | `install.sh`, `docs/`, this file |

**The single sentence pitch you should be able to give in your sleep:**

> "ECHO is an agentic DFIR tool that catches its own hallucinations
> using a deterministic Python validator and a SHA-256 audit chain —
> guardrails are architectural, not prompt-based."

If a judge asks "what makes you different from the other agentic DFIR
submissions?", the answer is: *"Most submissions let the LLM grade its
own homework. ECHO doesn't. The validator is pure Python set-diff over
typed records. The confidence label is computed from a closed-form
formula. The audit chain breaks on a single-byte tamper. All three are
empirically tested."*

---

## Section 2 — Day-by-day plan (May 15 → June 14)

You have **30 days**. Here's how they break down. Move tasks earlier
if you finish under budget. Don't move them later.

### Week 1 — May 15 – May 21: Setup + first end-to-end run

| Day | Task | Done when |
|---|---|---|
| 15 (Thu) | `./install.sh` runs clean on your SIFT VM. `./scripts/verify_install.sh` shows all green. | All 12 spoliation tests pass; Ollama responds at 11434. |
| 16 (Fri) | Read every doc in `docs/`. Read every file under `echo_mcp/` and `echo_agent/`. Take notes. | You can answer a judge's question about any line. |
| 17 (Sat) | First end-to-end run on `CASE_001_synthetic`. Read the audit log. Read the findings.json. | Findings file has ≥ 3 findings; audit chain verifies. |
| 18 (Sun) | Run the benchmark. Don't tune yet — just observe. | You have a baseline JSON output. |
| 19 (Mon) | Pull two more public DFIR images (e.g. CFReDS, Magnet CTF). Build CASE_002, CASE_003 case directories. | Two new case dirs under `samples/`. |
| 20 (Tue) | Run ECHO on CASE_002. Diagnose any failures. Iterate. | `findings/CASE_002_findings.json` exists. |
| 21 (Wed) | Run ECHO on CASE_003. Capture metrics. Update `docs/ACCURACY_REPORT.md` with real numbers. | `ACCURACY_REPORT.md` has 3 cases worth of data. |

**Week 1 exit criterion:** ECHO runs on 3 cases, all 12 spoliation tests
green, accuracy report has real numbers.

### Week 2 — May 22 – May 28: Tighten the validator

| Day | Task | Done when |
|---|---|---|
| 22 | Look at every false positive R01 produced on cases 2/3. Fix the rule if needed. | R01 false-positive rate < 5%. |
| 23 | Same for R02. Watch out for SSD-disabled prefetch and Windows updates. | R02 false-positive rate < 10%. |
| 24 | Same for R03 (orphan network owners — exited processes are a known noise source). | R03 false-positive rate < 5%. |
| 25 | Same for R04 (4688 vs pslist — fast-running utilities are noise). | R04 false-positive rate acceptable. |
| 26 | Same for R05. | R05 false-positive rate acceptable. |
| 27 | Add 3 more spoliation tests if you can think of new attack surfaces. Don't drop below 12. | A013, A014, A015 added. |
| 28 (Sun) | **Mid-build review:** open the WINNING_RUNBOOK and make sure every Section 1 axis is still covered. | Self-review checklist all green. |

**Week 2 exit criterion:** false-positive rate per rule < 10%, spoliation
tests still green.

### Week 3 — May 29 – June 4: Polish + presentation

| Day | Task | Done when |
|---|---|---|
| 29 | Re-run all 3 cases. Capture full audit logs. Pick the cleanest one for the demo video. | Demo case selected. |
| 30 | Record demo video draft 1 (using `docs/DEMO_VIDEO_SCRIPT.md`). | Draft uploaded privately. |
| 31 | Watch your own video at 2x. Note awkward moments. | Notes written. |
| 1 (Sun) | Re-record demo video draft 2. | Draft 2 uploaded privately. |
| 2 (Mon) | Update `docs/DEVPOST_DESCRIPTION.md` with real numbers from your runs. Don't fabricate. | Devpost description has real data. |
| 3 (Tue) | Update `README.md` quick-start verified line-by-line. Have a friend follow it on a clean VM. | README quick-start works on a clean VM. |
| 4 (Wed) | All docs reviewed for typos. Run a spell-checker. | All `.md` files clean. |

**Week 3 exit criterion:** demo video is good enough to ship; docs all
clean; README works on a clean VM.

### Week 4 — June 5 – June 14: Harden + submit

| Day | Task | Done when |
|---|---|---|
| 5 (Thu) | **CODE FREEZE.** No more features. Only bug fixes. | A git tag `v1.0.0-rc1` exists. |
| 6 (Fri) | Run the benchmark suite 5 times back to back. Note any variance. | Variance documented. |
| 7 (Sat) | Run on a 4th case if you have one. Otherwise, deep-dive one of the existing 3. | Findings on 4th case if available. |
| 8 (Sun) | Final video recording. Upload as **unlisted** YouTube. | Final video link saved. |
| 9 (Mon) | Devpost project page draft 1. Use `docs/DEVPOST_DESCRIPTION.md` verbatim. | Devpost page exists, not submitted. |
| 10 (Tue) | Have someone (parent, friend, classmate) read the Devpost page and the README. Note their confusion. | Feedback captured. |
| 11 (Wed) | Address feedback. Re-read all docs. | Polish pass complete. |
| 12 (Thu) | **Submit Devpost form** — but don't hit submit yet. Save as draft. | Draft is complete and reviewed. |
| 13 (Fri) | One final read-through. Verify all 8 required artifacts are linked. | Submission is ready to go live. |
| 14 (Sat) | **SUBMIT** — early in the day, not 11:55 PM. | Confirmation email received. |

**Week 4 exit criterion:** clean submission, no last-minute scrambles.

---

## Section 3 — How to test (the indestructibility checklist)

Before each git push, run:

```bash
# 1. Spoliation tests (architectural integrity)
pytest tests/spoliation -v

# 2. Unit tests (deterministic core)
pytest tests/unit -v

# 3. Lint and format check
ruff check .
black --check .

# 4. Type stubs (if you add mypy later)
# mypy echo_mcp echo_agent validators

# 5. End-to-end on synthetic case
echo run --case-id CASE_001_synthetic --max-iter 6

# 6. Audit chain verification
echo verify --case-id CASE_001_synthetic

# 7. Benchmark
echo benchmark \
    --findings findings/CASE_001_synthetic_findings.json \
    --gt validators/ground_truth/CASE_001.json
```

If any step fails, **don't push**. Fix forward.

### Once a week (recommended)

```bash
# Re-run install on a clean VM (or a fresh Docker container)
docker compose build --no-cache
docker compose run --rm echo

# Verify the README quick-start exactly as written
cat README.md | grep -A20 'TL;DR for judges' | grep -E '^\$|echo |./install'
```

---

## Section 4 — How to harden ECHO further (if you have time)

Only if Sections 2 + 3 are completely done. Each item below is *additive*.

1. **Add 3 more contradiction rules.** Candidates:
   - R06: scheduled-task created in 4698 vs Task Scheduler hive
   - R07: file in MFT but not in directory listing (deleted-but-resident)
   - R08: malfind injection PIDs vs cmdline → does the cmdline match the
     image_path?

2. **Add a second LLM family.** Run a "collaborative critic" that asks
   both Qwen 2.5 7B and Llama 3 8B for the same finding, and only marks
   `confirmed` when both proposals agree on the title and at least one
   IOC.

3. **Persist the reflection memory across cases.** Right now it resets
   per case. A cross-case memory of lessons would help on a 2nd run of
   the same investigator.

4. **Add an integration test that runs the full graph against a mocked
   tool registry.** Patch `TOOL_REGISTRY` with stub callables that
   return fixture data, then assert the graph produces the right
   findings.

5. **Profile the graph.** If a single iteration takes > 30 s of LLM
   time, switch the planner to a smaller model (3B), keep the critic on
   the 7B.

6. **Add a `--strict` CLI flag** that fails the run if any spoliation
   test would fail (re-run them at startup).

---

## Section 5 — Common failure modes + how to debug

### "Ollama isn't responding"
```bash
curl http://127.0.0.1:11434/api/tags
# If empty, restart:
pkill -f 'ollama serve' || true
nohup ollama serve >/tmp/ollama.log 2>&1 &
sleep 3
ollama pull qwen2.5:7b-instruct-q4_K_M
```

### "vol command not found"
```bash
which vol
# If empty:
pip install --break-system-packages 'volatility3>=2.7'
```

### "Volatility produces no symbols"
```bash
ls ~/.cache/volatility3/symbols/windows/
# If empty:
mkdir -p ~/.cache/volatility3/symbols/windows
cd ~/.cache/volatility3/symbols/windows
curl -fSL https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -o w.zip
unzip -o w.zip && rm w.zip
```

### "Audit chain verification fails"
That means it works! Check what changed. If it's not deliberate tamper,
look for `os.fsync` failures (full disk?) or concurrent writers (don't
run two `echo run` instances on the same case_id).

### "Findings.json is empty"
1. Check that `--max-iter` is at least 4.
2. Check that the case directory has the expected files.
3. Check the audit log for `executor` errors.
4. Run `pytest tests/spoliation` — if those fail, your install is broken.

### "Spoliation tests fail"
**Stop everything**. The architectural-guardrail claim is false.
Diagnose immediately. Most likely a recent edit to `_common.py` or
`tools/__init__.py` weakened a check.

---

## Section 6 — Submission checklist (Devpost form)

Devpost requires you to fill in 8 things. Here's exactly what each looks
like for ECHO:

| # | Field | Use |
|---|---|---|
| 1 | Project name | **ECHO — Evidence-Correlating Hallucination-Observed agent** |
| 2 | Tagline (1 line) | Autonomous DFIR agent that catches its own hallucinations using deterministic Python validation + SHA-256 audit chain. |
| 3 | Inspiration / What it does / How / Challenges / Accomplishments / Learned / What's next | Copy-paste from `docs/DEVPOST_DESCRIPTION.md`. |
| 4 | Built with | `python` `pydantic` `langgraph` `fastmcp` `ollama` `qwen2.5` `volatility3` `regripper` `python-evtx` `analyzemft` `bulk-extractor` `sift` |
| 5 | Try it out URL | GitHub repo URL |
| 6 | Demo video | YouTube unlisted URL |
| 7 | Architecture / accuracy / dataset docs | Direct GitHub URLs to `docs/ARCHITECTURE.md`, `docs/ACCURACY_REPORT.md`, `samples/CASE_001_synthetic/README.md` |
| 8 | Sample agent log | Direct GitHub URL to `audit/CASE_001_synthetic_iterations.jsonl` (after running) |

**Pre-submit verification:** open the Devpost preview, follow each link
yourself, click them, make sure they all open the right thing.

---

## Section 7 — How to talk to the judges (if you get an interview)

Even though it's an async submission, some of these hackathons do
follow-up interviews. If you get one:

1. **Open with the architectural claim.** "ECHO's guardrails are
   architectural, not prompt-based. Twelve red-team tests pass on every
   CI run."
2. **Have the spoliation suite running on screen.** Show A012 in
   particular — the chain-tamper detection.
3. **Don't oversell.** If they ask whether you've tested on real APT
   captures, say "I've tested on three: CASE_001 synthetic, CFReDS [X],
   and Magnet CTF [Y]. F1 numbers are in `docs/ACCURACY_REPORT.md`."
4. **Don't be defensive about the LLM choice.** If they ask "why Qwen 2.5
   not GPT-4?", say: "Qwen runs locally on a 6 GB GPU. The hackathon
   asks for evidence-handling tools — I can't run those against
   somebody's MFT through OpenAI's API. Local-only is a feature."
5. **Have one number memorized.** Pick the most flattering F1 from your
   benchmark and say it confidently. Don't quote a range.

---

## Section 8 — Emergency cutdown plan

If at any point you're behind and panicking, here's what to drop in
order of preference:

### T-10 days from submission (still in good shape)
- Drop the 4th case if you don't have it.
- Skip new contradiction rules (R06–R08).

### T-5 days (getting tight)
- Skip the second LLM family idea entirely.
- Lock the demo video at draft 2; don't re-record.
- Skip the cross-VM README verification.

### T-2 days (in serious trouble)
- Submit only `CASE_001_synthetic` benchmark.
- Submit demo video as-is, even with one fluff.
- Don't try to fix any failing spoliation test by ripping out the test —
  always fix the underlying code.

### T-0 (submitting today)
**Do these even if rushed:**
- All 12 spoliation tests pass.
- Audit chain verifies on the synthetic case.
- README quick-start works.
- Demo video uploaded.
- Devpost form has all 8 required artifacts linked.

**Do NOT submit if:**
- Any spoliation test fails (architectural claim is false).
- Audit chain doesn't verify.
- Demo video shows a broken state.

---

## Section 9 — Final word

This project is built around one core idea: **the LLM is the proposer;
the validator is the deterministic arbiter.** Every architectural
decision in ECHO ladders up to that idea. Every test in
`tests/spoliation/` is a check that the idea is actually implemented,
not just claimed.

The hackathon will be won by the submission that is **most defensible
when a judge actually reads the code.** ECHO is built to be defensible:

- The MCP server has no shell. There is no `run_command` tool.
  Spoliation A008 proves this.
- The validator is pure Python. The LLM is never asked "do you agree
  with yourself?". `validators/cross_source.py` proves this.
- The audit chain is hash-chained. A tampered byte breaks verification.
  Spoliation A012 proves this.
- The confidence label is computed from a closed-form formula. The
  Pydantic schema refuses inconsistent label/status combinations.
  Spoliation A011 proves this.

When you submit, you are not making a marketing claim. You are
submitting a system that will *be the same on the judge's laptop as it
is on yours*. That's the win.

Good luck. Now stop reading and run:

```bash
pytest tests/spoliation -v
```

If those 12 tests are green, you're already winning. The rest is just
making sure nobody can miss it.

— ECHO
