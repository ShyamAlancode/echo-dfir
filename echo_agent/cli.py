"""
ECHO command-line interface.

Subcommands:
    echo run    --case-id CASE_001 [--max-iter 8] [--budget 60000]
    echo verify --case-id CASE_001
    echo replay --case-id CASE_001
    echo benchmark --gt validators/ground_truth/CASE_001.json
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import orjson
import typer
from rich.console import Console
from rich.table import Table

from echo_agent.audit import verify_chain
from echo_agent.graph import run_case

app = typer.Typer(
    no_args_is_help=True,
    help="ECHO — Evidence-Correlating Hallucination-Observed DFIR agent.",
    rich_markup_mode=None,
)

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


# -------------------------------------------------------------- RUN ----


@app.command()
def run(
    case_id: str = typer.Option(..., "--case-id", help="Case identifier."),
    max_iter: int = typer.Option(8, "--max-iter"),
    budget: int = typer.Option(60_000, "--budget", help="Token budget."),
    wall_clock: int = typer.Option(900, "--wall-clock", help="Max wall-clock seconds."),
    audit_dir: Path = typer.Option(Path("audit"), "--audit-dir"),
    findings_dir: Path = typer.Option(Path("findings"), "--findings-dir"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run ECHO end-to-end on one case."""
    _setup_logging(verbose)
    audit_log = audit_dir / f"{case_id}_iterations.jsonl"
    audit_dir.mkdir(parents=True, exist_ok=True)
    findings_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan]ECHO[/] running case [bold]{case_id}[/]")
    console.print(f"  audit log : {audit_log}")
    console.print(f"  findings  : {findings_dir}")
    console.print(f"  caps      : iter={max_iter} tokens={budget} wallclock={wall_clock}s")

    final_state = run_case(
        case_id=case_id,
        case_outdir=findings_dir,
        audit_log_path=audit_log,
        max_iter=max_iter,
        budget_tokens=budget,
        wall_clock_max_seconds=wall_clock,
    )

    table = Table(title=f"ECHO Run Summary — {case_id}", show_lines=True)
    table.add_column("Metric"); table.add_column("Value")
    table.add_row("Iterations run", str(final_state.iter))
    table.add_row("Tokens used", f"{final_state.tokens_used} / {final_state.budget_tokens}")
    table.add_row("Findings", str(len(final_state.findings)))
    table.add_row(
        "Confirmed",
        str(sum(1 for f in final_state.findings if f.status == "confirmed")),
    )
    table.add_row(
        "Low confidence",
        str(sum(1 for f in final_state.findings if f.status == "low_confidence")),
    )
    table.add_row("Contradictions", str(len(final_state.contradictions)))
    table.add_row("Halt reason", final_state.halt_reason or "completed")
    console.print(table)

    ok, msg = verify_chain(audit_log)
    style = "green" if ok else "red"
    console.print(f"[{style}]audit chain: {msg}[/]")


# ----------------------------------------------------------- VERIFY ----


@app.command()
def verify(
    case_id: str = typer.Option(..., "--case-id"),
    audit_dir: Path = typer.Option(Path("audit"), "--audit-dir"),
) -> None:
    """Verify the SHA-256 Merkle chain of an audit log."""
    log_path = audit_dir / f"{case_id}_iterations.jsonl"
    ok, msg = verify_chain(log_path)
    if ok:
        console.print(f"[green]✓ audit chain verified — {msg}[/]")
        raise typer.Exit(0)
    console.print(f"[red]✗ audit chain FAILED — {msg}[/]")
    raise typer.Exit(1)


# ----------------------------------------------------------- REPLAY ----


@app.command()
def replay(
    case_id: str = typer.Option(..., "--case-id"),
    audit_dir: Path = typer.Option(Path("audit"), "--audit-dir"),
) -> None:
    """Stream a recorded run for deterministic demos / judges."""
    log_path = audit_dir / f"{case_id}_iterations.jsonl"
    if not log_path.exists():
        console.print(f"[red]no audit log at {log_path}[/]")
        raise typer.Exit(1)

    table = Table(title=f"ECHO Replay — {case_id}", show_lines=False)
    for col in ("iter", "node", "phase", "tokens", "tool", "rows", "this_hash[:12]"):
        table.add_column(col)

    with log_path.open("rb") as f:
        for line in f:
            if not line.strip():
                continue
            entry = orjson.loads(line)
            tc = entry.get("tool_call") or {}
            trs = entry.get("tool_result_summary") or {}
            table.add_row(
                str(entry["iter"]),
                entry["node"],
                entry["phase"],
                str(entry.get("tokens_used", 0)),
                str(tc.get("tool", "")),
                str(trs.get("rows", "")),
                entry["this_hash"][:12],
            )
    console.print(table)


# ---------------------------------------------------------- BENCHMARK --


@app.command()
def benchmark(
    findings_path: Path = typer.Option(..., "--findings"),
    ground_truth: Path = typer.Option(..., "--gt"),
) -> None:
    """Score findings.json vs ground truth (P/R/F1)."""
    from validators.run_benchmark import score_against_ground_truth
    summary = score_against_ground_truth(findings_path, ground_truth)
    console.print_json(data=summary)


if __name__ == "__main__":
    app()
