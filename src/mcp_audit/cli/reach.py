"""The ``reach`` command: what can the agents on this machine touch? (STORY-0145).

``mcp-audit reach`` runs one default scan (no explicit path, no rug-pull state
written) and the settings readers in :mod:`mcp_audit.reach`, and prints one
card per agent: where it runs, whose credentials it can read, what it can reach
on the network, whether policy is enforced, whether activity is logged, and a
verdict against the sanctioned path.  Static and offline; nothing is executed.

``--path`` is not accepted: this is a machine view.  ``--fleet DIR`` reads
saved ``reach --format json`` files instead of scanning.

Exit codes: 0 when every agent is ready or couldn't-check-only (or none was
found), 1 when any agent needs work or is not safe to allow, 2 error.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import date
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console

from mcp_audit.cli import app, run_scan
from mcp_audit.cli._helpers import _write_output
from mcp_audit.output.reach import print_fleet, print_reach

err_console = Console(stderr=True)


class _Format(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"


def _fail(message: str) -> typer.Exit:
    err_console.print(f"[red]Error:[/red] {message}", highlight=False)
    return typer.Exit(2)


def _shared_registry(analyzers: list) -> object | None:
    """The registry the supply-chain analyzer loaded, for ``tag_server``."""
    from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer  # noqa: PLC0415

    for analyzer in analyzers:
        if isinstance(analyzer, SupplyChainAnalyzer):
            return analyzer.registry
    return None


def _write_pdf(report, output_file: Path | None, org: str | None) -> Path:  # noqa: ANN001
    """Write the one-page-per-machine PDF; return where it went."""
    from mcp_audit.cli.check import _resolve_org_name  # noqa: PLC0415
    from mcp_audit.output.reach_pdf import ReachPdfFormatter  # noqa: PLC0415

    target = output_file or Path(f"mcp-audit-reach-{date.today().isoformat()}.pdf")
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    pdf = ReachPdfFormatter(report, org_name=_resolve_org_name(org)).generate()
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pdf)
    finally:
        os.close(fd)
    return target


def _run_fleet(fleet: Path, fmt: _Format, output_file: Path | None) -> None:
    from mcp_audit.reach.fleet import load_fleet  # noqa: PLC0415

    if not fleet.is_dir():
        raise _fail(f"--fleet takes a directory of reach JSON files: {fleet}")
    try:
        roll_up = load_fleet(fleet)
    except OSError as exc:
        raise _fail(
            f"cannot read {fleet}: {exc.strerror or type(exc).__name__}"
        ) from None
    if fmt is _Format.JSON:
        text = json.dumps(roll_up.to_dict(), indent=2) + "\n"
        if output_file is not None:
            _write_output(output_file, text)
        else:
            sys.stdout.write(text)
    else:
        print_fleet(roll_up, Console())
    raise typer.Exit(roll_up.exit_code)


@app.command("reach")
def reach(
    fmt: _Format = typer.Option(  # noqa: B008
        _Format.TERMINAL,
        "--format",
        "-f",
        help="Output format: terminal (default) or json (docs/reach.schema.json).",
    ),
    report: str | None = typer.Option(  # noqa: B008
        None,
        "--report",
        help="Write a one-page-per-machine report. Currently supported: pdf.",
    ),
    output_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--output-file",
        "-o",
        help="Where to write the JSON or the PDF (JSON goes to stdout by default).",
    ),
    org: str | None = typer.Option(  # noqa: B008
        None, "--org", help="Organisation name printed in the PDF."
    ),
    fleet: Path | None = typer.Option(  # noqa: B008
        None,
        "--fleet",
        help=(
            "Roll up a directory of reach --format json files (one per machine)"
            " instead of scanning this machine."
        ),
    ),
) -> None:
    """What can the agents on this machine touch? One card per agent.

    Reads settings files and one default scan; never runs an agent. Exits 1
    when any agent needs work or is not safe to allow.
    """
    if report is not None and report.lower() != "pdf":
        raise _fail(f"unsupported --report format {report!r}. Currently supported: pdf")
    if fleet is not None:
        if report is not None:
            raise _fail("--report pdf is per machine; drop --fleet or --report")
        _run_fleet(fleet, fmt, output_file)

    from mcp_audit.reach import build_machine_reach  # noqa: PLC0415
    from mcp_audit.scanner import get_default_analyzers  # noqa: PLC0415

    try:
        analyzers = get_default_analyzers()
        result = run_scan(
            analyzers=analyzers, skip_rug_pull=True, offline=True, connect=False
        )
        machine = build_machine_reach(result, registry=_shared_registry(analyzers))
    except Exception as exc:  # noqa: BLE001 — the CLI turns any failure into exit 2
        raise _fail(f"reach failed: {type(exc).__name__}") from None

    if report is not None:
        try:
            target = _write_pdf(machine, output_file, org)
        except Exception as exc:  # noqa: BLE001
            raise _fail(f"PDF generation error: {type(exc).__name__}") from None
        console = Console()
        console.print(f"[green]PDF report written:[/green] {target}", highlight=False)
        console.print(machine.summary_line(), highlight=False)
    elif fmt is _Format.JSON:
        text = json.dumps(machine.to_dict(), indent=2) + "\n"
        if output_file is not None:
            _write_output(output_file, text)
        else:
            sys.stdout.write(text)
    else:
        print_reach(machine, Console())
    raise typer.Exit(machine.exit_code)
