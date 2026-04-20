"""fleet merge command — consolidate JSON scan outputs from multiple machines."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from mcp_audit._gate import gate
from mcp_audit.cli import app, console
from mcp_audit.cli._helpers import _write_output

# ── Private helpers ───────────────────────────────────────────────────────────


def _collect_json_paths_from_dir(directory: Path) -> list[Path]:
    """Return all ``*.json`` files in *directory* (non-recursive).

    Silently skips non-JSON files.  Logs a warning and skips files that fail
    mcp-audit JSON validation so that a single corrupt file does not abort the
    entire merge operation.
    """
    from mcp_audit.fleet.merger import FleetMerger  # noqa: PLC0415

    json_files = sorted(directory.glob("*.json"))
    valid: list[Path] = []
    _tmp_merger = FleetMerger()
    for path in json_files:
        try:
            _tmp_merger.load_report(path)
            valid.append(path)
        except ValueError as exc:
            console.print(f"[yellow]Warning: skipping {path.name}: {exc}[/yellow]")
    return valid


def _print_fleet_report(report: object, con: Console) -> None:
    """Render a FleetReport to the terminal using Rich tables."""
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415

    from mcp_audit.fleet.merger import FleetReport as _FleetReport  # noqa: PLC0415
    from mcp_audit.models import Severity  # noqa: PLC0415

    if not isinstance(report, _FleetReport):
        return

    s = report.stats
    score_line = f"{s.average_score:.1f}/100" if s.average_score is not None else "N/A"

    lines: list[str] = [
        f"[bold]Total machines scanned:[/bold] {s.total_machines}",
        f"[bold]Total findings:[/bold]         {s.total_findings}",
        f"[bold]Unique findings:[/bold]         {s.unique_findings}",
        f"[bold]Average config score:[/bold]    {score_line}",
    ]

    if s.riskiest_machine:
        risk_count = sum(
            1
            for m in report.machines
            if m.machine_id == s.riskiest_machine
            for f in m.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        lines.append(
            f"[bold]Riskiest machine:[/bold]        [red]{s.riskiest_machine}[/red] "
            f"({risk_count} critical/high finding{'s' if risk_count != 1 else ''})"
        )

    if s.most_common_finding and report.deduplicated_findings:
        top = report.deduplicated_findings[0]
        lines.append(
            f"[bold]Most widespread issue:[/bold]   {s.most_common_finding} "
            f"(affects {top.affected_count}/{s.total_machines} machines)"
        )

    con.print(Panel("\n".join(lines), title="Fleet Summary", border_style="cyan"))

    if not report.deduplicated_findings:
        con.print("[green]No findings across fleet.[/green]")
        return

    _SEV_STYLE = {  # noqa: N806
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[blue]LOW[/blue]",
        "INFO": "[dim]INFO[/dim]",
    }

    table = Table(show_header=True, header_style="bold", title="Finding Breakdown")
    table.add_column("Severity", width=10)
    table.add_column("Finding")
    table.add_column("Affected Machines", justify="center", width=20)
    table.add_column("First Seen", width=20)

    for df in report.deduplicated_findings:
        sev_display = _SEV_STYLE.get(df.severity.value, df.severity.value)
        machines_display = f"{df.affected_count}/{s.total_machines} machines"
        first_seen_str = df.first_seen.strftime("%Y-%m-%d %H:%M")
        table.add_row(sev_display, df.title, machines_display, first_seen_str)

    con.print(table)


# ── merge ─────────────────────────────────────────────────────────────────────


@app.command()
def merge(
    files: list[Path] | None = typer.Argument(  # noqa: B008
        default=None,
        help="One or more JSON scan output files to merge",
    ),
    dir_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--dir",
        help=(
            "Merge all .json files found in DIRECTORY (non-recursive). "
            "Cannot combine with FILES."
        ),
    ),
    asset_prefix: str | None = typer.Option(  # noqa: B008
        None,
        "--asset-prefix",
        help=(
            "Only include machines whose hostname starts with PREFIX. "
            "Example: --asset-prefix prod- to include only prod machines."
        ),
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal (default), json, html",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "--output-file",
        "-o",
        help="Write output to file instead of stdout",
    ),
) -> None:
    """Merge JSON scan outputs from multiple machines into a fleet report.

    Requires an Enterprise license.

    Examples:

        mcp-audit merge results/*.json

        mcp-audit merge --dir ./fleet-results/ --format json -o fleet.json

        mcp-audit merge --dir ./results/ --asset-prefix prod-
    """
    from mcp_audit.fleet.merger import FleetMerger, generate_fleet_html  # noqa: PLC0415

    if not gate("fleet_merge", console):
        raise typer.Exit(0)  # noqa: B904

    if dir_path is not None and files:
        console.print("[red]Cannot combine FILES arguments with --dir.[/red]")
        raise typer.Exit(2)  # noqa: B904

    if dir_path is not None:
        if not dir_path.is_dir():
            console.print(f"[red]--dir path is not a directory: {dir_path}[/red]")
            raise typer.Exit(2)  # noqa: B904
        paths = _collect_json_paths_from_dir(dir_path)
        if not paths:
            console.print(f"[red]No .json files found in {dir_path}[/red]")
            raise typer.Exit(2)  # noqa: B904
    elif files:
        paths = list(files)
    else:
        console.print(
            "[red]Provide at least one scan file, or use --dir DIRECTORY.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    merger = FleetMerger(asset_prefix_filter=asset_prefix)

    try:
        report = merger.merge(paths)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)  # noqa: B904

    if report.version_mismatches:
        for warning in report.version_mismatches:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

    if output_format == "json":
        out = report.model_dump_json(indent=2)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif output_format == "html":
        out = generate_fleet_html(report)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif output_format == "terminal":
        _print_fleet_report(report, console)
    else:
        console.print(
            f"[red]Unknown format: {output_format!r}. "
            "Choose terminal, json, or html.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    if report.stats.total_findings > 0:
        raise typer.Exit(1)
