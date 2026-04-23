"""sast command — run Semgrep SAST rules against MCP server source code."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from mcp_audit.cli import app, console

# ── sast ──────────────────────────────────────────────────────────────────────


@app.command()
def sast(
    target: Path = typer.Argument(  # noqa: B008
        ..., help="Directory or file to scan with Semgrep SAST rules"
    ),
    rules_dir: Path | None = typer.Option(  # noqa: B008
        None,
        "--rules-dir",
        help="Override the default semgrep-rules/ directory",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json",
    ),
) -> None:
    """Scan MCP server source code with Semgrep SAST rules.

    Requires semgrep to be installed: pip install semgrep

    Exit codes: 0 = no findings, 1 = findings found, 2 = error.
    """
    from mcp_audit.sast.runner import (  # noqa: PLC0415
        SastResult,
        find_semgrep,
        run_semgrep,
    )

    if find_semgrep() is None:
        console.print(
            "[red]semgrep is not installed.[/red]\n"
            "   Install it with: [bold]pip install semgrep[/bold]"
        )
        raise typer.Exit(2)  # noqa: B904

    if not target.exists():
        console.print(f"[red]Path does not exist:[/red] {target}")
        raise typer.Exit(2)  # noqa: B904

    console.print(f"[dim]Scanning {target} with Semgrep SAST rules…[/dim]")
    sast_result: SastResult = run_semgrep(target_path=target, rules_dir=rules_dir)

    if sast_result.error:
        console.print(f"[red]SAST error:[/red] {sast_result.error}")
        raise typer.Exit(2)  # noqa: B904

    findings = sast_result.findings

    if output_format == "json":
        import json as _json  # noqa: PLC0415

        typer.echo(_json.dumps([f.model_dump() for f in findings], indent=2))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    if not findings:
        console.print("[green]✓ No SAST findings.[/green]")
        return

    table = Table(
        "File",
        "Line",
        "Rule",
        "Severity",
        "Message",
        show_header=True,
        header_style="bold",
    )
    import contextlib  # noqa: PLC0415
    import json as _json  # noqa: PLC0415

    for f in findings:
        evidence: dict = {}
        with contextlib.suppress(Exception):
            evidence = _json.loads(f.evidence)
        file_short = Path(evidence.get("file", f.server)).name
        line = str(evidence.get("line", ""))
        sev_colour = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "blue",
            "INFO": "dim",
        }.get(f.severity.value, "white")
        table.add_row(
            file_short,
            line,
            f.title,
            f"[{sev_colour}]{f.severity.value}[/{sev_colour}]",
            f.description[:80],
        )

    console.print(table)
    console.print(
        f"\n[bold]{len(findings)} finding(s)[/bold] across "
        f"{sast_result.files_scanned} file(s)"
    )
    raise typer.Exit(1)  # noqa: B904
