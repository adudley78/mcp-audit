"""agent-files sub-app: discover / scan agent instruction and memory files."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from mcp_audit.cli import agent_files_app, console

# ── agent-files discover ───────────────────────────────────────────────────────


@agent_files_app.command("discover")
def agent_files_discover(
    project: Path | None = typer.Option(  # noqa: B008
        None,
        "--project",
        help=(
            "Walk this directory tree for project-level agent files"
            " (.claude/commands/, .cursor/rules/, .github/ subtrees)."
        ),
        exists=False,
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json",
    ),
) -> None:
    """Discover agent instruction and memory files across supported AI clients."""
    import json as _json  # noqa: PLC0415

    from mcp_audit.agent_files.discovery import discover_agent_files  # noqa: PLC0415

    project_root: Path | None = None
    if project is not None:
        project_root = project.resolve()
        if not project_root.exists():
            console.print(f"[red]Error:[/red] --project path not found: {project}")
            raise typer.Exit(2)
        if not project_root.is_dir():
            console.print(f"[red]Error:[/red] --project must be a directory: {project}")
            raise typer.Exit(2)

    files = discover_agent_files(project_root=project_root)

    if output_format == "json":
        typer.echo(
            _json.dumps(
                [
                    {
                        "path": str(f.path),
                        "surface": f.surface.value,
                        "client": f.client,
                        "scope": f.scope,
                        "size_chars": len(f.raw_content),
                    }
                    for f in files
                ],
                indent=2,
            )
        )
        return

    summary = (
        f"Found [bold]{len(files)}[/bold] agent file(s) "
        f"across [bold]{len({f.client for f in files})}[/bold] client(s)"
    )

    if not files:
        console.print(summary)
        return

    table = Table(
        "Client",
        "Surface",
        "Scope",
        "File",
        "Size",
        show_header=True,
        header_style="bold",
    )
    for f in files:
        table.add_row(
            f.client,
            f.surface.value,
            f.scope,
            str(f.path),
            f"{len(f.raw_content):,} chars",
        )
    console.print(table)
    console.print(f"\n{summary}")


# ── agent-files scan ───────────────────────────────────────────────────────────


@agent_files_app.command("scan")
def agent_files_scan(
    project: Path | None = typer.Option(  # noqa: B008
        None,
        "--project",
        help=(
            "Walk this directory tree for project-level agent files"
            " (.claude/commands/, .cursor/rules/, .github/ subtrees)."
        ),
        exists=False,
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif",
    ),
) -> None:
    """Scan agent instruction and memory files for security issues."""
    import json as _json  # noqa: PLC0415

    from mcp_audit.agent_files.analyzer import analyze_agent_files  # noqa: PLC0415
    from mcp_audit.agent_files.discovery import discover_agent_files  # noqa: PLC0415

    project_root: Path | None = None
    if project is not None:
        project_root = project.resolve()
        if not project_root.exists():
            console.print(f"[red]Error:[/red] --project path not found: {project}")
            raise typer.Exit(2)
        if not project_root.is_dir():
            console.print(f"[red]Error:[/red] --project must be a directory: {project}")
            raise typer.Exit(2)

    files = discover_agent_files(project_root=project_root)
    findings = analyze_agent_files(files)

    if output_format == "json":
        typer.echo(_json.dumps([f.model_dump() for f in findings], indent=2))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    if output_format == "sarif":
        from mcp_audit.models import ScanResult  # noqa: PLC0415
        from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

        _mock_result = ScanResult(findings=findings)
        typer.echo(format_sarif(_mock_result))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    # Terminal output
    if not findings:
        console.print(
            f"[green]✓ No issues found[/green] in {len(files)} agent file(s)."
        )
        return

    sev_colour = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "cyan",
        "LOW": "blue",
        "INFO": "dim",
    }
    table = Table(
        "File",
        "Client",
        "Severity",
        "Finding",
        show_header=True,
        header_style="bold",
        border_style="blue",
    )
    for f in findings:
        colour = sev_colour.get(f.severity.value, "white")
        table.add_row(
            f.server,
            f.client,
            f"[{colour}]{f.severity.value}[/{colour}]",
            f.title,
        )
    console.print(table)
    console.print(
        f"\n[bold]{len(findings)} finding(s)[/bold] across {len(files)} agent file(s)"
    )
    raise typer.Exit(1)  # noqa: B904
