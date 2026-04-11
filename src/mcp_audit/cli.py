"""mcp-audit CLI — MCP Security Scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from mcp_audit.discovery import discover_configs
from mcp_audit.output.terminal import print_results
from mcp_audit.scanner import run_scan
from mcp_audit.models import Severity

app = typer.Typer(
    name="mcp-audit",
    help="Privacy-first security scanner for MCP server configurations.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Scan a specific config file or directory"),
    format: str = typer.Option("terminal", "--format", "-f", help="Output format: terminal, json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write results to file"),
    severity_threshold: str = typer.Option("INFO", "--severity-threshold", "-s", help="Minimum severity to report"),
    offline: bool = typer.Option(False, "--offline", help="Skip all network calls"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: minimal output, exit code on findings"),
    json_flag: bool = typer.Option(False, "--json", help="Shortcut for --format json"),
) -> None:
    """Scan MCP configurations for security issues."""
    extra_paths = [path] if path else None
    fmt = "json" if json_flag else format

    result = run_scan(extra_paths=extra_paths)

    # Filter by severity threshold
    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2)

    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    threshold_idx = severity_order.index(threshold)
    result.findings = [f for f in result.findings if severity_order.index(f.severity) <= threshold_idx]

    # Output
    if fmt == "json":
        json_str = result.model_dump_json(indent=2)
        if output:
            output.write_text(json_str)
        else:
            typer.echo(json_str)
    else:
        print_results(result, console=console)

    # Exit code
    if result.has_findings:
        raise typer.Exit(1)


@app.command()
def discover(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Additional path to check"),
    json_flag: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """List all detected MCP clients and server configurations."""
    extra_paths = [path] if path else None
    configs = discover_configs(extra_paths=extra_paths)

    if json_flag:
        data = [{"client": c.client_name, "path": str(c.path)} for c in configs]
        typer.echo(json.dumps(data, indent=2))
        return

    if not configs:
        console.print("[yellow]No MCP configurations found on this machine.[/yellow]")
        return

    console.print(f"\n[bold]Found {len(configs)} MCP configuration(s):[/bold]\n")
    for config in configs:
        console.print(f"  [cyan]{config.client_name}[/cyan]  {config.path}")
    console.print()


@app.command()
def version() -> None:
    """Show version information."""
    console.print("mcp-audit v0.1.0")


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
