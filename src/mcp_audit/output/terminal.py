"""Rich-formatted terminal output for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_audit.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange1",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def print_results(result: ScanResult, console: Console | None = None) -> None:
    """Print scan results to the terminal with Rich formatting."""
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print("[bold]mcp-audit[/bold] v0.1.0 — MCP Security Scanner", style="cyan")
    console.print()

    # Summary
    console.print(
        f"Scanned [bold]{result.clients_scanned}[/bold] client(s), "
        f"[bold]{result.servers_found}[/bold] server(s) found"
    )
    console.print()

    if not result.findings:
        console.print(Panel("✅ No security issues found", style="green"))
        return

    # Findings summary
    counts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        n = sum(1 for f in result.findings if f.severity == sev)
        if n > 0:
            color = SEVERITY_COLORS[sev]
            counts.append(f"[{color}]{n} {sev.value.lower()}[/{color}]")

    console.print(Panel(
        f"[bold]{len(result.findings)} finding(s):[/bold] {', '.join(counts)}",
        style="red" if result.critical_count > 0 else "yellow",
    ))
    console.print()

    # Individual findings
    sorted_findings = sorted(result.findings, key=lambda f: list(Severity).index(f.severity))
    for finding in sorted_findings:
        color = SEVERITY_COLORS[finding.severity]
        icon = SEVERITY_ICONS[finding.severity]

        console.print(
            f"{icon} [{color} bold]{finding.severity.value}[/{color} bold]  "
            f"[dim]{finding.analyzer}[/dim]  "
            f"{finding.client}/{finding.server}"
        )
        console.print(f"   {finding.title}")
        console.print(f"   [dim]→ {finding.evidence}[/dim]")
        console.print(f"   [italic]ℹ {finding.remediation}[/italic]")
        console.print()

    # Errors
    if result.errors:
        console.print("[yellow bold]Errors:[/yellow bold]")
        for error in result.errors:
            console.print(f"  ⚠ {error}", style="yellow")
