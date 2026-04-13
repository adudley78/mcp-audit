"""Rich-formatted terminal output for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from mcp_audit.models import AttackPathSummary, ScanResult, Severity

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


def _print_attack_path_summary(
    summary: AttackPathSummary, console: Console
) -> None:
    """Print the attack path summary panel before the detailed findings list.

    Shows the top-3 paths (by severity) with plain-English descriptions,
    then a highlighted recommendation based on the hitting set.
    """
    if not summary.paths:
        return

    total = len(summary.paths)
    console.print(Rule("[bold red]Attack Path Analysis[/bold red]"))
    console.print()

    top_paths = summary.paths[:3]  # Already sorted by severity.
    for path in top_paths:
        color = SEVERITY_COLORS[path.severity]
        icon = SEVERITY_ICONS[path.severity]
        hop_chain = " → ".join(path.hops)
        console.print(
            f"{icon} [{color} bold]{path.id}[/{color} bold]  "
            f"[bold]{path.title}[/bold]"
        )
        console.print(f"   [dim]Chain:[/dim] {hop_chain}")
        console.print(f"   {path.description}")
        console.print()

    if total > 3:
        console.print(
            "   [dim]… and "
            f"{total - 3} more path(s) — see JSON output for full list.[/dim]"
        )
        console.print()

    # Hitting-set recommendation.
    if summary.hitting_set:
        hs = summary.hitting_set
        # Find the single best server to highlight in the summary line.
        best = hs[0]
        broken_count = len(summary.paths_broken_by.get(best, []))
        if len(hs) == 1:
            rec_text = (
                f"Remove [bold yellow]'{best}'[/bold yellow] to break "
                f"[bold]{broken_count}[/bold] of [bold]{total}[/bold] attack path(s)."
            )
        else:
            others = ", ".join(f"'{s}'" for s in hs[1:])
            rec_text = (
                f"Remove [bold yellow]'{best}'[/bold yellow] to break "
                f"[bold]{broken_count}[/bold] of [bold]{total}[/bold] attack path(s). "
                f"Also remove {others} to eliminate all remaining paths."
            )
        console.print(
            Panel(
                Text.from_markup(f"[bold]Recommendation:[/bold] {rec_text}"),
                style="yellow",
                title="[bold]Minimum Hitting Set[/bold]",
            )
        )
    console.print()


def print_results(result: ScanResult, console: Console | None = None) -> None:
    """Print scan results to the terminal with Rich formatting."""
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print("[bold]mcp-audit[/bold] v0.1.0 — MCP Security Scanner", style="cyan")
    console.print(
        f"Machine: {result.machine.hostname} "
        f"({result.machine.username}@{result.machine.os})",
        style="dim",
    )
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

    # Attack path summary — printed before individual findings.
    if result.attack_path_summary and result.attack_path_summary.paths:
        _print_attack_path_summary(result.attack_path_summary, console)

    # Findings summary
    counts = []
    for sev in [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        Severity.LOW, Severity.INFO,
    ]:
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
    sorted_findings = sorted(
        result.findings, key=lambda f: list(Severity).index(f.severity)
    )
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
