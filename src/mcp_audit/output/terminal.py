"""Rich-formatted terminal output for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from mcp_audit import __version__
from mcp_audit.models import AttackPathSummary, RegistryStats, ScanResult, Severity
from mcp_audit.scoring import format_grade_terminal

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


def _print_attack_path_summary(summary: AttackPathSummary, console: Console) -> None:
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
            f"{icon} [{color} bold]{path.id}[/{color} bold]  [bold]{path.title}[/bold]"
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


def _format_registry_stats(stats: RegistryStats) -> str:
    """Return a dim-styled Rich markup string for the registry stats line.

    Args:
        stats: Registry metadata from the scan result.

    Returns:
        Rich markup string ready for ``console.print``.
    """
    return (
        f"[dim]Registry: {stats.entry_count} known servers "
        f"(v{stats.schema_version}, updated {stats.last_updated})[/dim]"
    )


def print_results(
    result: ScanResult,
    console: Console | None = None,
    show_score: bool = True,
) -> None:
    """Print scan results to the terminal with Rich formatting.

    Args:
        result: Completed scan result.
        console: Rich console to write to.  A new one is created if omitted.
        show_score: When ``False``, the score/grade panel is suppressed.
    """
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print(
        f"[bold]mcp-audit[/bold] v{__version__} — MCP Security Scanner",
        style="cyan",
    )
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

    # Registry stats — muted one-liner; always shown when available
    if result.registry_stats is not None:
        console.print(_format_registry_stats(result.registry_stats))

    console.print()

    if not result.findings:
        if result.findings_below_threshold > 0 and result.active_severity_threshold:
            threshold = result.active_severity_threshold
            count = result.findings_below_threshold
            msg = (
                f"✅ No findings at or above {threshold} severity "
                f"({count} finding(s) below threshold — see score panel)"
            )
            console.print(Panel(msg, style="green"))
        else:
            console.print(Panel("✅ No security issues found", style="green"))
        if show_score and result.score is not None:
            console.print()
            console.print(
                Panel(
                    format_grade_terminal(result.score),
                    style="green",
                )
            )
        return

    # Attack path summary — printed before individual findings.
    if result.attack_path_summary and result.attack_path_summary.paths:
        _print_attack_path_summary(result.attack_path_summary, console)

    # Findings summary
    counts = []
    for sev in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        n = sum(1 for f in result.findings if f.severity == sev)
        if n > 0:
            color = SEVERITY_COLORS[sev]
            counts.append(f"[{color}]{n} {sev.value.lower()}[/{color}]")

    console.print(
        Panel(
            f"[bold]{len(result.findings)} finding(s):[/bold] {', '.join(counts)}",
            style="red" if result.critical_count > 0 else "yellow",
        )
    )
    console.print()

    # Individual findings
    sorted_findings = sorted(
        result.findings, key=lambda f: list(Severity).index(f.severity)
    )
    for finding in sorted_findings:
        color = SEVERITY_COLORS[finding.severity]
        icon = SEVERITY_ICONS[finding.severity]

        # Show OWASP MCP codes inline when mapped (e.g. "[MCP03, MCP06]")
        owasp_badge = ""
        if finding.owasp_mcp_top_10:
            codes = ", ".join(finding.owasp_mcp_top_10)
            owasp_badge = f"  [dim cyan]\\[{codes}][/dim cyan]"

        cve_badge = ""
        if finding.cve:
            cve_ids = ", ".join(finding.cve)
            cve_badge = f"  [dim red]\\[{cve_ids}][/dim red]"

        console.print(
            f"{icon} [{color} bold]{finding.severity.value}[/{color} bold]  "
            f"[dim]{finding.analyzer}[/dim]  "
            f"{finding.client}/{finding.server}"
            f"{owasp_badge}"
            f"{cve_badge}"
        )
        console.print(f"   {finding.title}")
        console.print(f"   [dim]→ {finding.evidence}[/dim]")
        console.print(f"   [italic]ℹ {finding.remediation}[/italic]")
        console.print()

    # Policy violations panel — distinct from security findings
    gov_findings = [f for f in result.findings if f.analyzer == "governance"]
    if gov_findings:
        console.print()
        gov_lines = []
        sev_counts: dict[str, int] = {}
        for gf in gov_findings:
            sev_counts[gf.severity.value] = sev_counts.get(gf.severity.value, 0) + 1
        sev_summary = ", ".join(
            f"{count} {sev.lower()}" for sev, count in sev_counts.items()
        )
        gov_lines.append(
            f"[bold]{len(gov_findings)} policy violation(s):[/bold] {sev_summary}"
        )
        for gf in gov_findings:
            color = SEVERITY_COLORS[gf.severity]
            gov_lines.append(
                f"  [dim]{gf.client}/{gf.server}[/dim]  [{color}]{gf.title}[/{color}]"
            )
        console.print(
            Panel(
                "\n".join(gov_lines),
                title="[bold yellow]Policy Violations[/bold yellow]",
                style="yellow",
            )
        )

    # Score panel — after findings, before errors
    if show_score and result.score is not None:
        console.print()
        console.print(
            Panel(
                format_grade_terminal(result.score),
                style="green"
                if result.score.grade in ("A", "B")
                else ("yellow" if result.score.grade in ("C", "D") else "red"),
            )
        )

    # Errors
    if result.errors:
        console.print("[yellow bold]Errors:[/yellow bold]")
        for error in result.errors:
            console.print(f"  ⚠ {error}", style="yellow")
