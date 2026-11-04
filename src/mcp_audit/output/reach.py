"""Terminal output for ``mcp-audit reach`` (STORY-0145).

Reads :meth:`MachineReach.to_dict`, the same sanitised document the JSON output
and the PDF use, so a string reaches the screen only after credential
redaction and home masking.  Every dynamic string is escaped for Rich markup
(a config can name a server ``[red]x``).
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from mcp_audit.reach.fleet import FleetReport
from mcp_audit.reach.models import QUESTION_IDS, VERDICT_LABELS, MachineReach, Verdict

_VERDICT_STYLE = {
    Verdict.READY.value: "bold green",
    Verdict.NEEDS_WORK.value: "bold yellow",
    Verdict.NOT_SAFE.value: "bold red",
    Verdict.COULDNT_CHECK.value: "bold cyan",
}
_STATUS_TAG = {
    "pass": "[green]PASS[/green]",
    "fail": "[red]FAIL[/red]",
    "couldnt_check": "[cyan]COULDN'T CHECK[/cyan]",
    "info": "[dim]INFO[/dim]",
}
_FLEET_HEADERS = {
    Verdict.NOT_SAFE: "Not safe to allow",
    Verdict.NEEDS_WORK: "Needs work",
    Verdict.COULDNT_CHECK: "Couldn't check",
    Verdict.READY: "Ready",
}
_KIND_TAG = {
    "not_safe": "[red]not safe[/red]",
    "needs_work": "[yellow]needs work[/yellow]",
    "unknown": "[cyan]couldn't check[/cyan]",
}


def verdict_label(value: str) -> str:
    """Display label of a verdict value (``needs_work`` -> ``NEEDS WORK``)."""
    try:
        return VERDICT_LABELS[Verdict(value)]
    except ValueError:
        return value.upper()


def print_reach(report: MachineReach, console: Console) -> None:
    """Print one panel per agent and the machine summary line."""
    doc = report.to_dict()
    machine = doc["machine"]
    console.print(
        f"[bold]mcp-audit reach[/bold]  [dim]{escape(machine['hostname'])}"
        f" ({escape(machine['os'])})[/dim]"
    )
    if not doc["agents"]:
        console.print(
            "No agents found on this machine: no MCP client config, Claude Code,"
            " Codex or Gemini CLI settings were discovered."
        )
        _print_errors(console, doc["errors"])
        return
    for agent in doc["agents"]:
        console.print(_panel(agent))
    console.print(f"[bold]{escape(report.summary_line())}[/bold]")
    _print_errors(console, doc["errors"])
    console.print(
        "[dim]Static read of settings files and the default scan; nothing was"
        " run. Details: docs/reach.md[/dim]"
    )


def _panel(agent: dict) -> Panel:
    verdict = agent["verdict"]
    style = _VERDICT_STYLE.get(verdict, "bold")
    title = (
        f"[bold]{escape(agent['name'])}[/bold]  "
        f"[{style}]{escape(verdict_label(verdict))}[/{style}]"
    )
    body = Table.grid(padding=(0, 1))
    body.add_column(no_wrap=True)
    body.add_column(ratio=1)
    for qid in QUESTION_IDS:
        q = agent["questions"].get(qid)
        if q is None:
            continue
        body.add_row(
            _STATUS_TAG.get(q["status"], escape(q["status"])),
            f"[bold]{escape(q['title'])}[/bold] {escape(q['summary'])}",
        )
    if agent["reasons"]:
        body.add_row("", "")
        body.add_row("", "[bold]Why[/bold]")
        for reason in agent["reasons"]:
            refs = ", ".join(reason["refs"])
            tail = f" [dim]({escape(refs)})[/dim]" if refs else ""
            body.add_row(
                _KIND_TAG.get(reason["kind"], escape(reason["kind"])),
                escape(reason["text"]) + tail,
            )
    subtitle = f"{agent['servers']} MCP server(s)"
    return Panel(body, title=title, subtitle=subtitle, title_align="left")


def _print_errors(console: Console, errors: list[str]) -> None:
    if not errors:
        return
    console.print("[dim]Notes from reading files:[/dim]")
    for error in errors[:10]:
        console.print(f"[dim]  - {escape(error)}[/dim]")
    if len(errors) > 10:
        console.print(f"[dim]  ... and {len(errors) - 10} more[/dim]")


def print_fleet(report: FleetReport, console: Console) -> None:
    """Print verdict counts per agent, the unsafe machines, and skipped files."""
    console.print(
        f"[bold]mcp-audit reach --fleet[/bold]  {len(report.machines)} machine(s)"
    )
    per_agent = report.per_agent()
    if per_agent:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Agent")
        for verdict in (
            Verdict.NOT_SAFE,
            Verdict.NEEDS_WORK,
            Verdict.COULDNT_CHECK,
            Verdict.READY,
        ):
            table.add_column(_FLEET_HEADERS[verdict], justify="right")
        for name, counts in per_agent.items():
            table.add_row(
                escape(name),
                str(counts[Verdict.NOT_SAFE.value]),
                str(counts[Verdict.NEEDS_WORK.value]),
                str(counts[Verdict.COULDNT_CHECK.value]),
                str(counts[Verdict.READY.value]),
            )
        console.print(table)
    unsafe = report.not_safe()
    if unsafe:
        console.print("[bold red]Not safe to allow:[/bold red]")
        for machine, agents in unsafe:
            console.print(f"  {escape(machine)}: {escape(', '.join(agents))}")
    elif report.machines:
        console.print("No machine has an agent that is not safe to allow.")
    if report.skipped:
        console.print(f"[yellow]Skipped {len(report.skipped)} file(s):[/yellow]")
        for name, why in report.skipped:
            console.print(f"  {escape(name)} {escape(why)}")
    if report.truncated:
        console.print(
            "[yellow]More files than the limit; the rest were not read.[/yellow]"
        )
