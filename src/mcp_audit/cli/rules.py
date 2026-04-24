"""rule sub-app: validate / test / list."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from mcp_audit import cli as _cli
from mcp_audit.cli import console, rule_app

# ── rule validate ─────────────────────────────────────────────────────────────


@rule_app.command(name="validate")
def rule_validate(
    file: Path = typer.Argument(help="Path to a YAML rule file to validate"),  # noqa: B008
) -> None:
    """Validate a rule file without running a scan.

    Checks that all rules in the file conform to the PolicyRule schema.
    Exits 0 if all rules are valid, 1 if any errors are found.
    """
    if not file.exists():
        console.print(f"[red]Error:[/red] Rule file not found: {file}")
        raise typer.Exit(2)  # noqa: B904

    from mcp_audit.rules.engine import load_rules_from_file  # noqa: PLC0415

    rules = load_rules_from_file(file)

    if not rules:
        console.print(f"[red]✗ No valid rules loaded from {file}[/red]")
        raise typer.Exit(1)  # noqa: B904

    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Enabled", justify="center")

    _SEV_STYLE = {  # noqa: N806
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[blue]LOW[/blue]",
        "INFO": "[dim]INFO[/dim]",
    }

    for rule in rules:
        sev_display = _SEV_STYLE.get(rule.severity.value, rule.severity.value)
        enabled_display = "[green]✓[/green]" if rule.enabled else "[dim]✗[/dim]"
        table.add_row(rule.id, rule.name, sev_display, enabled_display)

    console.print(f"\n[bold green]✓ Valid — {len(rules)} rule(s) loaded[/bold green]\n")
    console.print(table)
    console.print()


# ── rule test ─────────────────────────────────────────────────────────────────


@rule_app.command(name="test")
def rule_test(
    file: Path = typer.Argument(help="Path to a YAML rule file"),  # noqa: B008
    against: Path = typer.Option(  # noqa: B008
        ..., "--against", help="MCP config file to test rules against"
    ),
) -> None:
    """Test a rule file against a specific MCP config file.

    Shows all rules × all servers so you can see what fired and what didn't.
    Exit code is always 0 (this is a testing tool, not a pass/fail gate).
    """
    if not file.exists():
        console.print(f"[red]Error:[/red] Rule file not found: {file}")
        raise typer.Exit(2)  # noqa: B904

    if not against.exists():
        console.print(f"[red]Error:[/red] Config file not found: {against}")
        raise typer.Exit(2)  # noqa: B904

    from mcp_audit.discovery import DiscoveredConfig  # noqa: PLC0415
    from mcp_audit.rules.engine import (  # noqa: PLC0415
        _evaluate_rule_match,
        load_rules_from_file,
    )

    rules = load_rules_from_file(file)
    if not rules:
        console.print(f"[yellow]No valid rules loaded from {file}[/yellow]")
        raise typer.Exit(0)  # noqa: B904

    config = DiscoveredConfig(
        client_name="custom",
        root_key="mcpServers",
        path=against.resolve(),
    )
    try:
        servers = _cli.parse_config(config)
    except ValueError as exc:
        console.print(f"[red]Cannot parse config: {exc}[/red]")
        raise typer.Exit(0)  # noqa: B904

    if not servers:
        console.print("[yellow]No servers found in config file.[/yellow]")
        raise typer.Exit(0)  # noqa: B904

    table = Table(
        show_header=True, header_style="bold", title=f"Rule test: {file.name}"
    )
    table.add_column("Server", style="cyan")
    table.add_column("Rule ID")
    table.add_column("Rule Name")
    table.add_column("Matched?", justify="center")
    table.add_column("Matched Value")

    for server in servers:
        for rule in rules:
            matched, matched_value = _evaluate_rule_match(rule.match, server)
            matched_display = "[green]✓ YES[/green]" if matched else "[dim]✗ no[/dim]"
            table.add_row(
                server.name,
                rule.id,
                rule.name,
                matched_display,
                matched_value if matched else "",
            )

    console.print()
    console.print(table)
    console.print(
        f"\n[dim]{len(rules)} rule(s) × {len(servers)} server(s) evaluated[/dim]\n"
    )


# ── rule list ─────────────────────────────────────────────────────────────────


@rule_app.command(name="list")
def rule_list(
    rules_dir: Path | None = typer.Option(  # noqa: B008
        None,
        "--rules-dir",
        help="Additional rules directory to include in listing",
    ),
) -> None:
    """List all currently loaded rules (bundled + user-local).

    Shows bundled community rules plus user-local rules from the platform
    user config directory under ``mcp-audit/rules/`` (path resolved via
    ``platformdirs``).
    """
    from mcp_audit.rules.engine import (  # noqa: PLC0415
        load_bundled_community_rules,
        load_rules_from_dir,
    )
    from mcp_audit.scanner import _USER_RULES_DIR  # noqa: PLC0415

    _SEV_STYLE = {  # noqa: N806
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[blue]LOW[/blue]",
        "INFO": "[dim]INFO[/dim]",
    }

    table = Table(show_header=True, header_style="bold", title="Loaded Rules")
    table.add_column("Source", style="dim")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Tags")

    # Bundled community rules (always shown)
    bundled = load_bundled_community_rules()
    for rule in bundled:
        sev_display = _SEV_STYLE.get(rule.severity.value, rule.severity.value)
        table.add_row(
            "bundled",
            rule.id,
            rule.name,
            sev_display,
            ", ".join(rule.tags),
        )

    if _USER_RULES_DIR.is_dir():
        user_rules = load_rules_from_dir(_USER_RULES_DIR)
        for rule in user_rules:
            sev_display = _SEV_STYLE.get(rule.severity.value, rule.severity.value)
            table.add_row(
                "user",
                rule.id,
                rule.name,
                sev_display,
                ", ".join(rule.tags),
            )

    if rules_dir is not None and rules_dir.is_dir():
        extra_rules = load_rules_from_dir(rules_dir)
        for rule in extra_rules:
            sev_display = _SEV_STYLE.get(rule.severity.value, rule.severity.value)
            table.add_row(
                str(rules_dir),
                rule.id,
                rule.name,
                sev_display,
                ", ".join(rule.tags),
            )

    console.print()
    console.print(table)
    console.print(f"\n[dim]{len(bundled)} bundled community rule(s)[/dim]\n")
