"""baseline sub-app: save / list / compare / delete / export."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from mcp_audit import cli as _cli
from mcp_audit.cli import baseline_app, console

# ── baseline save ─────────────────────────────────────────────────────────────


@baseline_app.command(name="save")
def baseline_save(
    name: str | None = typer.Argument(  # noqa: B008
        None, help="Baseline label (auto-generated if omitted)"
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Scan a specific config file or directory"
    ),
) -> None:
    """Capture a baseline snapshot of the current MCP configuration."""
    from mcp_audit.baselines.manager import BaselineManager  # noqa: PLC0415

    extra_paths = [path] if path else None
    configs = _cli.discover_configs(extra_paths=extra_paths)

    all_servers = []
    for config in configs:
        try:
            all_servers.extend(_cli.parse_config(config))
        except ValueError as exc:
            console.print(f"[yellow]Warning: {exc}[/yellow]")

    config_paths = [str(c.path) for c in configs]
    mgr = BaselineManager()
    baseline = mgr.save(all_servers, config_paths, name=name)
    console.print(
        f"[bold green]Baseline saved:[/bold green] {baseline.name} "
        f"({baseline.server_count} server(s) captured)"
    )


# ── baseline list ─────────────────────────────────────────────────────────────


@baseline_app.command(name="list")
def baseline_list() -> None:
    """List all saved baselines."""
    from mcp_audit.baselines.manager import BaselineManager  # noqa: PLC0415

    mgr = BaselineManager()
    baselines = mgr.list()

    if not baselines:
        console.print(
            "No baselines saved. "
            "Run [bold]mcp-audit baseline save[/bold] to create one."
        )
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Created")
    table.add_column("Servers", justify="right")
    table.add_column("Scanner Version")

    for bl in baselines:
        created = bl.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        table.add_row(bl.name, created, str(bl.server_count), bl.scanner_version)

    console.print(table)


# ── baseline compare ──────────────────────────────────────────────────────────


@baseline_app.command(name="compare")
def baseline_compare(
    baseline_name: str | None = typer.Option(  # noqa: B008
        None,
        "--baseline",
        help="Baseline name to compare against (defaults to latest)",
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Scan a specific config file or directory"
    ),
) -> None:
    """Compare the current MCP configuration against a saved baseline."""
    from mcp_audit.baselines.manager import BaselineManager  # noqa: PLC0415

    mgr = BaselineManager()

    if baseline_name is not None:
        try:
            bl = mgr.load(baseline_name)
        except FileNotFoundError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2)  # noqa: B904
    else:
        bl = mgr.load_latest()
        if bl is None:
            console.print(
                "[red]No baselines found.[/red]  "
                "Run [bold]mcp-audit baseline save[/bold] to create one."
            )
            raise typer.Exit(2)  # noqa: B904

    extra_paths = [path] if path else None
    configs = _cli.discover_configs(extra_paths=extra_paths)
    all_servers = []
    for config in configs:
        try:
            all_servers.extend(_cli.parse_config(config))
        except ValueError as exc:
            console.print(f"[yellow]Warning: {exc}[/yellow]")

    drift = mgr.compare(bl, all_servers)

    if not drift:
        console.print(
            f"[green]No drift detected[/green] — configuration matches "
            f"baseline [bold]{bl.name!r}[/bold]"
        )
        return

    _SEV_STYLE = {  # noqa: N806
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[blue]LOW[/blue]",
        "INFO": "[dim]INFO[/dim]",
    }

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Client", style="cyan")
    table.add_column("Server", style="cyan")
    table.add_column("Detail")

    for df in drift:
        sev_display = _SEV_STYLE.get(df.severity.value, df.severity.value)
        detail = ""
        if df.baseline_value is not None and df.current_value is not None:
            detail = f"{df.baseline_value!r} → {df.current_value!r}"
        elif df.baseline_value is not None:
            detail = f"was: {df.baseline_value!r}"
        elif df.current_value is not None:
            detail = f"now: {df.current_value!r}"

        table.add_row(
            sev_display,
            df.drift_type.value,
            df.client,
            df.server_name,
            detail,
        )

    console.print(
        f"\n[bold]Drift against baseline [cyan]{bl.name!r}[/cyan][/bold] "
        f"(created {bl.created_at.strftime('%Y-%m-%d %H:%M UTC')})\n"
    )
    console.print(table)
    console.print(f"\n[bold]{len(drift)} drift finding(s) detected.[/bold]\n")
    raise typer.Exit(1)


# ── baseline delete ───────────────────────────────────────────────────────────


@baseline_app.command(name="delete")
def baseline_delete(
    name: str = typer.Argument(help="Name of the baseline to delete"),  # noqa: B008
) -> None:
    """Delete a saved baseline."""
    from mcp_audit.baselines.manager import BaselineManager  # noqa: PLC0415

    confirmed = typer.confirm(f"Delete baseline {name!r}?", default=False)
    if not confirmed:
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(0)  # noqa: B904

    mgr = BaselineManager()
    try:
        mgr.delete(name)
        console.print(f"[green]Baseline {name!r} deleted.[/green]")
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)  # noqa: B904


# ── baseline export ───────────────────────────────────────────────────────────


@baseline_app.command(name="export")
def baseline_export(
    name: str = typer.Argument(help="Name of the baseline to export"),  # noqa: B008
) -> None:
    """Write a baseline as raw JSON to stdout (pipeable)."""
    from mcp_audit.baselines.manager import BaselineManager  # noqa: PLC0415

    mgr = BaselineManager()
    try:
        raw = mgr.export(name)
        typer.echo(raw)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)  # noqa: B904
