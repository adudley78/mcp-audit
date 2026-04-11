"""mcp-audit CLI — MCP Security Scanner."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_audit.analyzers.rug_pull import (
    DEFAULT_STATE_PATH,
    build_state_entry,
    compute_hashes,
    load_state,
    save_state,
    server_key,
)
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.models import Severity
from mcp_audit.output.nucleus import format_nucleus
from mcp_audit.output.sarif import format_sarif
from mcp_audit.output.terminal import print_results
from mcp_audit.scanner import run_scan

app = typer.Typer(
    name="mcp-audit",
    help="Privacy-first security scanner for MCP server configurations.",
    no_args_is_help=True,
)
console = Console()


# ── scan ──────────────────────────────────────────────────────────────────────


@app.command()
def scan(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Scan a specific config file or directory"
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal", "--format", "-f",
        help="Output format: terminal, json, nucleus, sarif",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Write results to file"
    ),
    severity_threshold: str = typer.Option(  # noqa: B008
        "INFO", "--severity-threshold", "-s",
        help="Minimum severity to report",
    ),
    offline: bool = typer.Option(  # noqa: B008
        False, "--offline", help="Skip all network calls"
    ),
    ci: bool = typer.Option(  # noqa: B008
        False, "--ci", help="CI mode: minimal output, exit code on findings"
    ),
    json_flag: bool = typer.Option(  # noqa: B008
        False, "--json", help="Shortcut for --format json"
    ),
    connect: bool = typer.Option(  # noqa: B008
        False,
        "--connect",
        help=(
            "Connect to running MCP servers via the protocol handshake and "
            "analyze live tool descriptions (requires: pip install mcp-audit[mcp])"
        ),
    ),
) -> None:
    """Scan MCP configurations for security issues."""
    extra_paths = [path] if path else None
    fmt = "json" if json_flag else output_format

    result = run_scan(extra_paths=extra_paths, connect=connect)

    # Filter by severity threshold
    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2)  # noqa: B904

    severity_order = [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
    ]
    threshold_idx = severity_order.index(threshold)
    result.findings = [
        f for f in result.findings
        if severity_order.index(f.severity) <= threshold_idx
    ]

    # Output
    if fmt == "json":
        out = result.model_dump_json(indent=2)
        if output:
            output.write_text(out)
        else:
            typer.echo(out)
    elif fmt == "nucleus":
        out = format_nucleus(result)
        if output:
            output.write_text(out)
        else:
            typer.echo(out)
    elif fmt == "sarif":
        out = format_sarif(result)
        if output:
            output.write_text(out)
        else:
            typer.echo(out)
    elif fmt == "terminal":
        print_results(result, console=console)
    else:
        console.print(
            "[red]Unknown format: "
            f"{fmt!r}. Choose terminal, json, nucleus, or sarif.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    # Exit code
    if result.has_findings:
        raise typer.Exit(1)


# ── discover ──────────────────────────────────────────────────────────────────


@app.command()
def discover(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional path to check"
    ),
    json_flag: bool = typer.Option(False, "--json", help="Output as JSON"),  # noqa: B008
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


# ── pin ───────────────────────────────────────────────────────────────────────


@app.command()
def pin(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional path to check"
    ),
) -> None:
    """Record current MCP server configurations as the trusted baseline.

    Overwrites any existing baseline.  Preserves the original ``first_seen``
    timestamp for servers already tracked.
    """
    extra_paths = [path] if path else None
    configs = discover_configs(extra_paths=extra_paths)

    all_servers = []
    for config in configs:
        try:
            all_servers.extend(parse_config(config))
        except ValueError as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")

    if not all_servers:
        console.print("[yellow]No MCP servers found — nothing to pin.[/yellow]")
        return

    # Load existing state so we can preserve first_seen timestamps.
    existing = load_state(DEFAULT_STATE_PATH)
    stored = existing.get("servers", {})

    now = datetime.now(UTC).isoformat()
    for srv in all_servers:
        key = server_key(srv)
        first_seen = stored.get(key, {}).get("first_seen", now)
        stored[key] = build_state_entry(srv, first_seen=first_seen)

    save_state({"version": 1, "servers": stored}, DEFAULT_STATE_PATH)

    console.print(
        f"\n[bold green]Pinned baseline for {len(all_servers)} server(s).[/bold green]"
        f"  (state → {DEFAULT_STATE_PATH})\n"
    )
    for srv in all_servers:
        console.print(f"  [cyan]{server_key(srv)}[/cyan]  {srv.config_path}")
    console.print()


# ── diff ──────────────────────────────────────────────────────────────────────


@app.command()
def diff(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional path to check"
    ),
) -> None:
    """Show configuration changes since the last baseline.

    Does NOT run the full analyzer pipeline — only compares hashes.
    Exit code 1 if any changes detected, 0 if clean.
    """
    if not DEFAULT_STATE_PATH.exists():
        console.print(
            "[red]No baseline found.[/red]  "
            "Run [bold]mcp-audit pin[/bold] or [bold]mcp-audit scan[/bold] first."
        )
        raise typer.Exit(2)  # noqa: B904

    state = load_state(DEFAULT_STATE_PATH)
    stored: dict = state.get("servers", {})
    baseline_ts = _newest_last_seen(stored)

    extra_paths = [path] if path else None
    configs = discover_configs(extra_paths=extra_paths)

    all_servers = []
    for config in configs:
        try:
            all_servers.extend(parse_config(config))
        except ValueError as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")

    current: dict[str, object] = {server_key(s): s for s in all_servers}

    changed_rows: list[tuple[str, str, str]] = []
    new_rows: list[str] = []
    removed_rows: list[tuple[str, str]] = []

    for key, srv in current.items():  # type: ignore[assignment]
        if key not in stored:
            new_rows.append(key)
        else:
            curr_hashes = compute_hashes(srv)  # type: ignore[arg-type]
            stored_hashes = stored[key].get("hashes", {})
            if curr_hashes["raw"] != stored_hashes.get("raw"):
                diff_fields = ", ".join(
                    f for f in ("command", "args", "env_keys", "raw")
                    if curr_hashes.get(f) != stored_hashes.get(f)
                )
                changed_rows.append(
                    (key, diff_fields, stored[key].get("last_seen", ""))
                )

    for key, entry in stored.items():
        if key not in current:
            removed_rows.append((key, entry.get("last_seen", "unknown")))

    has_changes = bool(changed_rows or new_rows or removed_rows)

    if not has_changes:
        ts = f" (baseline: {baseline_ts})" if baseline_ts else ""
        console.print(f"[green]No changes detected since last baseline.[/green]{ts}")
        return

    ts_label = f"[dim]baseline: {baseline_ts}[/dim]" if baseline_ts else ""
    console.print(f"\n[bold]MCP configuration diff[/bold]  {ts_label}\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Server", style="cyan")
    table.add_column("Status")
    table.add_column("Detail")

    for key, fields, _last_seen in changed_rows:
        table.add_row(key, "[red]CHANGED[/red]", fields)
    for key in new_rows:
        table.add_row(key, "[yellow]NEW[/yellow]", "")
    for key, last_seen in removed_rows:
        table.add_row(key, "[dim]REMOVED[/dim]", f"last seen {last_seen}")

    console.print(table)
    console.print(
        f"\n{len(changed_rows)} changed, "
        f"{len(new_rows)} new, "
        f"{len(removed_rows)} removed\n"
    )
    raise typer.Exit(1)


# ── version ───────────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Show version information."""
    console.print("mcp-audit v0.1.0")


# ── entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()


# ── Private helpers ────────────────────────────────────────────────────────────


def _newest_last_seen(stored: dict) -> str:
    """Return the most recent last_seen timestamp across all stored servers."""
    timestamps = [
        entry.get("last_seen", "")
        for entry in stored.values()
        if entry.get("last_seen")
    ]
    return max(timestamps) if timestamps else ""
