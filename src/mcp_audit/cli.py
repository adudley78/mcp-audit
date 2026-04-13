"""mcp-audit CLI — MCP Security Scanner."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_audit.analyzers.rug_pull import (
    build_state_entry,
    compute_hashes,
    derive_state_path,
    load_state,
    save_state,
    server_key,
)
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.models import Severity
from mcp_audit.output.dashboard import generate_html
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


# ── Internal helpers ──────────────────────────────────────────────────────────


def _scoped_state_path(extra_paths: list[Path] | None) -> Path:
    """Derive the scoped rug-pull state path for the given extra paths."""
    from mcp_audit.discovery import discover_configs  # noqa: PLC0415
    configs = discover_configs(extra_paths=extra_paths)
    return derive_state_path(configs)


def _reset_scoped_state(
    extra_paths: list[Path] | None, con: Console
) -> None:
    """Delete the scoped state file if it exists, printing a status line."""
    scoped = _scoped_state_path(extra_paths)
    if scoped.exists():
        scoped.unlink()
        con.print(f"[dim]Reset state: {scoped.name}[/dim]\n")
    else:
        con.print(f"[dim]No state file to reset ({scoped.name}).[/dim]\n")


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
    reset_state: bool = typer.Option(  # noqa: B008
        False,
        "--reset-state",
        help=(
            "Delete the scoped rug-pull baseline before scanning, "
            "giving a clean slate without manual file removal."
        ),
    ),
) -> None:
    """Scan MCP configurations for security issues."""
    extra_paths = [path] if path else None
    fmt = "json" if json_flag else output_format

    if reset_state:
        _reset_scoped_state(extra_paths, console)

    result = run_scan(extra_paths=extra_paths, connect=connect, offline=offline)

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

    scoped_path = derive_state_path(configs)

    # Load existing state so we can preserve first_seen timestamps.
    existing = load_state(scoped_path)
    stored = existing.get("servers", {})

    now = datetime.now(UTC).isoformat()
    for srv in all_servers:
        key = server_key(srv)
        first_seen = stored.get(key, {}).get("first_seen", now)
        stored[key] = build_state_entry(srv, first_seen=first_seen)

    save_state({"version": 1, "servers": stored}, scoped_path)

    console.print(
        f"\n[bold green]Pinned baseline for {len(all_servers)} server(s).[/bold green]"
        f"  (state → {scoped_path.name})\n"
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
    extra_paths = [path] if path else None
    configs = discover_configs(extra_paths=extra_paths)
    scoped_path = derive_state_path(configs)

    if not scoped_path.exists():
        console.print(
            "[red]No baseline found.[/red]  "
            "Run [bold]mcp-audit pin[/bold] or [bold]mcp-audit scan[/bold] first.\n"
            f"[dim](expected state file: {scoped_path.name})[/dim]"
        )
        raise typer.Exit(2)  # noqa: B904

    state = load_state(scoped_path)
    stored: dict = state.get("servers", {})
    baseline_ts = _newest_last_seen(stored)

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
        ts = f", baseline: {baseline_ts}" if baseline_ts else ""
        console.print(
            f"[green]No changes detected since last baseline.[/green]"
            f" [dim](state: {scoped_path.name}{ts})[/dim]"
        )
        return

    ts_label = f"baseline: {baseline_ts}" if baseline_ts else ""
    console.print(
        f"\n[bold]MCP configuration diff[/bold]  "
        f"[dim]{scoped_path.name}  {ts_label}[/dim]\n"
    )

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


# ── dashboard ─────────────────────────────────────────────────────────────────


@app.command()
def dashboard(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Scan a specific config file or directory"
    ),
    port: int = typer.Option(  # noqa: B008
        8088, "--port", help="Local port for the dashboard server"
    ),
    connect: bool = typer.Option(  # noqa: B008
        False,
        "--connect",
        help="Connect to live MCP servers during scan",
    ),
    no_open: bool = typer.Option(  # noqa: B008
        False, "--no-open", help="Don't auto-open browser"
    ),
) -> None:
    """Run a full scan and open an interactive attack-graph dashboard."""
    import http.server  # noqa: PLC0415
    import tempfile  # noqa: PLC0415
    import threading  # noqa: PLC0415
    import webbrowser  # noqa: PLC0415

    extra_paths = [path] if path else None

    console.print("\n[cyan]Running scan…[/cyan]")
    result = run_scan(extra_paths=extra_paths, connect=connect)

    console.print("[cyan]Generating dashboard…[/cyan]")
    html = generate_html(result)
    html_bytes = html.encode("utf-8")

    # Write a copy the user can open directly later.
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix="-mcp-audit-dashboard.html",
        delete=False,
        encoding="utf-8",
    ) as fh:
        fh.write(html)
        html_path = Path(fh.name)

    # In-memory HTTP handler — no I/O on every request.
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)

        def log_message(self, *_args: object) -> None:  # type: ignore[override]
            pass  # suppress default request logging

    url = f"http://localhost:{port}"
    try:
        srv = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    except OSError as exc:
        console.print(
            f"[red]Cannot bind port {port}: {exc}.[/red]  "
            "Try [bold]--port[/bold] with a different value."
        )
        raise typer.Exit(2)  # noqa: B904

    console.print(
        f"\n[bold cyan]Dashboard running at {url}[/bold cyan] — press Ctrl+C to stop"
    )
    console.print(f"[dim]HTML saved to: {html_path}[/dim]\n")

    if not no_open:
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        html_path.unlink(missing_ok=True)
        console.print("\n[dim]Dashboard stopped.[/dim]")


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
