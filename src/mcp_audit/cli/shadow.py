"""``mcp-audit shadow`` — continuous detection of shadow MCP servers.

Find your shadow MCP servers — every one on every developer's machine,
classified, scored, and event-logged. OWASP MCP09. Open source. No agent.
No telemetry.

This command sweeps every known MCP config location on the host, classifies
each server as ``sanctioned`` or ``shadow`` against an optional allowlist, and
attaches a structured risk summary (capability tags, toxic-flow signals,
OWASP MCP09 mapping) to each server.

In ``--continuous`` mode the command runs as a daemon that emits structured
events whenever a new shadow server appears, an existing server drifts, or a
server is removed.
"""

from __future__ import annotations

import logging
import platform
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_audit.analyzers.supply_chain import extract_npm_package
from mcp_audit.analyzers.toxic_flow import tag_server
from mcp_audit.cli import app
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import DiscoveredConfig, discover_configs
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import KnownServerRegistry, load_registry
from mcp_audit.shadow.allowlist import (
    ShadowAllowlist,
    find_unmatched_allowlist_entries,
    load_allowlist,
)
from mcp_audit.shadow.classifier import classify
from mcp_audit.shadow.events import (
    NewShadowServerEvent,
    ServerDriftEvent,
    ServerRemovedEvent,
    ShadowServerRecord,
    emit,
    records_to_json,
)
from mcp_audit.shadow.risk import RiskLevel, score_risk
from mcp_audit.shadow.state import ShadowState

console = Console(stderr=True)

# Risk-level colour map for Rich terminal output.
_RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "cyan",
    RiskLevel.INFO: "green",
    RiskLevel.UNKNOWN: "dim",
}

logger = logging.getLogger(__name__)


# ── Core pipeline helpers ─────────────────────────────────────────────────────


def _discover_all_servers(
    extra_paths: list[Path] | None = None,
) -> tuple[list[ServerConfig], int]:
    """Discover and parse every MCP server reachable on this host.

    Args:
        extra_paths: Additional config file / directory paths to include.

    Returns:
        Tuple of (de-duplicated ServerConfig list, number of config files found).
    """
    discovered: list[DiscoveredConfig] = discover_configs(extra_paths=extra_paths)
    servers: list[ServerConfig] = []
    seen: set[tuple[str, str]] = set()

    for cfg in discovered:
        try:
            result = parse_config(cfg)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping unparseable config %s: %s", cfg.path, exc)
            continue
        for server in result:
            key = (server.client, server.name)
            if key not in seen:
                seen.add(key)
                servers.append(server)

    return servers, len(discovered)


def _extract_package_name(server: ServerConfig) -> str | None:
    """Return the npm package name for a server, if determinable."""
    if server.command in {"npx", "bunx", "pnpx"}:
        return extract_npm_package(server.args)
    return None


def _build_record(
    server: ServerConfig,
    allowlist: ShadowAllowlist | None,
    registry: KnownServerRegistry,
    state: ShadowState,
    now: datetime,
) -> ShadowServerRecord:
    """Build a :class:`ShadowServerRecord` for one server."""
    caps = tag_server(server, registry=registry)
    risk, _rationale = score_risk(server, registry=registry)
    classification = classify(server, allowlist)
    state_entry = state.touch(server, now)

    return ShadowServerRecord(
        host=platform.node(),
        client=server.client,
        server_name=server.name,
        package_name=_extract_package_name(server),
        classification=classification,
        risk_level=risk,
        capability_tags=sorted(c.value for c in caps),
        findings=[],
        owasp_mcp_top_10=["MCP09"],
        first_seen=state_entry.first_seen,
        last_seen=state_entry.last_seen,
    )


def _run_sweep(
    extra_paths: list[Path] | None,
    allowlist: ShadowAllowlist | None,
    registry: KnownServerRegistry,
    state: ShadowState,
) -> tuple[list[ShadowServerRecord], list[ServerConfig], int]:
    """Run a full sweep and return (records, raw_servers, configs_found)."""
    now = datetime.now(UTC)
    servers, configs_found = _discover_all_servers(extra_paths=extra_paths)
    records = [_build_record(s, allowlist, registry, state, now) for s in servers]
    state.save()
    return records, servers, configs_found


# ── Continuous-mode event emission ────────────────────────────────────────────


def _emit_change_events(
    old_servers: list[ServerConfig],
    new_servers: list[ServerConfig],
    allowlist: ShadowAllowlist | None,
    registry: KnownServerRegistry,
    state: ShadowState,
    now: datetime,
    use_json: bool,
    event_sink_path: Path | None,
) -> None:
    """Diff old vs new server lists and emit events for changes.

    Args:
        old_servers: Server list from the previous sweep.
        new_servers: Server list from the current sweep.
        allowlist: Operator's allowlist.
        registry: Pre-loaded registry.
        state: Persistent shadow state.
        now: Timestamp for this sweep.
        use_json: Emit JSON lines when True, plain text otherwise.
        event_sink_path: File path for file-sink events (or None for stdout).
    """
    old_map = {(s.client, s.name): s for s in old_servers}
    new_map = {(s.client, s.name): s for s in new_servers}

    sink = "file" if event_sink_path is not None else "stdout"

    for key, server in new_map.items():
        caps = tag_server(server, registry=registry)
        risk, _rationale = score_risk(server, registry=registry)
        classification = classify(server, allowlist)
        pkg = _extract_package_name(server)
        cap_tags = sorted(c.value for c in caps)
        state_entry = state.touch(server, now)

        common = {
            "host": platform.node(),
            "client": server.client,
            "server_name": server.name,
            "package_name": pkg,
            "classification": classification,
            "risk_level": risk,
            "capability_tags": cap_tags,
            "first_seen": state_entry.first_seen,
            "last_seen": state_entry.last_seen,
        }

        if key not in old_map:
            event: NewShadowServerEvent | ServerDriftEvent | ServerRemovedEvent = (
                NewShadowServerEvent(**common)
            )
            emit(event, sink=sink, file_path=event_sink_path, use_json=use_json)
        else:
            old = old_map[key]
            changed: list[str] = []
            if server.command != old.command:
                changed.append("command")
            if list(server.args) != list(old.args):
                changed.append("args")
            if set(server.env.keys()) != set(old.env.keys()):
                changed.append("env")
            old_tools = old.raw.get("tools") if old.raw else None
            new_tools = server.raw.get("tools") if server.raw else None
            if old_tools != new_tools:
                changed.append("tools")
            if changed:
                event = ServerDriftEvent(**common, changed_fields=changed)
                emit(event, sink=sink, file_path=event_sink_path, use_json=use_json)

    for key, server in old_map.items():
        if key not in new_map:
            old_state = state.get(server)
            if old_state is not None:
                caps = tag_server(server, registry=registry)
                risk, _ = score_risk(server, registry=registry)
                classification = classify(server, allowlist)
                event = ServerRemovedEvent(
                    host=platform.node(),
                    client=server.client,
                    server_name=server.name,
                    package_name=_extract_package_name(server),
                    classification=classification,
                    risk_level=risk,
                    capability_tags=sorted(c.value for c in caps),
                    first_seen=old_state.first_seen,
                    last_seen=old_state.last_seen,
                )
                emit(event, sink=sink, file_path=event_sink_path, use_json=use_json)


# ── Terminal output ────────────────────────────────────────────────────────────


def _print_terminal_results(
    records: list[ShadowServerRecord],
    unmatched_allowlist: list[str],
    allowlist: ShadowAllowlist | None,
) -> None:
    """Render scan results to the terminal using Rich."""
    shadow_count = sum(1 for r in records if r.classification == "shadow")
    sanctioned_count = len(records) - shadow_count

    # Header panel
    header_lines = [
        f"[bold]Servers found:[/bold] {len(records)}  "
        f"[red]Shadow: {shadow_count}[/red]  "
        f"[green]Sanctioned: {sanctioned_count}[/green]",
        "[dim]OWASP MCP09 — Shadow MCP Servers[/dim]",
    ]
    if allowlist is None:
        header_lines.append(
            "[dim]No allowlist configured — all servers are shadow by default.[/dim]"
        )

    console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold blue]mcp-audit shadow[/bold blue]",
            border_style="blue",
        )
    )

    if not records:
        console.print("[green]No MCP servers are configured on this host.[/green]")
        return

    # Results table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Client", style="dim", no_wrap=True)
    table.add_column("Server", no_wrap=True)
    table.add_column("Package", overflow="fold")
    table.add_column("Class", no_wrap=True)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Capabilities", overflow="fold")

    for rec in sorted(
        records,
        key=lambda r: (r.classification, r.risk_level, r.client, r.server_name),
    ):
        classification_text = (
            Text("shadow", style="bold red")
            if rec.classification == "shadow"
            else Text("sanctioned", style="bold green")
        )
        risk_style = _RISK_COLORS.get(rec.risk_level, "white")
        risk_text = Text(rec.risk_level.value, style=risk_style)

        table.add_row(
            rec.client,
            rec.server_name,
            rec.package_name or "—",
            classification_text,
            risk_text,
            ", ".join(rec.capability_tags) or "—",
        )

    console.print(table)

    # Warn about unmatched allowlist entries
    if unmatched_allowlist:
        console.print(
            Panel(
                "\n".join(
                    f"  [yellow]⚠[/yellow]  Allowlist entry [bold]{e!r}[/bold] "
                    "did not match any discovered server — check for typos."
                    for e in unmatched_allowlist
                ),
                title="[yellow]Allowlist warnings[/yellow]",
                border_style="yellow",
            )
        )


# ── Command ───────────────────────────────────────────────────────────────────


@app.command(
    "shadow",
    help=(
        "Find your shadow MCP servers — every one on every developer's machine, "
        "classified, scored, and event-logged. OWASP MCP09. Open source. "
        "No agent. No telemetry.\n\n"
        "Sweeps every known MCP config location on this host. Each server is "
        "classified as [bold]sanctioned[/bold] (matches your allowlist) or "
        "[bold red]shadow[/bold red] (does not). Shadow servers receive a risk "
        "summary: capability tags, toxic-flow signals, OWASP MCP09 mapping.\n\n"
        "Use --continuous to run as a daemon that emits events whenever a new "
        "shadow server appears, an existing server drifts, or a server is removed."
    ),
    rich_help_panel=None,
)
def shadow(
    allowlist: Annotated[
        Path | None,
        typer.Option(
            "--allowlist",
            help=(
                "Path to an allowlist YAML file listing sanctioned servers. "
                "Supports .mcp-audit-allowlist.yml in CWD / repo root / user config "
                "as well as an explicit path. When absent, all servers are shadow."
            ),
            show_default=False,
        ),
    ] = None,
    continuous: Annotated[
        bool,
        typer.Option(
            "--continuous",
            help=(
                "Run as a daemon. Emits events whenever a config file changes: "
                "new_shadow_server, server_drift, server_removed. "
                "Press Ctrl-C to stop."
            ),
        ),
    ] = False,
    format_: Annotated[
        str,
        typer.Option(
            "--format",
            help="Output format: 'text' (Rich terminal) or 'json' (structured JSON).",
            metavar="FORMAT",
        ),
    ] = "text",
    path: Annotated[
        Path | None,
        typer.Option(
            "--path",
            help="Additional config file or directory to include in the sweep.",
            show_default=False,
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output-file",
            "-o",
            help=(
                "Write JSON output or event log to this file (appends in --continuous)."
            ),
            show_default=False,
        ),
    ] = None,
    offline_registry: Annotated[
        bool,
        typer.Option(
            "--offline-registry",
            help="Use only the bundled registry; skip the user-local cache.",
        ),
    ] = False,
) -> None:
    """Find your shadow MCP servers — OWASP MCP09."""
    use_json = format_.lower() == "json"
    extra_paths = [path] if path is not None else None

    # ── Preflight ─────────────────────────────────────────────────────────────

    if allowlist is not None:
        allowlist = allowlist.resolve()
        if not allowlist.exists():
            console.print(
                f"[bold red]Error:[/bold red] Allowlist file not found: {allowlist}",
            )
            raise typer.Exit(code=2)

    # ── Load supporting infrastructure ────────────────────────────────────────

    try:
        registry = load_registry(offline=offline_registry)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        loaded_allowlist = load_allowlist(allowlist)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    state = ShadowState()

    # ── Initial sweep ─────────────────────────────────────────────────────────

    records, current_servers, configs_found = _run_sweep(
        extra_paths=extra_paths,
        allowlist=loaded_allowlist,
        registry=registry,
        state=state,
    )

    if not records:
        if use_json:
            sys.stdout.write("[]\n")
        else:
            if configs_found == 0:
                console.print("[green]No MCP config files found on this host.[/green]")
            else:
                console.print(
                    f"[green]Found {configs_found} MCP config file(s) but no servers "
                    "are configured in them.[/green]"
                )
        if not continuous:
            raise typer.Exit(code=0)

    unmatched = (
        find_unmatched_allowlist_entries(loaded_allowlist, current_servers)
        if loaded_allowlist is not None
        else []
    )

    if unmatched and not use_json:
        pass  # surfaced inside _print_terminal_results

    if not continuous:
        # Single-shot output
        if use_json:
            output = records_to_json(records)
            if output_file is not None:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(output, encoding="utf-8")
            else:
                sys.stdout.write(output + "\n")
        else:
            _print_terminal_results(records, unmatched, loaded_allowlist)

        has_shadow = any(r.classification == "shadow" for r in records)
        raise typer.Exit(code=1 if has_shadow else 0)

    # ── Continuous mode ───────────────────────────────────────────────────────

    if not use_json:
        console.print(
            Panel(
                "[bold]Continuous mode active.[/bold] Watching for config changes…\n"
                "[dim]Press Ctrl-C to stop.[/dim]",
                border_style="blue",
            )
        )
        # Print initial state to terminal
        _print_terminal_results(records, unmatched, loaded_allowlist)

    prev_servers: list[ServerConfig] = current_servers
    prev_lock = threading.Lock()

    def _on_change(changed_path: Path, event_type: str) -> None:  # noqa: ARG001
        nonlocal prev_servers
        now = datetime.now(UTC)
        new_servers, _ = _discover_all_servers(extra_paths=extra_paths)

        with prev_lock:
            _emit_change_events(
                old_servers=prev_servers,
                new_servers=new_servers,
                allowlist=loaded_allowlist,
                registry=registry,
                state=state,
                now=now,
                use_json=use_json,
                event_sink_path=output_file,
            )
            state.save()
            prev_servers = new_servers

    from mcp_audit.watcher import ConfigWatcher  # noqa: PLC0415

    watcher = ConfigWatcher(
        on_change_callback=_on_change,
        extra_paths=extra_paths,
    )
    watcher.run_until_interrupt()
