"""``mcp-audit lock`` — write and verify the committable MCP server lock.

See ``docs/decisions/ADR-0005-mcp-audit-lock.md`` for the design.  This
command is intentionally a single Typer command with flags
(``--verify``, ``--resolve``, ``--accept``) rather than a sub-app, matching
the shape shown throughout STORY-0069.

``--connect`` (STORY-0086) adds the live layer: ``lock --connect`` records a
digest of every tool each server lists, and ``lock --verify --connect``
compares the live tool lists against those digests. Both start every
configured stdio server, exactly like ``scan --connect``.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import typer
from rich.console import Console

from mcp_audit import cli as _cli
from mcp_audit import mcp_client as _mcp_client
from mcp_audit._network import NetworkPolicy, require_offline_compatible
from mcp_audit.analyzers.rug_pull import server_key
from mcp_audit.analyzers.supply_chain import build_deprecated_package_finding
from mcp_audit.cli import app, console
from mcp_audit.discovery import discover_project_configs
from mcp_audit.lock import tool_digests
from mcp_audit.lock.model import LOCK_FILENAME
from mcp_audit.lock.verifier import servers_to_connect
from mcp_audit.lock.verifier import verify as verify_lock
from mcp_audit.lock.writer import (
    LockWriteError,
    check_tools_writable,
    load_existing,
    regenerate,
    tools_tampered,
    write_lock,
)
from mcp_audit.models import ServerConfig, ServerEnumeration, Severity
from mcp_audit.output.sarif import format_sarif
from mcp_audit.registry.loader import KnownServerRegistry, RegistryLoadError

_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _discover_lock_servers(
    root: Path, include_user: bool, con: Console
) -> list[ServerConfig]:
    """Discover and parse every server ``lock`` should consider.

    Args:
        root: Project root to walk for project-level MCP configs.
        include_user: Also include the user-global (dotfiles-repo) configs.
        con: Console for parse-warning output.

    Returns:
        All parsed servers, project-scoped first, then user-global.
    """
    servers: list[ServerConfig] = []
    for config in discover_project_configs(root):
        try:
            servers.extend(_cli.parse_config(config))
        except ValueError as exc:
            con.print(f"[yellow]Warning: {exc}[/yellow]")
    if include_user:
        # Plugin-shipped servers are pinned by their marketplace sha and
        # checked by PLUGIN-001, and their cache paths are machine-specific,
        # so they never belong in a committed lock. Inline subagent servers
        # (STORY-0094) stay out too, so locks written before they were
        # discovered keep verifying (scan's auto-verify skips them as well).
        for config in _cli.discover_configs(
            include_plugins=False, include_agents=False
        ):
            try:
                servers.extend(_cli.parse_config(config))
            except ValueError as exc:
                con.print(f"[yellow]Warning: {exc}[/yellow]")
    return servers


def _load_registry(
    registry_path: Path | None, con: Console
) -> KnownServerRegistry | None:
    """Load the known-server registry, exiting 2 on a corrupt file."""
    try:
        return KnownServerRegistry(path=registry_path)
    except (FileNotFoundError, RegistryLoadError) as exc:
        con.print(
            f"[yellow]Warning: registry unavailable ({exc}) — "
            "continuing without it.[/yellow]"
        )
        return None


def _deprecation_findings(doc: dict) -> list:
    """Return SC-005 findings for every locked entry with a deprecated package.

    Called after :func:`~mcp_audit.lock.writer.regenerate` builds the new
    document — walks ``doc["servers"]`` rather than re-resolving, so this
    reflects exactly what was just written (whether freshly resolved this
    run or reused byte-for-byte via ADR-0005 §6 write-on-change). Empty
    under ``--offline`` (no resolution ever attempted, so every
    ``package.deprecated`` is ``None``) — STORY-0073/R58, scope-cut to the
    ``lock`` write path and ``lock --verify --resolve`` only.
    """
    findings = []
    for key in sorted(doc.get("servers", {})):
        entry = doc["servers"][key]
        package = entry.get("package")
        if not package:
            continue
        finding = build_deprecated_package_finding(
            client=entry.get("client", ""),
            server=entry.get("name", ""),
            config_path=entry.get("config", ""),
            package=package,
        )
        if finding is not None:
            findings.append(finding)
    return findings


_stderr = Console(stderr=True)


def _sdk_problem() -> str | None:
    """Return why ``--connect`` cannot run here, or ``None`` when it can."""
    if importlib.util.find_spec("mcp") is None:
        return _mcp_client._mcp_missing_message()
    return None


def _enumerate_tools(
    servers: list[ServerConfig], auth_token: str | None
) -> dict[tuple[str, str], ServerEnumeration]:
    """Connect to each server in turn and list its tools.

    Progress goes to stderr so ``--format json`` output stays parseable.

    Returns:
        Enumerations keyed by :func:`tool_digests.enumeration_key`.
    """
    if not servers:
        return {}
    _stderr.print(
        f"[dim]Listing tools from {len(servers)} server(s); this starts each one…[/dim]"
    )

    async def _run() -> dict[tuple[str, str], ServerEnumeration]:
        results: dict[tuple[str, str], ServerEnumeration] = {}
        for server in servers:
            results[
                tool_digests.enumeration_key(server)
            ] = await _mcp_client.connect_and_enumerate(server, auth_token=auth_token)
        return results

    return asyncio.run(_run())


@app.command()
def lock(
    path: Path | None = typer.Argument(  # noqa: B008
        None, help="Project root to lock (defaults to the current directory)"
    ),
    verify: bool = typer.Option(  # noqa: B008
        False, "--verify", help="Verify the existing lock instead of writing a new one"
    ),
    resolve: bool = typer.Option(  # noqa: B008
        False,
        "--resolve",
        help="With --verify, also re-resolve floating specs against the "
        "registry (network; produces LOCK-004)",
    ),
    allow_unverified: bool = typer.Option(  # noqa: B008
        False,
        "--allow-unverified",
        help="With --verify, waive unresolved package versions and populated "
        "foreign sections (e.g. a populated `trees`) from the exit code, "
        "restoring exit 0. Prints exactly what was waived. Never waives an "
        "actual LOCK-001/002/004/005 finding.",
    ),
    accept: bool = typer.Option(  # noqa: B008
        False,
        "--accept",
        help="Re-write the lock from the current state, preserving first_locked",
    ),
    include_user: bool = typer.Option(  # noqa: B008
        False,
        "--include-user",
        help="Also lock user-global configs (for dotfiles repositories)",
    ),
    offline: bool = typer.Option(  # noqa: B008
        False, "--offline", help="Never touch the network while writing the lock"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help=f"Write to PATH instead of <root>/{LOCK_FILENAME}"
    ),
    registry_path: Path | None = typer.Option(  # noqa: B008
        None, "--registry", help="Override the known-server registry"
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format for --verify: terminal, json, sarif",
    ),
    connect: bool = typer.Option(  # noqa: B008
        False,
        "--connect",
        help=(
            "Start each configured server and list its tools. Writing: "
            "record a digest of every tool definition. With --verify: report "
            "tools added (LOCK-006), changed (LOCK-007 schema/annotations, "
            "LOCK-008 description only) or removed (LOCK-009). Requires the "
            "mcp extra."
        ),
    ),
    connect_token: str | None = typer.Option(  # noqa: B008
        None,
        "--connect-token",
        help=(
            "Bearer token sent to remote (SSE/HTTP) servers during --connect. "
            "Never stored or logged."
        ),
    ),
    if_present: bool = typer.Option(  # noqa: B008
        False,
        "--if-present",
        help=(
            "With --verify: treat a missing mcp-lock.json as a soft skip "
            "(exit 0, dim informational message) instead of an error "
            "(exit 2). For CI/pre-commit adoption paths that must not break "
            "a repo that has not adopted `lock` yet — e.g. the GitHub "
            "Action's `lock-verify` input and the `mcp-audit-lock-verify` "
            "pre-commit hook both pass this flag."
        ),
    ),
) -> None:
    """Write, verify, or re-accept a committable MCP server lock.

    ``mcp-audit lock`` writes ``mcp-lock.json`` at the project root from the
    configs the scanner sees.  ``--verify`` checks it against the current
    state instead (offline by default; ``--resolve`` also asks the registry).
    ``--accept`` re-writes the lock, preserving each surviving entry's
    ``first_locked`` — the explicit "I reviewed the drift" step after a
    failed ``--verify``.  EXPERIMENTAL for one release: ``lock_version`` may
    change before it is frozen. See docs/lock.md.
    """
    if verify and accept:
        console.print("[red]Error:[/red] --verify and --accept are mutually exclusive.")
        raise typer.Exit(2)

    root = (path or Path.cwd()).resolve()
    if not root.exists():
        console.print(f"[red]Error:[/red] Path not found: {root}")
        raise typer.Exit(2)

    lock_path = output.resolve() if output else root / LOCK_FILENAME

    if connect:
        require_offline_compatible(NetworkPolicy(connect=True), offline)
        problem = _sdk_problem()
        if problem is not None:
            console.print(f"[red]Error:[/red] --connect: {problem}")
            raise typer.Exit(2)

    if verify:
        _run_verify(
            root,
            lock_path,
            include_user,
            resolve,
            registry_path,
            output_format,
            if_present=if_present,
            allow_unverified=allow_unverified,
            connect=connect,
            connect_token=connect_token,
        )
        return

    _run_write(
        root,
        lock_path,
        include_user,
        offline,
        registry_path,
        accept=accept,
        connect=connect,
        connect_token=connect_token,
    )


def _run_write(
    root: Path,
    lock_path: Path,
    include_user: bool,
    offline: bool,
    registry_path: Path | None,
    *,
    accept: bool,
    connect: bool = False,
    connect_token: str | None = None,
) -> None:
    """Handle plain ``lock`` and ``lock --accept`` (same regeneration)."""
    servers = _discover_lock_servers(root, include_user, console)
    if not servers:
        configs = discover_project_configs(root)
        if not configs:
            console.print(
                "[yellow]No MCP config files found — nothing to lock.[/yellow]"
            )
        else:
            console.print(
                f"[yellow]Found {len(configs)} MCP config file(s) but no "
                "servers are configured in them — nothing to lock.[/yellow]"
            )
        return

    existing_doc = load_existing(lock_path)
    tool_records: dict[str, dict] | None = None
    tool_failures: list[tuple[str, str]] = []
    discarded = False
    if connect:
        try:
            check_tools_writable(existing_doc)  # before starting anything
        except LockWriteError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(2) from None
        discarded = tools_tampered(existing_doc)
        enumerations = _enumerate_tools(servers, connect_token)
        tool_records = {}
        for server in servers:
            enumeration = enumerations[tool_digests.enumeration_key(server)]
            problem = enumeration.error or enumeration.tools_error
            if problem:
                tool_failures.append((server_key(server), problem))
                continue
            tool_records[server_key(server)] = tool_digests.server_record(
                enumeration.tools
            )

    registry = None if offline else _load_registry(registry_path, console)
    try:
        doc = regenerate(
            existing_doc,
            servers,
            root,
            offline=offline,
            registry=registry,
            tool_records=tool_records,
        )
        write_lock(lock_path, doc)
    except LockWriteError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None

    tools_section = doc.get(tool_digests.TOOLS_KEY)
    recorded: dict = (
        tools_section["servers"] if tool_digests.is_owned(tools_section) else {}
    )

    verb = "Re-locked" if accept else "Locked"
    console.print(
        f"\n[bold green]{verb} {len(servers)} server(s).[/bold green]  → {lock_path}\n"
    )
    for key in sorted(doc["servers"]):
        entry = doc["servers"][key]
        pkg = entry.get("package")
        version_note = (
            f"  {pkg['resolved_version']}"
            if pkg and pkg.get("resolved_version")
            else ""
        )
        tools_note = (
            f"  [dim]{len(recorded[key].get('tools', {}))} tools[/dim]"
            if key in recorded
            else ""
        )
        console.print(f"  [cyan]{key}[/cyan]{version_note}{tools_note}")
    console.print()

    if connect:
        if discarded:
            console.print(
                "[yellow]WARN[/yellow] the previous `tools` section did not "
                "match its own checksum; none of its records were kept."
            )
        console.print(
            f"Tool definitions recorded for {len(tool_records or {})} of "
            f"{len(servers)} server(s)."
        )
        for key, problem in tool_failures:
            kept = " (kept the previous record)" if key in recorded else ""
            console.print(
                f"[yellow]WARN[/yellow] {key}: tools not recorded{kept} — {problem}"
            )
    elif recorded:
        console.print(
            f"[dim]Kept tool records for {len(recorded)} server(s) from the "
            "previous lock; add --connect to refresh them.[/dim]"
        )

    for finding in _deprecation_findings(doc):
        color = _SEVERITY_COLOR.get(finding.severity, "white")
        console.print(f"[{color}]{finding.id}[/{color}]  {finding.title}")
        console.print(f"  {finding.evidence}")


def _run_verify(
    root: Path,
    lock_path: Path,
    include_user: bool,
    resolve: bool,
    registry_path: Path | None,
    output_format: str,
    *,
    if_present: bool = False,
    allow_unverified: bool = False,
    connect: bool = False,
    connect_token: str | None = None,
) -> None:
    """Handle ``lock --verify`` (and ``--verify --resolve`` / ``--connect``).

    With ``if_present=True``, a missing lock file is a soft, non-failing
    skip rather than an error — see the ``--if-present`` flag's help text.
    This lets an Action step or pre-commit hook adopt lock verification
    unconditionally without breaking a repo that has not run `mcp-audit
    lock` yet.

    With ``allow_unverified=True`` (``--allow-unverified``, R56), unresolved
    entries and populated foreign sections no longer fail the exit code —
    see :func:`mcp_audit.lock.verifier.verify`'s ``allow_unverified`` param.
    """
    # Machine-readable formats own stdout; every other line goes to stderr.
    con = console if output_format not in ("json", "sarif") else _stderr
    if not lock_path.exists():
        if if_present:
            con.print(
                f"[dim]No mcp-lock.json found at {lock_path} — "
                "skipping lock verification (--if-present).[/dim]"
            )
            raise typer.Exit(0)
        con.print(
            f"[red]Error:[/red] No lock file found at {lock_path}. "
            "Run `mcp-audit lock` first."
        )
        raise typer.Exit(2)

    servers = _discover_lock_servers(root, include_user, con)
    registry = _load_registry(registry_path, con) if resolve else None
    # Start only servers whose tools can be compared: never one the lock
    # does not approve, one whose launch line drifted, or anything when the
    # lock fails its checksum.
    enumerations = (
        _enumerate_tools(servers_to_connect(lock_path, servers), connect_token)
        if connect
        else None
    )

    result = verify_lock(
        lock_path,
        servers,
        resolve=resolve,
        registry=registry,
        allow_unverified=allow_unverified,
        tool_enumerations=enumerations,
    )

    if output_format == "json":
        payload = {
            "unsupported_version": result.unsupported_version,
            "checked_servers": result.checked_servers,
            "unverified_sections": result.unverified_sections,
            "unresolved_entries": result.unresolved_entries,
            "unverified": [
                {"kind": item.kind, "name": item.name, "reason": item.reason}
                for item in result.unverified
            ],
            "waived": result.waived,
            "tools_recorded": result.tools_recorded,
            "tools_compared": result.tools_compared,
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "exit_code": result.exit_code,
        }
        # typer.echo, not console.print: Rich soft-wraps long lines at the
        # terminal width, which corrupts JSON once a string (e.g. a
        # `reason`) exceeds it — R56 surfaced this once `reason` strings
        # got long enough to trigger it.
        typer.echo(json.dumps(payload, indent=2))
    elif output_format == "sarif":
        from mcp_audit.models import ScanResult  # noqa: PLC0415

        scan_result = ScanResult(servers=[], findings=result.findings)
        # typer.echo for the same reason as the JSON branch: console.print
        # hard-wraps a piped SARIF document at 80 columns.
        typer.echo(format_sarif(scan_result))
    else:
        _print_verify_terminal(result, lock_path)

    raise typer.Exit(result.exit_code)


def _print_verify_terminal(result, lock_path: Path) -> None:  # noqa: ANN001
    """Rich terminal rendering of a :class:`~mcp_audit.lock.verifier.VerifyResult`."""
    if result.tampered:
        console.print("[bold red]Lock file tampered or hand-edited.[/bold red]")
        console.print(result.findings[0].evidence)
        return
    if result.unsupported_version is not None:
        console.print(
            f"[red]Error:[/red] {lock_path} declares lock_version "
            f"{result.unsupported_version}, newer than this mcp-audit can "
            "verify. Upgrade mcp-audit; nothing was checked."
        )
        return

    for finding in result.findings:
        color = _SEVERITY_COLOR.get(finding.severity, "white")
        console.print(f"[{color}]{finding.id}[/{color}]  {finding.title}")
        console.print(f"  {finding.evidence}")

    if not result.findings and not result.unverified:
        console.print(
            f"[green]Lock: {result.checked_servers} servers verified[/green]", end=""
        )
    elif not result.findings:
        # Findings are clean, but something was not checked (unresolved
        # entry / populated foreign section) — R56: never say "verified"
        # when that is not literally true, waived or not.
        console.print(
            f"[yellow]Lock: {result.checked_servers} servers checked[/yellow]", end=""
        )
    else:
        console.print(f"Lock: {result.checked_servers} servers checked", end="")

    if result.unverified_sections:
        named = ", ".join(result.unverified_sections)
        console.print(f"; not verified: {named} (see docs/lock.md)")
    else:
        console.print()

    for key in result.unresolved_entries:
        console.print(
            f"[yellow]WARN[/yellow] {key} was locked with an unresolved version "
            "(offline at lock time) — never treated as verified."
        )

    if result.tools_compared is not None:
        console.print(
            f"Tool definitions compared for {result.tools_compared} server(s)."
        )
    elif result.tools_recorded:
        console.print(
            f"[dim]Tool definitions are recorded for {result.tools_recorded} "
            "server(s) but were not compared (add --connect).[/dim]"
        )

    if result.outside_root:
        console.print(
            "[yellow]WARN[/yellow] config(s) outside the lock root were "
            "skipped (no LOCK findings): " + ", ".join(result.outside_root)
        )

    if result.waived:
        for item in result.unverified:
            console.print(
                f"[yellow]WAIVED[/yellow] by --allow-unverified: "
                f"{item.kind} {item.name!r} — {item.reason}"
            )
    elif result.unverified and result.exit_code != 0:
        console.print(
            "[red]Unverified state is present and not waived — exit code "
            "reflects this. Re-run with --allow-unverified to waive "
            "explicitly, or resolve/populate it and re-lock.[/red]"
        )
