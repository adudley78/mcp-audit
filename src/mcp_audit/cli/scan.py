"""scan / discover / pin / diff / watch commands."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_audit import cli as _cli
from mcp_audit._gate import gate
from mcp_audit.analyzers.rug_pull import (
    build_state_entry,
    compute_hashes,
    derive_state_path,
    load_state,
    save_state,
    server_key,
)
from mcp_audit.cli import app, console
from mcp_audit.cli._helpers import _write_output
from mcp_audit.models import Severity
from mcp_audit.output.nucleus import format_nucleus
from mcp_audit.output.sarif import format_sarif
from mcp_audit.output.terminal import print_results

# ── Private helpers ───────────────────────────────────────────────────────────


def _scoped_state_path(extra_paths: list[Path] | None) -> Path:
    """Derive the scoped rug-pull state path for the given extra paths."""
    configs = _cli.discover_configs(extra_paths=extra_paths)
    return derive_state_path(configs)


def _reset_scoped_state(extra_paths: list[Path] | None, con: Console) -> None:
    """Delete the scoped state file if it exists, printing a status line."""
    scoped = _scoped_state_path(extra_paths)
    if scoped.exists():
        scoped.unlink()
        con.print(f"[dim]Reset state: {scoped.name}[/dim]\n")
    else:
        con.print(f"[dim]No state file to reset ({scoped.name}).[/dim]\n")


def _newest_last_seen(stored: dict) -> str:
    """Return the most recent last_seen timestamp across all stored servers."""
    timestamps = [
        entry.get("last_seen", "")
        for entry in stored.values()
        if entry.get("last_seen")
    ]
    return max(timestamps) if timestamps else ""


def _drift_to_findings(
    drift: list,  # list[DriftFinding]
) -> list:
    """Convert DriftFinding objects to standard Finding objects.

    Uses ``analyzer="baseline"`` so drift findings appear in all output
    formats alongside analyzer findings.
    """
    from mcp_audit.models import Finding  # noqa: PLC0415

    findings = []
    for i, df in enumerate(drift):
        evidence_parts = []
        if df.baseline_value is not None:
            evidence_parts.append(f"baseline: {df.baseline_value}")
        if df.current_value is not None:
            evidence_parts.append(f"current: {df.current_value}")
        evidence = "; ".join(evidence_parts) if evidence_parts else "N/A"

        findings.append(
            Finding(
                id=f"DRIFT-{i + 1:03d}",
                severity=df.severity,
                analyzer="baseline",
                client=df.client,
                server=df.server_name,
                title=f"Baseline drift [{df.drift_type.value}]: {df.server_name}",
                description=df.description,
                evidence=evidence,
                remediation=(
                    "Review this change. If intentional, run "
                    "'mcp-audit baseline save' to update your baseline."
                ),
            )
        )
    return findings


# ── scan ──────────────────────────────────────────────────────────────────────


@app.command()
def scan(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Scan a specific config file or directory"
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, nucleus, sarif",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "--output-file",
        "-o",
        help="Write results to file (--output-file is an alias)",
    ),
    severity_threshold: str = typer.Option(  # noqa: B008
        "INFO",
        "--severity-threshold",
        "-s",
        help=(
            "Minimum severity to report. "
            "Exit code 1 if findings at or above this level exist. "
            "Accepted: critical, high, medium, low, info"
        ),
    ),
    offline: bool = typer.Option(  # noqa: B008
        False, "--offline", help="Skip all network calls"
    ),
    json_flag: bool = typer.Option(  # noqa: B008
        False, "--json", help="Shortcut for --format json"
    ),
    connect: bool = typer.Option(  # noqa: B008
        False,
        "--connect",
        help=(
            "Connect to running MCP servers via the protocol handshake and "
            "analyze live tool descriptions "
            "(requires: pip install 'mcp-audit\\[mcp]')"
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
    asset_prefix: str | None = typer.Option(  # noqa: B008
        None,
        "--asset-prefix",
        help=(
            "Override the hostname prefix used in Nucleus and SARIF output. "
            "Useful when the hostname is not meaningful (e.g. 'MacBookAir') "
            "and the team prefers an asset tag or employee ID."
        ),
    ),
    no_score: bool = typer.Option(  # noqa: B008
        False,
        "--no-score",
        help="Suppress the score/grade panel in terminal output.",
    ),
    registry: Path | None = typer.Option(  # noqa: B008
        None,
        "--registry",
        help="Custom registry file path (overrides user cache and bundled registry)",
    ),
    baseline_name: str | None = typer.Option(  # noqa: B008
        None,
        "--baseline",
        help=(
            "Compare scan results against a named baseline. "
            "Use 'latest' to select the most recent baseline automatically."
        ),
    ),
    rules_dir: Path | None = typer.Option(  # noqa: B008
        None,
        "--rules-dir",
        help=(
            "Load additional detection rules from this directory. "
            "Requires a Pro or Enterprise license."
        ),
    ),
    offline_registry: bool = typer.Option(  # noqa: B008
        False,
        "--offline-registry",
        help="Use bundled registry only, skip user cache",
    ),
    policy: Path | None = typer.Option(  # noqa: B008
        None,
        "--policy",
        help=(
            "Path to a governance policy file (.mcp-audit-policy.yml). "
            "When omitted, auto-discovery checks cwd → repo root → "
            f"{_cli._USER_CONFIG_DIR / 'policy.yml'}."
        ),
    ),
    verify_hashes: bool = typer.Option(  # noqa: B008
        False,
        "--verify-hashes",
        help=(
            "Download and verify package hashes against registry "
            "(requires network access; free for all tiers)"
        ),
    ),
    sast: Path | None = typer.Option(  # noqa: B008
        None,
        "--sast",
        help=(
            "Path to MCP server source code to scan with Semgrep SAST rules. "
            "Requires semgrep (pip install semgrep) and a Pro license."
        ),
    ),
    include_extensions: bool = typer.Option(  # noqa: B008
        False,
        "--include-extensions",
        help=(
            "Also scan installed IDE extensions for security issues. "
            "Requires a Pro or Enterprise license."
        ),
    ),
) -> None:
    """Scan MCP configurations for security issues."""
    extra_paths = [path] if path else None
    fmt = "json" if json_flag else output_format

    if reset_state:
        _reset_scoped_state(extra_paths, console)

    if offline and verify_hashes:
        console.print(
            "[red]Error:[/red] --verify-hashes makes network requests "
            "and cannot be used with --offline."
        )
        raise typer.Exit(code=2)  # noqa: B904

    # Validate user-supplied paths upfront — non-existent paths produce a clean
    # exit-2 error rather than a Python traceback deep in a library call.
    if registry is not None and not registry.resolve().exists():
        console.print(f"[red]Registry file not found:[/red] {registry}")
        raise typer.Exit(2)  # noqa: B904

    if sast is not None and not sast.resolve().exists():
        console.print(f"[red]SAST target path does not exist:[/red] {sast}")
        raise typer.Exit(2)  # noqa: B904

    # Build a custom analyzers list when a custom registry path or offline
    # registry flag is supplied.
    analyzers = None
    if registry is not None or offline_registry:
        from mcp_audit.analyzers.credentials import CredentialsAnalyzer  # noqa: PLC0415, I001
        from mcp_audit.analyzers.poisoning import PoisoningAnalyzer  # noqa: PLC0415, I001
        from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer  # noqa: PLC0415, I001
        from mcp_audit.analyzers.transport import TransportAnalyzer  # noqa: PLC0415, I001

        analyzers = [
            PoisoningAnalyzer(),
            CredentialsAnalyzer(),
            TransportAnalyzer(),
            SupplyChainAnalyzer(
                registry_path=registry,
                offline_registry=offline_registry,
            ),
        ]

    # ── Pro-gated custom rules ─────────────────────────────────────────────────
    # Build the list of extra rules directories.  Community rules (bundled) are
    # always loaded by the scanner regardless of license tier.
    extra_rules_dirs: list[Path] = []
    from mcp_audit.scanner import _USER_RULES_DIR  # noqa: PLC0415

    if rules_dir is not None and gate(
        "custom_rules",
        console,
        message="--rules-dir skipped; bundled community rules still apply.",
    ):
        if not rules_dir.is_dir():
            console.print(
                f"[red]--rules-dir path is not a directory: {rules_dir}[/red]"
            )
            raise typer.Exit(2)  # noqa: B904
        extra_rules_dirs.append(rules_dir)

    if _USER_RULES_DIR.is_dir() and _cli.cached_is_pro_feature_available(
        "custom_rules"
    ):
        extra_rules_dirs.append(_USER_RULES_DIR)

    result = _cli.run_scan(
        extra_paths=extra_paths,
        analyzers=analyzers,
        connect=connect,
        offline=offline,
        extra_rules_dirs=extra_rules_dirs if extra_rules_dirs else None,
    )

    # ── Hash verification (opt-in via --verify-hashes) ────────────────────────
    if verify_hashes and result.servers:
        from mcp_audit.attestation.verifier import verify_server_hashes  # noqa: PLC0415
        from mcp_audit.registry.loader import KnownServerRegistry  # noqa: PLC0415

        _vh_registry = KnownServerRegistry(path=registry, offline=offline_registry)
        _hashable = [
            s
            for s in result.servers
            if _vh_registry.get(s.name) is not None
            and _vh_registry.get(s.name).known_hashes  # type: ignore[union-attr]
        ]
        console.print(
            f"[dim]Hash verification: checking {len(_hashable)} package(s)…[/dim]"
        )
        hash_findings = verify_server_hashes(result.servers, _vh_registry)
        result.findings.extend(hash_findings)

    # Surface parse failures for user-specified paths.
    # Auto-discovered configs that fail are silently recorded in result.errors
    # and surfaced in JSON output. User-specified paths must exit 2 — the user
    # explicitly asked for that file and a clean result would be misleading.
    if extra_paths and result.errors:
        resolved_extra = {p.expanduser().resolve() for p in extra_paths}
        user_path_errors = [
            e for e in result.errors if any(str(rp) in e for rp in resolved_extra)
        ]
        if user_path_errors:
            for err in user_path_errors:
                console.print(f"[red]Error:[/red] {err}")
            raise typer.Exit(2)  # noqa: B904

    # Baseline drift detection (opt-in via --baseline)
    if baseline_name is not None:
        from mcp_audit.baselines.manager import BaselineManager  # noqa: PLC0415

        mgr = BaselineManager()
        try:
            if baseline_name == "latest":
                bl = mgr.load_latest()
                if bl is None:
                    console.print(
                        "[red]No baselines found.[/red]  "
                        "Run [bold]mcp-audit baseline save[/bold] first."
                    )
                    raise typer.Exit(2)  # noqa: B904
            else:
                bl = mgr.load(baseline_name)
        except FileNotFoundError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2)  # noqa: B904

        drift = mgr.compare(bl, result.servers)
        drift_findings = _drift_to_findings(drift)
        result.findings.extend(drift_findings)

    # Governance policy evaluation (auto-discovered or explicit --policy)
    _resolved_policy = None
    try:
        from mcp_audit.governance.loader import load_policy  # noqa: PLC0415

        _resolved_policy = load_policy(policy)
    except ValueError as _gov_load_err:
        console.print(f"[red]Governance policy error:[/red] {_gov_load_err}")
        raise typer.Exit(2)  # noqa: B904

    if _resolved_policy is not None:
        from mcp_audit.governance.evaluator import evaluate_governance  # noqa: PLC0415

        _gov_registry = None
        if analyzers is not None:
            for _a in analyzers:
                from mcp_audit.analyzers.supply_chain import (
                    SupplyChainAnalyzer,  # noqa: PLC0415
                )

                if isinstance(_a, SupplyChainAnalyzer):
                    _gov_registry = _a.registry
                    break

        gov_findings = evaluate_governance(
            servers=result.servers,
            policy=_resolved_policy,
            registry=_gov_registry,
            scan_result=result,
        )
        result.findings.extend(gov_findings)

    # ── SAST scan (Pro-gated, requires semgrep) ────────────────────────────────
    if sast is not None and gate(
        "sast",
        console,
        message="--sast skipped; MCP config scan continues.",
    ):
        from mcp_audit.sast.runner import run_semgrep  # noqa: PLC0415

        console.print(f"[dim]SAST: scanning {sast} with Semgrep rules…[/dim]")
        sast_result = run_semgrep(target_path=sast)
        if sast_result.error:
            console.print(
                f"[yellow]SAST warning:[/yellow] {sast_result.error}",
                err=True,
            )
        else:
            result.findings.extend(sast_result.findings)
            console.print(
                f"[dim]SAST: scanned {sast_result.files_scanned} file(s), "
                f"found {len(sast_result.findings)} issue(s)[/dim]"
            )

    # ── Extension scan (Pro-gated, --include-extensions) ─────────────────────
    if include_extensions and gate(
        "extensions",
        console,
        message="--include-extensions skipped; MCP config scan continues.",
    ):
        from mcp_audit.extensions.analyzer import analyze_extensions  # noqa: I001, PLC0415
        from mcp_audit.extensions.discovery import discover_extensions  # noqa: PLC0415

        _ext_list = discover_extensions()
        _ext_findings = analyze_extensions(_ext_list)
        result.findings.extend(_ext_findings)
        console.print(
            f"[dim]Extensions: {len(_ext_list)} extension(s) scanned, "
            f"{len(_ext_findings)} issue(s) found[/dim]"
        )

    # Filter by severity threshold
    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2)  # noqa: B904

    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    threshold_idx = severity_order.index(threshold)
    result.findings = [
        f for f in result.findings if severity_order.index(f.severity) <= threshold_idx
    ]

    # Suppress score for non-terminal formatters when --no-score is requested.
    # The scanner always calculates the score; suppression is a presentation-layer
    # decision applied here, after scanning, before any formatter is called.
    if no_score:
        result.score = None

    # Output
    if fmt == "json":
        out = result.model_dump_json(indent=2)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif fmt == "nucleus":
        out = format_nucleus(result, asset_prefix=asset_prefix, console=console)
        if out is None:
            raise typer.Exit(0)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif fmt == "sarif":
        out = format_sarif(result, asset_prefix=asset_prefix)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif fmt == "terminal":
        print_results(result, console=console, show_score=not no_score)
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
    configs = _cli.discover_configs(extra_paths=extra_paths)

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
    configs = _cli.discover_configs(extra_paths=extra_paths)

    all_servers = []
    for config in configs:
        try:
            all_servers.extend(_cli.parse_config(config))
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
    configs = _cli.discover_configs(extra_paths=extra_paths)
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
            all_servers.extend(_cli.parse_config(config))
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
                    f
                    for f in ("command", "args", "env_keys", "raw")
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


# ── watch ─────────────────────────────────────────────────────────────────────


@app.command()
def watch(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional config file or directory to watch"
    ),
    severity_threshold: str = typer.Option(  # noqa: B008
        "INFO",
        "--severity-threshold",
        "-s",
        help="Minimum severity to report",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, nucleus, sarif",
    ),
    connect: bool = typer.Option(  # noqa: B008
        False,
        "--connect",
        help="Connect to live MCP servers during each re-scan",
    ),
    rules_dir: Path | None = typer.Option(  # noqa: B008
        None,
        "--rules-dir",
        help="Additional YAML rules directory per re-scan (Pro/Enterprise)",
    ),
) -> None:
    """Continuously monitor MCP configs and scan on changes."""
    import threading  # noqa: PLC0415
    from datetime import datetime  # noqa: PLC0415

    from rich.rule import Rule  # noqa: PLC0415

    from mcp_audit.output.nucleus import format_nucleus  # noqa: PLC0415
    from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415
    from mcp_audit.scanner import (
        _USER_RULES_DIR as _WATCH_USER_RULES_DIR,  # noqa: PLC0415
    )
    from mcp_audit.watcher import ConfigWatcher  # noqa: PLC0415

    extra_paths = [path] if path else None

    extra_rules_dirs: list[Path] = []
    if rules_dir is not None and gate(
        "custom_rules",
        console,
        message="--rules-dir skipped; bundled community rules still apply.",
    ):
        if not rules_dir.is_dir():
            console.print(
                f"[red]--rules-dir path is not a directory: {rules_dir}[/red]"
            )
            raise typer.Exit(2)  # noqa: B904
        extra_rules_dirs.append(rules_dir)

    if _WATCH_USER_RULES_DIR.is_dir() and _cli.cached_is_pro_feature_available(
        "custom_rules"
    ):
        extra_rules_dirs.append(_WATCH_USER_RULES_DIR)

    watch_extra_rules = extra_rules_dirs if extra_rules_dirs else None

    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2)  # noqa: B904

    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    threshold_idx = severity_order.index(threshold)

    def _run_and_print(label: str) -> None:
        """Execute a full scan and emit results with the configured formatter."""
        result = _cli.run_scan(
            extra_paths=extra_paths,
            connect=connect,
            extra_rules_dirs=watch_extra_rules,
        )
        result.findings = [
            f
            for f in result.findings
            if severity_order.index(f.severity) <= threshold_idx
        ]

        console.print()
        console.print(Rule(f"[dim]{label}[/dim]"))

        if output_format == "terminal":
            print_results(result, console=console)
        elif output_format == "json":
            typer.echo(result.model_dump_json(indent=2))
        elif output_format == "nucleus":
            out = format_nucleus(result, console=console)
            if out is not None:
                typer.echo(out)
        elif output_format == "sarif":
            typer.echo(format_sarif(result))
        else:
            console.print(
                f"[red]Unknown format: {output_format!r}. "
                "Choose terminal, json, nucleus, or sarif.[/red]"
            )

        console.print()
        console.print("[dim]Watching for changes…[/dim]")

    def _on_change(changed_path: Path, event_type: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")  # noqa: DTZ005
        console.print(
            f"\n[bold cyan][{ts}][/bold cyan] "
            f"Config {event_type}: [cyan]{changed_path}[/cyan]"
        )
        _run_and_print(f"{ts} — triggered by {event_type}: {changed_path.name}")

    watcher = ConfigWatcher(
        on_change_callback=_on_change,
        extra_paths=extra_paths,
    )

    n = len(watcher.watchable_dirs)
    console.print(
        f"\n[bold cyan]Watching {n} config location(s) for changes…"
        "  (Ctrl+C to stop)[/bold cyan]\n"
    )
    for d in watcher.watchable_dirs:
        console.print(f"  [green]✓[/green] {d}")
    for d in watcher.skipped_dirs:
        console.print(f"  [dim]✗ {d}  (not found — will watch if created)[/dim]")
    console.print()

    _run_and_print("initial scan")

    watcher.start()
    stop_event = threading.Event()
    try:
        while not stop_event.wait(timeout=1.0):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        watcher.stop()
        console.print("\n[dim]Stopped watching.[/dim]")
