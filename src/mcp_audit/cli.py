"""mcp-audit CLI — MCP Security Scanner."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_audit import __version__
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
from mcp_audit.licensing import (
    LicenseInfo,
    get_active_license,
    is_pro_feature_available,
    save_license,
)
from mcp_audit.models import Severity
from mcp_audit.output.dashboard import generate_html
from mcp_audit.output.nucleus import format_nucleus
from mcp_audit.output.sarif import format_sarif
from mcp_audit.output.terminal import print_results
from mcp_audit.scanner import run_scan

_UPDATE_REGISTRY_URL = "https://raw.githubusercontent.com/adudley78/mcp-audit/main/registry/known-servers.json"
_REGISTRY_CACHE_PATH = (
    Path.home() / ".config" / "mcp-audit" / "registry" / "known-servers.json"
)

app = typer.Typer(
    name="mcp-audit",
    help="Privacy-first security scanner for MCP server configurations.",
    no_args_is_help=True,
)
console = Console()

# ── baseline sub-app ──────────────────────────────────────────────────────────

baseline_app = typer.Typer(
    name="baseline",
    help="Save and compare MCP configuration baselines.",
    no_args_is_help=True,
)
app.add_typer(baseline_app, name="baseline")

# ── rule sub-app ──────────────────────────────────────────────────────────────

rule_app = typer.Typer(
    name="rule",
    help="Manage and test policy-as-code detection rules.",
    no_args_is_help=True,
)
app.add_typer(rule_app, name="rule")

# ── policy sub-app ────────────────────────────────────────────────────────────

policy_app = typer.Typer(
    name="policy",
    help="Manage governance policy files (.mcp-audit-policy.yml).",
    no_args_is_help=True,
)
app.add_typer(policy_app, name="policy")

# ── extensions sub-app ────────────────────────────────────────────────────────

extensions_app = typer.Typer(
    name="extensions",
    help="Discover and scan installed IDE extensions for security issues.",
    no_args_is_help=True,
)
app.add_typer(extensions_app, name="extensions")


# ── Internal helpers ──────────────────────────────────────────────────────────


def _scoped_state_path(extra_paths: list[Path] | None) -> Path:
    """Derive the scoped rug-pull state path for the given extra paths."""
    from mcp_audit.discovery import discover_configs  # noqa: PLC0415

    configs = discover_configs(extra_paths=extra_paths)
    return derive_state_path(configs)


def _reset_scoped_state(extra_paths: list[Path] | None, con: Console) -> None:
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
            "~/.config/mcp-audit/policy.yml."
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

    if rules_dir is not None:
        if not is_pro_feature_available("custom_rules"):
            console.print(
                "[yellow]--rules-dir requires a Pro or Enterprise license.[/yellow]\n"
                "  Bundled community rules still apply.\n"
                "  Upgrade at [link=https://mcp-audit.dev/pro]"
                "https://mcp-audit.dev/pro[/link]"
            )
        else:
            if not rules_dir.is_dir():
                console.print(
                    f"[red]--rules-dir path is not a directory: {rules_dir}[/red]"
                )
                raise typer.Exit(2)  # noqa: B904
            extra_rules_dirs.append(rules_dir)

    if _USER_RULES_DIR.is_dir() and is_pro_feature_available("custom_rules"):
        extra_rules_dirs.append(_USER_RULES_DIR)

    result = run_scan(
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
    if sast is not None:
        if not is_pro_feature_available("sast"):
            console.print(
                "[yellow]⚡ Pro feature:[/yellow] SAST scanning requires "
                "a Pro or Enterprise license.\n"
                "   Activate with: [bold]mcp-audit activate <key>[/bold]"
            )
        else:
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
    if include_extensions:
        if not is_pro_feature_available("extensions"):
            console.print(
                "[yellow]⚡ Pro feature:[/yellow] --include-extensions requires "
                "a Pro or Enterprise license.\n"
                "   Activate with: [bold]mcp-audit activate <key>[/bold]\n"
                "   MCP config scan continues without extension scanning."
            )
        else:
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
    html = generate_html(result, console=console)
    if html is None:
        raise typer.Exit(0)
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
) -> None:
    """Continuously monitor MCP configs and scan on changes."""
    import threading  # noqa: PLC0415
    from datetime import datetime  # noqa: PLC0415

    from rich.rule import Rule  # noqa: PLC0415

    from mcp_audit.output.nucleus import format_nucleus  # noqa: PLC0415
    from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415
    from mcp_audit.watcher import ConfigWatcher  # noqa: PLC0415

    extra_paths = [path] if path else None

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
        result = run_scan(extra_paths=extra_paths, connect=connect)
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


# ── update-registry ───────────────────────────────────────────────────────────


@app.command(name="update-registry")
def update_registry() -> None:
    """Fetch the latest known-server registry from the upstream repository.

    Saves the registry to ``~/.config/mcp-audit/registry/known-servers.json``.
    On the next scan the updated registry is used automatically.

    Requires a Pro or Enterprise license.
    """
    if not is_pro_feature_available("update_registry"):
        console.print(
            "[yellow]update-registry is a Pro feature.[/yellow]\n"
            "  Upgrade at [link=https://mcp-audit.dev/pro]https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(0)  # noqa: B904

    console.print(f"[dim]Fetching registry from {_UPDATE_REGISTRY_URL}…[/dim]")

    try:
        with urllib.request.urlopen(_UPDATE_REGISTRY_URL, timeout=30) as resp:  # noqa: S310  # nosec B310 -- _UPDATE_REGISTRY_URL is a hardcoded https://raw.githubusercontent.com/ constant
            raw = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        console.print(f"[red]Network error fetching registry: {exc}[/red]")
        raise typer.Exit(2)  # noqa: B904

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON in downloaded registry: {exc}[/red]")
        raise typer.Exit(2)  # noqa: B904

    if "entries" not in data or not isinstance(data.get("entries"), list):
        console.print(
            "[red]Malformed registry: missing or invalid 'entries' key.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    # Security: 0o700 directory, 0o600 file — registry cache may contain
    # proprietary server metadata; restrict to the owning user only.
    _REGISTRY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import os as _os  # noqa: PLC0415

    _reg_fd = _os.open(
        str(_REGISTRY_CACHE_PATH),
        _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC,
        0o600,
    )
    with _os.fdopen(_reg_fd, "w", encoding="utf-8") as _reg_fh:
        _reg_fh.write(raw)

    count = data.get("entry_count", len(data["entries"]))
    version_str = data.get("schema_version", "unknown")
    last_updated = data.get("last_updated", "unknown")

    console.print(
        f"[green]Registry updated:[/green] {count} entries, "
        f"version {version_str}, last updated {last_updated}"
    )


# ── merge ─────────────────────────────────────────────────────────────────────


@app.command()
def merge(
    files: list[Path] | None = typer.Argument(  # noqa: B008
        default=None,
        help="One or more JSON scan output files to merge",
    ),
    dir_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--dir",
        help=(
            "Merge all .json files found in DIRECTORY (non-recursive). "
            "Cannot combine with FILES."
        ),
    ),
    asset_prefix: str | None = typer.Option(  # noqa: B008
        None,
        "--asset-prefix",
        help=(
            "Only include machines whose hostname starts with PREFIX. "
            "Example: --asset-prefix prod- to include only prod machines."
        ),
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal (default), json, html",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "--output-file",
        "-o",
        help="Write output to file instead of stdout",
    ),
) -> None:
    """Merge JSON scan outputs from multiple machines into a fleet report.

    Requires an Enterprise license.

    Examples:

        mcp-audit merge results/*.json

        mcp-audit merge --dir ./fleet-results/ --format json -o fleet.json

        mcp-audit merge --dir ./results/ --asset-prefix prod-
    """
    from mcp_audit.fleet.merger import FleetMerger, generate_fleet_html  # noqa: PLC0415

    if not is_pro_feature_available("fleet_merge"):
        console.print(
            "[yellow]mcp-audit merge requires an Enterprise license.[/yellow]\n"
            "  Upgrade at [link=https://mcp-audit.dev/pro]https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(0)  # noqa: B904

    if dir_path is not None and files:
        console.print("[red]Cannot combine FILES arguments with --dir.[/red]")
        raise typer.Exit(2)  # noqa: B904

    if dir_path is not None:
        if not dir_path.is_dir():
            console.print(f"[red]--dir path is not a directory: {dir_path}[/red]")
            raise typer.Exit(2)  # noqa: B904
        paths = _collect_json_paths_from_dir(dir_path)
        if not paths:
            console.print(f"[red]No .json files found in {dir_path}[/red]")
            raise typer.Exit(2)  # noqa: B904
    elif files:
        paths = list(files)
    else:
        console.print(
            "[red]Provide at least one scan file, or use --dir DIRECTORY.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    merger = FleetMerger(asset_prefix_filter=asset_prefix)

    try:
        report = merger.merge(paths)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)  # noqa: B904

    if report.version_mismatches:
        for warning in report.version_mismatches:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

    if output_format == "json":
        out = report.model_dump_json(indent=2)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif output_format == "html":
        out = generate_fleet_html(report)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif output_format == "terminal":
        _print_fleet_report(report, console)
    else:
        console.print(
            f"[red]Unknown format: {output_format!r}. "
            "Choose terminal, json, or html.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    if report.stats.total_findings > 0:
        raise typer.Exit(1)


# ── version ───────────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Show version information."""
    info = get_active_license()
    if info is not None and info.is_valid:
        tier_label = info.tier.capitalize()
    else:
        tier_label = "Community"
    console.print(f"mcp-audit {__version__} ({tier_label})")


# ── activate ──────────────────────────────────────────────────────────────────


@app.command()
def activate(
    key: str = typer.Argument(help="License key string to activate"),  # noqa: B008
) -> None:
    """Activate a Pro or Enterprise license key."""
    try:
        info: LicenseInfo = save_license(key)
    except ValueError:
        console.print("[red]✗ Invalid license key. Check your key and try again.[/red]")
        console.print(
            "  Purchase a license at [link=https://mcp-audit.dev/pro]"
            "https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(1)  # noqa: B904

    tier_label = info.tier.capitalize()
    console.print(f"[green]✓ License activated: {tier_label} tier[/green]")
    console.print(f"  Email:   {info.email}")
    console.print(f"  Expires: {info.expires.isoformat()}")


# ── license ───────────────────────────────────────────────────────────────────


@app.command()
def license() -> None:  # noqa: A001
    """Show current license status."""
    info = get_active_license()
    if info is None:
        console.print("[bold]mcp-audit Community (free)[/bold]")
        console.print(
            "  Upgrade to Pro: [link=https://mcp-audit.dev/pro]"
            "https://mcp-audit.dev/pro[/link]"
        )
        return

    status = "[green]Active[/green]" if info.is_valid else "[red]Expired[/red]"
    tier_label = info.tier.capitalize()
    console.print(f"[bold]mcp-audit {tier_label}[/bold]")
    console.print(f"  Email:   {info.email}")
    console.print(f"  Expires: {info.expires.isoformat()}")
    console.print(f"  Status:  {status}")


# ── entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()


# ── Private helpers ────────────────────────────────────────────────────────────


def _write_output(path: Path, content: str) -> None:
    """Write *content* to *path*, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _newest_last_seen(stored: dict) -> str:
    """Return the most recent last_seen timestamp across all stored servers."""
    timestamps = [
        entry.get("last_seen", "")
        for entry in stored.values()
        if entry.get("last_seen")
    ]
    return max(timestamps) if timestamps else ""


def _collect_json_paths_from_dir(directory: Path) -> list[Path]:
    """Return all ``*.json`` files in *directory* (non-recursive).

    Silently skips non-JSON files.  Logs a warning and skips files that fail
    mcp-audit JSON validation so that a single corrupt file does not abort the
    entire merge operation.
    """
    from mcp_audit.fleet.merger import FleetMerger  # noqa: PLC0415

    json_files = sorted(directory.glob("*.json"))
    valid: list[Path] = []
    _tmp_merger = FleetMerger()
    for path in json_files:
        try:
            _tmp_merger.load_report(path)
            valid.append(path)
        except ValueError as exc:
            console.print(f"[yellow]Warning: skipping {path.name}: {exc}[/yellow]")
    return valid


def _print_fleet_report(report: object, con: Console) -> None:
    """Render a FleetReport to the terminal using Rich tables."""
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415

    from mcp_audit.fleet.merger import FleetReport as _FleetReport  # noqa: PLC0415
    from mcp_audit.models import Severity  # noqa: PLC0415

    if not isinstance(report, _FleetReport):
        return

    s = report.stats
    score_line = f"{s.average_score:.1f}/100" if s.average_score is not None else "N/A"

    lines: list[str] = [
        f"[bold]Total machines scanned:[/bold] {s.total_machines}",
        f"[bold]Total findings:[/bold]         {s.total_findings}",
        f"[bold]Unique findings:[/bold]         {s.unique_findings}",
        f"[bold]Average config score:[/bold]    {score_line}",
    ]

    if s.riskiest_machine:
        risk_count = sum(
            1
            for m in report.machines
            if m.machine_id == s.riskiest_machine
            for f in m.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        lines.append(
            f"[bold]Riskiest machine:[/bold]        [red]{s.riskiest_machine}[/red] "
            f"({risk_count} critical/high finding{'s' if risk_count != 1 else ''})"
        )

    if s.most_common_finding and report.deduplicated_findings:
        top = report.deduplicated_findings[0]
        lines.append(
            f"[bold]Most widespread issue:[/bold]   {s.most_common_finding} "
            f"(affects {top.affected_count}/{s.total_machines} machines)"
        )

    con.print(Panel("\n".join(lines), title="Fleet Summary", border_style="cyan"))

    if not report.deduplicated_findings:
        con.print("[green]No findings across fleet.[/green]")
        return

    _SEV_STYLE = {  # noqa: N806
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[blue]LOW[/blue]",
        "INFO": "[dim]INFO[/dim]",
    }

    table = Table(show_header=True, header_style="bold", title="Finding Breakdown")
    table.add_column("Severity", width=10)
    table.add_column("Finding")
    table.add_column("Affected Machines", justify="center", width=20)
    table.add_column("First Seen", width=20)

    for df in report.deduplicated_findings:
        sev_display = _SEV_STYLE.get(df.severity.value, df.severity.value)
        machines_display = f"{df.affected_count}/{s.total_machines} machines"
        first_seen_str = df.first_seen.strftime("%Y-%m-%d %H:%M")
        table.add_row(sev_display, df.title, machines_display, first_seen_str)

    con.print(table)


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


# ── rule validate ─────────────────────────────────────────────────────────────


@rule_app.command(name="validate")
def rule_validate(
    file: Path = typer.Argument(help="Path to a YAML rule file to validate"),  # noqa: B008
) -> None:
    """Validate a rule file without running a scan.

    Checks that all rules in the file conform to the PolicyRule schema.
    Exits 0 if all rules are valid, 1 if any errors are found.

    Requires a Pro or Enterprise license.
    """
    if not is_pro_feature_available("custom_rules"):
        console.print(
            "[yellow]rule validate is a Pro feature.[/yellow]\n"
            "  Upgrade at [link=https://mcp-audit.dev/pro]https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(0)  # noqa: B904

    from mcp_audit.rules.engine import load_rules_from_file  # noqa: PLC0415

    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)  # noqa: B904

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

    Requires a Pro or Enterprise license.
    """
    if not is_pro_feature_available("custom_rules"):
        console.print(
            "[yellow]rule test is a Pro feature.[/yellow]\n"
            "  Upgrade at [link=https://mcp-audit.dev/pro]https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(0)  # noqa: B904

    from mcp_audit.config_parser import parse_config  # noqa: PLC0415
    from mcp_audit.discovery import DiscoveredConfig  # noqa: PLC0415
    from mcp_audit.rules.engine import (  # noqa: PLC0415
        _evaluate_rule_match,
        load_rules_from_file,
    )

    if not file.exists():
        console.print(f"[red]Rule file not found: {file}[/red]")
        raise typer.Exit(0)  # noqa: B904

    if not against.exists():
        console.print(f"[red]Config file not found: {against}[/red]")
        raise typer.Exit(0)  # noqa: B904

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
        servers = parse_config(config)
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

    Shows bundled community rules and, for Pro users, user-local rules from
    ``~/.config/mcp-audit/rules/``.  Always free — transparency about what runs.
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

    # User-local rules (shown for Pro users only)
    if _USER_RULES_DIR.is_dir() and is_pro_feature_available("custom_rules"):
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

    # Extra --rules-dir (shown for Pro users only)
    if rules_dir is not None:
        if not is_pro_feature_available("custom_rules"):
            console.print(
                "[yellow]--rules-dir listing requires a Pro or Enterprise "
                "license.[/yellow]"
            )
        elif rules_dir.is_dir():
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
    from mcp_audit.config_parser import parse_config  # noqa: PLC0415

    extra_paths = [path] if path else None
    configs = discover_configs(extra_paths=extra_paths)

    all_servers = []
    for config in configs:
        try:
            all_servers.extend(parse_config(config))
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
    from mcp_audit.config_parser import parse_config  # noqa: PLC0415

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
    configs = discover_configs(extra_paths=extra_paths)
    all_servers = []
    for config in configs:
        try:
            all_servers.extend(parse_config(config))
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


# ── policy validate ───────────────────────────────────────────────────────────

_POLICY_TEMPLATE = """\
# mcp-audit governance policy
# Reference: https://github.com/adudley78/mcp-audit/blob/main/docs/governance.md
version: 1
name: "My organisation governance policy"

# ── Approved servers ──────────────────────────────────────────────────────────
# mode: "allowlist" (only listed servers allowed) or "denylist" (listed forbidden)
# entries: list of approved/denied servers; name supports fnmatch glob patterns
# approved_servers:
#   mode: allowlist
#   violation_severity: high    # critical | high | medium | low | info
#   message: "Server {server_name} is not on the approved server list"
#   entries:
#     - name: "@modelcontextprotocol/server-filesystem"
#       source: npm    # npm | pip | github | null (any)
#       notes: "Official filesystem server"
#     - name: "@modelcontextprotocol/*"
#       notes: "All official MCP servers"

# ── Minimum scan score ────────────────────────────────────────────────────────
# Fails if the numeric scan score (0-100) falls below `minimum`.
# score_threshold:
#   minimum: 70
#   violation_severity: medium
#   message: "Configuration scored {score} ({grade}), below minimum of {minimum}"

# ── Transport policy ──────────────────────────────────────────────────────────
# Controls which MCP transport types are permitted.
# transport_policy:
#   require_tls: false     # block all unencrypted HTTP URLs
#   allow_stdio: true      # stdio (subprocess) transport
#   allow_sse: true        # Server-Sent Events transport
#   allow_http: true       # HTTP/HTTPS (streamable-http) transport
#   block_http: false      # explicit HTTP block (overrides allow_http)
#   violation_severity: high

# ── Registry membership ───────────────────────────────────────────────────────
# Requires servers to appear in the Known-Server Registry.
# registry_policy:
#   require_known: false    # server must be in the registry
#   require_verified: false # server must be marked verified: true
#   violation_severity: medium
#   message: "Server {server_name} is not in the Known-Server Registry"

# ── Finding count limits ──────────────────────────────────────────────────────
# Cap the number of findings at each severity. null means no limit.
# finding_policy:
#   max_critical: 0   # zero tolerance for critical findings
#   max_high: null    # no high-finding limit
#   max_medium: null
#   violation_severity: high

# ── Per-client overrides ──────────────────────────────────────────────────────
# Override any policy block for a specific MCP client.
# Valid client keys: claude-desktop, cursor, vscode, windsurf, claude-code,
#                    copilot-cli, augment
# client_overrides:
#   cursor:
#     approved_servers:
#       mode: allowlist
#       entries:
#         - name: "my-internal-server"
#           notes: "Cursor-only dev tool"
#   claude-desktop:
#     transport_policy:
#       allow_stdio: true
#       allow_http: false
#       block_http: true
"""


@policy_app.command(name="validate")
def policy_validate(
    file: Path = typer.Argument(help="Path to the governance policy file"),  # noqa: B008
) -> None:
    """Validate a governance policy file (schema check only).

    Exits 0 on success, 2 on any validation error.
    This command is free — no license required.
    """
    from mcp_audit.governance.loader import load_policy  # noqa: PLC0415

    try:
        loaded = load_policy(file)
    except ValueError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(2)  # noqa: B904

    if loaded is None:
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(2)  # noqa: B904

    console.print(
        f"[green]✔ Policy valid:[/green] {loaded.name!r}  "
        f"[dim](version {loaded.version})[/dim]"
    )
    if loaded.approved_servers:
        n = len(loaded.approved_servers.entries)
        console.print(
            f"  approved_servers: {loaded.approved_servers.mode.value}, "
            f"{n} entr{'y' if n == 1 else 'ies'}"
        )
    if loaded.score_threshold:
        console.print(f"  score_threshold: minimum={loaded.score_threshold.minimum}")
    if loaded.transport_policy:
        console.print("  transport_policy: configured")
    if loaded.registry_policy:
        console.print(
            f"  registry_policy: require_known={loaded.registry_policy.require_known}, "
            f"require_verified={loaded.registry_policy.require_verified}"
        )
    if loaded.finding_policy:
        console.print("  finding_policy: configured")
    if loaded.client_overrides:
        console.print(
            f"  client_overrides: {', '.join(loaded.client_overrides.keys())}"
        )


# ── policy init ───────────────────────────────────────────────────────────────


@policy_app.command(name="init")
def policy_init(
    output: Path = typer.Option(  # noqa: B008
        Path(".mcp-audit-policy.yml"),
        "--output",
        "-o",
        help="Destination path for the generated policy file",
    ),
) -> None:
    """Write a commented governance policy template to disk.

    Aborts if the destination file already exists.
    Requires a Pro or Enterprise license.
    """
    if not is_pro_feature_available("governance"):
        console.print(
            "[yellow]policy init requires a Pro or Enterprise license.[/yellow]\n"
            "  Upgrade at [link=https://mcp-audit.dev/pro]"
            "https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(1)  # noqa: B904

    if output.exists():
        console.print(
            f"[red]File already exists:[/red] {output}\n"
            "  Delete it manually or choose a different path with --output."
        )
        raise typer.Exit(2)  # noqa: B904

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_POLICY_TEMPLATE, encoding="utf-8")
    console.print(f"[green]✔ Policy template written to:[/green] {output}")
    console.print(
        "\nNext steps:\n"
        "  1. Edit the file to define your organisation's requirements.\n"
        "  2. Run [bold]mcp-audit policy validate[/bold] to check syntax.\n"
        "  3. Run [bold]mcp-audit scan[/bold] — policy is auto-discovered.\n"
    )


# ── policy check ─────────────────────────────────────────────────────────────


@policy_app.command(name="check")
def policy_check(
    policy: Path | None = typer.Option(  # noqa: B008
        None,
        "--policy",
        help="Path to governance policy file (auto-discovered when omitted)",
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional config path to check"
    ),
) -> None:
    """Evaluate governance policy violations only (no full security scan).

    Fast: skips all security analyzers, hashing, and network calls.
    Requires a Pro or Enterprise license.
    """
    if not is_pro_feature_available("governance"):
        console.print(
            "[yellow]policy check requires a Pro or Enterprise license.[/yellow]\n"
            "  Upgrade at [link=https://mcp-audit.dev/pro]"
            "https://mcp-audit.dev/pro[/link]"
        )
        raise typer.Exit(1)  # noqa: B904

    from mcp_audit.config_parser import parse_config  # noqa: PLC0415
    from mcp_audit.governance.evaluator import evaluate_governance  # noqa: PLC0415
    from mcp_audit.governance.loader import load_policy  # noqa: PLC0415

    # Load policy.
    try:
        loaded_policy = load_policy(policy)
    except ValueError as exc:
        console.print(f"[red]Governance policy error:[/red] {exc}")
        raise typer.Exit(2)  # noqa: B904

    if loaded_policy is None:
        console.print(
            "[yellow]No governance policy found.[/yellow]  "
            "Use [bold]mcp-audit policy init[/bold] to create one or "
            "pass [bold]--policy <path>[/bold]."
        )
        raise typer.Exit(0)  # noqa: B904

    # Discover and parse configs (no analyzers, no scoring).
    extra_paths = [path] if path else None
    configs = discover_configs(extra_paths=extra_paths)

    all_servers = []
    for config in configs:
        try:
            all_servers.extend(parse_config(config))
        except ValueError as exc:
            console.print(f"[yellow]Warning: {exc}[/yellow]")

    violations = evaluate_governance(
        servers=all_servers,
        policy=loaded_policy,
    )

    console.print(
        f"\n[bold]Governance check:[/bold] {loaded_policy.name!r}\n"
        f"  {len(configs)} client(s), {len(all_servers)} server(s) evaluated\n"
    )

    if not violations:
        console.print("[green]✔ No policy violations found.[/green]\n")
        raise typer.Exit(0)  # noqa: B904

    from mcp_audit.output.terminal import (  # noqa: PLC0415
        SEVERITY_COLORS,
        SEVERITY_ICONS,
    )

    console.print(f"[yellow bold]{len(violations)} violation(s) found:[/yellow bold]\n")
    for v in violations:
        color = SEVERITY_COLORS[v.severity]
        icon = SEVERITY_ICONS[v.severity]
        console.print(
            f"{icon} [{color} bold]{v.severity.value}[/{color} bold]  "
            f"[dim]{v.client}/{v.server}[/dim]"
        )
        console.print(f"   {v.title}")
        console.print(f"   [dim]→ {v.evidence}[/dim]")
        console.print()

    raise typer.Exit(1)  # noqa: B904


# ── verify ────────────────────────────────────────────────────────────────────


@app.command()
def verify(
    server_name: str | None = typer.Argument(  # noqa: B008
        None, help="Registry package name to verify (e.g. @scope/server-name)"
    ),
    all_servers: bool = typer.Option(  # noqa: B008
        False,
        "--all",
        help="Verify all configured servers that have pinned hashes in the registry",
    ),
    registry: Path | None = typer.Option(  # noqa: B008
        None,
        "--registry",
        help="Custom registry file path (overrides user cache and bundled registry)",
    ),
) -> None:
    """Verify package integrity by comparing hashes against registry pins.

    Downloads each package tarball, computes SHA-256, and compares against the
    pinned hash stored in the known-server registry.  Requires network access.

    Exit codes: 0 = all pass or unknown, 1 = hash mismatch detected, 2 = error.
    This command is free (Community tier) — verification is never paywalled.
    """
    from mcp_audit.attestation.hasher import verify_package_hash  # noqa: PLC0415
    from mcp_audit.attestation.verifier import (
        extract_version_from_server,  # noqa: PLC0415
    )
    from mcp_audit.registry.loader import KnownServerRegistry  # noqa: PLC0415

    if not server_name and not all_servers:
        console.print(
            "[red]Provide a SERVER_NAME argument or use --all to verify all "
            "configured servers.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    try:
        reg = KnownServerRegistry(path=registry)
    except FileNotFoundError as exc:
        console.print(f"[red]Registry not found:[/red] {exc}")
        raise typer.Exit(2)  # noqa: B904

    # ── Build the list of (package_name, version, source) to verify ───────────
    targets: list[tuple[str, str | None]] = []  # (package_name, version_or_None)

    if server_name:
        entry = reg.get(server_name)
        if entry is None:
            console.print(
                f"[yellow]{server_name!r} is not in the registry.[/yellow]  "
                "Only known-legitimate packages can be verified."
            )
            raise typer.Exit(0)  # noqa: B904
        if not entry.known_hashes:
            console.print(
                f"[yellow]No hashes pinned for {server_name!r} "
                "in the registry.[/yellow]"
            )
            raise typer.Exit(0)  # noqa: B904
        # Verify all pinned versions for the named package.
        for version in entry.known_hashes:
            targets.append((entry.name, version))
    else:
        # --all: discover configured servers, cross-reference with registry.
        import contextlib  # noqa: PLC0415

        configs = discover_configs()
        all_srv: list = []
        for config in configs:
            with contextlib.suppress(ValueError):
                all_srv.extend(parse_config(config))

        for srv in all_srv:
            entry = reg.get(srv.name)
            if entry is None or not entry.known_hashes:
                continue
            version = extract_version_from_server(srv)
            if version and version in entry.known_hashes:
                targets.append((entry.name, version))

        if not targets:
            console.print(
                "[yellow]No configured servers have pinned hashes "
                "in the registry.[/yellow]"
            )
            raise typer.Exit(0)  # noqa: B904

    # ── Run verifications ──────────────────────────────────────────────────────
    table = Table(
        "Server",
        "Version",
        "Expected Hash",
        "Computed Hash",
        "Status",
        title="[bold]Package Hash Verification[/bold]",
        show_lines=True,
    )

    any_fail = False

    for package_name, version in targets:
        entry = reg.get(package_name)
        if entry is None:
            continue

        if version is None:
            table.add_row(package_name, "?", "—", "—", "[yellow]~ UNKNOWN[/yellow]")
            continue

        expected = entry.known_hashes.get(version) if entry.known_hashes else None
        if expected is None:
            table.add_row(package_name, version, "—", "—", "[yellow]~ UNKNOWN[/yellow]")
            continue

        console.print(f"[dim]Downloading {package_name}@{version}…[/dim]")
        result = verify_package_hash(
            package_name=package_name,
            version=version,
            source=entry.source,
            expected_hash=expected,
        )

        exp_short = expected[7:15] + "…" if len(expected) > 15 else expected
        computed_short = (
            result.computed_hash[7:15] + "…"
            if result.computed_hash and len(result.computed_hash) > 15
            else (result.computed_hash or "—")
        )

        if result.match is True:
            status = "[green]✓ PASS[/green]"
        elif result.match is False:
            status = "[red bold]✗ FAIL[/red bold]"
            any_fail = True
        else:
            status = "[yellow]~ UNKNOWN[/yellow]"

        table.add_row(package_name, version, exp_short, computed_short, status)

    console.print(table)

    if any_fail:
        console.print(
            "\n[red bold]⚠ Hash mismatch detected.[/red bold]  "
            "One or more packages may have been tampered with."
        )
        raise typer.Exit(1)  # noqa: B904


# ── sast ──────────────────────────────────────────────────────────────────────


@app.command()
def sast(
    target: Path = typer.Argument(  # noqa: B008
        ..., help="Directory or file to scan with Semgrep SAST rules"
    ),
    rules_dir: Path | None = typer.Option(  # noqa: B008
        None,
        "--rules-dir",
        help="Override the default semgrep-rules/ directory",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json",
    ),
) -> None:
    """Scan MCP server source code with Semgrep SAST rules (Pro feature).

    Requires semgrep to be installed: pip install semgrep

    Exit codes: 0 = no findings, 1 = findings found, 2 = error.
    """
    if not is_pro_feature_available("sast"):
        console.print(
            "[yellow]⚡ Pro feature:[/yellow] SAST scanning requires "
            "a Pro or Enterprise license.\n"
            "   Activate with: [bold]mcp-audit activate <key>[/bold]"
        )
        raise typer.Exit(2)  # noqa: B904

    from mcp_audit.sast.runner import (  # noqa: PLC0415
        SastResult,
        find_semgrep,
        run_semgrep,
    )

    if find_semgrep() is None:
        console.print(
            "[red]semgrep is not installed.[/red]\n"
            "   Install it with: [bold]pip install semgrep[/bold]"
        )
        raise typer.Exit(2)  # noqa: B904

    if not target.exists():
        console.print(f"[red]Path does not exist:[/red] {target}")
        raise typer.Exit(2)  # noqa: B904

    console.print(f"[dim]Scanning {target} with Semgrep SAST rules…[/dim]")
    sast_result: SastResult = run_semgrep(target_path=target, rules_dir=rules_dir)

    if sast_result.error:
        console.print(f"[red]SAST error:[/red] {sast_result.error}")
        raise typer.Exit(2)  # noqa: B904

    findings = sast_result.findings

    if output_format == "json":
        import json as _json  # noqa: PLC0415

        typer.echo(_json.dumps([f.model_dump() for f in findings], indent=2))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    if not findings:
        console.print("[green]✓ No SAST findings.[/green]")
        return

    table = Table(
        "File",
        "Line",
        "Rule",
        "Severity",
        "Message",
        show_header=True,
        header_style="bold",
    )
    import contextlib  # noqa: PLC0415
    import json as _json  # noqa: PLC0415

    for f in findings:
        evidence: dict = {}
        with contextlib.suppress(Exception):
            evidence = _json.loads(f.evidence)
        file_short = Path(evidence.get("file", f.server)).name
        line = str(evidence.get("line", ""))
        sev_colour = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "blue",
            "INFO": "dim",
        }.get(f.severity.value, "white")
        table.add_row(
            file_short,
            line,
            f.title,
            f"[{sev_colour}]{f.severity.value}[/{sev_colour}]",
            f.description[:80],
        )

    console.print(table)
    console.print(
        f"\n[bold]{len(findings)} finding(s)[/bold] across "
        f"{sast_result.files_scanned} file(s)"
    )
    raise typer.Exit(1)  # noqa: B904


# ── extensions discover ───────────────────────────────────────────────────────


@extensions_app.command("discover")
def extensions_discover(
    client: str | None = typer.Option(  # noqa: B008
        None,
        "--client",
        help="Filter to a specific client (e.g. vscode, cursor)",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json",
    ),
) -> None:
    """Discover installed IDE extensions across supported AI coding clients.

    Free for all tiers.
    """
    import json as _json  # noqa: PLC0415

    from mcp_audit.extensions.discovery import discover_extensions  # noqa: PLC0415

    clients = [client] if client else None
    extensions = discover_extensions(clients=clients)

    if output_format == "json":
        typer.echo(_json.dumps([e.model_dump() for e in extensions], indent=2))
        return

    client_names = sorted({e.client_name for e in extensions})
    summary = (
        f"Found [bold]{len(extensions)}[/bold] extension(s) "
        f"across [bold]{len(client_names)}[/bold] client(s)"
    )

    if not extensions:
        console.print(summary)
        return

    table = Table(
        "Client",
        "Extension ID",
        "Publisher",
        "Version",
        "Last Updated",
        show_header=True,
        header_style="bold",
    )
    for ext in sorted(extensions, key=lambda e: (e.client_name, e.extension_id)):
        table.add_row(
            ext.client_name,
            ext.extension_id,
            ext.publisher,
            ext.version,
            ext.last_updated or "unknown",
        )
    console.print(table)
    console.print(f"\n{summary}")


# ── extensions scan ───────────────────────────────────────────────────────────


@extensions_app.command("scan")
def extensions_scan(
    client: str | None = typer.Option(  # noqa: B008
        None,
        "--client",
        help="Filter to a specific client (e.g. vscode, cursor)",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif",
    ),
) -> None:
    """Scan installed IDE extensions for security issues.

    Requires a Pro or Enterprise license.
    """
    import json as _json  # noqa: PLC0415

    if not is_pro_feature_available("extensions"):
        console.print(
            "[yellow]⚡ Pro feature:[/yellow] [bold]extensions scan[/bold] requires "
            "a Pro or Enterprise license.\n"
            "   [bold]extensions discover[/bold] is free — try that first.\n"
            "   Activate with: [bold]mcp-audit activate <key>[/bold]"
        )
        raise typer.Exit(0)  # noqa: B904

    from mcp_audit.extensions.analyzer import analyze_extensions  # noqa: PLC0415
    from mcp_audit.extensions.discovery import discover_extensions  # noqa: PLC0415

    clients = [client] if client else None
    extensions = discover_extensions(clients=clients)
    findings = analyze_extensions(extensions)

    if output_format == "json":
        typer.echo(_json.dumps([f.model_dump() for f in findings], indent=2))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    if output_format == "sarif":
        from mcp_audit.models import ScanResult  # noqa: PLC0415
        from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

        _mock_result = ScanResult(findings=findings)
        typer.echo(format_sarif(_mock_result))
        if findings:
            raise typer.Exit(1)  # noqa: B904
        return

    # Terminal output
    if not findings:
        console.print(
            f"[green]✓ No issues found[/green] in {len(extensions)} extension(s)."
        )
        return

    sev_colour = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "cyan",
        "LOW": "blue",
        "INFO": "dim",
    }
    table = Table(
        "Extension",
        "Client",
        "Severity",
        "Title",
        show_header=True,
        header_style="bold",
        border_style="blue",
    )
    for f in findings:
        colour = sev_colour.get(f.severity.value, "white")
        table.add_row(
            f.server,
            f.client,
            f"[{colour}]{f.severity.value}[/{colour}]",
            f.title,
        )
    console.print(table)
    console.print(
        f"\n[bold]{len(findings)} finding(s)[/bold] across "
        f"{len(extensions)} extension(s)"
    )
    raise typer.Exit(1)  # noqa: B904
