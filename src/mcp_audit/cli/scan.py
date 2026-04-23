"""scan / discover / pin / diff / watch commands.

The ``scan`` command is composed from small ``_apply_*`` pipeline stages and
``_write_*`` output helpers so that each optional phase (baseline drift,
governance, SAST, extensions, severity filtering, formatting) can be read and
reviewed in isolation.  New scan-pipeline stages should follow the same
pattern.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from mcp_audit import cli as _cli
from mcp_audit._network import NetworkPolicy, require_offline_compatible
from mcp_audit.analyzers.credentials import CredentialsAnalyzer
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.analyzers.rug_pull import (
    build_state_entry,
    compute_hashes,
    derive_state_path,
    load_state,
    save_state,
    server_key,
)
from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.analyzers.transport import TransportAnalyzer

# Import modules (rather than the bound names) for symbols that tests patch at
# their source location — e.g. ``patch("mcp_audit.sast.runner.run_semgrep")``.
# Accessing these via the module attribute at call time preserves those patch
# intercepts that would otherwise be bypassed by a ``from X import Y``.
from mcp_audit.attestation import verifier as _attestation_verifier
from mcp_audit.baselines.manager import BaselineManager
from mcp_audit.cli import app, console
from mcp_audit.cli._helpers import _write_output
from mcp_audit.extensions import analyzer as _extensions_analyzer
from mcp_audit.extensions import discovery as _extensions_discovery
from mcp_audit.governance.evaluator import evaluate_governance
from mcp_audit.governance.loader import load_policy
from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.output.nucleus import format_nucleus
from mcp_audit.output.sarif import format_sarif
from mcp_audit.output.terminal import print_results
from mcp_audit.registry.loader import KnownServerRegistry
from mcp_audit.sast import runner as _sast_runner
from mcp_audit.scanner import _USER_RULES_DIR
from mcp_audit.watcher import ConfigWatcher

# Severity comparison uses a descending-critical list so ``index`` returns a
# smaller value for higher severities — a finding is kept when its index is
# ``<=`` the threshold index.
_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


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
) -> list[Finding]:
    """Convert DriftFinding objects to standard Finding objects.

    Uses ``analyzer="baseline"`` so drift findings appear in all output
    formats alongside analyzer findings.
    """
    findings: list[Finding] = []
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


# ── scan() pipeline stages ────────────────────────────────────────────────────


def _preflight_checks(
    offline: bool,
    verify_hashes: bool,
    registry: Path | None,
    sast: Path | None,
    con: Console,
    path: Path | None = None,
    verify_signatures: bool = False,
    check_vulns: bool = False,
    connect: bool = False,
) -> None:
    """Validate incompatible flag combinations and user-supplied paths.

    Raises ``typer.Exit(2)`` with a human-readable message for any failure so
    callers never see a Python traceback for routine input mistakes.
    """
    if path is not None and not path.resolve().exists():
        con.print(f"[red]Error:[/red] Config path not found: {path}")
        raise typer.Exit(2)

    policy = NetworkPolicy(
        verify_hashes=verify_hashes,
        verify_signatures=verify_signatures,
        check_vulns=check_vulns,
        connect=connect,
    )
    require_offline_compatible(policy, offline)

    if registry is not None and not registry.resolve().exists():
        con.print(f"[red]Registry file not found:[/red] {registry}")
        raise typer.Exit(2)

    if sast is not None and not sast.resolve().exists():
        con.print(f"[red]SAST target path does not exist:[/red] {sast}")
        raise typer.Exit(2)


def _build_custom_analyzers(
    registry: Path | None,
    offline_registry: bool,
) -> list | None:
    """Build a custom analyzer list when a registry override is requested.

    Returns ``None`` when the default scanner analyzers should be used (i.e.
    neither ``--registry`` nor ``--offline-registry`` was supplied).
    """
    if registry is None and not offline_registry:
        return None
    supply_chain = SupplyChainAnalyzer(
        registry_path=registry,
        offline_registry=offline_registry,
    )
    return [
        PoisoningAnalyzer(),
        CredentialsAnalyzer(),
        TransportAnalyzer(registry=supply_chain.registry),
        supply_chain,
    ]


def _collect_extra_rules_dirs(
    rules_dir: Path | None,
    con: Console,
) -> list[Path]:
    """Collect Pro-gated extra rule directories for the scanner.

    Includes ``--rules-dir`` and the user-local rules directory at
    ``<user-config-dir>/mcp-audit/rules/`` when it exists.  Community rules ship
    bundled and are loaded by the scanner regardless of this list.
    """
    extra: list[Path] = []
    if rules_dir is not None:
        if not rules_dir.is_dir():
            con.print(f"[red]--rules-dir path is not a directory: {rules_dir}[/red]")
            raise typer.Exit(2)
        extra.append(rules_dir)

    if _USER_RULES_DIR.is_dir():
        extra.append(_USER_RULES_DIR)
    return extra


def _apply_hash_verification(
    result: ScanResult,
    registry: Path | None,
    offline_registry: bool,
    con: Console,
) -> ScanResult:
    """Download package tarballs and verify SHA-256 against registry pins.

    Only called when ``--verify-hashes`` is active.  Returns the result
    unchanged when there are no servers to verify.
    """
    if not result.servers:
        return result

    vh_registry = KnownServerRegistry(path=registry, offline=offline_registry)
    hashable = [
        s
        for s in result.servers
        if vh_registry.get(s.name) is not None and vh_registry.get(s.name).known_hashes  # type: ignore[union-attr]
    ]
    con.print(f"[dim]Hash verification: checking {len(hashable)} package(s)…[/dim]")
    hash_findings = _attestation_verifier.verify_server_hashes(
        result.servers, vh_registry
    )
    result.findings.extend(hash_findings)
    return result


def _apply_signature_verification(
    result: ScanResult,
    registry: Path | None,
    offline_registry: bool,
    strict: bool,
    console: Console,
) -> ScanResult:
    """Verify Sigstore provenance attestations for all registry-known servers.

    Only called when ``--verify-signatures`` is active.  Appends findings to
    ``result.findings`` before scoring so attestation outcomes affect the grade.
    """
    from mcp_audit.attestation.sigstore_findings import (  # noqa: PLC0415
        verify_server_signatures,
    )

    sig_registry = KnownServerRegistry(path=registry, offline=offline_registry)
    findings = verify_server_signatures(result.servers, sig_registry, strict=strict)
    result.findings.extend(findings)
    return result


def _surface_user_path_errors(
    result: ScanResult,
    extra_paths: list[Path] | None,
    con: Console,
) -> None:
    """Exit 2 when a user-specified ``--path`` failed to parse.

    Auto-discovered configs that fail are recorded in ``result.errors`` and
    surfaced through JSON output.  User-specified paths are stricter: the user
    explicitly asked for that file and a clean exit would be misleading.
    """
    if not (extra_paths and result.errors):
        return
    resolved = {p.expanduser().resolve() for p in extra_paths}
    user_errors = [e for e in result.errors if any(str(rp) in e for rp in resolved)]
    if not user_errors:
        return
    for err in user_errors:
        con.print(f"[red]Error:[/red] {err}")
    raise typer.Exit(2)


def _apply_baseline_drift(
    result: ScanResult,
    baseline_name: str | None,
    con: Console,
) -> ScanResult:
    """Compute drift against the named baseline and inject drift findings.

    Returns the result unchanged when ``baseline_name`` is ``None``.  A
    malformed baseline is degraded to an INFO finding rather than crashing the
    scan; a missing named baseline exits 2.
    """
    if baseline_name is None:
        return result

    mgr = BaselineManager()
    try:
        if baseline_name == "latest":
            bl = mgr.load_latest()
            if bl is None:
                con.print(
                    "[red]No baselines found.[/red]  "
                    "Run [bold]mcp-audit baseline save[/bold] first."
                )
                raise typer.Exit(2)
        else:
            bl = mgr.load(baseline_name)
    except FileNotFoundError as exc:
        con.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from None
    except Exception as exc:  # noqa: BLE001
        # Malformed baseline file — surface as an INFO finding rather than
        # crashing so the rest of the scan output is still usable.
        con.print(
            f"[yellow]Warning:[/yellow] Could not parse baseline "
            f"{baseline_name!r}: {exc}. Drift detection skipped."
        )
        result.findings.append(
            Finding(
                id="BL-001",
                severity=Severity.INFO,
                analyzer="baselines",
                client="",
                server="",
                title=f"Baseline {baseline_name!r} could not be parsed",
                description=(
                    f"The baseline file for {baseline_name!r} is malformed "
                    f"and drift detection was skipped: {exc}"
                ),
                evidence=str(exc),
                remediation=(
                    "Delete the corrupted baseline with "
                    "'mcp-audit baseline delete' and re-save with "
                    "'mcp-audit baseline save'."
                ),
            )
        )
        return result

    drift = mgr.compare(bl, result.servers)
    if not drift:
        con.print("[green]✓[/green] Baseline comparison: no drift detected.")
    result.findings.extend(_drift_to_findings(drift))
    return result


def _apply_governance(
    result: ScanResult,
    policy: Path | None,
    analyzers: list | None,
    con: Console,
) -> ScanResult:
    """Evaluate governance policy and inject ``GOV-`` findings.

    Resolves the policy via explicit ``--policy`` → cwd → repo root → user
    config.  Returns the result unchanged when no policy is resolved.  If a
    custom analyzer list was built with a shared ``SupplyChainAnalyzer``, its
    registry is reused to avoid re-reading the JSON file.
    """
    try:
        resolved = load_policy(policy)
    except ValueError as exc:
        con.print(f"[red]Governance policy error:[/red] {exc}")
        raise typer.Exit(2) from None

    if resolved is None:
        return result

    gov_registry = None
    if analyzers is not None:
        for a in analyzers:
            if isinstance(a, SupplyChainAnalyzer):
                gov_registry = a.registry
                break

    gov_findings = evaluate_governance(
        servers=result.servers,
        policy=resolved,
        registry=gov_registry,
        scan_result=result,
    )
    result.findings.extend(gov_findings)
    return result


def _apply_sast(
    result: ScanResult,
    sast_path: Path,
    con: Console,
) -> ScanResult:
    """Run Semgrep-based SAST analysis and inject findings.

    Only called when ``--sast`` is active and Pro-gating passes.  A semgrep
    launch failure is surfaced as a yellow warning and the scan continues.
    """
    con.print(f"[dim]SAST: scanning {sast_path} with Semgrep rules…[/dim]")
    sast_result = _sast_runner.run_semgrep(target_path=sast_path)
    if sast_result.error:
        con.print(
            f"[yellow]SAST warning:[/yellow] {sast_result.error}",
            err=True,
        )
    else:
        result.findings.extend(sast_result.findings)
        con.print(
            f"[dim]SAST: scanned {sast_result.files_scanned} file(s), "
            f"found {len(sast_result.findings)} issue(s)[/dim]"
        )
    return result


def _apply_vuln_check(
    result: ScanResult,
    registry: Path | None,
    offline_registry: bool,
    vuln_registry_url: str | None,
    console: Console,
) -> ScanResult:
    """Check for known CVEs in server dependencies via deps.dev + OSV.dev."""
    from mcp_audit.vulnerability.scanner import check_vulnerabilities  # noqa: PLC0415

    vuln_registry_obj = KnownServerRegistry(path=registry, offline=offline_registry)
    findings = check_vulnerabilities(
        result.servers,
        vuln_registry_obj,
        vuln_registry_url=vuln_registry_url,
    )
    result.findings.extend(findings)
    return result


def _apply_extensions(
    result: ScanResult,
    con: Console,
) -> ScanResult:
    """Run extension security analysis and inject findings.

    Only called when ``--include-extensions`` is active and Pro-gating passes.
    """
    ext_list = _extensions_discovery.discover_extensions()
    ext_findings = _extensions_analyzer.analyze_extensions(ext_list)
    result.findings.extend(ext_findings)
    con.print(
        f"[dim]Extensions: {len(ext_list)} extension(s) scanned, "
        f"{len(ext_findings)} issue(s) found[/dim]"
    )
    return result


def _apply_severity_threshold(
    result: ScanResult,
    severity_threshold: str,
    con: Console,
) -> ScanResult:
    """Filter ``result.findings`` to those at or above the threshold.

    ``severity_threshold`` is the raw string from the CLI; validation happens
    here so invalid values produce a clean exit 2.  The score is NOT
    recomputed — it reflects the pre-filter finding set.
    """
    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        con.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2) from None

    threshold_idx = _SEVERITY_ORDER.index(threshold)
    below = [
        f for f in result.findings if _SEVERITY_ORDER.index(f.severity) > threshold_idx
    ]
    result.findings_below_threshold = len(below)
    result.active_severity_threshold = threshold.value
    result.findings = [
        f for f in result.findings if _SEVERITY_ORDER.index(f.severity) <= threshold_idx
    ]
    return result


def _write_formatted_output(
    result: ScanResult,
    fmt: str,
    output: Path | None,
    asset_prefix: str | None,
    no_score: bool,
    con: Console,
) -> None:
    """Dispatch to the appropriate formatter and emit output.

    Handles both ``--output-file`` (writes to disk) and stdout cases.  Raises
    ``typer.Exit(2)`` for unknown formats and ``typer.Exit(0)`` when the
    ``nucleus`` formatter declines to produce output.
    """
    if fmt == "json":
        out = result.model_dump_json(indent=2, by_alias=True)
        if output:
            _write_output(output, out)
        else:
            typer.echo(out)
    elif fmt == "nucleus":
        nucleus_out = format_nucleus(result, asset_prefix=asset_prefix, console=con)
        if nucleus_out is None:
            raise typer.Exit(0)
        if output:
            _write_output(output, nucleus_out)
        else:
            typer.echo(nucleus_out)
    elif fmt == "sarif":
        sarif_out = format_sarif(result, asset_prefix=asset_prefix)
        if output:
            _write_output(output, sarif_out)
        else:
            typer.echo(sarif_out)
    elif fmt == "terminal":
        print_results(result, console=con, show_score=not no_score)
    else:
        con.print(
            "[red]Unknown format: "
            f"{fmt!r}. Choose terminal, json, nucleus, or sarif.[/red]"
        )
        raise typer.Exit(2)


# ── scan ──────────────────────────────────────────────────────────────────────


@app.command()
def scan(
    configs: list[Path] | None = typer.Argument(  # noqa: B008
        default=None,
        help=(
            "Config file to scan (single path only; "
            "for multiple configs use --path or 'mcp-audit discover')"
        ),
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Scan a specific config file or directory"
    ),
    output_format: str = typer.Option(  # noqa: B008
        "terminal",
        "--format",
        "-f",
        help=(
            "Output format: terminal, json, sarif, nucleus. "
            "HTML output is available via 'mcp-audit dashboard'."
        ),
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
    verify_signatures: bool = typer.Option(  # noqa: B008
        False,
        "--verify-signatures",
        help=(
            "Verify Sigstore provenance attestations for registry-known packages "
            "(requires network access; free for all tiers)."
        ),
    ),
    strict_signatures: bool = typer.Option(  # noqa: B008
        False,
        "--strict-signatures",
        help=(
            "Raise 'no attestation' findings to MEDIUM severity "
            "(use with --verify-signatures)."
        ),
    ),
    check_vulns: bool = typer.Option(  # noqa: B008
        False,
        "--check-vulns",
        help=(
            "Check server dependencies for known CVEs via deps.dev + OSV.dev "
            "(requires network access; free for all tiers)."
        ),
    ),
    vuln_registry: str | None = typer.Option(  # noqa: B008
        None,
        "--vuln-registry",
        help="Custom OSV-compatible API endpoint (Pro: for air-gapped deployments).",
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
    if configs and len(configs) > 1:
        console.print(
            "[red]Error:[/red] scan accepts a single config path. "
            "For multiple configs use 'mcp-audit discover' or run scan once per config."
        )
        raise typer.Exit(2)
    config = configs[0] if configs else None
    path = config or path
    extra_paths = [path] if path else None
    fmt = "json" if json_flag else output_format

    if reset_state:
        _reset_scoped_state(extra_paths, console)

    _preflight_checks(
        offline,
        verify_hashes,
        registry,
        sast,
        console,
        path=path,
        verify_signatures=verify_signatures,
        check_vulns=check_vulns,
        connect=connect,
    )

    analyzers = _build_custom_analyzers(registry, offline_registry)
    extra_rules_dirs = _collect_extra_rules_dirs(rules_dir, console)

    result = _cli.run_scan(
        extra_paths=extra_paths,
        analyzers=analyzers,
        connect=connect,
        offline=offline,
        extra_rules_dirs=extra_rules_dirs if extra_rules_dirs else None,
    )

    if asset_prefix:
        result.machine.asset_id = asset_prefix

    if verify_hashes:
        result = _apply_hash_verification(result, registry, offline_registry, console)

    if verify_signatures:
        result = _apply_signature_verification(
            result,
            registry,
            offline_registry,
            strict=strict_signatures,
            console=console,
        )

    if check_vulns:
        result = _apply_vuln_check(
            result, registry, offline_registry, vuln_registry, console
        )

    _surface_user_path_errors(result, extra_paths, console)

    result = _apply_baseline_drift(result, baseline_name, console)
    result = _apply_governance(result, policy, analyzers, console)

    if sast is not None:
        result = _apply_sast(result, sast, console)

    if include_extensions:
        result = _apply_extensions(result, console)

    result = _apply_severity_threshold(result, severity_threshold, console)

    # Suppress score for formatters when --no-score is requested.  The scanner
    # always calculates the score; suppression is a presentation-layer decision
    # applied here, after scanning, before any formatter is called.
    if no_score:
        result.score = None

    _write_formatted_output(result, fmt, output, asset_prefix, no_score, console)

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
    configs = _cli.discover_configs(
        extra_paths=extra_paths,
        skip_auto_discovery=bool(extra_paths),
    )

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
    config: Path | None = typer.Argument(  # noqa: B008
        None, help="Config file to pin (positional shorthand for --path/-p)"
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional path to check"
    ),
) -> None:
    """Record current MCP server configurations as the trusted baseline.

    Overwrites any existing baseline.  Preserves the original ``first_seen``
    timestamp for servers already tracked.
    """
    path = config or path
    if path is not None and not path.resolve().exists():
        console.print(f"[red]Error:[/red] Config path not found: {path}")
        raise typer.Exit(2)
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
    config: Path | None = typer.Argument(  # noqa: B008
        None, help="Config file to diff (positional shorthand for --path/-p)"
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", "-p", help="Additional path to check"
    ),
) -> None:
    """Show configuration changes since the last baseline.

    Does NOT run the full analyzer pipeline — only compares hashes.
    Exit code 1 if any changes detected, 0 if clean.
    """
    path = config or path
    if path is not None and not path.resolve().exists():
        console.print(f"[red]Error:[/red] Config path not found: {path}")
        raise typer.Exit(2)
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
    extra_paths = [path] if path else None

    extra_rules_dirs = _collect_extra_rules_dirs(rules_dir, console)
    watch_extra_rules = extra_rules_dirs if extra_rules_dirs else None

    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2) from None

    threshold_idx = _SEVERITY_ORDER.index(threshold)

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
            if _SEVERITY_ORDER.index(f.severity) <= threshold_idx
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
