"""The ``affected`` command: "is this advisory in my agent stack?" (STORY-0121).

``mcp-audit affected CVE-2025-53109`` or ``mcp-audit affected litellm@==1.107.0``
reads every MCP server mcp-audit discovers and answers per server: AFFECTED,
NOT AFFECTED or COULDN'T CHECK, with the evidence and where the version came
from (the launch command's exact pin, or a lock's ``resolved_version``).

Offline by default.  ``--live`` fetches an advisory that is not bundled from
OSV.dev, the same endpoint ``scan --check-vulns`` uses.

Exit codes: 0 nothing affected, 1 something affected (or, with
``--fail-on-unknown``, something could not be checked), 2 error.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console

from mcp_audit._network import NetworkPolicy, require_offline_compatible
from mcp_audit.affected.match import (
    LockIndex,
    RecordRule,
    Report,
    RuleSet,
    decide_servers,
    records_from_osv,
    research_rows,
    rules_for_advisory,
    rules_for_range,
)
from mcp_audit.affected.query import QueryError, parse_query
from mcp_audit.affected.render import render_json, render_sarif, render_terminal
from mcp_audit.cli import app
from mcp_audit.cli._helpers import _write_output
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.models import Finding, ServerConfig
from mcp_audit.registry.loader import RegistryLoadError, load_registry
from mcp_audit.registry.malicious import load_known_malicious
from mcp_audit.registry.research import load_research_records

logger = logging.getLogger(__name__)
err_console = Console(stderr=True)


class _Format(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"


def _fail(message: str) -> typer.Exit:
    err_console.print(f"[red]Error:[/red] {message}")
    return typer.Exit(2)


def _discover(paths: list[Path], errors: list[str]) -> list[ServerConfig]:
    """Every server mcp-audit can find (or the ones in the given files)."""
    for path in paths:
        if not path.exists():
            raise _fail(f"path does not exist: {path}")
    configs = discover_configs(
        extra_paths=paths or None,
        skip_auto_discovery=bool(paths),
        errors=errors,
    )
    servers: list[ServerConfig] = []
    for config in configs:
        try:
            servers.extend(parse_config(config))
        except ValueError as exc:
            errors.append(str(exc))
        errors.extend(config.parse_warnings)
    return servers


def _plugin_check_findings(errors: list[str]) -> list[Finding]:
    """PLUGIN-003/004 on Claude Code's plugin checkouts (reads files; no git)."""
    from mcp_audit.plugins import checkout as plugin_checkout  # noqa: PLC0415
    from mcp_audit.plugins import discovery as plugin_discovery  # noqa: PLC0415

    try:
        installed = plugin_discovery.discover_installed_plugins()
        return plugin_checkout.analyze_plugin_pins(installed, errors=errors)
    except Exception as exc:  # noqa: BLE001 — a failed check is reported, not fatal
        errors.append(f"plugin checkout check error: {type(exc).__name__}: {exc}")
        return []


def _live_rules(advisory_id: str, report: Report) -> RuleSet:
    """Fetch *advisory_id* from OSV.dev and make rules from its npm/PyPI ranges."""
    from mcp_audit.vulnerability.osv import fetch_vuln_details  # noqa: PLC0415

    records, failures = fetch_vuln_details([advisory_id], errors=report.errors)
    osv = records.get(advisory_id)
    if osv is None:
        why = failures.get(advisory_id, "not found")
        raise _fail(f"{advisory_id} could not be fetched from OSV.dev: {why}")
    rules = [RecordRule(rec, curated=False) for rec in records_from_osv(osv)]
    if not rules:
        raise _fail(
            f"{advisory_id} has no npm or PyPI version ranges mcp-audit can evaluate"
        )
    report.live = True
    return RuleSet(rules=list(rules), sources=["OSV.dev (--live)"])


@app.command("affected")
def affected(
    query: str = typer.Argument(  # noqa: B008
        ...,
        help=(
            "An advisory ID (CVE-…, GHSA-…, MAL-…, x_MCPRS-…) or package@range, "
            "e.g. 'litellm@==1.107.0' or '@scope/pkg@<2025.7.1'."
        ),
    ),
    path: list[Path] = typer.Option(  # noqa: B008
        [],
        "--path",
        "-p",
        help="Check only this MCP config file (repeatable). Default: discover all.",
    ),
    lock: list[Path] = typer.Option(  # noqa: B008
        [],
        "--lock",
        help=(
            "An mcp-lock.json to read resolved versions from (repeatable); the "
            "nearest lock beside each config is always read too."
        ),
    ),
    format_: _Format = typer.Option(  # noqa: B008
        _Format.TERMINAL, "--format", "-f", help="terminal, json or sarif."
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Write json/sarif here instead of stdout."
    ),
    show_all: bool = typer.Option(  # noqa: B008
        False,
        "--all",
        help="List servers on other packages and servers with no readable package.",
    ),
    fail_on_unknown: bool = typer.Option(  # noqa: B008
        False,
        "--fail-on-unknown",
        help="Exit 1 when a server running the package could not be checked.",
    ),
    live: bool = typer.Option(  # noqa: B008
        False,
        "--live",
        help="Fetch an advisory that is not bundled from OSV.dev (network).",
    ),
    offline: bool = typer.Option(  # noqa: B008
        False, "--offline", help="Refuse any network flag (this command is offline)."
    ),
) -> None:
    """Is this advisory (or package range) in any MCP server on this machine?"""
    require_offline_compatible(NetworkPolicy(live=live), offline)
    try:
        parsed = parse_query(query)
    except QueryError as exc:
        raise _fail(str(exc)) from exc
    for lock_path in lock:
        if not lock_path.is_file():
            raise _fail(f"lock file does not exist: {lock_path}")
    if output is not None and format_ is _Format.TERMINAL:
        raise _fail("--output needs --format json or sarif")

    report = Report(query=parsed)
    try:
        registry = load_registry()
    except RegistryLoadError as exc:
        raise _fail(f"the registry could not be loaded: {exc}") from exc
    malicious = load_known_malicious()
    research = load_research_records()
    for label, err in (
        ("known-malicious", malicious.load_error),
        ("research records", research.load_error),
    ):
        if err:
            report.errors.append(f"{label}: {err}")
    report.errors.extend(f"research records: skipped {s}" for s in research.skipped)

    if parsed.kind == "range":
        ruleset = rules_for_range(parsed)
        report.sources.append("your range, compared with each server's version")
    else:
        assert parsed.advisory_id is not None  # noqa: S101
        ruleset = rules_for_advisory(parsed.advisory_id, registry, malicious, research)
        if not ruleset.found and live:
            ruleset = _live_rules(parsed.advisory_id, report)
        if not ruleset.found:
            raise _fail(
                f"{parsed.advisory_id} is not in the registry, the known-malicious "
                "mirror or the research records. Pass --live to fetch it from "
                "OSV.dev."
            )
        report.sources.extend(ruleset.sources)

    if ruleset.research is not None:
        check_ids = ruleset.research.checks
        fetch = (
            (lambda: _plugin_check_findings(report.errors))
            if not path and any(c.startswith("PLUGIN-") for c in check_ids)
            else None
        )
        report.rows.extend(research_rows(ruleset.research, fetch, report.notes))
    if ruleset.rules:
        servers = _discover(path, report.errors)
        locks = LockIndex(lock, report.errors)
        report.rows.extend(
            decide_servers(servers, ruleset, registry, locks, parsed.label)
        )

    if format_ is _Format.TERMINAL:
        render_terminal(report, Console(), show_all=show_all)
    else:
        text = render_json(report) if format_ is _Format.JSON else render_sarif(report)
        if output is not None:
            _write_output(output, text)
        else:
            typer.echo(text, nl=False)
    raise typer.Exit(report.exit_code(fail_on_unknown=fail_on_unknown))
