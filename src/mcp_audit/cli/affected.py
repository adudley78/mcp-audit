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

import json
import logging
import re
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from mcp_audit._network import NetworkPolicy, require_offline_compatible
from mcp_audit.affected import respond
from mcp_audit.affected.match import (
    RAN_THE_PACKAGE,
    UNREADABLE,
    LockIndex,
    RecordRule,
    Report,
    Row,
    RuleSet,
    Status,
    decide_servers,
    records_from_osv,
    research_rows,
    rules_for_advisory,
    rules_for_range,
)
from mcp_audit.affected.query import Query, QueryError, parse_query
from mcp_audit.affected.render import render_json, render_sarif, render_terminal
from mcp_audit.cli import app
from mcp_audit.cli._bundle import open_bundle
from mcp_audit.cli._helpers import _write_output
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.harness_versions import find_harness_versions
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
    OPENVEX = "openvex"


def _fail(message: str) -> typer.Exit:
    err_console.print(f"[red]Error:[/red] {message}")
    return typer.Exit(2)


def _discover(
    paths: list[Path], errors: list[str], unreadable: list[Row]
) -> list[ServerConfig]:
    """Every server mcp-audit can find (or the ones in the given files).

    A config that cannot be parsed hides all of its servers, so it becomes a
    COULDN'T CHECK row in *unreadable* as well as a warning.
    """
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
            first = (str(exc).splitlines() or [type(exc).__name__])[0]
            errors.append(f"{config.path}: {first}")
            unreadable.append(
                Row(
                    f"{config.client_name}: {config.path.name}",
                    Status.COULDNT_CHECK,
                    "this config could not be parsed, so none of its servers were "
                    "checked",
                    config_path=str(config.path),
                    reason=UNREADABLE,
                )
            )
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


def _attach_exploit(report: Report, parsed: Query, live: bool) -> None:
    """Add KEV/EPSS/PoC for a CVE query (bundled data, or current with --live)."""
    from mcp_audit.exploit import signals  # noqa: PLC0415

    cve = (parsed.advisory_id or "").upper()
    if parsed.kind != "advisory" or not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return
    index = signals.load()
    if live:
        try:
            index = signals.fetch_live([cve])
        except (OSError, ValueError, RecursionError):
            report.errors.append(
                "exploit signals: could not refresh them live; using the bundled data"
            )
    report.exploit = {
        "cve": cve,
        "signals": index.for_cve(cve),
        "line": index.date_line(),
    }


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


def _run_fix(
    pairs: list[tuple[ServerConfig, Row]],
    rules: list,
    registry: object,
    apply: bool,
) -> None:
    """Pin AFFECTED servers to the advisory's fixed version (STORY-0127)."""
    from mcp_audit.affected.fixplan import (  # noqa: PLC0415
        Pin,
        candidates,
        crosses_major,
    )
    from mcp_audit.affected.match import would_close  # noqa: PLC0415
    from mcp_audit.fixer.fixer import run_pins  # noqa: PLC0415

    con = Console()
    by_config: dict[str, list[tuple[str, str, str]]] = {}
    skipped: list[Pin] = []
    for server, row in pairs:
        if row.status is not Status.AFFECTED or not row.package:
            continue
        package = row.package.split(":", 1)[1]
        found, why = candidates(row.version, row.fixes)
        target = None
        for option in found:
            if would_close(server, rules, registry, option):  # type: ignore[arg-type]
                target = option
                break
        if target is None and found:
            why = (
                "pinning to a fixed version would not clear every rule for this package"
            )
        pin = Pin(
            row.subject, str(server.config_path), server.name, package, row.version
        )
        if target is None:
            skipped.append(
                Pin(**{**pin.__dict__, "skipped": why})  # type: ignore[arg-type]
            )
            continue
        if crosses_major(row.version, target):
            con.print(
                f"[yellow]note[/yellow] {escape(row.subject)}: {row.version} → "
                f"{target} is a major-version change; check the release notes"
            )
        by_config.setdefault(pin.config_path, []).append((server.name, package, target))
    if not by_config and not skipped:
        con.print("\n[dim]--fix: no AFFECTED server to pin.[/dim]")
        return
    for config_path, pins in by_config.items():
        path = Path(config_path)
        con.print(f"\n[bold]{escape(str(path))}[/bold]")
        try:
            result = run_pins(path, pins, apply=apply)
        except (OSError, ValueError) as exc:
            # One unreadable, TOML or commented config must not stop the rest.
            first = (str(exc).splitlines() or [type(exc).__name__])[0]
            con.print(f"  [yellow]not pinned[/yellow] {escape(first)}")
            continue
        for line in result.fixes_applied:
            con.print(f"  {'✓' if apply else '~'} {escape(line)}")
        for line in result.skipped:
            con.print(f"  [yellow]not pinned[/yellow] {escape(line)}")
        if result.diff and not apply:
            con.print(escape(result.diff), highlight=False, soft_wrap=True)
        if apply and result.backup_path:
            con.print(f"  [dim]backup: {escape(str(result.backup_path))}[/dim]")
    for pin in skipped:
        con.print(
            f"\n[yellow]not pinned[/yellow] {escape(pin.subject)} "
            f"({escape(str(pin.current))}): {escape(pin.skipped or '')}"
        )
    if apply:
        con.print(
            "\n[dim]Pinned. Re-run `mcp-audit affected` to confirm, and "
            "`mcp-audit lock` to record the new version in your lock.[/dim]"
        )
    elif by_config:
        con.print("\n[dim]Dry run, no files modified. Pass --apply to write.[/dim]")


def _write_policy(
    path: Path,
    servers: list[ServerConfig],
    report: Report,
    unchecked: int,
    out: list[str],
) -> None:
    """Write the deniedMcpServers file, or say why nothing was written.

    Messages go to *out* (printed with the report, or to stderr for formats
    that cannot carry them).  An existing file is never overwritten.
    """
    if not servers:
        out.append("--policy-out: no server is AFFECTED, so no file was written")
        return
    document, notes = respond.policy_document(servers)
    entries = document["deniedMcpServers"]
    if not entries:
        out.extend(["--policy-out: no file written."] + notes)
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(document, indent=2) + "\n")
    except FileExistsError as exc:
        raise _fail(
            f"--policy-out: {path} already exists; remove it or choose another path"
        ) from exc
    except OSError as exc:
        raise _fail(f"--policy-out: could not write {path}: {exc.strerror}") from exc
    out.append(
        f"Wrote {len(entries)} deniedMcpServers entr"
        f"{'y' if len(entries) == 1 else 'ies'} to {path}. Each is the exact launch "
        "of an AFFECTED server, so it does not block the same package launched "
        "another way, and Claude Code is the only client that reads it. Deploy it "
        "as a managed-settings drop-in "
        "(https://code.claude.com/docs/en/managed-mcp); mcp-audit does not."
    )
    if unchecked:
        out.append(
            f"--policy-out: {unchecked} more server(s) run an advisory package but "
            "could not be checked (COULDN'T CHECK); they are not in the file."
        )
    out.extend(notes)


def _openvex_text(report: Report, parsed: Query) -> str:
    """The report as an OpenVEX document (advisory queries only)."""
    from mcp_audit.affected import vex  # noqa: PLC0415

    if parsed.kind != "advisory" or not parsed.advisory_id:
        raise _fail("--format openvex needs an advisory ID, not a package range")
    document = vex.build((parsed.advisory_id, row) for row in report.rows)
    if not document["statements"]:
        raise _fail(
            "no discovered server runs a package this advisory covers, so there "
            "is nothing to state"
        )
    return vex.render(document)


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
        _Format.TERMINAL, "--format", "-f", help="terminal, json, sarif or openvex."
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
    policy_out: Path | None = typer.Option(  # noqa: B008
        None,
        "--policy-out",
        help=(
            "Write Claude Code managed-policy JSON (deniedMcpServers) for the "
            "AFFECTED servers to this file, for an admin to deploy. mcp-audit "
            "never writes into the managed-settings directory."
        ),
    ),
    fix: bool = typer.Option(  # noqa: B008
        False,
        "--fix",
        help=(
            "Show the diff that pins each AFFECTED npx/uvx server to the "
            "advisory's fixed version (dry run; nothing is written)."
        ),
    ),
    apply: bool = typer.Option(  # noqa: B008
        False,
        "--apply",
        help="With --fix, write the pins (atomic rename, .bak backup beside each).",
    ),
    live: bool = typer.Option(  # noqa: B008
        False,
        "--live",
        help="Fetch an advisory that is not bundled from OSV.dev (network).",
    ),
    bundle: Path | None = typer.Option(  # noqa: B008
        None,
        "--bundle",
        help=(
            "Read the registry, known-malicious list, research records and exploit "
            "signals from this signed bundle directory (no network). Verified like "
            "`feed verify`; an unsigned, expired or altered bundle stops the run. "
            "See docs/air-gapped.md."
        ),
    ),
    bundle_key: Path | None = typer.Option(  # noqa: B008
        None,
        "--bundle-key",
        help=(
            "Minisign public key for --bundle (default: mcp-audit's project key, "
            "or $MCP_AUDIT_SIGNING_PUBKEY)."
        ),
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
    if policy_out is not None and respond.inside_managed_dir(policy_out):
        raise _fail(
            "--policy-out will not write into Claude Code's managed-settings "
            "directory; write it elsewhere and deploy it yourself"
        )
    if (
        policy_out is not None
        and output is not None
        and policy_out.resolve() == output.resolve()
    ):
        raise _fail("--policy-out and --output must be different files")
    if apply and not fix:
        raise _fail("--apply needs --fix")
    if fix and format_ is not _Format.TERMINAL:
        raise _fail("--fix prints a diff; use the terminal format")
    if output is not None and format_ is _Format.TERMINAL:
        raise _fail("--output needs --format json, sarif or openvex")

    report = Report(query=parsed)
    registry_path = None
    if bundle is not None:
        if live:
            raise _fail("--bundle reads no network; it cannot be combined with --live")
        opened = open_bundle(bundle, bundle_key, err_console)
        registry_path = opened.path("known-servers.json")
        report.sources.append(opened.line())
    fix_pairs: list[tuple[ServerConfig, Row]] = []
    fix_rules: list = []
    fix_registry = None
    policy_msgs: list[str] = []
    try:
        registry = load_registry(registry_path)
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
        harness = None
        if not path:
            harness = find_harness_versions()
            report.notes.extend(
                f"harness versions: skipped {s}" for s in harness.skipped
            )
        report.rows.extend(
            research_rows(ruleset.research, fetch, report.notes, harness)
        )
    if ruleset.rules:
        unreadable: list[Row] = []
        servers = _discover(path, report.errors, unreadable)
        locks = LockIndex(lock, report.errors)
        rows = decide_servers(servers, ruleset, registry, locks, parsed.label)
        report.rows.extend(rows + unreadable)
        affected_servers = [
            s
            for s, row in zip(servers, rows, strict=True)
            if row.status is Status.AFFECTED
        ]
        if affected_servers:
            try:
                home: Path | None = Path.home()
                cwd: Path | None = None if path else Path.cwd()
                stores = respond.credential_files(home, cwd, report.errors)
            except (OSError, RuntimeError) as exc:
                report.errors.append(
                    f"credential files: not listed ({type(exc).__name__})"
                )
                stores = []
            report.respond = [
                respond.build(s, servers, stores) for s in affected_servers
            ]
        if fix:
            fix_pairs = list(zip(servers, rows, strict=True))
            fix_rules = ruleset.rules
            fix_registry = registry
        if policy_out is not None:
            unchecked = sum(
                1
                for r in rows
                if r.status is Status.COULDNT_CHECK and r.reason in RAN_THE_PACKAGE
            )
            _write_policy(policy_out, affected_servers, report, unchecked, policy_msgs)
        if servers and not any(r.reason in RAN_THE_PACKAGE for r in rows):
            names = ", ".join(sorted({r.describes() for r in ruleset.rules}))
            report.notes.append(
                f"No discovered server runs {names}. If you meant another "
                "package, check the spelling."
            )

    if policy_out is not None and not ruleset.rules:
        policy_msgs.append(
            "--policy-out: this query names no servers, so no file was written"
        )
    _attach_exploit(report, parsed, live)
    if format_ is _Format.TERMINAL:
        report.notes.extend(policy_msgs)
    else:
        for msg in policy_msgs:
            err_console.print(msg)

    if format_ is _Format.TERMINAL:
        render_terminal(report, Console(), show_all=show_all)
        if fix:
            _run_fix(fix_pairs, fix_rules, fix_registry, apply)
    else:
        if format_ is _Format.OPENVEX:
            text = _openvex_text(report, parsed)
        elif format_ is _Format.JSON:
            text = render_json(report)
        else:
            text = render_sarif(report)
        if output is not None:
            _write_output(output, text)
        else:
            typer.echo(text, nl=False)
    raise typer.Exit(report.exit_code(fail_on_unknown=fail_on_unknown))
