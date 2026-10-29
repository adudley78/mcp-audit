"""Output for ``mcp-audit affected``: terminal, JSON and SARIF.

JSON and SARIF leave the machine, so config paths go through the same
redaction every other published sink uses (:mod:`mcp_audit._redact`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape

from mcp_audit import __version__
from mcp_audit._redact import redact_finding_path
from mcp_audit.affected.match import (
    NO_PACKAGE,
    OTHER_PACKAGE,
    Report,
    Row,
    Status,
)
from mcp_audit.analyzers.supply_chain import _advisory_url

_STYLE = {
    Status.AFFECTED: "bold red",
    Status.COULDNT_CHECK: "bold yellow",
    Status.NOT_AFFECTED: "bold green",
}
_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main"
    "/sarif-2.1/schema/sarif-schema-2.1.0.json"
)


def _scrub(text: str) -> str:
    """Replace the reader's home directory with ``~`` in text that leaves the host."""
    home = str(Path.home())
    return text.replace(home, "~") if len(home) > 3 else text


def _path(row: Row) -> str | None:
    if not row.config_path:
        return None
    return redact_finding_path(row.config_path, row.config_path).replace("\\", "/")


def _display_path(row: Row) -> str:
    """The path as the reader's own machine knows it, with ``$HOME`` as ``~``."""
    raw = row.config_path or ""
    home = str(Path.home())
    return "~" + raw[len(home) :] if home and raw.startswith(home) else raw


def _hidden(row: Row) -> bool:
    """Rows collapsed into a count unless ``--all``."""
    return (row.status is Status.NOT_AFFECTED and row.reason == OTHER_PACKAGE) or (
        row.status is Status.COULDNT_CHECK and row.reason == NO_PACKAGE
    )


def render_terminal(report: Report, console: Console, *, show_all: bool) -> None:
    """Print the report: affected first, then couldn't check, then not affected."""
    console.print(f"[bold]mcp-audit affected[/bold] {escape(report.query.text)}")
    if report.sources:
        console.print(f"[dim]Data: {escape('; '.join(report.sources))}[/dim]")
    if report.live:
        console.print("[dim]--live: the advisory was fetched from OSV.dev.[/dim]")
    for status in (Status.AFFECTED, Status.COULDNT_CHECK, Status.NOT_AFFECTED):
        rows = [r for r in report.rows if r.status is status]
        visible = [r for r in rows if show_all or not _hidden(r)]
        if not visible:
            continue
        console.print(f"\n[{_STYLE[status]}]{status.value}[/] ({len(rows)})")
        for row in visible:
            ver = f" {row.version}" if row.version else ""
            pkg = (
                f"  [dim]{escape(row.package)}{escape(ver)}[/dim]"
                if row.package
                else ""
            )
            console.print(f"  {escape(row.subject)}{pkg}")
            console.print(f"    {escape(row.evidence)}")
            if row.config_path:
                console.print(f"    [dim]{escape(_display_path(row))}[/dim]")
    hidden = [r for r in report.rows if _hidden(r)]
    if hidden and not show_all:
        other = sum(1 for r in hidden if r.reason == OTHER_PACKAGE)
        nopkg = len(hidden) - other
        parts = []
        if other:
            parts.append(f"{other} run a different package (NOT AFFECTED)")
        if nopkg:
            parts.append(
                f"{nopkg} launch no package mcp-audit can read (COULDN'T CHECK)"
            )
        console.print(
            f"\n[dim]Not listed: {'; '.join(parts)}. Use --all to list.[/dim]"
        )
    for note in report.notes:
        console.print(f"\n[dim]{escape(note)}[/dim]")
    for err in report.errors:
        console.print(f"[yellow]warning:[/yellow] {escape(err)}")
    console.print(
        f"\n{len(report.rows)} checked: "
        f"[{_STYLE[Status.AFFECTED]}]{report.count(Status.AFFECTED)} affected[/], "
        f"[{_STYLE[Status.NOT_AFFECTED]}]{report.count(Status.NOT_AFFECTED)} not "
        f"affected[/], [{_STYLE[Status.COULDNT_CHECK]}]"
        f"{report.count(Status.COULDNT_CHECK)} couldn't check[/]."
    )
    if report.needs_version():
        console.print(
            "[dim]COULDN'T CHECK is not 'not affected'. Pin the version, run "
            "`mcp-audit lock`, or pass a lock with --lock.[/dim]"
        )


def _row_dict(row: Row) -> dict[str, Any]:
    return {
        "subject": _scrub(row.subject),
        "status": row.status.value,
        "evidence": _scrub(row.evidence),
        "config_path": _path(row),
        "package": row.package,
        "version": row.version,
        "version_source": row.version_source,
        "fixed_in": row.fixed_in,
        "reason": row.reason,
    }


def render_json(report: Report) -> str:
    """The report as one JSON document."""
    doc = {
        "query": report.query.text,
        "kind": report.query.kind,
        "summary": {
            "checked": len(report.rows),
            "affected": report.count(Status.AFFECTED),
            "not_affected": report.count(Status.NOT_AFFECTED),
            "couldnt_check": report.count(Status.COULDNT_CHECK),
        },
        "sources": report.sources,
        "live": report.live,
        "notes": [_scrub(n) for n in report.notes],
        "errors": [_scrub(e) for e in report.errors],
        "results": [_row_dict(r) for r in report.rows],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def render_sarif(report: Report) -> str:
    """SARIF 2.1.0: one result per AFFECTED row, rule ID = the query's ID."""
    label = report.query.label
    rule: dict[str, Any] = {
        "id": label,
        "name": "AffectedByAdvisory",
        "shortDescription": {"text": f"Affected by {label}"},
    }
    if report.query.kind == "advisory" and report.query.advisory_id:
        rule["helpUri"] = _advisory_url(report.query.advisory_id)
    results = []
    for row in report.rows:
        if row.status is not Status.AFFECTED:
            continue
        uri = _path(row) or "unknown"
        results.append(
            {
                "ruleId": label,
                "level": "error",
                "message": {"text": _scrub(f"{row.subject}: {row.evidence}")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                "properties": {
                    "status": row.status.value,
                    "package": row.package,
                    "version": row.version,
                    "versionSource": row.version_source,
                    "fixedIn": row.fixed_in,
                },
            }
        )
    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/adudley78/mcp-audit",
                        "rules": [rule],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
