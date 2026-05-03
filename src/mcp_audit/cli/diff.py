"""``mcp-audit diff <base> <head>`` — MCP-aware diff for PRs and CI gates.

Surfaces what changed in MCP terms (servers, tools, capabilities, env vars,
endpoints, credentials) between two states, classified by risk.

Accepted input formats for *base* and *head*:

- Path to a directory of MCP configs (``--path``-style discovery).
- Path to a ``mcp-audit scan --output-file`` JSON.
- A git ref (SHA, branch, ``HEAD~1``, etc.) — resolved via ``git show``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mcp_audit.cli import app
from mcp_audit.diff.comparator import Change, compare
from mcp_audit.diff.loader import load_input
from mcp_audit.diff.render import render_json, render_pr_comment, render_terminal
from mcp_audit.models import Severity

_err = Console(stderr=True)

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _filter_by_threshold(changes: list[Change], threshold: Severity) -> list[Change]:
    """Return only changes at or above *threshold*."""
    cutoff = _SEVERITY_ORDER.index(threshold)
    return [c for c in changes if _SEVERITY_ORDER.index(c.severity) <= cutoff]


@app.command(name="diff")
def diff(  # noqa: PLR0912
    base: Annotated[
        str,
        typer.Argument(
            help=(
                "Base state: a directory of MCP configs, a scan JSON file, "
                "or a git ref (SHA / HEAD~1 / branch)."
            ),
        ),
    ],
    head: Annotated[
        str,
        typer.Argument(
            help=(
                "Head state: a directory of MCP configs, a scan JSON file, "
                "or a git ref (SHA / HEAD / branch)."
            ),
        ),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help=(
                "Output format: ``terminal`` (default, Rich-formatted), "
                "``json`` (structured records), or ``pr-comment`` "
                "(GitHub-flavored Markdown for PR comments)."
            ),
        ),
    ] = "terminal",
    severity_threshold: Annotated[
        str,
        typer.Option(
            "--severity-threshold",
            help=(
                "Only report changes at or above this level. "
                "One of: critical, high, medium, low, info."
            ),
        ),
    ] = "info",
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output-file",
            "-o",
            help="Write output to a file instead of stdout.",
            show_default=False,
        ),
    ] = None,
) -> None:
    """MCP-aware diff for PRs and CI gates.

    Surfaces what changed in MCP terms, classified by risk.  Accepts two
    inputs (directories, JSON scan files, or git refs) and reports added,
    removed, and changed servers, tools, capabilities, env vars, endpoints,
    and credentials.

    Exit codes: 0 = no findings at threshold, 1 = findings at threshold, 2 = error.
    """
    # ── Validate arguments ────────────────────────────────────────────────
    if output_format not in ("terminal", "json", "pr-comment"):
        _err.print(
            f"[red]Error:[/red] unknown --format {output_format!r}. "
            "Accepted values: terminal, json, pr-comment."
        )
        raise typer.Exit(2)

    threshold_upper = severity_threshold.upper()
    try:
        threshold = Severity(threshold_upper)
    except ValueError:
        _err.print(
            f"[red]Error:[/red] unknown --severity-threshold {severity_threshold!r}. "
            "Accepted values: critical, high, medium, low, info."
        )
        raise typer.Exit(2) from None

    if output_file is not None:
        output_file = output_file.resolve()

    # ── Load inputs ───────────────────────────────────────────────────────
    try:
        base_servers = load_input(base)
    except ValueError as exc:
        _err.print(f"[red]Error:[/red] could not load base input {base!r}: {exc}")
        raise typer.Exit(2) from exc

    try:
        head_servers = load_input(head)
    except ValueError as exc:
        _err.print(f"[red]Error:[/red] could not load head input {head!r}: {exc}")
        raise typer.Exit(2) from exc

    # ── Compare ───────────────────────────────────────────────────────────
    all_changes = compare(base_servers, head_servers)
    changes = _filter_by_threshold(all_changes, threshold)

    # ── Render ────────────────────────────────────────────────────────────
    if output_format == "json":
        output = render_json(changes)
        _write_output(output, output_file)

    elif output_format == "pr-comment":
        output = render_pr_comment(changes, base, head)
        _write_output(output, output_file)

    else:  # terminal
        if output_file is not None:
            # Write plain text (no Rich markup) to file
            output = render_pr_comment(changes, base, head)
            _write_output(output, output_file)
        else:
            render_terminal(changes, base, head)

    # ── No-change fast path ───────────────────────────────────────────────
    if not all_changes and output_format == "terminal" and output_file is None:
        # render_terminal already prints the "No MCP changes" message.
        pass

    # ── Exit code ─────────────────────────────────────────────────────────
    # Exit 1 if any changes at or above threshold are present (mirrors scan).
    if changes:
        raise typer.Exit(1)
    raise typer.Exit(0)


def _write_output(content: str, output_file: Path | None) -> None:
    """Write *content* to *output_file* or stdout."""
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(content, encoding="utf-8")
        _err.print(f"[dim]Output written to: {output_file}[/dim]")
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
