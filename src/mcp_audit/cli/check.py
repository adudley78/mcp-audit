"""The ``check`` command — one-command practitioner verdict."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from mcp_audit.cli import app, run_scan
from mcp_audit.models import Severity
from mcp_audit.output.check import print_check_results
from mcp_audit.output.terminal import print_results
from mcp_audit.registration import client as _reg_client
from mcp_audit.registration import manager as _reg_manager

# Severity order for exit-code threshold check (descending priority).
_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _exit_code(result) -> int:  # type: ignore[no-untyped-def]
    """Return the appropriate exit code for *result*.

    Exit codes:
    - 0: grade A or B (score >= 70) **and** no CRITICAL or HIGH findings
    - 1: grade C, D, or F (score < 70) **or** any CRITICAL/HIGH finding
    - 2: error (raised as ``typer.Exit(2)`` by the caller on exceptions)
    """
    if result.score is None:
        return 1
    has_critical_high = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings
    )
    if has_critical_high or result.score.numeric_score < 70:
        return 1
    return 0


@app.command("check")
def check(
    path: Path | None = typer.Option(  # noqa: B008
        None,
        "--path",
        "-p",
        help="Scan a specific config file instead of auto-discovering all configs.",
    ),
    verbose: bool = typer.Option(  # noqa: B008
        False,
        "--verbose",
        "-v",
        help="Show full scan output (equivalent to mcp-audit scan).",
    ),
    json_flag: bool = typer.Option(  # noqa: B008
        False,
        "--json",
        help="Output full scan JSON (no summary text).",
    ),
    register_flag: bool = typer.Option(  # noqa: B008
        False,
        "--register",
        help=(
            "After the scan, prompt for opt-in registration if not already registered."
        ),
    ),
) -> None:
    """One-command security verdict: grade, top findings, and fix hints.

    Runs a full scan internally and presents the result as a concise
    one-page verdict suitable for developers who are not security experts.
    Use ``mcp-audit scan`` when you need full finding details, OWASP codes,
    attack paths, or SARIF output.

    Exit codes:
    - 0: grade A or B (score >= 70, no CRITICAL/HIGH findings)
    - 1: grade C, D, or F, or any CRITICAL/HIGH finding
    - 2: error (invalid path, scan failure)
    """
    console = Console(width=80)

    # ── Path validation ───────────────────────────────────────────────────────
    if path is not None and not path.resolve().exists():
        console.print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(2)

    extra_paths = [path] if path else None

    # ── Run scan ──────────────────────────────────────────────────────────────
    try:
        result = run_scan(
            extra_paths=extra_paths,
            skip_rug_pull=False,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Scan error:[/red] {exc}")
        raise typer.Exit(2) from None

    # ── No configs found ──────────────────────────────────────────────────────
    if result.clients_scanned == 0 and result.servers_found == 0 and not extra_paths:
        console.print()
        console.print(
            "No MCP config files found on this machine. "
            "Run [bold]mcp-audit discover[/bold] to see where mcp-audit looks."
        )
        raise typer.Exit(0)

    grade = result.score.grade if result.score else "?"

    # ── JSON output ───────────────────────────────────────────────────────────
    if json_flag:
        sys.stdout.write(
            result.model_dump_json(by_alias=True, indent=2, exclude_none=False)
        )
        sys.stdout.write("\n")
        _maybe_ping(grade, console)
        raise typer.Exit(_exit_code(result))

    # ── Verbose output ────────────────────────────────────────────────────────
    if verbose:
        print_results(result, console=console)
        _maybe_ping(grade, console)
        raise typer.Exit(_exit_code(result))

    # ── One-page verdict ──────────────────────────────────────────────────────
    reg_config = _reg_manager.load_registration()
    print_check_results(result, console=console, registration=reg_config)
    _maybe_ping(grade, console)

    # ── Optional post-scan registration prompt ────────────────────────────────
    if register_flag and reg_config is None:
        # Deferred import avoids a circular import at module level.
        from mcp_audit.cli.register import _handle_register  # noqa: PLC0415

        _handle_register(console)

    raise typer.Exit(_exit_code(result))


def _maybe_ping(grade: str, console: Console) -> None:
    """Fire an anonymous ping if the user is registered; log dim warning on failure."""
    config = _reg_manager.load_registration()
    if config is None:
        return
    ok = _reg_client.post_ping(grade)
    if not ok:
        console.print("[dim]Registration ping failed (offline?)[/dim]")
