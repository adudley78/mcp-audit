"""The ``check`` command — one-command practitioner verdict."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import typer
from rich.console import Console

from mcp_audit.cli import app, run_scan
from mcp_audit.lock.auto_verify import auto_verify as _lock_auto_verify
from mcp_audit.models import LockStatus, ScanResult, Severity
from mcp_audit.output.check import print_check_results
from mcp_audit.output.terminal import print_results
from mcp_audit.registration import client as _reg_client
from mcp_audit.registration import manager as _reg_manager
from mcp_audit.scoring import calculate_score

# Severity order for exit-code threshold check (descending priority).
_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _apply_lock_verification(
    result: ScanResult, no_lock: bool, console: Console
) -> ScanResult:
    """Auto-verify ``mcp-lock.json`` for *result*'s servers (STORY-0070).

    Mirrors ``cli.scan._apply_lock_verification`` (kept as a separate,
    small copy rather than a cross-module import so ``check.py`` and
    ``scan.py`` stay independently importable — the two already have an
    asymmetric relationship where ``scan.py`` lazily imports from
    ``check.py`` for PDF reports, never the reverse). ``check`` has no
    governance-policy weight plumbing today, so the score recompute below
    always uses ``calculate_score``'s own defaults, matching the "default"
    weights ``run_scan`` itself used for the main score.

    Always offline; never adds ``--resolve``-equivalent network calls to
    ``check`` (an explicit STORY-0070 non-goal). Returns *result* unchanged
    (``lock_status.present=False``) when no ``mcp-lock.json`` is
    discoverable for any scanned server, or when *no_lock* is set.
    """
    if no_lock:
        result.lock_status = LockStatus()
        return result

    lock_findings, status = _lock_auto_verify(result.servers)
    result.lock_status = status
    if not status.present:
        return result

    if lock_findings:
        result.findings.extend(lock_findings)
        result.score = calculate_score(result.findings)
    return result


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
    configs: list[Path] | None = typer.Argument(  # noqa: B008
        default=None,
        help=(
            "Config file to scan (positional). "
            "Equivalent to --path; cannot be combined with --path."
        ),
    ),
    path: Path | None = typer.Option(  # noqa: B008
        None,
        "--path",
        "-p",
        help=(
            "Scan a specific config file instead of auto-discovering all configs. "
            "Cannot be combined with a positional path argument."
        ),
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
    report: str | None = typer.Option(  # noqa: B008
        None,
        "--report",
        help=(
            "Generate a compliance report in the given format. "
            "Currently supported: pdf. "
            "Output path is controlled by --output-file."
        ),
    ),
    output_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--output-file",
        "-o",
        help=(
            "Path for the compliance report file. "
            "Defaults to mcp-audit-report-<date>.pdf in the current directory. "
            "Parent directories are created automatically."
        ),
    ),
    org: str | None = typer.Option(  # noqa: B008
        None,
        "--org",
        help=(
            "Organisation name printed in the PDF report header. "
            "Falls back to the registered org name, then 'Not specified'."
        ),
    ),
    register_flag: bool = typer.Option(  # noqa: B008
        False,
        "--register",
        help=(
            "After the scan, prompt for opt-in registration if not already registered."
        ),
    ),
    no_lock: bool = typer.Option(  # noqa: B008
        False,
        "--no-lock",
        help=(
            "Skip automatic mcp-lock.json verification. By default, check "
            "auto-verifies the nearest ancestor lock file for each scanned "
            "server, if one exists."
        ),
    ),
) -> None:
    """One-command security verdict: grade, top findings, and fix hints.

    Runs a full scan internally and presents the result as a concise
    one-page verdict suitable for developers who are not security experts.
    Use ``mcp-audit scan`` when you need full finding details, OWASP codes,
    attack paths, or SARIF output.

    A config file can be supplied either as a positional argument or via
    ``--path``/``-p``; providing both at once is an error (exit code 2).

    Exit codes:
    - 0: grade A or B (score >= 70, no CRITICAL/HIGH findings)
    - 1: grade C, D, or F, or any CRITICAL/HIGH finding
    - 2: error (invalid path, ambiguous input, scan failure)
    """
    console = Console(width=80)

    # ── Resolve positional vs --path ──────────────────────────────────────────
    if configs and len(configs) > 1:
        console.print(
            "[red]Error:[/red] check accepts a single config path. "
            "Pass one path positionally or use --path."
        )
        raise typer.Exit(2)
    config = configs[0] if configs else None
    if config is not None and path is not None:
        console.print(
            "[red]Error:[/red] Provide a config path either as a positional argument "
            "or via --path, not both."
        )
        raise typer.Exit(2)
    resolved_path = config if config is not None else path

    # ── Path validation ───────────────────────────────────────────────────────
    if resolved_path is not None and not resolved_path.resolve().exists():
        console.print(f"[red]File not found:[/red] {resolved_path}")
        raise typer.Exit(2)

    extra_paths = [resolved_path] if resolved_path else None

    # ── Run scan ──────────────────────────────────────────────────────────────
    try:
        result = run_scan(
            extra_paths=extra_paths,
            skip_rug_pull=False,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Scan error:[/red] {exc}")
        raise typer.Exit(2) from None

    result = _apply_lock_verification(result, no_lock, console)

    # ── No configs found ──────────────────────────────────────────────────────
    if result.clients_scanned == 0 and result.servers_found == 0 and not extra_paths:
        console.print()
        console.print(
            "No MCP config files found on this machine. "
            "Run [bold]mcp-audit discover[/bold] to see where mcp-audit looks."
        )
        raise typer.Exit(0)

    grade = result.score.grade if result.score else "?"

    # ── PDF compliance report ─────────────────────────────────────────────────
    if report is not None:
        report_lower = report.strip().lower()
        if report_lower != "pdf":
            console.print(
                f"[red]Unknown report format:[/red] {report!r}. "
                "Currently supported: pdf"
            )
            raise typer.Exit(2)
        _write_pdf_report(result, output_file, org, console)
        _maybe_ping(grade, console)
        raise typer.Exit(_exit_code(result))

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


def _resolve_org_name(org_flag: str | None) -> str:
    """Resolve the organisation name for the compliance report.

    Precedence: ``--org`` flag → registered org → ``"Not specified"``.

    Args:
        org_flag: Value of the ``--org`` CLI flag, or ``None`` if omitted.

    Returns:
        A non-empty organisation name string.
    """
    if org_flag and org_flag.strip():
        return org_flag.strip()
    reg = _reg_manager.load_registration()
    if reg is not None and reg.org and reg.org.strip():
        return reg.org.strip()
    return "Not specified"


def _write_pdf_report(
    result,  # type: ignore[no-untyped-def]
    output_file: Path | None,
    org_flag: str | None,
    console: Console,
) -> None:
    """Generate a PDF compliance report and write it to disk.

    Resolves the output path (defaulting to ``mcp-audit-report-<date>.pdf``
    in the current working directory), creates parent directories, and writes
    the PDF with 0o644 permissions.

    Args:
        result: Completed scan result.
        output_file: Explicit output path from ``--output-file``, or ``None``.
        org_flag: Value of the ``--org`` flag, or ``None`` if omitted.
        console: Rich console for status/error messages.
    """
    from datetime import date  # noqa: PLC0415

    from mcp_audit.output.pdf import PdfReportFormatter  # noqa: PLC0415

    org_name = _resolve_org_name(org_flag)

    if output_file is None:
        today = date.today().isoformat()
        output_file = Path(f"mcp-audit-report-{today}.pdf")

    output_file = output_file.resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        formatter = PdfReportFormatter(result, org_name=org_name)
        pdf_bytes = formatter.generate()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]PDF generation error:[/red] {exc}")
        raise typer.Exit(2) from None

    fd = os.open(str(output_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, pdf_bytes)
    finally:
        os.close(fd)

    console.print(f"[green]PDF report written:[/green] {output_file}")
    console.print(f"[dim]Organisation: {org_name}[/dim]")
