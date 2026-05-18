"""The ``fix`` command — apply safe remediations back to MCP config files.

Dry-run by default: prints a unified diff showing what would change.
Pass ``--apply`` to write changes atomically with a ``.bak`` backup.

Supported finding types (MVP):
    credentials  CRED-001, CRED-002 — redact plaintext secrets with ${ENV_KEY}
    transport    TRANSPORT-001      — upgrade http:// URLs to https://
    pinning      SC-001, SC-002     — replace typosquatted pkg with verified@version

Exit codes:
    0  No fixable findings, or dry-run / apply completed successfully.
    2  Error (file not found, unreadable JSON, write failure, etc.).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.rule import Rule

from mcp_audit.cli import app
from mcp_audit.fixer.fixer import FixType, run_fix
from mcp_audit.models import Finding, ScanResult
from mcp_audit.scanner import run_scan

logger = logging.getLogger(__name__)

console = Console()
err_console = Console(stderr=True)

_FIX_TYPE_CHOICES = ["credentials", "transport", "pinning"]
_FIX_TYPE_CHOICES_STR = ", ".join(_FIX_TYPE_CHOICES)


@app.command("fix")
def fix(
    path: Path | None = typer.Option(  # noqa: B008
        None,
        "--path",
        "-p",
        help=(
            "Path to the MCP config file to fix. "
            "Defaults to auto-discovering all configs when neither "
            "--path nor --input is given."
        ),
    ),
    input_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--input",
        "-i",
        help=(
            "Path to an existing scan JSON file produced by "
            "'mcp-audit scan --output json'. "
            "Reads findings and config_path from the JSON "
            "instead of running a fresh scan."
        ),
    ),
    apply: bool = typer.Option(  # noqa: B008
        False,
        "--apply",
        help=(
            "Write the changes to disk (atomic rename). "
            "Without this flag, only a diff is shown."
        ),
    ),
    fix_type: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--fix-type",
        help=(
            "Restrict to a specific fix type. Can be repeated. "
            f"Choices: {_FIX_TYPE_CHOICES_STR}."
        ),
    ),
    offline: bool = typer.Option(  # noqa: B008
        False,
        "--offline",
        help=(
            "Suppress all network calls (version resolution for SC-001/002 is skipped)."
        ),
    ),
) -> None:
    """Apply safe remediations directly to MCP config files.

    Without ``--apply``, prints a unified diff to stdout (dry run).
    With ``--apply``, writes changes atomically and creates a ``.bak`` backup.

    Three fix types are supported:

    \b
    credentials  CRED-001/002 — redact plaintext secrets with ${ENV_KEY}
    transport    TRANSPORT-001 — upgrade http:// URLs to https://
    pinning      SC-001/002 — replace typosquatted package with verified@version
    """
    # ── Validate --fix-type values ────────────────────────────────────────────
    validated_types: list[FixType] | None = None
    if fix_type:
        invalid = [t for t in fix_type if t not in _FIX_TYPE_CHOICES]
        if invalid:
            err_console.print(
                f"[red]Error:[/red] Invalid --fix-type value(s): "
                f"{', '.join(invalid)}. "
                f"Choices: {_FIX_TYPE_CHOICES_STR}"
            )
            raise typer.Exit(2)
        validated_types = list(fix_type)  # type: ignore[assignment]

    # ── Validate mutually exclusive flags ─────────────────────────────────────
    if path and input_file:
        err_console.print(
            "[red]Error:[/red] --path and --input are mutually exclusive."
        )
        raise typer.Exit(2)

    # ── Resolve findings and config path ──────────────────────────────────────
    try:
        config_path, findings = _resolve_findings(path, input_file)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc

    # ── Load registry for pinning strategy ───────────────────────────────────
    registry = None
    if not offline:
        try:
            from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

            registry = load_registry()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Registry unavailable for pinning strategy: %s", exc)

    # ── Run fixer ─────────────────────────────────────────────────────────────
    try:
        result = run_fix(
            findings=findings,
            config_path=config_path,
            apply=apply,
            fix_types=validated_types,
            offline=offline,
            registry=registry,
        )
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except PermissionError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc

    # ── Render output ─────────────────────────────────────────────────────────
    _print_result(result, apply=apply)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _resolve_findings(
    path: Path | None, input_file: Path | None
) -> tuple[Path, list[Finding]]:
    """Return ``(config_path, findings)`` from a scan or an existing JSON file.

    Args:
        path: Optional explicit config path (triggers a fresh scan if given).
        input_file: Optional path to a saved scan JSON file.

    Returns:
        Tuple of ``(config_path, findings)`` ready for :func:`run_fix`.

    Raises:
        FileNotFoundError: When *path* or *input_file* does not exist.
        ValueError: When *input_file* is not valid JSON or is missing required
            fields.
    """
    if input_file is not None:
        input_file = input_file.resolve()
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        raw = input_file.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Input file is not valid JSON: {input_file}: {exc}"
            ) from exc

        scan_result = ScanResult.model_validate(data)
        if not scan_result.servers:
            raise ValueError(
                "Scan result has no servers; cannot determine config_path. "
                "Re-run 'mcp-audit scan --output json' and pass the output here."
            )
        # Use the config path from the first server found.
        config_path = scan_result.servers[0].config_path.resolve()
        if not config_path.exists():
            raise FileNotFoundError(
                f"Config path from scan result not found: {config_path}"
            )
        return config_path, scan_result.findings

    # Fresh scan path.
    extra_paths: list[Path] | None = None
    if path is not None:
        path = path.resolve()
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        extra_paths = [path]

    scan_result = run_scan(extra_paths=extra_paths)

    if extra_paths:
        config_path = extra_paths[0]
    elif scan_result.servers:
        config_path = scan_result.servers[0].config_path.resolve()
    else:
        raise ValueError("No config files found. Use --path to specify one explicitly.")

    return config_path, scan_result.findings


def _print_result(result, *, apply: bool) -> None:  # type: ignore[no-untyped-def]
    """Render the fix result to the console.

    Args:
        result: :class:`~mcp_audit.fixer.fixer.FixResult` instance.
        apply: Whether the fix was applied to disk.
    """
    console.print(Rule("[bold]mcp-audit fix[/bold]"))

    if result.no_fixable:
        console.print("[green]No fixable findings in this scan.[/green]")
        return

    # Print skipped / warning messages first so they appear before the diff.
    for warning in result.skipped:
        console.print(f"[yellow]⚠[/yellow]  {warning}")

    if result.fixes_applied:
        verb = "Applied" if apply else "Would apply"
        console.print(f"\n[bold]{verb} {len(result.fixes_applied)} fix(es):[/bold]")
        for description in result.fixes_applied:
            icon = "✓" if apply else "~"
            console.print(f"  [green]{icon}[/green]  {description}")

    if result.diff:
        console.print()
        console.print(Rule("diff"))
        for line in result.diff.splitlines():
            if line.startswith("+++") or line.startswith("---"):
                console.print(f"[bold]{line}[/bold]")
            elif line.startswith("+"):
                console.print(f"[green]{line}[/green]")
            elif line.startswith("-"):
                console.print(f"[red]{line}[/red]")
            elif line.startswith("@@"):
                console.print(f"[cyan]{line}[/cyan]")
            else:
                console.print(line)
    else:
        if result.fixes_applied:
            console.print(
                "[dim]No changes needed — all findings already remediated.[/dim]"
            )

    if apply and result.backup_path:
        console.print()
        console.print(f"[dim]Backup written to: {result.backup_path}[/dim]")
        console.print(f"[dim]Config updated:    {result.config_path}[/dim]")
    elif not apply and result.diff:
        console.print()
        console.print(
            "[dim]Dry run — no files modified. Pass --apply to write changes.[/dim]"
        )

    console.print(Rule())
