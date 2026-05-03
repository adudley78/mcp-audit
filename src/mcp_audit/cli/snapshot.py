"""``mcp-audit snapshot`` — time-stamped signed forensic exports.

Time-stamped signed forensic snapshots of every MCP server on this host.
CycloneDX AI/ML-BOM by default. Sigstore-signed. SIEM-ready.

Pipeline:

1. Discover and analyse MCP configs (or load a previous scan via ``--input``).
2. Format as CycloneDX 1.5+ JSON (default) or native JSON (``--format native``).
3. Optionally sign the snapshot with sigstore (``--sign``).
4. Write to ``--output`` file, stream one-finding-per-line (``--stream``),
   or print to stdout.

``--rehydrate <path>`` mode is a bypass: it reads a saved snapshot and
reconstructs the historical attack-path graph without running a new scan.
"""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_audit import __version__
from mcp_audit.cli import app
from mcp_audit.models import ScanResult
from mcp_audit.output.snapshot import (
    format_cyclonedx_aibom,
    format_native,
    format_stream_lines,
    sha256_snapshot,
    sign_snapshot,
)
from mcp_audit.scanner import run_scan
from mcp_audit.snapshot.diff import diff_snapshot_against_current
from mcp_audit.snapshot.rehydrate import rehydrate

_err = Console(stderr=True)
_out = Console()


def _host_id() -> str:
    """Return a stable host identifier for snapshot metadata.

    Returns:
        Platform node name (hostname), or ``"unknown"`` if unavailable.
    """
    try:
        return platform.node() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _build_result(
    input_file: Path | None,
    path: Path | None,
) -> ScanResult:
    """Run or load the scan to produce a :class:`~mcp_audit.models.ScanResult`.

    Args:
        input_file: Optional path to a previous ``mcp-audit scan --output-file``
            JSON result.  When provided, the file is loaded rather than running
            a new scan.
        path: Optional path override for config discovery (passed through to
            ``run_scan``).

    Returns:
        A completed :class:`~mcp_audit.models.ScanResult`.

    Raises:
        typer.Exit: With code 2 on validation or parse failure.
    """
    if input_file is not None:
        resolved = input_file.resolve()
        if not resolved.exists():
            _err.print(f"[red]Error:[/red] --input file not found: {input_file}")
            raise typer.Exit(2)
        try:
            raw = json.loads(resolved.read_text(encoding="utf-8"))
            return ScanResult.model_validate(raw)
        except Exception as exc:  # noqa: BLE001
            _err.print(
                f"[red]Error:[/red] Cannot parse --input file {input_file}: {exc}"
            )
            raise typer.Exit(2) from exc

    # Live scan
    extra_paths: list[Path] | None = None
    if path is not None:
        resolved_path = path.resolve()
        if not resolved_path.exists():
            _err.print(f"[red]Error:[/red] --path not found: {path}")
            raise typer.Exit(2)
        extra_paths = [resolved_path]

    return run_scan(
        extra_paths=extra_paths,
        skip_auto_discovery=bool(extra_paths),
    )


def _write_snapshot(content: str, output: Path | None) -> Path | None:
    """Write *content* to *output* or stdout.

    Args:
        content: Serialised snapshot string.
        output: Destination file path, or ``None`` for stdout.

    Returns:
        The resolved output :class:`~pathlib.Path`, or ``None`` when writing
        to stdout.
    """
    if output is not None:
        resolved = output.resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return resolved
    sys.stdout.write(content)
    if not content.endswith("\n"):
        sys.stdout.write("\n")
    return None


def _print_rehydrate_summary(rehydrated: object, delta: object | None) -> None:  # type: ignore[type-arg]
    """Print a Rich summary panel for rehydrate mode.

    Args:
        rehydrated: :class:`~mcp_audit.snapshot.rehydrate.RehydratedSnapshot`.
        delta: Optional :class:`~mcp_audit.snapshot.diff.SnapshotDelta`.
    """
    from mcp_audit.snapshot.diff import SnapshotDelta  # noqa: PLC0415
    from mcp_audit.snapshot.rehydrate import RehydratedSnapshot  # noqa: PLC0415

    assert isinstance(rehydrated, RehydratedSnapshot)  # noqa: S101

    result = rehydrated.result
    aps = result.attack_path_summary

    table = Table.grid(padding=(0, 1))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Snapshot timestamp:", rehydrated.snapshot_timestamp)
    table.add_row("Host:", rehydrated.host_id)
    table.add_row("mcp-audit version:", rehydrated.version)
    table.add_row("Servers:", str(len(result.servers)))
    table.add_row("Findings:", str(len(result.findings)))
    if aps:
        table.add_row("Attack paths:", str(len(aps.paths)))
        table.add_row(
            "Hitting set:",
            ", ".join(aps.hitting_set) if aps.hitting_set else "none",
        )

    if delta is not None and isinstance(delta, SnapshotDelta):
        table.add_row("", "")
        table.add_row("[bold]Delta vs current:[/bold]", "")
        table.add_row("  Added:", str(delta.added_count))
        table.add_row("  Removed:", str(delta.removed_count))
        if delta.added:
            table.add_row("  New servers:", ", ".join(delta.added))
        if delta.removed:
            table.add_row("  Gone servers:", ", ".join(delta.removed))

    _out.print(Panel(table, title="[bold cyan]Rehydrated Snapshot[/bold cyan]"))


# ── Command ────────────────────────────────────────────────────────────────────


@app.command("snapshot")
def snapshot(  # noqa: PLR0912, PLR0913, PLR0915
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write snapshot to this file. Omit to print to stdout.",
            show_default=False,
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help=(
                "Output format: ``cyclonedx`` (default, CycloneDX 1.5 AI/ML-BOM) "
                "or ``native`` (mcp-audit-native JSON)."
            ),
        ),
    ] = "cyclonedx",
    input_file: Annotated[
        Path | None,
        typer.Option(
            "--input",
            "-i",
            help=(
                "Path to a previous ``mcp-audit scan --output-file`` JSON result. "
                "When supplied, skips live discovery and uses this result instead."
            ),
            show_default=False,
        ),
    ] = None,
    path: Annotated[
        Path | None,
        typer.Option(
            "--path",
            "-p",
            help=(
                "MCP config file or directory for live scan. "
                "Defaults to auto-discovery."
            ),
            show_default=False,
        ),
    ] = None,
    sign: Annotated[
        bool,
        typer.Option(
            "--sign",
            help=(
                "Sign the snapshot with sigstore (requires ambient OIDC identity "
                "and the sigstore optional dependency). "
                "Produces <output>.sig alongside the snapshot."
            ),
        ),
    ] = False,
    rehydrate_path: Annotated[
        Path | None,
        typer.Option(
            "--rehydrate",
            help=(
                "Path to an old snapshot. Reconstructs the historical attack-path "
                "graph as it was at snapshot time and diffs against the current state."
            ),
            show_default=False,
        ),
    ] = None,
    stream: Annotated[
        bool,
        typer.Option(
            "--stream",
            help=(
                "Emit one JSON object per line on stdout (NDJSON). "
                "Each line is a finding record enriched with timestamp and host. "
                "Suitable for piping into vector, Splunk HEC, or any SIEM forwarder."
            ),
        ),
    ] = False,
) -> None:
    """Time-stamped signed forensic snapshots of every MCP server on this host.

    CycloneDX AI/ML-BOM by default. Sigstore-signed. SIEM-ready.

    Exit codes: 0 = success, 2 = error.
    """
    # ── Validate options ──────────────────────────────────────────────────────
    if output_format not in ("cyclonedx", "native"):
        _err.print(
            f"[red]Error:[/red] unknown --format {output_format!r}. "
            "Accepted values: cyclonedx, native."
        )
        raise typer.Exit(2)

    if stream and output_format != "cyclonedx":
        # stream mode always emits NDJSON regardless of format flag
        pass  # format flag is ignored in stream mode

    # ── Rehydrate mode ────────────────────────────────────────────────────────
    if rehydrate_path is not None:
        resolved_rp = rehydrate_path.resolve()
        if not resolved_rp.exists():
            _err.print(
                f"[red]Error:[/red] --rehydrate path not found: {rehydrate_path}"
            )
            raise typer.Exit(2)
        try:
            rehydrated = rehydrate(resolved_rp)
        except ValueError as exc:
            _err.print(f"[red]Error:[/red] Cannot rehydrate snapshot: {exc}")
            raise typer.Exit(2) from exc

        # Compute delta against current state (best-effort; ignore errors)
        delta = None
        try:
            live_result = _build_result(input_file=None, path=path)
            delta = diff_snapshot_against_current(resolved_rp, live_result.servers)
        except Exception:  # noqa: BLE001, S110
            pass  # delta is optional; don't fail rehydrate on live-scan errors

        _print_rehydrate_summary(rehydrated, delta)
        raise typer.Exit(0)

    # ── Build ScanResult ──────────────────────────────────────────────────────
    result = _build_result(input_file=input_file, path=path)
    host = _host_id()

    # ── Stream mode ───────────────────────────────────────────────────────────
    if stream:
        lines = format_stream_lines(result)
        for line in lines:
            sys.stdout.write(line + "\n")
        raise typer.Exit(0)

    # ── Format ────────────────────────────────────────────────────────────────
    if output_format == "cyclonedx":
        doc = format_cyclonedx_aibom(result, host_id=host)
    else:
        doc = format_native(result, host_id=host)

    content = json.dumps(doc, indent=2, default=str)

    # ── Write output ──────────────────────────────────────────────────────────
    written_path = _write_snapshot(content, output)

    # ── Sign ──────────────────────────────────────────────────────────────────
    if sign:
        if written_path is None:
            _err.print(
                "[red]Error:[/red] --sign requires --output (cannot sign stdout)."
            )
            raise typer.Exit(2)
        try:
            sig_path = sign_snapshot(written_path)
            _err.print(f"[green]Signed:[/green] {sig_path}")
        except ImportError as exc:
            _err.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(2) from exc
        except RuntimeError as exc:
            _err.print(f"[red]Error:[/red] Signing failed: {exc}")
            _err.print(
                f"[yellow]Note:[/yellow] Unsigned snapshot still written "
                f"to {written_path}"
            )
            raise typer.Exit(2) from exc

    # ── Summary ───────────────────────────────────────────────────────────────
    if written_path is not None:
        sha = sha256_snapshot(written_path)
        _err.print(
            f"[green]Snapshot written to[/green] {written_path} "
            f"[dim](sha256:{sha[:16]}…)[/dim]"
        )
        _err.print(
            f"[dim]  format={output_format}  servers={len(result.servers)}  "
            f"findings={len(result.findings)}  version={__version__}[/dim]"
        )
