"""``mcp-audit killchain`` — opinionated remediation view of the attack-path graph.

Find the 2–3 changes that cut your blast radius.  Decision engine on top of
the attack-path graph mcp-audit already computes.

This command:

1. Runs the existing static analysis pipeline (or accepts a previously-generated
   ``mcp-audit scan --output-file scan.json`` via ``--input``).
2. Identifies the top N "kill switches" — specific configuration changes that,
   applied in order, cut the largest blast radius from the attack-path graph.
3. Outputs a short, prescriptive Markdown report (default) or JSON payload
   (``--format json``).
4. Optionally emits a YAML governance-policy patch (``--patch yaml``) that
   blocks re-introduction of the flagged servers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mcp_audit import __version__
from mcp_audit.cli import app
from mcp_audit.killchain.patches import generate_pr_comment, generate_yaml_patch
from mcp_audit.killchain.recommender import recommend
from mcp_audit.killchain.render import render_json, render_markdown
from mcp_audit.killchain.simulator import simulate
from mcp_audit.models import AttackPathSummary, ScanResult

console = Console()
_err = Console(stderr=True)

# ── Schema-version guard ──────────────────────────────────────────────────────
# Accept scan results produced by mcp-audit ≥ 0.1.0.  We compare only the
# major component so minor/patch bumps are always compatible.
_MIN_SUPPORTED_VERSION = (0, 1, 0)


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a semver string into an integer tuple, ignoring pre-release tags."""
    try:
        return tuple(int(p) for p in v.split(".")[:3] if p.isdigit())
    except (ValueError, AttributeError):
        return (0, 0, 0)


def _load_scan_result(path: Path) -> ScanResult:
    """Load and validate a ``ScanResult`` from *path*.

    Raises:
        typer.Exit: On file-not-found, JSON decode error, or incompatible
            schema version.
    """
    if not path.exists():
        _err.print(f"[red]Error:[/red] file not found: {path}")
        raise typer.Exit(2)

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _err.print(f"[red]Error:[/red] could not parse JSON from {path}: {exc}")
        raise typer.Exit(2) from exc

    # Schema-version check: warn on unknown fields but still load.
    file_version = raw.get("version", "0.0.0")
    parsed = _parse_version(file_version)
    if parsed < _MIN_SUPPORTED_VERSION:
        min_v = ".".join(str(x) for x in _MIN_SUPPORTED_VERSION)
        _err.print(
            f"[red]Error:[/red] scan file version {file_version!r} is below "
            f"minimum supported version {min_v}. "
            "Re-generate the scan file with a current mcp-audit version."
        )
        raise typer.Exit(2)

    try:
        return ScanResult.model_validate(raw)
    except Exception as exc:  # noqa: BLE001
        _err.print(
            f"[red]Error:[/red] scan file {path} does not match expected schema: {exc}"
        )
        raise typer.Exit(2) from exc


def _run_inline_scan(extra_paths: list[Path] | None) -> ScanResult:
    """Run the full static analysis pipeline and return the result."""
    from mcp_audit.scanner import run_scan  # noqa: PLC0415

    return run_scan(extra_paths=extra_paths or None, skip_rug_pull=False)


# ── CLI command ───────────────────────────────────────────────────────────────


@app.command(name="killchain")
def killchain(
    input_file: Annotated[
        Path | None,
        typer.Option(
            "--input",
            "-i",
            help=(
                "Path to a previously-generated scan JSON file "
                "(``mcp-audit scan --output-file scan.json``). "
                "When omitted, a fresh scan is run automatically."
            ),
            show_default=False,
        ),
    ] = None,
    path: Annotated[
        list[Path] | None,
        typer.Option(
            "--path",
            "-p",
            help="MCP config path(s) to scan (used only when --input is not provided).",
            show_default=False,
        ),
    ] = None,
    top: Annotated[
        int,
        typer.Option(
            "--top",
            help="Number of kill-switch recommendations to produce.",
            min=1,
        ),
    ] = 3,
    patch: Annotated[
        str | None,
        typer.Option(
            "--patch",
            help=(
                "Emit a policy patch artifact alongside the report. "
                "Accepted values: ``yaml`` (governance denylist), "
                "``pr`` (pull-request comment stub)."
            ),
            show_default=False,
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: ``markdown`` (default, copy-paste friendly) or ``json``.",  # noqa: E501
        ),
    ] = "markdown",
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output-file",
            "-o",
            help="Write the report to a file instead of stdout.",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Find the 2–3 changes that cut your blast radius.

    Decision engine on top of the attack-path graph mcp-audit already
    computes.  Runs a fresh scan by default; pass ``--input scan.json``
    to consume an existing scan result.
    """
    # ── Validate arguments ────────────────────────────────────────────────────
    if output_format not in ("markdown", "json"):
        _err.print(
            f"[red]Error:[/red] unknown --format {output_format!r}. "
            "Accepted values: markdown, json."
        )
        raise typer.Exit(2)

    if patch is not None and patch not in ("yaml", "pr"):
        _err.print(
            f"[red]Error:[/red] unknown --patch {patch!r}. Accepted values: yaml, pr."
        )
        raise typer.Exit(2)

    if input_file is not None:
        input_file = input_file.resolve()

    # ── Acquire scan result ───────────────────────────────────────────────────
    if input_file is not None:
        scan_result = _load_scan_result(input_file)
    else:
        if output_format == "markdown":
            _err.print(f"[dim]mcp-audit killchain v{__version__} — running scan…[/dim]")
        scan_result = _run_inline_scan(path)

    # ── Check for attack paths ────────────────────────────────────────────────
    summary: AttackPathSummary = scan_result.attack_path_summary or AttackPathSummary()

    if not summary.paths:
        report = (
            "No reachable attack paths — no changes recommended.\n"
            if output_format == "markdown"
            else json.dumps(
                {
                    "generated": __import__("datetime")
                    .datetime.now(__import__("datetime").timezone.utc)
                    .isoformat(),
                    "original_blast_radius": 0,
                    "simulated_blast_radius": 0,
                    "kill_switches": [],
                },
                indent=2,
            )
            + "\n"
        )
        _write_output(report, output_file)
        raise typer.Exit(0)

    # ── Recommend ─────────────────────────────────────────────────────────────
    switches = recommend(summary, top_n=top)

    # Attach governance patch to each switch if requested.
    if patch == "yaml" and switches:
        yaml_patch = generate_yaml_patch(switches)
        for ks in switches:
            ks.governance_patch = yaml_patch

    # ── Simulate what-if ──────────────────────────────────────────────────────
    simulated: AttackPathSummary | None = None
    if switches:
        simulated = simulate(scan_result, switches)

    # ── Render ────────────────────────────────────────────────────────────────
    if output_format == "json":
        report = render_json(switches, summary, simulated)
    else:
        report = render_markdown(switches, summary, simulated)

    _write_output(report, output_file)

    # ── Optional patch artifact ───────────────────────────────────────────────
    if patch == "yaml" and output_format != "json":
        yaml_patch = generate_yaml_patch(switches)
        if output_file is not None:
            patch_path = output_file.with_suffix(".patch.yml")
            patch_path.parent.mkdir(parents=True, exist_ok=True)
            patch_path.write_text(yaml_patch, encoding="utf-8")
            _err.print(f"[dim]Governance patch written to: {patch_path}[/dim]")
        else:
            sys.stdout.write("\n---\n\n")
            sys.stdout.write(yaml_patch)

    if patch == "pr" and output_format != "json":
        pr_comment = generate_pr_comment(switches)
        if output_file is not None:
            pr_path = output_file.with_suffix(".pr-comment.md")
            pr_path.parent.mkdir(parents=True, exist_ok=True)
            pr_path.write_text(pr_comment, encoding="utf-8")
            _err.print(f"[dim]PR comment stub written to: {pr_path}[/dim]")
        else:
            sys.stdout.write("\n---\n\n")
            sys.stdout.write(pr_comment)

    raise typer.Exit(0)


# ── Internal output helper ────────────────────────────────────────────────────


def _write_output(content: str, output_file: Path | None) -> None:
    """Write *content* to *output_file* or stdout."""
    if output_file is not None:
        output_file = output_file.resolve()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(content, encoding="utf-8")
        _err.print(f"[dim]Report written to: {output_file}[/dim]")
    else:
        sys.stdout.write(content)
