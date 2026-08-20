"""mcp-audit advise / feed verify — publish and verify the MCP advisory feed.

``advise`` runs a scan, converts the findings into OSV-compatible advisory records,
writes them to a feed directory, and signs them. ``feed verify`` re-canonicalizes an
existing feed and checks every signature.

Exit codes follow the project convention: 0 success, 1 verification failure, 2 error.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_audit.advisory.feed import BuildReport, build_advisories, write_feed
from mcp_audit.advisory.sign import (
    BACKENDS,
    SigningConfig,
    SigningError,
    sign_feed,
    verify_feed,
)
from mcp_audit.cli import app, feed_app
from mcp_audit.models import ScanResult, Severity
from mcp_audit.scanner import run_scan

# Reproducible-builds convention: when set, this fixes every generated timestamp so a
# third party can regenerate the feed and get byte-identical files.
# https://reproducible-builds.org/docs/source-date-epoch/
ENV_SOURCE_DATE_EPOCH = "SOURCE_DATE_EPOCH"

_OBSERVATIONS = ("package-intrinsic", "deployment", "all")


def _resolve_now(published_at: str | None) -> str:
    """Return the RFC 3339 timestamp stamped on every advisory in this run.

    Precedence: explicit ``--published-at``, then ``SOURCE_DATE_EPOCH``, then now.

    Raises:
        typer.Exit: The supplied value is not a valid timestamp.
    """
    if published_at is not None:
        try:
            parsed = datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise typer.BadParameter(
                f"--published-at must look like 2026-07-30T12:00:00Z ({exc})"
            ) from exc
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")

    epoch = os.environ.get(ENV_SOURCE_DATE_EPOCH)
    if epoch:
        try:
            seconds = int(epoch)
        except ValueError as exc:
            raise typer.BadParameter(
                f"${ENV_SOURCE_DATE_EPOCH} must be an integer, got {epoch!r}"
            ) from exc
        return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.command("advise")
def advise(
    target: Path = typer.Argument(  # noqa: B008
        None,
        help="MCP config file or directory to scan. Defaults to auto-discovery.",
    ),
    out_dir: Path = typer.Option(  # noqa: B008
        Path("feed"),
        "--out",
        "-o",
        help="Directory to write the feed into.",
    ),
    input_scan: Path | None = typer.Option(  # noqa: B008
        None,
        "--input",
        help="Reuse an existing 'scan --format json' result instead of re-scanning.",
    ),
    sign: bool = typer.Option(  # noqa: B008
        True,
        "--sign/--no-sign",
        help="Sign each advisory and the index. --no-sign writes an unsigned feed.",
    ),
    key_alt: str = typer.Option(  # noqa: B008
        "cosign",
        "--key-alt",
        help=(
            "Signing backend: 'cosign' (default) or 'minisign' for low-dependency "
            "environments."
        ),
    ),
    key: Path | None = typer.Option(  # noqa: B008
        None,
        "--key",
        help="Private project key to sign with (or set $MCP_AUDIT_SIGNING_KEY).",
    ),
    keyless: bool = typer.Option(  # noqa: B008
        False,
        "--keyless",
        help=(
            "Sign via cosign's ambient OIDC instead of a key. Binds signatures to an "
            "individual identity and needs Rekor to verify — not for a published feed."
        ),
    ),
    severity_threshold: str = typer.Option(  # noqa: B008
        "medium",
        "--severity-threshold",
        help="Only advise on findings at or above this severity (or 'info' for all).",
    ),
    observation: str = typer.Option(  # noqa: B008
        "all",
        "--observation",
        help=(
            "Which records to publish: 'package-intrinsic' (defects in the published "
            "package), 'deployment' (local misconfiguration), or 'all'."
        ),
    ),
    published_at: str | None = typer.Option(  # noqa: B008
        None,
        "--published-at",
        help=(
            "Fix the published/modified timestamp (YYYY-MM-DDTHH:MM:SSZ) so the feed "
            f"is byte-reproducible. Also read from ${ENV_SOURCE_DATE_EPOCH}."
        ),
    ),
    offline: bool = typer.Option(  # noqa: B008
        False,
        "--offline",
        help="Fail rather than make any network call during the scan.",
    ),
) -> None:
    """Scan TARGET and publish signed, OSV-compatible advisories to ./feed.

    Advisories are minted only for servers that resolve to a published npm or PyPI
    package, because OSV records are keyed by package coordinate. Servers run from a
    local path or reachable only at a URL are counted and reported, not invented.
    """
    console = Console()

    if key_alt not in BACKENDS:
        console.print(
            f"[red]Error:[/red] Unknown backend '{key_alt}'. "
            f"Use one of: {', '.join(BACKENDS)}."
        )
        raise typer.Exit(2)

    if observation not in _OBSERVATIONS:
        console.print(
            f"[red]Error:[/red] Unknown --observation '{observation}'. "
            f"Use one of: {', '.join(_OBSERVATIONS)}."
        )
        raise typer.Exit(2)

    try:
        min_severity = Severity(severity_threshold.upper())
    except ValueError:
        console.print(
            f"[red]Error:[/red] Unknown severity '{severity_threshold}'. Use one of: "
            "critical, high, medium, low, info."
        )
        raise typer.Exit(2) from None

    if target is not None and not target.resolve().exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(2)

    now = _resolve_now(published_at)

    result = _load_scan(console, target, input_scan, offline=offline)

    report = build_advisories(
        result,
        now=now,
        min_severity=min_severity,
        only_observation=None if observation == "all" else observation,
    )

    manifest = write_feed(report.advisories, out_dir)

    if sign:
        try:
            config = SigningConfig.from_env(
                backend=key_alt, private_key=key, keyless=keyless
            )
            signatures = sign_feed(out_dir, config)
        except SigningError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            console.print(
                f"[dim]The unsigned feed is still at {out_dir}.[/dim]",
            )
            raise typer.Exit(2) from None
        console.print(
            f"[green]Signed[/green] {len(signatures)} artifact(s) with {key_alt}"
            f" ({'keyless' if config.keyless else 'project key'} mode)."
        )
    else:
        console.print(
            "[yellow]Warning:[/yellow] --no-sign: this feed carries no signatures. "
            "Consumers can still check integrity against index.json, but nothing "
            "attests to who produced it."
        )

    _print_summary(console, report, manifest.out_dir)


def _load_scan(
    console: Console,
    target: Path | None,
    input_scan: Path | None,
    *,
    offline: bool,
) -> ScanResult:
    """Return the scan result to advise on, from --input or a fresh scan."""
    if input_scan is not None:
        if not input_scan.resolve().is_file():
            console.print(f"[red]Error:[/red] Scan file not found: {input_scan}")
            raise typer.Exit(2)
        try:
            payload = json.loads(input_scan.read_text(encoding="utf-8"))
            return ScanResult.model_validate(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            console.print(
                f"[red]Error:[/red] {input_scan} is not an mcp-audit JSON scan "
                f"result: {exc}"
            )
            raise typer.Exit(2) from None

    try:
        return run_scan(
            extra_paths=[target] if target else None,
            offline=offline,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Error:[/red] Scan failed: {exc}")
        raise typer.Exit(2) from None


def _print_summary(console: Console, report: BuildReport, out_dir: Path) -> None:
    """Print what was published and, just as importantly, what was not."""
    table = Table(title="Advisory feed", title_justify="left", show_edge=False)
    table.add_column("Advisory", style="cyan", no_wrap=True)
    table.add_column("Package")
    table.add_column("Class")
    table.add_column("OWASP")

    for advisory in report.advisories[:20]:
        table.add_row(
            advisory.id or "",
            f"{advisory.package.ecosystem}:{advisory.package.name}",
            advisory.finding_class,
            ", ".join(advisory.owasp_mcp) or "—",
        )

    if report.advisories:
        console.print(table)
        if len(report.advisories) > 20:
            console.print(f"[dim]… and {len(report.advisories) - 20} more[/dim]")
    else:
        console.print("[yellow]No advisories generated.[/yellow]")

    console.print(
        f"\n[bold]{len(report.advisories)}[/bold] advisories written to "
        f"[cyan]{out_dir}[/cyan]"
    )
    skipped = []
    if report.skipped_no_package:
        skipped.append(
            f"{report.skipped_no_package} finding(s) on servers with no published "
            "package"
        )
    if report.merged_duplicates:
        skipped.append(
            f"{report.merged_duplicates} finding(s) merged into an existing advisory"
        )
    if report.skipped_no_server:
        skipped.append(
            f"{report.skipped_no_server} finding(s) with no matching server entry"
        )
    if report.skipped_non_advisory:
        skipped.append(
            f"{report.skipped_non_advisory} informational finding(s) that assert no "
            "vulnerability"
        )
    for line in skipped:
        console.print(f"[dim]Skipped: {line}[/dim]")


@feed_app.command("verify")
def feed_verify(
    directory: Path = typer.Argument(  # noqa: B008
        ...,
        help="Feed directory to verify (the one containing index.json).",
    ),
    key_alt: str = typer.Option(  # noqa: B008
        "cosign",
        "--key-alt",
        help="Signing backend the feed was signed with: 'cosign' or 'minisign'.",
    ),
    public_key: Path | None = typer.Option(  # noqa: B008
        None,
        "--public-key",
        help="Public key for key-based verification. Omit for cosign keyless.",
    ),
    identity: str | None = typer.Option(  # noqa: B008
        None,
        "--identity",
        help="Expected cosign certificate identity (regex). Required for keyless.",
    ),
    oidc_issuer: str | None = typer.Option(  # noqa: B008
        None,
        "--oidc-issuer",
        help="Expected cosign OIDC issuer (regex). Required for keyless.",
    ),
) -> None:
    """Re-canonicalize and verify every signature in a feed directory.

    Verifies the index signature, each advisory's signature, and that each advisory's
    recomputed canonical digest matches the one the signed index records — so an
    advisory cannot be swapped for a differently-signed forgery.

    A feed with no signatures at all is checked for integrity only, and the verdict
    says so. A feed that claims to be signed but is not still fails.
    """
    console = Console()

    if not directory.resolve().exists():
        console.print(f"[red]Error:[/red] Feed directory not found: {directory}")
        raise typer.Exit(2)

    if key_alt not in BACKENDS:
        console.print(
            f"[red]Error:[/red] Unknown backend '{key_alt}'. "
            f"Use one of: {', '.join(BACKENDS)}."
        )
        raise typer.Exit(2)

    try:
        config = SigningConfig.from_env(
            backend=key_alt,
            public_key=public_key,
            identity=identity,
            oidc_issuer=oidc_issuer,
        )
    except SigningError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None

    report = verify_feed(directory, config)

    for name in report.verified:
        console.print(f"[green]OK[/green]      {name}")
    for failure in report.failures:
        console.print(f"[red]FAILED[/red]  {failure}")

    if report.ok and not report.signed:
        console.print(
            f"\n[yellow]Integrity verified for {report.checked} artifact(s), but this "
            f"feed is unsigned.[/yellow] Every record matches the digest index.json "
            f"records, yet nothing attests to who produced it.\n"
            f"Feed: [cyan]{directory}[/cyan]"
        )
        raise typer.Exit(0)

    if report.ok:
        console.print(
            f"\n[green]All {report.checked} artifact(s) verified.[/green] "
            f"Feed: [cyan]{directory}[/cyan]"
        )
        raise typer.Exit(0)

    console.print(
        f"\n[red]{len(report.failures)} of {report.checked} artifact(s) failed "
        f"verification.[/red]"
    )
    raise typer.Exit(1)
