"""mcp-audit advise / feed verify — publish and verify the MCP advisory feed.

``advise`` runs a scan, converts the findings into OSV-compatible advisory records,
writes them to a feed directory, and signs them. ``feed verify`` re-canonicalizes an
existing feed and checks every signature.

EXPERIMENTAL: the advisory record **format** is not yet stable — fields may be added,
renamed, or reshaped, and existing records are not guaranteed to be byte-stable across
that change. Do not build automation that depends on the exact shape of a record
today. Signing is no longer experimental: mcp-audit's own published feed is signed
with a minisign project key (see ``docs/advisory-feed.md``, "Key custody and
rotation"), and ``feed verify --key-alt minisign`` resolves the bundled public key
(``keys/mcp-audit-feed.pub``) by default when neither ``--public-key`` nor
``$MCP_AUDIT_SIGNING_PUBKEY`` is given.

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
from mcp_audit.advisory.freshness import DEFAULT_TTL_DAYS, FreshnessError
from mcp_audit.advisory.sign import (
    BACKEND_MINISIGN,
    BACKENDS,
    ENV_PUBLIC_KEY,
    SigningConfig,
    SigningError,
    bundled_public_key_path,
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


def _resolve_timestamp(value: str, *, flag: str) -> str:
    """Parse an RFC 3339 UTC timestamp from a CLI flag."""
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise typer.BadParameter(
            f"{flag} must look like 2026-07-30T12:00:00Z ({exc})"
        ) from exc
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_now(published_at: str | None) -> str:
    """Return the RFC 3339 timestamp stamped on every advisory in this run.

    Precedence: explicit ``--published-at``, then ``SOURCE_DATE_EPOCH``, then now.

    Raises:
        typer.Exit: The supplied value is not a valid timestamp.
    """
    if published_at is not None:
        return _resolve_timestamp(published_at, flag="--published-at")

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
    snapshot_version: int | None = typer.Option(  # noqa: B008
        None,
        "--snapshot-version",
        help=(
            "Monotonic snapshot counter written on index.json. Required with "
            "--sign unless --previous-index is given."
        ),
    ),
    previous_index: Path | None = typer.Option(  # noqa: B008
        None,
        "--previous-index",
        help="Previous index.json; next snapshot_version is previous + 1.",
    ),
    expires: str | None = typer.Option(  # noqa: B008
        None,
        "--expires",
        help=(
            "RFC 3339 expiry (YYYY-MM-DDTHH:MM:SSZ) written on index.json. "
            "Default is published_at plus --ttl-days."
        ),
    ),
    ttl_days: int = typer.Option(  # noqa: B008
        DEFAULT_TTL_DAYS,
        "--ttl-days",
        help="Days until the feed expires, used when --expires is omitted.",
    ),
    offline: bool = typer.Option(  # noqa: B008
        False,
        "--offline",
        help="Fail rather than make any network call during the scan.",
    ),
) -> None:
    """Scan TARGET and publish signed, OSV-compatible advisories to ./feed.

    EXPERIMENTAL: the record format is not yet stable. Expect breaking changes before
    this ships as a first-class, byte-stable feed. --sign always requires a key you
    supply via --key or $MCP_AUDIT_SIGNING_KEY — mcp-audit's own published feed is
    signed in CI with a project key that never leaves the `feed-signing` GitHub
    environment; this command has no way to reach it and does not need to.

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
    expires_at = _resolve_timestamp(expires, flag="--expires") if expires else None

    if previous_index is not None and not previous_index.resolve().is_file():
        console.print(f"[red]Error:[/red] Previous index not found: {previous_index}")
        raise typer.Exit(2)

    result = _load_scan(console, target, input_scan, offline=offline)

    report = build_advisories(
        result,
        now=now,
        min_severity=min_severity,
        only_observation=None if observation == "all" else observation,
    )

    try:
        manifest = write_feed(
            report.advisories,
            out_dir,
            published_at=now,
            snapshot_version=snapshot_version,
            expires=expires_at,
            previous_index=previous_index.resolve() if previous_index else None,
            ttl_days=ttl_days,
            require_snapshot_version=sign,
        )
    except FreshnessError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None

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
    now: str | None = typer.Option(  # noqa: B008
        None,
        "--now",
        hidden=True,
        help="Override current UTC time (tests only).",
    ),
) -> None:
    """Re-canonicalize and verify every signature in a feed directory.

    EXPERIMENTAL: the advisory record *format* this verifies against is not yet
    stable. Expect breaking changes before this ships as a first-class, byte-stable
    feed. Signing itself is not experimental: mcp-audit's own published feed is signed
    with a minisign project key (docs/advisory-feed.md, "Key custody and rotation").

    Verifies the index signature, each advisory's signature, and that each advisory's
    recomputed canonical digest matches the one the signed index records — so an
    advisory cannot be swapped for a differently-signed forgery.

    A feed with no signatures at all is checked for integrity only, and the verdict
    says so. A feed that claims to be signed but is not still fails.

    For --key-alt minisign, --public-key defaults to mcp-audit's own bundled project
    key (keys/mcp-audit-feed.pub) when neither --public-key nor
    $MCP_AUDIT_SIGNING_PUBKEY is given — verifying mcp-audit's own published feed then
    needs no extra flag. An explicit --public-key or $MCP_AUDIT_SIGNING_PUBKEY always
    wins over this default, and it never applies to cosign or keyless verification,
    which pin identity through their own key path or --identity/--oidc-issuer.
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

    used_bundled_key = False
    if (
        key_alt == BACKEND_MINISIGN
        and public_key is None
        and not os.environ.get(ENV_PUBLIC_KEY)
    ):
        bundled = bundled_public_key_path()
        if bundled is not None:
            public_key = bundled
            used_bundled_key = True

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

    if used_bundled_key:
        console.print(
            f"[dim]No --public-key given; using mcp-audit's bundled project key "
            f"({config.public_key}).[/dim]"
        )

    clock = datetime.now(UTC)
    if now is not None:
        clock = datetime.strptime(
            _resolve_timestamp(now, flag="--now"), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)

    report = verify_feed(directory, config, now=clock)

    for name in report.verified:
        console.print(f"[green]OK[/green]      {name}")
    for failure in report.failures:
        console.print(f"[red]FAILED[/red]  {failure}")

    published_line = ""
    if report.published_at is not None and report.age_days is not None:
        published_line = (
            f"Verified. Published {report.published_at[:10]}, "
            f"{report.age_days} days old."
        )

    if report.ok and not report.signed:
        console.print(
            f"\n[yellow]Integrity verified for {report.checked} artifact(s), but this "
            f"feed is unsigned.[/yellow] Every record matches the digest index.json "
            f"records, yet nothing attests to who produced it.\n"
            f"Feed: [cyan]{directory}[/cyan]"
        )
        if published_line:
            console.print(published_line)
        raise typer.Exit(0)

    if report.ok:
        console.print(
            f"\n[green]All {report.checked} artifact(s) verified.[/green] "
            f"Feed: [cyan]{directory}[/cyan]"
        )
        if published_line:
            console.print(published_line)
        raise typer.Exit(0)

    console.print(
        f"\n[red]{len(report.failures)} of {report.checked} artifact(s) failed "
        f"verification.[/red]"
    )
    raise typer.Exit(1)
