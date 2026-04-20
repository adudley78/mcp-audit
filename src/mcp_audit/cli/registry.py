"""update-registry and verify commands."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import typer
from rich.table import Table

from mcp_audit import cli as _cli
from mcp_audit._gate import gate
from mcp_audit.cli import app, console

# ── update-registry ───────────────────────────────────────────────────────────


@app.command(name="update-registry")
def update_registry() -> None:
    """Fetch the latest known-server registry from the upstream repository.

    Saves the registry to the platform user config directory under
    ``mcp-audit/registry/known-servers.json`` (path resolved via ``platformdirs``).
    On the next scan the updated registry is used automatically.

    Requires a Pro or Enterprise license.
    """
    if not gate("update_registry", console):
        raise typer.Exit(0)  # noqa: B904

    console.print(f"[dim]Fetching registry from {_cli._UPDATE_REGISTRY_URL}…[/dim]")

    try:
        with urllib.request.urlopen(_cli._UPDATE_REGISTRY_URL, timeout=30) as resp:  # noqa: S310  # nosec B310 -- _UPDATE_REGISTRY_URL is a hardcoded https://raw.githubusercontent.com/ constant
            raw = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        console.print(f"[red]Network error fetching registry: {exc}[/red]")
        raise typer.Exit(2)  # noqa: B904

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON in downloaded registry: {exc}[/red]")
        raise typer.Exit(2)  # noqa: B904

    if "entries" not in data or not isinstance(data.get("entries"), list):
        console.print(
            "[red]Malformed registry: missing or invalid 'entries' key.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    # Security: 0o700 directory, 0o600 file — registry cache may contain
    # proprietary server metadata; restrict to the owning user only.
    _cli._REGISTRY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import os as _os  # noqa: PLC0415

    _reg_fd = _os.open(
        str(_cli._REGISTRY_CACHE_PATH),
        _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC,
        0o600,
    )
    with _os.fdopen(_reg_fd, "w", encoding="utf-8") as _reg_fh:
        _reg_fh.write(raw)

    count = data.get("entry_count", len(data["entries"]))
    version_str = data.get("schema_version", "unknown")
    last_updated = data.get("last_updated", "unknown")

    console.print(
        f"[green]Registry updated:[/green] {count} entries, "
        f"version {version_str}, last updated {last_updated}"
    )


# ── verify ────────────────────────────────────────────────────────────────────


@app.command()
def verify(
    server_name: str | None = typer.Argument(  # noqa: B008
        None, help="Registry package name to verify (e.g. @scope/server-name)"
    ),
    all_servers: bool = typer.Option(  # noqa: B008
        False,
        "--all",
        help="Verify all configured servers that have pinned hashes in the registry",
    ),
    registry: Path | None = typer.Option(  # noqa: B008
        None,
        "--registry",
        help="Custom registry file path (overrides user cache and bundled registry)",
    ),
) -> None:
    """Verify package integrity by comparing hashes against registry pins.

    Downloads each package tarball, computes SHA-256, and compares against the
    pinned hash stored in the known-server registry.  Requires network access.

    Exit codes: 0 = all pass or unknown, 1 = hash mismatch detected, 2 = error.
    This command is free (Community tier) — verification is never paywalled.
    """
    from mcp_audit.attestation.hasher import verify_package_hash  # noqa: PLC0415
    from mcp_audit.attestation.verifier import (
        extract_version_from_server,  # noqa: PLC0415
    )
    from mcp_audit.registry.loader import KnownServerRegistry  # noqa: PLC0415

    if not server_name and not all_servers:
        console.print(
            "[red]Provide a SERVER_NAME argument or use --all to verify all "
            "configured servers.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    try:
        reg = KnownServerRegistry(path=registry)
    except FileNotFoundError as exc:
        console.print(f"[red]Registry not found:[/red] {exc}")
        raise typer.Exit(2)  # noqa: B904

    # ── Build the list of (package_name, version, source) to verify ───────────
    targets: list[tuple[str, str | None]] = []  # (package_name, version_or_None)

    if server_name:
        entry = reg.get(server_name)
        if entry is None:
            console.print(
                f"[yellow]{server_name!r} is not in the registry.[/yellow]  "
                "Only known-legitimate packages can be verified."
            )
            raise typer.Exit(0)  # noqa: B904
        if not entry.known_hashes:
            console.print(
                f"[yellow]No hashes pinned for {server_name!r} "
                "in the registry.[/yellow]"
            )
            raise typer.Exit(0)  # noqa: B904
        # Verify all pinned versions for the named package.
        for version in entry.known_hashes:
            targets.append((entry.name, version))
    else:
        # --all: discover configured servers, cross-reference with registry.
        import contextlib  # noqa: PLC0415

        configs = _cli.discover_configs()
        all_srv: list = []
        for config in configs:
            with contextlib.suppress(ValueError):
                all_srv.extend(_cli.parse_config(config))

        for srv in all_srv:
            entry = reg.get(srv.name)
            if entry is None or not entry.known_hashes:
                continue
            version = extract_version_from_server(srv)
            if version and version in entry.known_hashes:
                targets.append((entry.name, version))

        if not targets:
            console.print(
                "[yellow]No configured servers have pinned hashes "
                "in the registry.[/yellow]"
            )
            raise typer.Exit(0)  # noqa: B904

    # ── Run verifications ──────────────────────────────────────────────────────
    table = Table(
        "Server",
        "Version",
        "Expected Hash",
        "Computed Hash",
        "Status",
        title="[bold]Package Hash Verification[/bold]",
        show_lines=True,
    )

    any_fail = False

    for package_name, version in targets:
        entry = reg.get(package_name)
        if entry is None:
            continue

        if version is None:
            table.add_row(package_name, "?", "—", "—", "[yellow]~ UNKNOWN[/yellow]")
            continue

        expected = entry.known_hashes.get(version) if entry.known_hashes else None
        if expected is None:
            table.add_row(package_name, version, "—", "—", "[yellow]~ UNKNOWN[/yellow]")
            continue

        console.print(f"[dim]Downloading {package_name}@{version}…[/dim]")
        result = verify_package_hash(
            package_name=package_name,
            version=version,
            source=entry.source,
            expected_hash=expected,
        )

        exp_short = expected[7:15] + "…" if len(expected) > 15 else expected
        computed_short = (
            result.computed_hash[7:15] + "…"
            if result.computed_hash and len(result.computed_hash) > 15
            else (result.computed_hash or "—")
        )

        if result.match is True:
            status = "[green]✓ PASS[/green]"
        elif result.match is False:
            status = "[red bold]✗ FAIL[/red bold]"
            any_fail = True
        else:
            status = "[yellow]~ UNKNOWN[/yellow]"

        table.add_row(package_name, version, exp_short, computed_short, status)

    console.print(table)

    if any_fail:
        console.print(
            "\n[red bold]⚠ Hash mismatch detected.[/red bold]  "
            "One or more packages may have been tampered with."
        )
        raise typer.Exit(1)  # noqa: B904
