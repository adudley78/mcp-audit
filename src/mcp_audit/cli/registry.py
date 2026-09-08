"""update-registry and verify commands."""

from __future__ import annotations

import contextlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.table import Table

from mcp_audit import cli as _cli
from mcp_audit.cli import app, console
from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry

# ── update-registry ───────────────────────────────────────────────────────────


def _validate_registry_payload(data: dict) -> None:
    """Refuse a registry payload that the loader would later reject.

    R45: ``update_registry`` used to accept anything with an ``entries``
    list, so a bad upstream push (or a manual edit) could cache a file
    guaranteed to crash the *next* scan/vet/fix/shadow/check with a
    ``RegistryLoadError`` — the corrupt file just sat there until a human
    found and deleted it. This runs the exact same checks
    :class:`~mcp_audit.registry.loader.KnownServerRegistry` performs at load
    time — Pydantic validation via :class:`RegistryEntry`, then
    :meth:`KnownServerRegistry._build_name_index` for the duplicate-name
    rule — *before* anything touches disk, by reusing those two pieces
    directly rather than forking a second copy of either check (the DO NOT
    that follows from R43's own postmortem: two copies of the same rule is
    how they drift).

    Args:
        data: Parsed JSON payload (already confirmed to be a dict with a list
            ``entries`` key by the caller).

    Raises:
        typer.Exit: With code 2 and a human-readable message naming the
            offending entries, if the payload fails Pydantic validation or
            contains a duplicate (case-insensitive) entry name.
    """
    try:
        entries = [RegistryEntry.model_validate(e) for e in data["entries"]]
    except ValidationError as exc:
        console.print(
            "[red]Refusing to cache: downloaded registry has invalid entry "
            f"data and would fail to load on the next scan:[/red]\n{exc}"
        )
        raise typer.Exit(2) from exc

    try:
        KnownServerRegistry._build_name_index(entries)  # noqa: SLF001
    except ValueError as exc:
        console.print(
            "[red]Refusing to cache: downloaded registry has a duplicate "
            f"entry name and would fail to load on the next scan:[/red]\n{exc}"
        )
        raise typer.Exit(2) from exc


def _write_registry_cache_atomic(path: Path, raw: str) -> None:
    """Write *raw* to *path* atomically: temp file, fsync, then ``os.replace``.

    R45: the previous implementation opened *path* directly with
    ``O_TRUNC`` and wrote into it in place. Interrupting that write (Ctrl-C,
    a laptop lid closing, a stalled read) left a truncated or half-written
    cache file at the real destination — the exact "truncated cache" shape
    reproduced in this PR's tests. Writing to a same-directory temp file
    first and only replacing the destination via ``os.replace()`` (atomic on
    both POSIX and Windows) means an interrupt anywhere before the final
    replace leaves the *old* cache (or no cache) in place, never a partial
    new one; an interrupt can never land "in between" because there is no
    step that mutates *path* except the single atomic replace.

    The temp file is created directly at mode 0o600 via the ``os.open``
    mode argument (never a ``chmod`` after the fact — CLAUDE.md's own
    invariant is that a sensitive file must never be briefly
    world-readable), and ``os.replace`` preserves the temp file's own mode
    across the rename, so the destination is 0o600 immediately, with no
    window where it is not.

    Args:
        path: Final destination path (the registry cache file).
        raw: Exact bytes (as ``str``) to write — the downloaded registry JSON
            verbatim, unmodified, so the cached file is byte-identical to
            what was validated.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp_path), str(path))
    except BaseException:
        # Best-effort cleanup of the temp file on any failure (including a
        # KeyboardInterrupt landing mid-write) — the destination is
        # untouched either way, since only the line above ever mutates it.
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise


@app.command(name="update-registry")
def update_registry() -> None:
    """Fetch the latest known-server registry from the upstream repository.

    Saves the registry to the platform user config directory under
    ``mcp-audit/registry/known-servers.json`` (path resolved via ``platformdirs``).
    On the next scan the updated registry is used automatically.

    The write is atomic (temp file + ``os.replace``, see
    :func:`_write_registry_cache_atomic`) and the payload is validated the
    same way :class:`~mcp_audit.registry.loader.KnownServerRegistry` will
    later load it (see :func:`_validate_registry_payload`) before anything
    is written — a registry that cannot be loaded never reaches the cache.
    """
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

    # Refuse to cache anything the loader would later reject (STEP 3).
    _validate_registry_payload(data)

    # Security: 0o700 directory, 0o600 file — registry cache may contain
    # proprietary server metadata; restrict to the owning user only.
    # Write is atomic (STEP 2): see _write_registry_cache_atomic.
    try:
        _write_registry_cache_atomic(_cli._REGISTRY_CACHE_PATH, raw)
    except OSError as exc:
        console.print(f"[red]Error writing registry cache: {exc}[/red]")
        raise typer.Exit(2) from exc

    count = data.get("entry_count", len(data["entries"]))
    version_str = data.get("schema_version", "unknown")
    last_updated = data.get("last_updated", "unknown")

    console.print(
        f"[green]Registry updated:[/green] {count} entries, "
        f"version {version_str}, last updated {last_updated}"
    )


# ── verify ────────────────────────────────────────────────────────────────────


def _arg_is_config_path(arg: str) -> bool:
    """Return True when *arg* should be treated as a config file path.

    Filesystem-path indicators (any of these → config path):
    - The path already exists on disk.
    - Starts with ``/`` or ``.`` (absolute or relative path prefix).
    - Ends with ``.json``.
    - Contains a ``\\`` (Windows path separator).

    Exclusions — these are unambiguously package names, not paths:
    - Starts with ``@`` (NPM scoped package, e.g. ``@scope/server-name``).
    """
    if arg.startswith("@"):
        return False  # NPM scoped package name
    if Path(arg).exists():
        return True
    return (
        arg.startswith("/")
        or arg.startswith(".")
        or arg.endswith(".json")
        or "\\" in arg
    )


@app.command()
def verify(
    server_name: str | None = typer.Argument(  # noqa: B008
        None,
        help=(
            "Registry package name (e.g. @scope/server-name) "
            "OR a config file path to verify all servers in that config."
        ),
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

    SERVER_NAME can be either a registry package name (e.g. ``@scope/pkg``)
    or a path to an MCP config file.  When a config file is given every server
    in that config is looked up against the registry; servers with pinned hashes
    are downloaded and verified, others are shown as UNKNOWN or NOT IN REGISTRY.

    Downloads each package tarball, computes SHA-256, and compares against the
    pinned hash stored in the known-server registry.  Requires network access.

    Exit codes: 0 = all pass or unknown, 1 = hash mismatch detected, 2 = error.
    This command is free (Community tier) — verification is never paywalled.
    """
    import contextlib  # noqa: PLC0415

    from mcp_audit.attestation.hasher import verify_package_hash  # noqa: PLC0415
    from mcp_audit.attestation.verifier import (
        extract_version_from_server,  # noqa: PLC0415
    )
    from mcp_audit.discovery import DiscoveredConfig  # noqa: PLC0415
    from mcp_audit.registry.loader import KnownServerRegistry  # noqa: PLC0415

    if not server_name and not all_servers:
        console.print(
            "[red]Provide a SERVER_NAME or config path, or use --all to verify "
            "all configured servers.[/red]"
        )
        raise typer.Exit(2)  # noqa: B904

    try:
        reg = KnownServerRegistry(path=registry)
    except FileNotFoundError as exc:
        console.print(f"[red]Registry not found:[/red] {exc}")
        raise typer.Exit(2)  # noqa: B904

    # ── Determine mode ────────────────────────────────────────────────────────
    config_mode = server_name is not None and _arg_is_config_path(server_name)

    # ── Build the list of (package_name, version) to verify ───────────────────
    targets: list[tuple[str, str | None]] = []

    # Rows to show in the table for servers that don't need hash downloads.
    # Each entry: (name, version_str, status_markup)
    pre_rows: list[tuple[str, str, str]] = []

    if config_mode:
        # ── Config-file mode: verify every server in the specified config ──────
        assert server_name is not None
        config_p = Path(server_name).resolve()
        if not config_p.exists():
            console.print(f"[red]Error:[/red] Config file not found: {server_name}")
            raise typer.Exit(2)  # noqa: B904

        discovered = DiscoveredConfig(
            client_name="cli-verify",
            root_key="mcpServers",
            path=config_p,
        )
        servers: list = []
        with contextlib.suppress(ValueError):
            servers = _cli.parse_config(discovered)

        if not servers:
            console.print(f"[yellow]No MCP servers found in {server_name}[/yellow]")
            raise typer.Exit(0)  # noqa: B904

        for srv in servers:
            entry = reg.get(srv.name)
            if entry is None:
                pre_rows.append((srv.name, "—", "[yellow]~ NOT IN REGISTRY[/yellow]"))
                continue
            if not entry.known_hashes:
                pre_rows.append((srv.name, "—", "[yellow]~ NO HASHES PINNED[/yellow]"))
                continue
            version = extract_version_from_server(srv)
            if version and version in entry.known_hashes:
                targets.append((entry.name, version))
            else:
                pre_rows.append(
                    (srv.name, version or "?", "[yellow]~ UNKNOWN VERSION[/yellow]")
                )

    elif server_name:
        # ── Package-name mode: verify a single named package ──────────────────
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
        # ── --all mode: discover configured servers, cross-reference registry ──
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
    title = (
        "[bold]Config Verification[/bold]"
        if config_mode
        else "[bold]Package Hash Verification[/bold]"
    )
    table = Table(
        "Server",
        "Version",
        "Expected Hash",
        "Computed Hash",
        "Status",
        title=title,
        show_lines=True,
    )

    # Emit pre-built rows first (no-hash-download entries from config mode).
    for name, ver, status in pre_rows:
        table.add_row(name, ver, "—", "—", status)

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
