"""``mcp-audit vet <package>`` — pre-install verdict on a public MCP server package.

Offline by default (zero network calls for a plain ``vet``).  Reports facts
from the bundled known-server registry: verification status, known CVEs,
declared capabilities, hash pins.  No letter grades — a package's risk depends
on your deployment context.

Offline behaviour:
- Plain ``vet``: reads the bundled or user-cached registry.  No network.
- ``--online``: fetches a live verdict from ``mcp-audit.dev`` and caches it.

Exit codes:
- 0: package known, verified, no CVEs  (or unknown but ``--strict`` not set)
- 1: CVEs present **or** typosquat suspicion (or unknown + ``--strict``)
- 2: invalid / empty package name, network error that cannot fall back, etc.

Supersedes the stale ``lookup`` command on branch ``story/0016-mcp-audit-dev``
which used a different URL shape and included letter grades.  See
``docs/decisions/ADR-0003-vet-verdict.md``.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import typer
from platformdirs import user_config_dir
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from mcp_audit.cli import app
from mcp_audit.registry.loader import (
    KnownServerRegistry,
    RegistryEntry,
    levenshtein,
    load_registry,
    normalize_pypi_name,
)
from mcp_audit.verdict import (
    _REGISTRY_CONTRIBUTION_URL,
    badge_url,
    build_verdict,
    name_to_slug,
    verdict_page_url,
)

# ── Types ──────────────────────────────────────────────────────────────────────

# Use built-in X | None union syntax (Python 3.10+; project targets 3.11+).
# Typer option annotations still need Optional[] spelling for Click compat —
# use the alias below to silence UP007 while keeping Typer happy.
_StrOpt = str | None

# ── Constants ──────────────────────────────────────────────────────────────────

_VERDICT_ONLINE_BASE = "https://mcp-audit.dev/v1/verdicts"
_VERDICT_CACHE_PATH = Path(user_config_dir("mcp-audit")) / "verdict-cache.json"

# Levenshtein threshold mirrors supply_chain.py:
# short names (≤5 chars) use threshold=1; long names use threshold=3.
_TYPO_THRESHOLD_SHORT = 1
_TYPO_THRESHOLD_LONG = 3
_SHORT_NAME_LIMIT = 5


# ── Ecosystem resolution ───────────────────────────────────────────────────────


def _detect_ecosystem(name: str) -> str:
    """Heuristically determine ecosystem from the package name.

    Scoped npm names start with ``@``; all others default to ``"npm"`` and the
    pypi sub-index is also tried automatically when no ``--ecosystem`` is given.

    Args:
        name: Raw package name string.

    Returns:
        ``"npm"`` or ``"pypi"``.
    """
    return "npm" if name.startswith("@") else "npm"


def _lookup(
    name: str,
    ecosystem: str,
    registry: KnownServerRegistry,
) -> RegistryEntry | None:
    """Look up *name* in the registry for the given *ecosystem*.

    Args:
        name: Package name exactly as supplied.
        ecosystem: ``"npm"`` or ``"pypi"``.
        registry: Loaded registry instance.

    Returns:
        Matching :class:`~mcp_audit.registry.loader.RegistryEntry` or ``None``.
    """
    if ecosystem == "pypi":
        return registry.get_pypi(name)
    return registry.get_npm(name)


def _typosquat_check(
    name: str,
    ecosystem: str,
    registry: KnownServerRegistry,
) -> RegistryEntry | None:
    """Check whether *name* is a close edit-distance match to a known entry.

    Applies the same threshold logic as
    :class:`~mcp_audit.analyzers.supply_chain.SupplyChainAnalyzer`:
    threshold=1 for names ≤5 chars, threshold=3 otherwise.

    Args:
        name: Package name to check.
        ecosystem: ``"npm"`` or ``"pypi"``.
        registry: Loaded registry instance.

    Returns:
        The closest :class:`~mcp_audit.registry.loader.RegistryEntry` when a
        typosquat candidate is found, else ``None``.
    """
    check_name = normalize_pypi_name(name) if ecosystem == "pypi" else name.lower()
    threshold = (
        _TYPO_THRESHOLD_SHORT
        if len(check_name) <= _SHORT_NAME_LIMIT
        else _TYPO_THRESHOLD_LONG
    )

    if ecosystem == "pypi":
        return registry.find_closest_pypi(name, threshold=threshold)
    return registry.find_closest_npm(name, threshold=threshold)


# ── Online fetch + cache ───────────────────────────────────────────────────────


def _fetch_online_verdict(
    ecosystem: str,
    name: str,
    console: Console,
) -> dict[str, Any] | None:
    """Fetch a live verdict from mcp-audit.dev and write it to the local cache.

    Uses ``urllib.request`` only (no third-party HTTP library).  Enforces an
    ``https://`` scheme guard before opening the URL.

    The cache file is written at ``0o600`` (registry-cache pattern) so verdict
    data is not world-readable on multi-user systems.

    Args:
        ecosystem: ``"npm"`` or ``"pypi"``.
        name: Raw package name (slug conversion applied internally).
        console: Rich console for dim status messages.

    Returns:
        Parsed verdict ``dict`` on success, ``None`` on any failure (the caller
        falls back to the bundled registry).
    """
    slug = name_to_slug(name)
    url = f"{_VERDICT_ONLINE_BASE}/{ecosystem}/{slug}.json"

    # https scheme guard — never open http:// or file:// URLs.
    if not url.startswith("https://"):
        console.print(
            "[dim]Online verdict URL must use HTTPS — skipping online fetch.[/dim]"
        )
        return None

    try:
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — https:// guard above
            url,
            headers={"User-Agent": f"mcp-audit/{_ua_version()}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310  # nosec B310
            raw = resp.read().decode("utf-8")
        verdict: dict[str, Any] = json.loads(raw)
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        OSError,
    ):
        return None

    # Cache the verdict.
    _write_verdict_cache(ecosystem, name, verdict, console)
    return verdict


def _write_verdict_cache(
    ecosystem: str,
    name: str,
    verdict: dict[str, Any],
    console: Console,
) -> None:
    """Persist a fetched verdict into the local cache file at 0o600.

    Args:
        ecosystem: ``"npm"`` or ``"pypi"``.
        name: Raw package name.
        verdict: Parsed verdict dict to store.
        console: Rich console for error reporting.
    """
    cache_key = f"{ecosystem}/{name_to_slug(name)}"
    cache: dict[str, Any] = {}

    _VERDICT_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)

    if _VERDICT_CACHE_PATH.exists():
        try:
            cache = json.loads(_VERDICT_CACHE_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            cache = {}

    cache[cache_key] = verdict

    try:
        fd = os.open(
            str(_VERDICT_CACHE_PATH),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, json.dumps(cache, indent=2).encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as exc:
        console.print(f"[dim]Could not write verdict cache: {exc}[/dim]")


def _ua_version() -> str:
    """Return the mcp-audit version string for the User-Agent header."""
    try:
        from mcp_audit import __version__  # noqa: PLC0415

        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


# ── Rich output helpers ────────────────────────────────────────────────────────


def _print_known_verdict(
    verdict: dict[str, Any],
    console: Console,
) -> None:
    """Render a Rich panel for a known (listed) package.

    Args:
        verdict: Fully built verdict dict.
        console: Rich console to print to.
    """
    pkg = verdict["package"]
    reg = verdict["registry"]
    vulns = verdict["known_vulnerabilities"]
    caps = verdict["capabilities"]
    att = verdict["attestation"]
    links = verdict["links"]

    t = Text()

    verified_str = (
        "[green]Verified[/green]"
        if reg.get("verified")
        else "[yellow]Unverified[/yellow]"
    )
    listed_str = (
        "[green]Listed[/green]" if reg.get("listed") else "[red]Not listed[/red]"
    )
    maintainer = reg.get("maintainer") or "unknown"
    t.append(f"{pkg['name']}  ", style="bold")
    t.append(f"({pkg['ecosystem']})\n\n", style="dim")
    t.append_text(
        Text.from_markup(
            f"  Registry:      {listed_str} · {verified_str} · {maintainer}\n"
        )
    )
    entry_updated = reg.get("entry_updated") or "n/a"
    t.append(f"  Entry updated: {entry_updated}\n\n", style="dim")

    # Capabilities.
    if caps:
        t.append_text(Text.from_markup(f"  Capabilities:  {', '.join(caps)}\n"))
    else:
        t.append("  Capabilities:  none declared\n", style="dim")

    # Hash pins.
    hash_note = "yes" if att.get("hash_pins_available") else "no"
    t.append(f"  Hash pins:     {hash_note}\n")
    att_note = "yes" if att.get("attestation_expected") else "no"
    t.append(f"  Sigstore attestation expected: {att_note}\n\n")

    # CVEs.
    if vulns:
        t.append_text(
            Text.from_markup(
                f"  [red bold]Known vulnerabilities: {len(vulns)}[/red bold]\n\n"
            )
        )
        for v in vulns:
            cve = v.get("cve", "unknown")
            desc = v.get("description") or ""
            fixed = v.get("fixed_in")
            fixed_str = f"fixed in {fixed}" if fixed else "no fix available"
            link = v.get("link", "")
            t.append_text(Text.from_markup(f"    [red]{cve}[/red]"))
            if desc:
                short_desc = desc[:80] + ("…" if len(desc) > 80 else "")
                t.append(f" — {short_desc}")
            t.append("\n")
            t.append(f"    {fixed_str}\n", style="dim")
            if link:
                t.append(f"    {link}\n", style="dim")
            t.append("\n")
    else:
        t.append_text(
            Text.from_markup("  [green]Known vulnerabilities: none[/green]\n\n")
        )

    # Links.
    if links.get("repo"):
        t.append(f"  Repo: {links['repo']}\n", style="dim")
    t.append(f"  Verdict page: {links['verdict_page']}\n", style="dim")

    border = "red" if vulns else ("green" if reg.get("verified") else "yellow")
    console.print(Panel(t, title="[bold]mcp-audit verdict[/bold]", border_style=border))


def _print_typosquat_warning(
    name: str,
    typosquat_of: RegistryEntry,
    console: Console,
) -> None:
    """Render a typosquat warning panel.

    Args:
        name: The queried package name.
        typosquat_of: The registry entry the name closely resembles.
        console: Rich console to print to.
    """
    dist = levenshtein(name.lower(), typosquat_of.name.lower())
    t = Text()
    t.append(f"  Queried:  {name}\n", style="bold")
    t.append_text(
        Text.from_markup(
            f"  Closest:  [bold]{typosquat_of.name}[/bold]"
            f" (maintainer: {typosquat_of.maintainer},"
            f" verified: {typosquat_of.verified})\n"
        )
    )
    t.append(f"  Distance: {dist} edit(s)\n\n")
    t.append(
        "  Did you mean the known-legitimate package above?\n"
        "  Verify the name is intentional before installing.\n",
        style="yellow",
    )
    console.print(
        Panel(
            t,
            title="[bold yellow]Possible typosquat — vet exit 1[/bold yellow]",
            border_style="yellow",
        )
    )


def _print_unknown_verdict(
    name: str,
    ecosystem: str,
    entry_count: int,
    console: Console,
) -> None:
    """Render an 'unknown package' informational panel.

    The absence of a registry entry is **not** a safety signal — the registry
    covers a curated corpus, not all MCP packages.

    Args:
        name: Queried package name.
        ecosystem: ``"npm"`` or ``"pypi"``.
        entry_count: Total number of entries in the registry (for context).
        console: Rich console to print to.
    """
    t = Text()
    t.append(f"  {name}  ", style="bold")
    t.append(f"({ecosystem})\n\n", style="dim")
    t.append(
        f"  No verdict available. The registry covers {entry_count} known servers;\n"
        "  this package is not among them.\n\n"
    )
    t.append(
        "  Absence of registry data is NOT a safety signal.\n"
        "  The registry covers a curated corpus, not every MCP package.\n\n",
        style="dim",
    )
    t.append("  After installing and configuring, run:\n")
    t.append("    mcp-audit scan\n\n", style="bold")
    t.append(
        f"  Help grow the registry: {_REGISTRY_CONTRIBUTION_URL}\n",
        style="dim",
    )
    console.print(
        Panel(
            t,
            title="[bold]mcp-audit verdict — unknown package[/bold]",
            border_style="dim",
        )
    )


# ── Terminal output dispatch ───────────────────────────────────────────────────


def print_verdict(
    verdict: dict[str, Any],
    registry: KnownServerRegistry,
    typosquat_entry: RegistryEntry | None,
    console: Console,
) -> None:
    """Render the appropriate Rich terminal panel for *verdict*.

    Args:
        verdict: Fully built verdict dict.
        registry: Loaded registry (for unknown panel entry count).
        typosquat_entry: Pre-resolved :class:`~mcp_audit.registry.loader.RegistryEntry`
            for the typosquat candidate when known; ``None`` otherwise.
        console: Rich console to print to.
    """
    reg = verdict["registry"]
    typosquat_name = verdict.get("typosquat_of")

    if typosquat_name is not None:
        if typosquat_entry is not None:
            _print_typosquat_warning(
                verdict["package"]["name"], typosquat_entry, console
            )
        else:
            console.print(
                f"[yellow]Warning:[/yellow] Possible typosquat of {typosquat_name!r}"
            )
        return

    if reg.get("listed"):
        _print_known_verdict(verdict, console)
    else:
        _print_unknown_verdict(
            verdict["package"]["name"],
            verdict["package"]["ecosystem"],
            len(registry.entries),
            console,
        )


# ── Exit code logic ────────────────────────────────────────────────────────────


def _verdict_exit_code(verdict: dict[str, Any], strict: bool) -> int:
    """Map a verdict dict to the appropriate process exit code.

    Rules:
    - 0: listed in registry, no CVEs, no typosquat suspicion
    - 1: CVEs present **or** typosquat suspicion **or** (not listed + ``--strict``)

    Args:
        verdict: Fully built verdict dict.
        strict: When ``True``, unlisted packages exit 1 instead of 0.

    Returns:
        Integer exit code (0 or 1).
    """
    vulns = verdict.get("known_vulnerabilities", [])
    typosquat = verdict.get("typosquat_of")
    listed = verdict.get("registry", {}).get("listed", False)

    if vulns or typosquat:
        return 1
    if not listed and strict:
        return 1
    return 0


# ── Command ────────────────────────────────────────────────────────────────────


@app.command("vet")
def vet(
    package: str = typer.Argument(  # noqa: B008
        ...,
        help=(
            "Package name to vet (npm: '@scope/name' or 'name'; "
            "pypi: 'package-name'). Use --ecosystem to disambiguate."
        ),
    ),
    ecosystem: _StrOpt = typer.Option(  # noqa: B008
        None,
        "--ecosystem",
        "-e",
        help="Force ecosystem lookup: 'npm' or 'pypi'. Auto-detected when omitted.",
        show_default=False,
    ),
    format_flag: _StrOpt = typer.Option(  # noqa: B008
        None,
        "--format",
        "-f",
        help="Output format. 'json' emits the full verdict document.",
        show_default=False,
    ),
    badge: bool = typer.Option(  # noqa: B008
        False,
        "--badge",
        help="Print a Shields.io Markdown badge for this package and exit.",
    ),
    online: bool = typer.Option(  # noqa: B008
        False,
        "--online",
        help=(
            "Fetch a live verdict from mcp-audit.dev (HTTPS GET) and cache it. "
            "Falls back to the bundled registry on network failure."
        ),
    ),
    strict: bool = typer.Option(  # noqa: B008
        False,
        "--strict",
        help="Exit 1 when the package is not in the registry (CI mode).",
    ),
    offline_registry: bool = typer.Option(  # noqa: B008
        False,
        "--offline-registry",
        help="Use the bundled registry only, skip the user-local cache.",
    ),
) -> None:
    """Pre-install verdict on a public MCP server package.

    Reports facts from the known-server registry: verification status, known CVEs,
    declared capabilities, hash pins, and typosquat detection.  Offline by default
    — no network calls for a plain ``vet``.

    Exit codes:
    - 0: known + no CVEs + no typosquat (or unknown without --strict)
    - 1: CVEs present, typosquat suspicion, or unknown + --strict
    - 2: invalid/empty package name or unrecoverable error

    Examples::

        mcp-audit vet @modelcontextprotocol/server-filesystem
        mcp-audit vet mcp-atlassian --ecosystem pypi
        mcp-audit vet @azure/mcp --format json
        mcp-audit vet @scope/name --badge
        mcp-audit vet @scope/name --online
    """
    console = Console()

    # ── Input validation ──────────────────────────────────────────────────────
    pkg_name = package.strip() if package else ""
    if not pkg_name:
        console.print("[red]Error:[/red] Package name must not be empty.")
        raise typer.Exit(2)

    # ── Ecosystem resolution ──────────────────────────────────────────────────
    if ecosystem is not None:
        eco = ecosystem.lower()
        if eco not in ("npm", "pypi"):
            console.print(
                f"[red]Error:[/red] Unknown ecosystem {ecosystem!r}. "
                "Use 'npm' or 'pypi'."
            )
            raise typer.Exit(2)
    else:
        eco = _detect_ecosystem(pkg_name)

    # ── Badge-only output ─────────────────────────────────────────────────────
    if badge:
        url = badge_url(eco, pkg_name)
        vpage = verdict_page_url(eco, pkg_name)
        sys.stdout.write(f"[![mcp-audit verdict]({url})]({vpage})\n")
        raise typer.Exit(0)

    # ── Load registry ─────────────────────────────────────────────────────────
    try:
        registry = load_registry(offline=offline_registry)
    except FileNotFoundError as exc:
        console.print(f"[red]Registry not found:[/red] {exc}")
        raise typer.Exit(2) from None

    # ── Online mode: attempt live fetch, fall back to registry ────────────────
    if online:
        online_verdict = _fetch_online_verdict(eco, pkg_name, console)
        if online_verdict is None:
            console.print(
                "[dim]Online fetch failed or package not found on mcp-audit.dev — "
                "using bundled registry.[/dim]"
            )
        else:
            # Emit and exit.  We have no typosquat_entry for online verdicts
            # (the server computed it), so pass None.
            if format_flag == "json":
                sys.stdout.write(json.dumps(online_verdict, indent=2))
                sys.stdout.write("\n")
            else:
                print_verdict(online_verdict, registry, None, console)
            raise typer.Exit(_verdict_exit_code(online_verdict, strict))

    # ── Registry lookup ───────────────────────────────────────────────────────
    entry = _lookup(pkg_name, eco, registry)

    # If not found in the primary ecosystem and no explicit flag was given,
    # also try pypi (for plain names like "mcp-atlassian" without --ecosystem).
    if entry is None and ecosystem is None and eco == "npm":
        pypi_entry = registry.get_pypi(pkg_name)
        if pypi_entry is not None:
            entry = pypi_entry
            eco = "pypi"

    # ── Typosquat check (only for unlisted packages) ──────────────────────────
    typosquat_of: RegistryEntry | None = None
    if entry is None:
        typosquat_of = _typosquat_check(pkg_name, eco, registry)

    # ── Build verdict ─────────────────────────────────────────────────────────
    verdict = build_verdict(
        name=pkg_name,
        ecosystem=eco,
        entry=entry,
        typosquat_of=typosquat_of,
        registry=registry,
    )

    # ── Emit output ───────────────────────────────────────────────────────────
    if format_flag == "json":
        sys.stdout.write(json.dumps(verdict, indent=2))
        sys.stdout.write("\n")
    else:
        print_verdict(verdict, registry, typosquat_of, console)

    # ── Exit code ─────────────────────────────────────────────────────────────
    raise typer.Exit(_verdict_exit_code(verdict, strict))
