"""Package resolution for ``mcp-lock.json`` — thin wrappers, no new resolver.

Per STORY-0069's architectural notes, this module reuses
``vulnerability.resolver`` (the dist-tag resolver PR #96 verified) and
``attestation.hasher`` rather than the second, unverified resolver in
``fixer.strategies.pinning``.  Package *name* extraction reuses
``analyzers.supply_chain`` so the name mcp-audit locks is identical to the
name the supply-chain analyzer already uses for registry lookups —
otherwise a lock entry's ``capabilities`` could silently resolve against a
different registry entry than the one the rest of the scan sees.

Network policy: this module makes network calls only when *offline* is
``False`` and a version needs resolving.  Callers (``lock`` write path,
``lock --verify --resolve``) are responsible for deciding whether to call it
at all — ``lock --verify`` without ``--resolve`` never imports this module's
network-touching functions in the first place.
"""

from __future__ import annotations

import urllib.error
from datetime import UTC, datetime

from mcp_audit.analyzers.supply_chain import extract_npm_package, extract_pypi_package
from mcp_audit.attestation.hasher import compute_hash_from_url, resolve_npm_tarball_url
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import KnownServerRegistry
from mcp_audit.vulnerability.models import Ecosystem
from mcp_audit.vulnerability.resolver import (
    extract_ecosystem_and_version,
    is_version_range,
    resolve_latest_version,
)

_NPM_LAUNCHERS = {"npx", "bunx", "pnpx"}
_PYPI_LAUNCHERS = {"uvx", "pipx"}


def _strip_npm_version_suffix(name: str) -> str:
    """Strip a trailing ``@version`` from an npm package token.

    ``analyzers.supply_chain.extract_npm_package`` deliberately does *not*
    strip a version suffix (it is used only for typosquat detection against
    a bare package name, and its own test suite pins the un-stripped
    behaviour — see ``tests/test_supply_chain.py::TestExtractNpmPackage``).
    A lock entry's ``package.name`` must be the bare name regardless: for a
    scoped package the version sits after the *second* ``@``
    (``@scope/name@1.2.3``); for an unscoped package, after the first.
    """
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        pkg_name = rest.rsplit("@", 1)[0] if "@" in rest else rest
        return f"{scope}/{pkg_name}"
    return name.rsplit("@", 1)[0] if "@" in name else name


def extract_package_identity(server: ServerConfig) -> tuple[str, str] | None:
    """Return ``(ecosystem, name)`` for a registry-fetched launcher, or ``None``.

    Mirrors the launcher recognition in
    :func:`vulnerability.resolver.extract_ecosystem_and_version`, but never
    requires a version to already be present — a bare ``npx -y foo`` (no
    version at all) still yields ``("npm", "foo")`` here, which
    ``extract_ecosystem_and_version`` alone cannot do. The npm branch also
    strips a trailing ``@version`` (see :func:`_strip_npm_version_suffix`);
    ``extract_pypi_package`` already strips its own ``@version`` suffix, so
    the pypi branch needs no equivalent post-processing.

    Args:
        server: A parsed MCP server configuration.

    Returns:
        ``(ecosystem, name)`` where *ecosystem* is ``"npm"`` or ``"pypi"``,
        or ``None`` when the launch command is not a recognised package
        launcher (a local script, ``docker run``, a custom binary, etc.).
    """
    cmd = server.command or ""
    args = server.args or []

    if cmd == "yarn" and args and args[0] == "dlx":
        name = extract_npm_package(args[1:])
        return ("npm", _strip_npm_version_suffix(name)) if name else None
    if cmd in _NPM_LAUNCHERS:
        name = extract_npm_package(args)
        return ("npm", _strip_npm_version_suffix(name)) if name else None
    if cmd in _PYPI_LAUNCHERS:
        name = extract_pypi_package(cmd, args)
        return ("pypi", name) if name else None
    return None


def _spec_as_written(server: ServerConfig) -> str:
    """Return the literal version/range token from *server*'s args, or ``"latest"``.

    Reuses :func:`extract_ecosystem_and_version` purely for its version
    extraction (its own name extraction is ignored here — name comes from
    :func:`extract_package_identity` so it matches the supply-chain
    analyzer's registry-lookup key exactly).
    """
    extracted = extract_ecosystem_and_version(server)
    if extracted is not None:
        _, _, version = extracted
        return version
    return "latest"


def resolve_package(
    server: ServerConfig,
    *,
    offline: bool,
    registry: KnownServerRegistry | None,
    existing: dict | None = None,
) -> dict | None:
    """Build the ``package`` sub-object for one lock entry.

    Implements ADR-0005 §6 (``resolved_at`` is write-on-change, not
    write-on-run): when *existing* is supplied and the newly resolved
    version is identical to ``existing["resolved_version"]``, the entire
    *existing* sub-object is returned unchanged so a no-op re-lock never
    churns ``resolved_at``/``integrity``/``resolution.method``.

    Args:
        server: A parsed MCP server configuration.
        offline: When ``True``, never make a network call; an unpinned spec
            resolves to ``resolved_version: None, source: "unresolved"``.
        registry: The known-server registry, consulted for
            ``known_hashes`` before any network hash lookup.
        existing: The previous lock entry's ``package`` dict, if any.

    Returns:
        A dict matching :class:`~mcp_audit.lock.model.LockPackage`'s shape,
        or ``None`` when the launch command has no recognisable package
        identity (a local script, a custom launcher, ``docker run``, …) —
        callers store ``package: null`` for these; config-drift
        verification still applies via ``identity``/``env_keys``.
    """
    identity = extract_package_identity(server)
    if identity is None:
        return None
    ecosystem, name = identity
    spec = _spec_as_written(server)
    range_spec = is_version_range(spec)
    eco_enum = Ecosystem.NPM if ecosystem == "npm" else Ecosystem.PYPI

    if not range_spec and spec not in ("latest", "*"):
        resolved_version: str | None = spec
        method: str = "exact-pin"
    elif offline:
        resolved_version = None
        method = "unresolved"
    else:
        try:
            resolved_version = resolve_latest_version(eco_enum, name)
            method = "dist-tag:latest"
        except (ValueError, urllib.error.URLError, OSError):
            resolved_version = None
            method = "unresolved"

    # ── ADR-0005 §6: write-on-change only ───────────────────────────────────
    if (
        existing is not None
        and resolved_version is not None
        and existing.get("resolved_version") == resolved_version
    ):
        return existing

    now = datetime.now(UTC).isoformat()
    resolved_at: str | None
    if method == "exact-pin":
        prior = (existing or {}).get("resolution", {})
        resolved_at = prior.get("resolved_at") or now
    elif method == "unresolved":
        resolved_at = None
    else:
        resolved_at = now

    integrity: str | None = None
    source = "unresolved"
    if resolved_version is not None:
        registry_entry = registry.get(name) if registry else None
        known_hashes = registry_entry.known_hashes if registry_entry else None
        if known_hashes and resolved_version in known_hashes:
            integrity = known_hashes[resolved_version]
            source = "known_hashes"
        elif ecosystem == "npm" and not offline:
            try:
                tarball_url = resolve_npm_tarball_url(name, resolved_version)
                integrity = compute_hash_from_url(tarball_url)
                source = "registry"
            except (urllib.error.URLError, OSError):
                source = "registry"
        else:
            source = "registry"

    return {
        "ecosystem": ecosystem,
        "name": name,
        "spec_as_written": spec,
        "range_spec": range_spec,
        "resolved_version": resolved_version,
        "resolution": {"method": method, "resolved_at": resolved_at},
        "integrity": integrity,
        "source": source,
    }
