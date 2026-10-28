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

import http.client
import urllib.error
from datetime import UTC, datetime

from mcp_audit.analyzers.supply_chain import (
    extract_npm_package,
    extract_pypi_package,
    strip_npm_version_suffix,
)
from mcp_audit.attestation.hasher import compute_hash_from_url, resolve_npm_tarball_url
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import KnownServerRegistry
from mcp_audit.vulnerability.models import Ecosystem
from mcp_audit.vulnerability.resolver import (
    extract_ecosystem_and_version,
    extract_package,
    is_version_range,
    resolve_latest_version_info,
)

#: ``spec_as_written`` for a launch that names a package and no version
#: (``npx -y foo``, ``uvx pkg``, ``foo@``). npm-package-arg reads a bare name
#: as the range ``*`` (``lib/npa.js``, v14.0.0: ``spec = '*'``), not as the
#: ``latest`` tag; lock_version 1 wrote ``"latest"`` here (STORY-0116).
BARE_SPEC = "*"

#: Longest registry deprecation notice copied into ``resolution_context``
#: (``package.deprecated`` keeps version 1's full text, unchanged).
MAX_CONTEXT_NOTICE = 1024

_NPM_LAUNCHERS = {"npx", "bunx", "pnpx"}
_PYPI_LAUNCHERS = {"uvx", "pipx"}


def _strip_npm_version_suffix(name: str) -> str:
    """Strip a trailing ``@version`` from an npm package token.

    Thin alias for :func:`mcp_audit.analyzers.supply_chain.strip_npm_version_suffix`
    (moved there in STORY-0078 so the supply-chain analyzer's registry lookup
    and the lock agree on what a bare npm name is).
    """
    return strip_npm_version_suffix(name)


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
    """Return the version/range token from *server*'s args as ``lock`` records it.

    Reuses :func:`extract_ecosystem_and_version` purely for its version
    extraction (its own name extraction is ignored here — name comes from
    :func:`extract_package_identity` so it matches the supply-chain
    analyzer's registry-lookup key exactly). That reading is unchanged from
    lock_version 1, so every spec it already read is recorded and resolved
    exactly as before.

    lock_version 2 changes one case: a launch that names the package with no
    version at all is recorded as :data:`BARE_SPEC` (``"*"``) instead of
    ``"latest"``; ``foo@latest`` stays ``"latest"``. "Bare" is decided by the
    lookup reading (:func:`extract_package`): no version, and the package
    name it sees is the same name ``lock`` locks. Every other launch this
    reading cannot parse (``uvx pkg==1.2.3``, ``uvx pkg>=1``, ``pipx run
    pkg==1.0``) keeps lock_version 1's ``"latest"``: reading it as a pin
    would change its resolved version, which a version-1 lock would then
    report as LOCK-004 under ``--resolve`` on an untouched config.
    """
    extracted = extract_ecosystem_and_version(server)
    if extracted is not None:
        _, _, version = extracted
        return version
    identity = extract_package_identity(server)
    looked_up = extract_package(server, for_lookup=True)
    if (
        identity is not None
        and looked_up is not None
        and looked_up[2] is None
        and looked_up[1] == identity[1]
    ):
        return BARE_SPEC
    return "latest"


def _resolution_context(
    method: str, resolved_at: str | None, latest: str | None, deprecated: str | None
) -> dict | None:
    """Return ``resolution.resolution_context`` (lock_version 2).

    An object only when the registry was consulted (``dist-tag:latest``):
    then ``latest`` is the version the registry's ``latest`` pointed at and
    ``latest_deprecated`` its deprecation notice, as seen at *resolved_at*.
    ``npm_major`` and ``node_version`` stay ``None``: mcp-audit reads the
    dist-tag over HTTPS and runs neither npm nor Node, so neither shaped
    this resolution. ``None`` for an exact pin or an unresolved entry.
    """
    if method != "dist-tag:latest":
        return None
    if deprecated is not None and len(deprecated) > MAX_CONTEXT_NOTICE:
        deprecated = deprecated[:MAX_CONTEXT_NOTICE] + "…"
    return {
        "resolved_at": resolved_at,
        "latest": latest,
        "latest_deprecated": deprecated,
        "npm_major": None,
        "node_version": None,
    }


def _is_current_shape(existing: dict, spec: str, range_spec: bool) -> bool:
    """Whether a reused *existing* package already has lock_version 2's shape."""
    resolution = existing.get("resolution")
    return (
        isinstance(resolution, dict)
        and "resolution_context" in resolution
        and existing.get("spec_as_written") == spec
        and existing.get("range_spec") == range_spec
    )


def _upgrade(existing: dict, spec: str, range_spec: bool) -> dict:
    """Bring a reused version-1 *existing* package to lock_version 2's shape.

    Called only when the version (and deprecation) just resolved equal what
    *existing* records, so its ``resolved_at`` and ``integrity`` stay: the
    first re-lock after upgrading adds keys and never churns a timestamp.
    """
    upgraded = dict(existing)
    resolution = dict(existing.get("resolution") or {})
    method = str(resolution.get("method", ""))
    resolution["resolution_context"] = _resolution_context(
        method,
        resolution.get("resolved_at"),
        existing.get("resolved_version"),
        existing.get("deprecated"),
    )
    upgraded["resolution"] = resolution
    upgraded["spec_as_written"] = spec
    upgraded["range_spec"] = range_spec
    return upgraded


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
        verification still applies via ``identity``/``env_keys``. The
        ``deprecated`` key is populated only when *offline* is ``False``
        and the spec required a ``dist-tag:latest`` network resolution
        (STORY-0073/R58) — ``None`` for an exact pin or an unresolved entry.
    """
    identity = extract_package_identity(server)
    if identity is None:
        return None
    ecosystem, name = identity
    spec = _spec_as_written(server)
    range_spec = is_version_range(spec)
    eco_enum = Ecosystem.NPM if ecosystem == "npm" else Ecosystem.PYPI

    deprecated: str | None = None
    if not range_spec and spec not in ("latest", BARE_SPEC):
        resolved_version: str | None = spec
        method: str = "exact-pin"
    elif offline:
        resolved_version = None
        method = "unresolved"
    else:
        try:
            resolved_version, deprecated = resolve_latest_version_info(eco_enum, name)
            method = "dist-tag:latest"
        except (
            ValueError,
            urllib.error.URLError,
            OSError,
            http.client.HTTPException,
            RecursionError,
        ):
            resolved_version = None
            method = "unresolved"

    # ── ADR-0005 §6: write-on-change only ───────────────────────────────────
    # Also requires `deprecated` to be unchanged: a package going deprecated
    # in place (no version bump) is itself a real change worth re-recording
    # and re-emitting SC-005 for — STORY-0073/R58 — not something write-on-change
    # should silently suppress by returning the stale cached sub-object.
    if (
        existing is not None
        and resolved_version is not None
        and existing.get("resolved_version") == resolved_version
        and existing.get("deprecated") == deprecated
    ):
        if _is_current_shape(existing, spec, range_spec):
            return existing
        return _upgrade(existing, spec, range_spec)

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
        "resolution": {
            "method": method,
            "resolved_at": resolved_at,
            "resolution_context": _resolution_context(
                method, resolved_at, resolved_version, deprecated
            ),
        },
        "integrity": integrity,
        "source": source,
        "deprecated": deprecated,
    }
