"""Known-server registry: load, query, and typosquat-check MCP package names.

The registry is a versioned JSON dataset of legitimate MCP servers that the
supply chain analyzer queries instead of a hardcoded package list.

Resolution order when locating the registry file:
  1. Caller-supplied ``path`` argument (explicit override).
  2. User-cached registry: ``<user-config-dir>/mcp-audit/registry/known-servers.json``
     (written by ``mcp-audit update-registry``; path resolved via ``platformdirs``).
  3. PyInstaller frozen binary: resolved from ``sys._MEIPASS/registry/``.
  4. importlib.resources (pip-installed wheel at
     ``mcp_audit/registry/known-servers.json``).
  5. Dev / editable install fallback: repo-root ``registry/known-servers.json``.

Research basis: Levenshtein edit distance for typosquatting detection.
Ref: "Typosquatting in Package Managers" — Vu et al., NDSS 2021
  https://www.ndss-symposium.org/ndss-paper/detecting-node-js-package-name-squatting/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from platformdirs import user_config_dir
from pydantic import BaseModel

# ── Constants ──────────────────────────────────────────────────────────────────

_USER_CACHE_PATH = (
    Path(user_config_dir("mcp-audit")) / "registry" / "known-servers.json"
)


def _resolve_bundled_path() -> Path:
    """Locate the bundled ``known-servers.json`` regardless of execution context.

    Resolution order (delegated to :func:`~mcp_audit._paths.resolve_bundled_resource`):

    1. PyInstaller frozen binary (``sys._MEIPASS/registry/known-servers.json``).
    2. importlib.resources (pip-installed wheel at
       ``mcp_audit/registry/known-servers.json``).
    3. Dev / editable install fallback (repo-root
       ``registry/known-servers.json``).

    Returns:
        Path to the bundled registry file.  The path may not exist if the
        package was installed without the registry file (e.g. a bare source
        checkout without running the package install).
    """
    from mcp_audit._paths import resolve_bundled_resource  # noqa: PLC0415

    _dev_fallback = (
        Path(__file__).parent.parent.parent.parent / "registry" / "known-servers.json"
    )
    result = resolve_bundled_resource(
        package="mcp_audit.registry",
        subdir="known-servers.json",
        frozen_subpath="registry/known-servers.json",
        dev_fallback=_dev_fallback,
    )
    return result if result is not None else _dev_fallback


BUNDLED_REGISTRY_PATH: Path = _resolve_bundled_path()


# ── Data models ────────────────────────────────────────────────────────────────


class RegistryEntry(BaseModel):
    """A single entry in the known-server registry."""

    name: str
    source: Literal["npm", "pip", "github", "docker"]
    repo: str | None
    maintainer: str
    verified: bool
    last_verified: str
    known_versions: list[str]
    tags: list[str]

    # Hash-based integrity pinning (Layer 1 supply chain attestation).
    # key = version string (e.g. "0.6.2")
    # value = "sha256:<hex>"
    # None means no hashes have been pinned for this entry yet.
    known_hashes: dict[str, str] | None = None

    # Coarse-grained capability labels consumed by the toxic-flow analyzer
    # (e.g. ["file_read", "file_write", "network_out"]).  ``None`` means the
    # registry has no capability data for this entry and the toxic-flow
    # analyzer should fall back to its keyword-matching logic.
    capabilities: list[str] | None = None

    # Supply chain risk metadata — populated manually or via scripts/enrich_registry.py.
    # None means data has not been collected for this entry yet.

    # ISO date string (YYYY-MM-DD) when the package was first published to npm/PyPI.
    # A very recent first-publish date on an otherwise unknown package is a risk signal.
    first_published: str | None = None

    # Weekly download count sourced from npm or PyPI at last_verified time.
    # Very low download counts on a package claiming to be widely-used is a risk signal.
    weekly_downloads: int | None = None

    # Ordered list of publisher account names that have released this package,
    # most recent first. A new unknown publisher displacing the original is a
    # risk signal for an account-takeover supply chain attack.
    publisher_history: list[str] | None = None


# ── Registry class ─────────────────────────────────────────────────────────────


class KnownServerRegistry:
    """An in-memory snapshot of the known-server registry.

    Attributes:
        entries: All parsed registry entries.
        schema_version: Registry schema version string.
        last_updated: ISO date string of the last registry update.
    """

    def __init__(self, path: Path | None = None, offline: bool = False) -> None:
        """Load the registry from *path*, user cache, or bundled fallback.

        Args:
            path: Explicit path to a registry JSON file.  When ``None``, the
                loader tries the user cache then the bundled registry.
            offline: When ``True``, skip the user-local cache at
                ``<user-config-dir>/mcp-audit/registry/known-servers.json`` and load
                directly from the bundled registry.  Equivalent to passing
                ``path=BUNDLED_REGISTRY_PATH`` but does not override an
                explicit *path* argument.

        Raises:
            FileNotFoundError: If no registry file can be located.
            ValueError: If the registry JSON is malformed.
        """
        resolved = self._locate(path, offline=offline)
        raw = resolved.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed registry JSON at {resolved}: {exc}") from exc

        self.schema_version: str = str(data.get("schema_version", "unknown"))
        self.last_updated: str = str(data.get("last_updated", "unknown"))

        raw_entries = data.get("entries", [])
        self.entries: list[RegistryEntry] = [
            RegistryEntry.model_validate(e) for e in raw_entries
        ]

        # Build a lowercase name → entry index for O(1) exact lookups.
        self._name_index: dict[str, RegistryEntry] = {
            e.name.lower(): e for e in self.entries
        }

    # ── Query methods ──────────────────────────────────────────────────────────

    def get(self, name: str) -> RegistryEntry | None:
        """Return the registry entry for *name*, or ``None`` if not found.

        Args:
            name: Package name to look up (case-insensitive).

        Returns:
            :class:`RegistryEntry` when the name is a known-legitimate entry,
            otherwise ``None``.
        """
        return self._name_index.get(name.lower())

    def is_known(self, name: str) -> bool:
        """Return True if *name* exactly matches a registry entry (case-insensitive).

        Args:
            name: Package name to look up.

        Returns:
            ``True`` when the name is a known-legitimate entry.
        """
        return name.lower() in self._name_index

    def find_closest(self, name: str, threshold: int = 2) -> RegistryEntry | None:
        """Return the closest registry entry within *threshold* edit distance.

        Returns ``None`` for exact matches (the caller should use
        :meth:`is_known` to filter those out first) and for names that are
        farther than *threshold* edits from every entry.

        Args:
            name: Lowercase package name to check.
            threshold: Maximum Levenshtein distance to consider (inclusive).

        Returns:
            Closest :class:`RegistryEntry`, or ``None``.
        """
        lower = name.lower()

        # Exact match → not a typosquat.
        if lower in self._name_index:
            return None

        closest_entry: RegistryEntry | None = None
        min_dist = threshold + 1  # sentinel: one beyond threshold

        for entry in self.entries:
            d = levenshtein(lower, entry.name.lower())
            if d == 0:
                # Should not happen given the index check above, but guard anyway.
                return None
            if d < min_dist:
                min_dist = d
                closest_entry = entry
                if d == 1:
                    break  # can't do better without an exact match

        return closest_entry if min_dist <= threshold else None

    def names(self) -> list[str]:
        """Return all entry names (original casing) for external iteration.

        Returns:
            List of package name strings from every registry entry.
        """
        return [e.name for e in self.entries]

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _locate(path: Path | None, offline: bool = False) -> Path:
        """Resolve the registry file path from explicit arg, cache, or bundle.

        Args:
            path: Explicit path override.  When supplied, *offline* has no effect.
            offline: When ``True``, skip the user-cache path and resolve directly
                to the bundled registry.
        """
        if path is not None:
            # Security: resolve() canonicalises the path (eliminates .., symlinks).
            # No boundary check needed — the user may legitimately point anywhere.
            path = path.resolve()
            if not path.exists():
                raise FileNotFoundError(f"Registry file not found: {path}")
            return path

        if not offline and _USER_CACHE_PATH.exists():
            return _USER_CACHE_PATH

        if BUNDLED_REGISTRY_PATH.exists():
            return BUNDLED_REGISTRY_PATH

        raise FileNotFoundError(
            "No registry file found. Run 'mcp-audit update-registry' to fetch "
            f"the latest, or ensure the package is installed correctly. "
            f"(searched: {_USER_CACHE_PATH}, {BUNDLED_REGISTRY_PATH})"
        )


# ── Module-level convenience ───────────────────────────────────────────────────


def load_registry(
    path: Path | None = None, offline: bool = False
) -> KnownServerRegistry:
    """Load and return a :class:`KnownServerRegistry`.

    Resolution order (unless *path* is given):
    1. User-local cache at ``<user-config-dir>/mcp-audit/registry/known-servers.json``
       (resolved via ``platformdirs``; skipped when *offline* is ``True``).
    2. Bundled registry shipped with the package.

    Args:
        path: Optional explicit registry file path.  Overrides the resolution
            order entirely — *offline* has no effect when *path* is supplied.
        offline: When ``True``, skip the user-local cache and use only the
            bundled registry.  Useful for reproducible scans that must not
            depend on externally-written cache files.

    Returns:
        Populated :class:`KnownServerRegistry` instance.
    """
    return KnownServerRegistry(path=path, offline=offline)


# ── Levenshtein implementation ─────────────────────────────────────────────────


def levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings.

    Standard Wagner-Fischer edit distance. Uses a space-optimised two-row DP
    approach: O(min(|a|,|b|)) space, O(|a| * |b|) time.

    Canonical implementation — imported by
    :mod:`mcp_audit.analyzers.supply_chain` for typosquatting detection.

    Args:
        a: First string.
        b: Second string.

    Returns:
        Non-negative integer edit distance.
    """
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                curr[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + cost,
            )
        prev = curr
    return prev[n]
