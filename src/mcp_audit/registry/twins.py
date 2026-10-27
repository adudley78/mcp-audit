"""Unscoped twins: names that copy a known package's name without its scope.

``SC-007`` (STORY-0097).  Levenshtein typosquat detection cannot see an
unscoped twin: ``mcp-server-github`` is a long way, in edits, from
``@modelcontextprotocol/server-github``, because the difference is a scope
and a naming convention, not a few letters.  In June 2026 OSV listed ten
unscoped npm names of exactly this shape as malicious (``MAL-2026-5476`` to
``MAL-2026-5485``, among them ``mcp-server-github``), and npm has since
replaced several more twins of the official servers with ``0.0.1-security``
placeholders.

The twin keys are derived from the registry's own entries, using only the
naming conventions those entries and the 2026 squats actually show (measured
on npm and PyPI on 2026-10-25, see ``docs/supply-chain.md``):

* **basename** — a scoped npm package whose name part is ``server-<x>`` or
  ``mcp-server-<x>`` has its name part as a twin:
  ``@modelcontextprotocol/server-github`` → ``server-github``,
  ``@supabase/mcp-server-supabase`` → ``mcp-server-supabase``.
* **mcp-server spelling** — ``@scope/server-<x>`` and ``@scope/<x>-mcp-server``
  have ``mcp-server-<x>`` as a twin: ``@modelcontextprotocol/server-github`` →
  ``mcp-server-github``, ``@notionhq/notion-mcp-server`` → ``mcp-server-notion``.
* **same name, other registry** — a PyPI entry named ``mcp-server-<x>`` is a
  twin for the same name on npm (``npx mcp-server-git`` installs an npm
  package, not Anthropic's PyPI ``mcp-server-git``), and the npm-derived keys
  above are twins for a PyPI launch (``uvx mcp-server-memory``).

Deliberately **not** keys: the exact name part of any other scoped package
(``@notionhq/notion-mcp-server`` → ``notion-mcp-server``,
``@upstash/context7-mcp`` → ``context7-mcp``, ``@azure/mcp`` → ``mcp``).  Those
are the names a community server for the same product would naturally take
(an unrelated ``notion-mcp-server`` with ~2,500 weekly downloads exists), and a
generic name part such as ``mcp``, ``cli`` or ``server`` names nothing at all.

Names are compared after PEP 503-style folding (lowercase, runs of ``-``,
``_`` and ``.`` collapsed to ``-``), so ``mcp_server_github`` is the same twin
as ``mcp-server-github`` in either ecosystem.  Pure functions, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from mcp_audit.registry.loader import (
    KnownServerRegistry,
    RegistryEntry,
    normalize_pypi_name,
)

TwinRule = Literal["basename", "mcp-server-spelling", "same-name"]
Ecosystem = Literal["npm", "pypi"]

_SERVER_PREFIX = "server-"
_MCP_SERVER_PREFIX = "mcp-server-"
_MCP_SERVER_SUFFIX = "-mcp-server"

# A service slug must name something.  ``@x/server-mcp`` would otherwise make
# ``mcp-server-mcp`` a twin of nothing in particular.
_GENERIC_SLUGS: frozenset[str] = frozenset({"mcp", "server", "servers"})
_SLUG_CHARS: frozenset[str] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def fold_name(name: str) -> str:
    """Fold a package name for twin comparison (PEP 503 rules, any ecosystem).

    Args:
        name: A package name (npm or PyPI), without a version suffix.

    Returns:
        The lowercased name with runs of ``-``, ``_`` and ``.`` collapsed to
        a single ``-``.
    """
    return normalize_pypi_name(name)


@dataclass(frozen=True)
class Twin:
    """One registry entry that a configured name is an unscoped twin of.

    Attributes:
        entry: The known registry entry the configured name copies.
        rule: Which naming convention links the two names.
        other_ecosystem: ``True`` when the configured package and *entry*
            live in different registries (npm vs PyPI).
    """

    entry: RegistryEntry
    rule: TwinRule
    other_ecosystem: bool

    def explain(self) -> str:
        """One clause saying how the configured name relates to the entry."""
        if self.rule == "same-name":
            return (
                f"the name of the PyPI package {self.entry.name!r}, launched from npm"
            )
        official = (
            f"the npm package {self.entry.name!r}"
            if self.other_ecosystem
            else repr(self.entry.name)
        )
        where = ", launched from PyPI" if self.other_ecosystem else ""
        if self.rule == "basename":
            return f"the name of {official} without its scope{where}"
        return f"the 'mcp-server-<name>' spelling of {official}{where}"


def _entry_ecosystem(entry: RegistryEntry) -> str:
    return entry.package_ecosystem


def _service_slug(slug: str) -> str | None:
    """Return the folded slug when it names something, else ``None``.

    A plain character check (no regex) keeps this linear on any input.
    """
    folded = fold_name(slug)
    if (
        not folded
        or folded in _GENERIC_SLUGS
        or folded[0] == "-"
        or folded[-1] == "-"
        or not set(folded) <= _SLUG_CHARS
    ):
        return None
    return folded


def twin_keys_for_entry(entry: RegistryEntry) -> list[tuple[str, TwinRule]]:
    """Return the npm-side twin keys a scoped npm registry entry implies.

    Args:
        entry: A registry entry.  Only scoped npm (or ``any``) entries yield
            keys; PyPI entries are handled by :class:`TwinIndex` directly.

    Returns:
        ``(folded_key, rule)`` pairs, possibly empty.
    """
    if _entry_ecosystem(entry) == "pypi" or not entry.name.startswith("@"):
        return []
    _scope, slash, base = entry.name.partition("/")
    if not slash or not base:
        return []
    base = fold_name(base)
    keys: list[tuple[str, TwinRule]] = []
    if base.startswith(_SERVER_PREFIX):
        slug = _service_slug(base[len(_SERVER_PREFIX) :])
        if slug:
            keys.append((base, "basename"))
            keys.append((_MCP_SERVER_PREFIX + slug, "mcp-server-spelling"))
    elif base.startswith(_MCP_SERVER_PREFIX):
        if _service_slug(base[len(_MCP_SERVER_PREFIX) :]):
            keys.append((base, "basename"))
    elif base.endswith(_MCP_SERVER_SUFFIX):
        slug = _service_slug(base[: -len(_MCP_SERVER_SUFFIX)])
        if slug:
            keys.append((_MCP_SERVER_PREFIX + slug, "mcp-server-spelling"))
    return keys


class TwinIndex:
    """Look up the unscoped twins a configured package name is of.

    Built once from a :class:`~mcp_audit.registry.loader.KnownServerRegistry`;
    lookups are dictionary reads.
    """

    def __init__(self, registry: KnownServerRegistry) -> None:
        """Index *registry*'s scoped npm entries and PyPI ``mcp-server-*`` entries.

        Args:
            registry: The loaded known-server registry.
        """
        self._registry = registry
        self._npm_keys: dict[str, list[tuple[RegistryEntry, TwinRule]]] = {}
        self._pypi_names: dict[str, list[RegistryEntry]] = {}
        for entry in registry.entries:
            for key, rule in twin_keys_for_entry(entry):
                self._npm_keys.setdefault(key, []).append((entry, rule))
            if _entry_ecosystem(entry) in ("pypi", "any"):
                folded = fold_name(entry.name)
                if folded.startswith(_MCP_SERVER_PREFIX) and _service_slug(
                    folded[len(_MCP_SERVER_PREFIX) :]
                ):
                    self._pypi_names.setdefault(folded, []).append(entry)

    def find(self, name: str, ecosystem: Ecosystem) -> list[Twin]:
        """Return the registry entries *name* is an unscoped twin of.

        A package that is itself in the registry for *ecosystem* is never a
        twin, and a scoped npm name never is (scope lookalikes are SC-001..003's
        job).

        Args:
            name: The configured package name, without a version suffix.
            ecosystem: ``"npm"`` for npx/bunx/pnpx/yarn dlx, ``"pypi"`` for
                uvx/pipx/``python -m``.

        Returns:
            Twins, same-registry ones first, then verified entries first.
        """
        if not name or name.startswith("@"):
            return []
        if ecosystem == "npm":
            if self._registry.is_known_npm(name):
                return []
        elif self._registry.is_known_pypi(name):
            return []
        key = fold_name(name)
        twins: list[Twin] = []
        for entry, rule in self._npm_keys.get(key, []):
            twins.append(Twin(entry, rule, other_ecosystem=ecosystem == "pypi"))
        if ecosystem == "npm":
            for entry in self._pypi_names.get(key, []):
                twins.append(Twin(entry, "same-name", other_ecosystem=True))
        twins.sort(
            key=lambda t: (t.other_ecosystem, not t.entry.verified, t.entry.name)
        )
        return twins
