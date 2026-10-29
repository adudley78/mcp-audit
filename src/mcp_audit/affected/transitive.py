"""``affected --transitive``: check a server's dependency tree (STORY-0131).

A server that launches ``some-wrapper@1.2.0`` can still run a vulnerable
package that wrapper depends on.  With ``--live --transitive`` each server whose
exact version is known has its dependency graph read from deps.dev (the client
``vulnerability/depsdev.py`` already used by ``scan --check-vulns``), and the
advisory's rules are evaluated against every dependency in it.

Three rules keep the answer honest:

* A dependency hit is AFFECTED, with the path ``server@ver -> dep@ver``.
  deps.dev reports the relation (DIRECT or INDIRECT) of each node but not the
  chain between them, so the path is server, dependency and relation.
* A graph that could not be read (404, network, size, malformed) or that
  deps.dev flagged as incomplete is COULDN'T CHECK, never NOT AFFECTED.
* A server with no exact version has no graph to look up, so it is COULDN'T
  CHECK too; ``--transitive`` never turns a missing check into a clean answer.

No semver range is resolved; no package manager is run.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import replace

from mcp_audit.affected.match import (
    DEPENDENCY,
    DEPS_UNCHECKED,
    EXTRA_PACKAGES,
    Decision,
    Dependency,
    Launch,
    LockIndex,
    Row,
    Rule,
    Status,
    server_version,
)
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import KnownServerRegistry
from mcp_audit.vulnerability import depsdev
from mcp_audit.vulnerability.models import Ecosystem, ResolvedPackage

#: Distinct dependency graphs fetched in one run; the rest are COULDN'T CHECK.
MAX_GRAPH_FETCHES = 100

_UNSAFE = re.compile(r"[^\x20-\x7e]")

Fetcher = Callable[..., depsdev.DependencyGraph]


def _clean(text: str) -> str:
    """Printable ASCII only, bounded: deps.dev strings reach the terminal."""
    return _UNSAFE.sub("?", text)[:200]


class GraphSource:
    """deps.dev graphs for one run: cached by package, fetched at most N times."""

    def __init__(self, fetch: Fetcher | None = None) -> None:
        self._fetch = fetch
        self._cache: dict[tuple[str, str, str], depsdev.DependencyGraph] = {}
        self.fetches = 0

    def graph(self, ecosystem: str, name: str, version: str) -> depsdev.DependencyGraph:
        """The dependency graph for ``name@version``; never raises."""
        key = (ecosystem, name, version)
        held = self._cache.get(key)
        if held is not None:
            return held
        if self.fetches >= MAX_GRAPH_FETCHES:
            return depsdev.DependencyGraph(
                packages=[],
                error=f"more than {MAX_GRAPH_FETCHES} dependency lookups in one run",
            )
        self.fetches += 1
        fetch = self._fetch or depsdev.fetch_dependency_graph
        eco = Ecosystem.NPM if ecosystem == "npm" else Ecosystem.PYPI
        try:
            result = fetch(eco, name, version, source_server="")
        except Exception as exc:  # noqa: BLE001 - a lookup must not stop the run
            result = depsdev.DependencyGraph(
                packages=[], error=f"dependency lookup failed ({type(exc).__name__})"
            )
        self._cache[key] = result
        return result


def _rank(decision: Decision, dep: ResolvedPackage) -> tuple[int, int]:
    return (0 if decision.status is Status.AFFECTED else 1, 0 if dep.direct else 1)


def _scan_dependencies(
    graph: depsdev.DependencyGraph,
    rules: Sequence[Rule],
    registry: KnownServerRegistry,
    server_pkg: str,
    server_version: str,
) -> tuple[Row | None, int]:
    """First AFFECTED dependency (as a partial row), and how many COULDN'T CHECK."""
    hit: tuple[tuple[int, int], Decision, ResolvedPackage] | None = None
    unsure = 0
    seen: set[tuple[str, str, str]] = set()
    for dep in graph.packages[1:]:  # [0] is the server's own package
        eco = "npm" if dep.ecosystem == Ecosystem.NPM else "pypi"
        key = (eco, dep.name, dep.version)
        if key in seen:
            continue
        seen.add(key)
        entry = (
            registry.get_npm(dep.name) if eco == "npm" else registry.get_pypi(dep.name)
        )
        source = f"dependency of {server_pkg}@{server_version} (deps.dev)"
        launch = Launch(eco, _clean(dep.name), _clean(dep.version), source, entry)
        for rule in rules:
            if not rule.matches(launch):
                continue
            decision = rule.decide(launch)
            if decision.status is Status.COULDNT_CHECK:
                unsure += 1
            elif decision.status is Status.AFFECTED:
                rank = _rank(decision, dep)
                if hit is None or rank < hit[0]:
                    hit = (rank, decision, dep)
    if hit is None:
        return None, unsure
    _, decision, dep = hit
    relation = dep.relation.upper()
    path = (
        f"{_clean(server_pkg)}@{_clean(server_version)} -> "
        f"{_clean(dep.name)}@{_clean(dep.version)} ({relation})"
    )
    partial = Row(
        "",
        Status.AFFECTED,
        f"{_clean(dep.name)}@{_clean(dep.version)} ({relation} dependency): "
        f"{decision.evidence}",
        fixed_in=decision.fixed_in,
        reason=DEPENDENCY,
        dependency=Dependency(
            eco_name(dep), _clean(dep.name), _clean(dep.version), dep.relation, path
        ),
    )
    return partial, unsure


def eco_name(dep: ResolvedPackage) -> str:
    """``npm`` or ``pypi`` for a deps.dev node."""
    return "npm" if dep.ecosystem == Ecosystem.NPM else "pypi"


def _unchecked(row: Row, why: str) -> Row:
    """COULDN'T CHECK: the direct answer stands but the tree was not read."""
    if row.status is Status.COULDNT_CHECK:
        return replace(row, evidence=f"{row.evidence}; --transitive: {why}")
    return replace(
        row,
        status=Status.COULDNT_CHECK,
        evidence=f"{row.evidence}; --transitive: {why}",
        reason=DEPS_UNCHECKED,
        fixed_in=None,
        fixes=(),
    )


def check_dependencies(
    servers: Sequence[ServerConfig],
    rows: Sequence[Row],
    rules: Sequence[Rule],
    registry: KnownServerRegistry,
    source: GraphSource,
    locks: LockIndex,
) -> list[Row]:
    """Extend per-server *rows* (parallel to *servers*) with dependency answers.

    AFFECTED rows, rows with no package (a remote URL) and rows that already
    stand for packages mcp-audit does not read (``--with`` / ``-p``) are kept
    as they are.
    """
    out: list[Row] = []
    for server, row in zip(servers, rows, strict=True):
        if (
            row.status is Status.AFFECTED
            or row.package is None
            or row.reason == EXTRA_PACKAGES
        ):
            out.append(row)
            continue
        ecosystem, _, name = row.package.partition(":")
        version, version_source = row.version, row.version_source
        if not version:
            # A server on another package never had its version read.
            version, version_source = server_version(server, ecosystem, name, locks)
        if not version:
            out.append(
                _unchecked(
                    row,
                    "no exact version, so the dependency tree was not looked up",
                )
            )
            continue
        graph = source.graph(ecosystem, name, version)
        if graph.error:
            out.append(_unchecked(row, f"dependencies not checked: {graph.error}"))
            continue
        partial, unsure = _scan_dependencies(graph, rules, registry, name, version)
        if partial is not None:
            out.append(
                replace(
                    partial,
                    subject=row.subject,
                    config_path=row.config_path,
                    package=row.package,
                    version=version,
                    version_source=version_source,
                    machine=row.machine,
                )
            )
        elif graph.incomplete:
            out.append(
                _unchecked(row, f"dependencies not fully checked: {graph.incomplete}")
            )
        elif unsure:
            out.append(
                _unchecked(
                    row,
                    f"{unsure} dependency version(s) could not be ordered against "
                    "the advisory",
                )
            )
        elif row.status is Status.NOT_AFFECTED:
            n = max(len(graph.packages) - 1, 0)
            out.append(
                replace(
                    row,
                    evidence=f"{row.evidence}; none of its {n} dependencies "
                    "(deps.dev) is affected",
                )
            )
        else:
            out.append(row)
    return out
