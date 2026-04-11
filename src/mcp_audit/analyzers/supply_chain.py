"""Detect supply-chain attacks via typosquatting of known MCP npm packages.

Research basis: single-edit-distance substitutions, additions, and deletions
are the dominant typosquatting technique for scoped npm packages.
Ref: "Typosquatting in Package Managers" — Vu et al., NDSS 2021
  https://www.ndss-symposium.org/ndss-paper/detecting-node-js-package-name-squatting/
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity

_DATA_FILE = Path(__file__).parent.parent / "data" / "known_npm_packages.yaml"

# Commands that download and execute npm packages at runtime.
_NPX_LIKE: frozenset[str] = frozenset({"npx", "bunx", "pnpx"})

# Flags that consume the following token as their value, not as a package name.
_FLAGS_WITH_VALUE: frozenset[str] = frozenset({"-p", "--package", "--call", "-c"})


@lru_cache(maxsize=1)
def _load_known_packages() -> frozenset[str]:
    """Load and cache known-legitimate npm package names from the data file."""
    with _DATA_FILE.open() as fh:
        data = yaml.safe_load(fh)
    return frozenset(pkg.lower() for pkg in data.get("npm", []))


def levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings.

    Uses a space-optimised two-row DP approach: O(min(|a|,|b|)) space,
    O(|a| * |b|) time.

    Args:
        a: First string.
        b: Second string.

    Returns:
        Non-negative integer edit distance.
    """
    if a == b:
        return 0
    # Keep `a` as the longer string so the inner row is shorter.
    if len(a) < len(b):
        a, b = b, a
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                curr[j - 1] + 1,   # insertion
                prev[j] + 1,       # deletion
                prev[j - 1] + cost,  # substitution
            )
        prev = curr
    return prev[n]


def extract_npm_package(args: list[str]) -> str | None:
    """Return the first npm package name found in an npx-style argument list.

    Skips flag arguments (``-y``, ``--yes``, etc.) and their associated values.
    Rejects anything that looks like a local path or URL.

    Args:
        args: The ``args`` list from a :class:`~mcp_audit.models.ServerConfig`.

    Returns:
        Lowercase package name, or ``None`` if no package-like token is found.
    """
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in _FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        # Reject local paths and URLs — not npm packages.
        if arg.startswith(("/", ".", "http://", "https://", "file:")):
            continue
        # Accept scoped (@org/name) or plain package names.
        return arg.lower()
    return None


class SupplyChainAnalyzer(BaseAnalyzer):
    """Detect typosquatting of known-legitimate MCP npm packages.

    For each server that invokes ``npx`` (or equivalent), the analyzer:

    1. Extracts the package name from the argument list.
    2. Skips it if it matches a known-good package exactly.
    3. Computes the minimum Levenshtein distance to any known-good package.
    4. Emits a finding if the distance is ≤ 3, with severity scaled to proximity.
    """

    @property
    def name(self) -> str:
        return "supply_chain"

    @property
    def description(self) -> str:
        return "Detect typosquatting of known-legitimate MCP npm packages"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Analyze a server config for npm typosquatting.

        Args:
            server: The MCP server configuration to analyze.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects (empty if clean).
        """
        if server.command not in _NPX_LIKE:
            return []

        package = extract_npm_package(server.args)
        if package is None:
            return []

        known = _load_known_packages()

        if package in known:
            return []

        closest, min_dist = _closest_known(package, known)

        if closest is None or min_dist > 3:
            return []

        severity, finding_id = _severity_for_distance(min_dist)

        return [
            Finding(
                id=finding_id,
                severity=severity,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title=f"Possible typosquatting: {package!r}",
                description=(
                    f"Package {package!r} is {min_dist} edit(s) away from the "
                    f"known-legitimate package {closest!r}. This pattern is consistent "
                    "with a typosquatting supply-chain attack."
                ),
                evidence=f"command: {server.command} {' '.join(server.args[:4])}",
                remediation=(
                    f"Verify {package!r} is intentional. If you meant {closest!r}, "
                    "correct the configuration. Inspect the package's npm page and "
                    "source repository before trusting it."
                ),
                cwe="CWE-829",
            )
        ]


# ── Private helpers ────────────────────────────────────────────────────────────

def _closest_known(
    package: str, known: frozenset[str]
) -> tuple[str | None, int]:
    """Return the closest known package and its distance from *package*.

    Args:
        package: Lowercase npm package name to check.
        known: Set of known-legitimate lowercase package names.

    Returns:
        ``(closest_name, distance)`` tuple, or ``(None, 0)`` if *known* is empty.
    """
    closest: str | None = None
    min_dist = 10_000  # sentinel larger than any realistic distance
    for candidate in known:
        d = levenshtein(package, candidate)
        if d < min_dist:
            min_dist = d
            closest = candidate
            if d == 0:
                break  # can't do better
    return closest, min_dist


def _severity_for_distance(distance: int) -> tuple[Severity, str]:
    """Map a Levenshtein distance to a (Severity, finding_id) pair.

    Args:
        distance: Edit distance to the nearest known-good package (1–3).

    Returns:
        Tuple of severity and finding ID string.
    """
    if distance == 1:
        return Severity.CRITICAL, "SC-001"
    if distance == 2:
        return Severity.HIGH, "SC-002"
    return Severity.MEDIUM, "SC-003"
