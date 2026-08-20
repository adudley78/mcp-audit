"""Detect supply-chain attacks via typosquatting of known MCP npm and PyPI packages.

Research basis: single-edit-distance substitutions, additions, and deletions
are the dominant typosquatting technique for scoped npm packages, and the same
technique applies to Python packages installed via uvx / pipx / pip.
Ref: "Typosquatting in Package Managers" — Vu et al., NDSS 2021
  https://www.ndss-symposium.org/ndss-paper/detecting-node-js-package-name-squatting/
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import (
    KnownServerRegistry,
    RegistryEntry,
    levenshtein,
    load_registry,
    normalize_pypi_name,
)

# Commands that download and execute npm packages at runtime.
_NPX_LIKE: frozenset[str] = frozenset({"npx", "bunx", "pnpx"})

# Flags that consume the following token as their value, not as a package name.
_FLAGS_WITH_VALUE: frozenset[str] = frozenset({"-p", "--package", "--call", "-c"})

# Commands that download and execute Python packages at runtime.
_PYPI_LIKE: frozenset[str] = frozenset({"uvx", "pipx"})

# Recognises the CPython interpreter under every common spelling so a
# ``python -m <pkg>`` typosquat cannot evade detection simply by being launched
# as ``python3`` / ``python3.11`` / ``/usr/bin/python3`` — the same word-boundary
# false-negative class as the historic ``nc -e`` and HOOK-001 ``python3`` misses.
_PY_INTERPRETER_RE: re.Pattern[str] = re.compile(r"^(?:python(?:[23](?:\.\d+)?)?|py)$")


def _is_python_interpreter(command: str | None) -> bool:
    """Return True if *command* is a CPython interpreter under any common spelling.

    Matches bare names (``python``, ``python3``, ``python3.11``, ``py``) as well
    as absolute / relative paths whose basename is one of those (e.g.
    ``/usr/bin/python3``).  Used to gate the ``python -m`` typosquat path so that
    the dominant real-world spelling ``python3`` is not silently skipped.

    Args:
        command: The ``command`` field from a :class:`~mcp_audit.models.ServerConfig`.

    Returns:
        ``True`` when *command* resolves to a Python interpreter.
    """
    if not command:
        return False
    base = command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return bool(_PY_INTERPRETER_RE.match(base))


# uvx/pipx flags whose *next* token is a value rather than a package name.
_UVX_FLAGS_WITH_VALUE: frozenset[str] = frozenset(
    {
        "--from",
        "-f",
        "--python",
        "--with",
        "--index-url",
        "--extra-index-url",
        "--default-index",
        "--override-index",
    }
)


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


def extract_pypi_package(command: str, args: list[str]) -> str | None:
    """Return the Python package name from a uvx, pipx, or ``python -m`` invocation.

    Parsing rules:

    * ``uvx <pkg>[@ver]`` → *pkg* is the first non-flag positional argument.
    * ``uvx --from <pkg> <executable>`` → *pkg* is the token after ``--from``/``-f``;
      the ``--from`` flag takes precedence over the positional scan so the
      *executable* name is not mistakenly used.
    * ``uvx --python 3.11 <pkg>`` → ``--python`` and its value are skipped; the
      first remaining non-flag token is *pkg*.
    * ``uvx <pkg>@<version>`` → the ``@<version>`` suffix is stripped before checking.
    * ``pipx run <pkg>`` / ``pipx install <pkg>`` → the ``run``/``install`` sub-command
      is consumed and the remaining args are parsed with the same uvx rules.
    * ``python -m <module>`` → *module* is PEP 503-normalised and returned.

    All names are normalised via :func:`~mcp_audit.registry.loader.normalize_pypi_name`
    before being returned so callers receive a canonical form for registry lookups.

    Args:
        command: The ``command`` field from a :class:`~mcp_audit.models.ServerConfig`.
        args: The ``args`` list from the same config.

    Returns:
        Normalised package name, or ``None`` if no package-like token is found.
    """
    if _is_python_interpreter(command):
        try:
            m_idx = args.index("-m")
            module = args[m_idx + 1]
        except (ValueError, IndexError):
            return None
        return normalize_pypi_name(module)

    if command == "pipx":
        # Consume the sub-command token (run / install / inject / …) so that
        # the remaining args can be parsed by the same flag-scanning logic below.
        # Only strip tokens that are known pipx sub-commands to avoid accidentally
        # consuming a package name when no sub-command is present.
        _pipx_subcommands = frozenset(
            {"run", "install", "inject", "upgrade", "upgrade-all", "uninstall"}
        )
        effective = args[1:] if args and args[0] in _pipx_subcommands else args
    elif command == "uvx":
        effective = args
    else:
        return None

    # Check for --from / -f flag first — it explicitly names the package even
    # when a separate executable name follows it.
    for i, arg in enumerate(effective):
        if arg in ("--from", "-f") and i + 1 < len(effective):
            pkg = effective[i + 1].split("@")[0]
            return normalize_pypi_name(pkg)

    # General flag-skipping scan: consume known-value flags and their arguments,
    # ignore bare flags, and take the first remaining positional as the package.
    skip_next = False
    for arg in effective:
        if skip_next:
            skip_next = False
            continue
        if arg in _UVX_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("--"):
            # --flag=value style embeds the value — no token to skip.
            if "=" not in arg:
                # Unknown --flag without =; treat as a bare flag (no value skip).
                pass
            continue
        if arg.startswith("-"):
            continue
        # First non-flag positional: strip optional @version suffix.
        return normalize_pypi_name(arg.split("@")[0])

    return None


def _emit_known_cve_findings(
    server: ServerConfig,
    entry: RegistryEntry,
) -> list[Finding]:
    """Emit SC-004 findings for each CVE in *entry.known_vulnerabilities*.

    Called when an exact-match package has public CVE advisories recorded in
    the bundled registry.  Severity is HIGH — the package is confirmed
    vulnerable; the operator should check whether the installed version is
    affected and upgrade if so.

    Args:
        server: The MCP server configuration that references this package.
        entry: Registry entry for the matched package.

    Returns:
        One SC-004 :class:`~mcp_audit.models.Finding` per CVE ID.
    """
    findings: list[Finding] = []
    for cve_id in entry.known_vulnerabilities or []:
        findings.append(
            Finding(
                id="SC-004",
                severity=Severity.HIGH,
                analyzer="supply_chain",
                client=server.client,
                server=server.name,
                title=f"Known CVE advisory: {entry.name} ({cve_id})",
                description=(
                    f"Package {entry.name!r} has a public CVE advisory "
                    f"({cve_id}) recorded in the mcp-audit known-server registry. "
                    "Verify whether the version pinned in your config falls within "
                    "the affected range and upgrade to the patched version if so. "
                    "Check NVD (https://nvd.nist.gov/vuln/detail/"
                    f"{cve_id}) for the full advisory."
                ),
                evidence=(
                    f"package: {entry.name} | "
                    f"cve: {cve_id} | "
                    f"maintainer: {entry.maintainer}"
                ),
                remediation=(
                    f"Review {cve_id} at https://nvd.nist.gov/vuln/detail/{cve_id} "
                    f"and upgrade {entry.name!r} to the patched version."
                ),
                cwe="CWE-1104",
                owasp_mcp_top_10=["MCP04"],
                finding_path=str(server.config_path),
            )
        )
    return findings


class SupplyChainAnalyzer(BaseAnalyzer):
    """Detect typosquatting of known-legitimate MCP npm and PyPI packages.

    For each server that invokes a package-manager command, the analyzer:

    1. Extracts the package name from the argument list.
    2. Skips it if it matches a known-good package exactly (via registry).
    3. Finds the closest registry entry by Levenshtein distance.
    4. Emits a finding if the distance is ≤ threshold, with severity scaled
       to proximity.

    Supported package managers:
    - npm ecosystem: ``npx``, ``bunx``, ``pnpx``, ``yarn dlx``
    - Python ecosystem: ``uvx``, ``pipx``, ``python -m``
    """

    def __init__(
        self,
        registry: KnownServerRegistry | None = None,
        registry_path: Path | None = None,
        offline_registry: bool = False,
    ) -> None:
        """Initialise the analyzer with an optional pre-loaded registry.

        Args:
            registry: Pre-built :class:`~mcp_audit.registry.loader.KnownServerRegistry`
                instance.  When supplied, *registry_path* and *offline_registry*
                are both ignored.
            registry_path: Path to a custom registry JSON file.  Falls back to
                the user-cached or bundled registry when ``None``.
            offline_registry: When ``True``, skip the user-local cache and load
                from the bundled registry only.  Ignored when *registry* or
                *registry_path* is supplied.
        """
        if registry is not None:
            self._registry = registry
        else:
            self._registry = load_registry(registry_path, offline=offline_registry)

    @property
    def registry(self) -> KnownServerRegistry:
        """The registry instance used by this analyzer."""
        return self._registry

    @property
    def name(self) -> str:
        return "supply_chain"

    @property
    def description(self) -> str:
        return "Detect typosquatting of known-legitimate MCP npm and PyPI packages"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Analyze a server config for supply-chain typosquatting and known CVEs.

        Dispatches to the npm or Python detection path based on the command
        field.  Both paths apply the same Levenshtein threshold logic and
        produce findings with the same SC-00x IDs.  Exact registry matches are
        further checked for ``known_vulnerabilities`` entries (SC-004).

        Args:
            server: The MCP server configuration to analyze.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects (empty if clean).
        """
        # Python ecosystem: uvx, pipx, python -m (any interpreter spelling)
        if server.command in _PYPI_LIKE or _is_python_interpreter(server.command):
            return self._check_pypi_typosquatting(server)

        # npm ecosystem: npx / bunx / pnpx / yarn dlx
        # ``yarn dlx <pkg>`` is semantically identical to ``npx <pkg>`` for
        # typosquatting purposes; normalise it before the command gate.
        if server.command == "yarn":
            if not server.args or server.args[0] != "dlx":
                return []
            effective_args = server.args[1:]
        elif server.command in _NPX_LIKE:
            effective_args = server.args
        else:
            return []

        package = extract_npm_package(effective_args)
        if package is None:
            return []

        if self._registry.is_known_npm(package):
            entry = self._registry.get_npm(package)
            if entry and entry.known_vulnerabilities:
                return _emit_known_cve_findings(server, entry)
            return []

        # Short names (≤5 chars) are too close to almost any other short name
        # at distance 3, producing high FP rates. Use a tighter threshold of 1
        # for those; long names keep the standard threshold of 3.
        typo_threshold = 1 if len(package) <= 5 else 3
        closest_entry = self._registry.find_closest_npm(
            package, threshold=typo_threshold
        )

        if closest_entry is None:
            return []

        # Compute actual distance so severity mapping stays accurate.
        min_dist = levenshtein(package, closest_entry.name.lower())
        severity, finding_id = _severity_for_distance(min_dist)

        verified_label = "verified" if closest_entry.verified else "unverified"

        # Optional provenance metadata surfaced in the description to help
        # analysts quickly distinguish suspicious newcomers from established
        # packages with a long publish history.
        meta_parts: list[str] = []
        if closest_entry.first_published:
            meta_parts.append(f"first published {closest_entry.first_published}")
        if closest_entry.weekly_downloads is not None:
            meta_parts.append(f"~{closest_entry.weekly_downloads:,} weekly downloads")
        meta_blurb = f"; {'; '.join(meta_parts)}" if meta_parts else ""

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
                    f"known-legitimate package {closest_entry.name!r} "
                    f"(maintainer: {closest_entry.maintainer}, {verified_label}"
                    f"{meta_blurb})."
                    " This pattern is consistent with a typosquatting"
                    " supply-chain attack."
                ),
                evidence=(
                    f"command: {server.command} {' '.join(server.args[:4])} | "
                    f"closest: {closest_entry.name!r} (maintainer="
                    f"{closest_entry.maintainer},"
                    f" verified={closest_entry.verified})"
                ),
                remediation=(
                    f"Verify {package!r} is intentional. "
                    f"If you meant {closest_entry.name!r}, "
                    "correct the configuration. Inspect the package's npm page"
                    " and source repository before trusting it."
                ),
                cwe="CWE-829",
                owasp_mcp_top_10=["MCP04"],
            )
        ]

    def _check_pypi_typosquatting(self, server: ServerConfig) -> list[Finding]:
        """Run the Python-ecosystem typosquat check for *server*.

        Extracts the package name from uvx / pipx / ``python -m`` invocations,
        checks it against the PyPI sub-index of the known-server registry, and
        emits a finding if the name is suspiciously close to a known-good entry.

        Args:
            server: The MCP server configuration to analyse.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects (empty if clean).
        """
        package = extract_pypi_package(server.command or "", server.args)
        if package is None:
            return []

        if self._registry.is_known_pypi(package):
            entry = self._registry.get_pypi(package)
            if entry and entry.known_vulnerabilities:
                return _emit_known_cve_findings(server, entry)
            return []

        typo_threshold = 1 if len(package) <= 5 else 3
        closest_entry = self._registry.find_closest_pypi(
            package, threshold=typo_threshold
        )
        if closest_entry is None:
            return []

        min_dist = levenshtein(package, normalize_pypi_name(closest_entry.name))
        severity, finding_id = _severity_for_distance(min_dist)

        verified_label = "verified" if closest_entry.verified else "unverified"

        meta_parts: list[str] = []
        if closest_entry.first_published:
            meta_parts.append(f"first published {closest_entry.first_published}")
        if closest_entry.weekly_downloads is not None:
            meta_parts.append(f"~{closest_entry.weekly_downloads:,} weekly downloads")
        meta_blurb = f"; {'; '.join(meta_parts)}" if meta_parts else ""

        return [
            Finding(
                id=finding_id,
                severity=severity,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title=f"Possible Python package typosquat: {package!r}",
                description=(
                    f"Python package {package!r} is {min_dist} edit(s) away from the "
                    f"known-legitimate package {closest_entry.name!r} "
                    f"(maintainer: {closest_entry.maintainer}, {verified_label}"
                    f"{meta_blurb})."
                    " This pattern is consistent with a typosquatting"
                    " supply-chain attack targeting Python MCP packages."
                ),
                evidence=(
                    f"command: {server.command} {' '.join(server.args[:4])} | "
                    f"closest: {closest_entry.name!r} (maintainer="
                    f"{closest_entry.maintainer},"
                    f" verified={closest_entry.verified})"
                ),
                remediation=(
                    f"Verify {package!r} is intentional. "
                    f"If you meant {closest_entry.name!r}, "
                    "correct the configuration. Check the package's PyPI page"
                    " and source repository before trusting it."
                ),
                cwe="CWE-829",
                owasp_mcp_top_10=["MCP04"],
            )
        ]


# ── Private helpers ────────────────────────────────────────────────────────────


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
