"""Fix strategy for SC-001 and SC-002 — replace typosquatted packages with
the verified name and pin to the latest published version.

Resolution logic:
  * Extract the closest known-legitimate package name from the finding evidence.
  * Resolve the latest version from npm (for npx/bunx/pnpx) or PyPI (for uvx/pipx).
  * Replace the typosquatted package name in args with ``verified-pkg@version``.
  * Emit a warning (non-blocking) when the replacement package is not in the
    known-server registry (shouldn't happen for SC-001/002, but guards edge cases).
  * When ``--offline`` is active or the network call fails, skip pinning and
    record a warning instead.
"""

from __future__ import annotations

import copy
import json
import re
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

from mcp_audit.fixer.strategies.base import BaseFixStrategy, find_server_section
from mcp_audit.models import Finding

if TYPE_CHECKING:
    from mcp_audit.registry.loader import KnownServerRegistry

# Commands whose first non-flag positional arg is an npm package.
_NPX_LIKE: frozenset[str] = frozenset({"npx", "bunx", "pnpx"})

# Commands whose first non-flag positional arg is a PyPI package.
_PYPI_LIKE: frozenset[str] = frozenset({"uvx", "pipx"})

# Parses the closest known-good package name from the SC-001/002 evidence:
# "command: npx some-pkg ... | closest: 'real-pkg' (maintainer=..., verified=True)"
_CLOSEST_RE: re.Pattern[str] = re.compile(r"closest:\s*'([^']+)'")

# Detects an already-pinned package argument (e.g. "pkg@1.2.3").
_PINNED_RE: re.Pattern[str] = re.compile(r"^[^@]+@[^@]+$")


def _resolve_npm_version(package: str) -> str | None:
    """Fetch the latest version of *package* from the npm registry.

    Args:
        package: npm package name (may be scoped, e.g. ``@org/pkg``).

    Returns:
        Version string (e.g. ``"1.2.3"``), or ``None`` on network/parse failure.
    """
    url = f"https://registry.npmjs.org/{package}/latest"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310  # nosec B310 -- always https://registry.npmjs.org
            data = json.loads(resp.read().decode())
        return data.get("version")
    except Exception:
        return None


def _resolve_pypi_version(package: str) -> str | None:
    """Fetch the latest version of *package* from PyPI.

    Args:
        package: PyPI package name.

    Returns:
        Version string, or ``None`` on network/parse failure.
    """
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310  # nosec B310 -- always https://pypi.org
            data = json.loads(resp.read().decode())
        return data.get("info", {}).get("version")
    except Exception:
        return None


class PackagePinningStrategy(BaseFixStrategy):
    """Replace typosquatted package names with the verified equivalent and pin.

    For each SC-001 / SC-002 finding the strategy:

    1. Parses the closest known-good package name from the finding evidence.
    2. Checks the known-server registry: if the replacement is a registry
       entry, the fix is applied silently; otherwise a warning is emitted but
       the fix still proceeds.
    3. Resolves the latest version from npm (npx) or PyPI (uvx/pipx).
    4. Replaces the typosquatted arg token with ``{verified-pkg}@{version}``.

    When ``offline=True`` or the version registry is unreachable, the fix is
    skipped and a warning is added to :attr:`warnings`.  The caller inspects
    the warnings list after :meth:`apply` returns.
    """

    def __init__(
        self,
        registry: KnownServerRegistry | None = None,
        offline: bool = False,
    ) -> None:
        """Initialise the strategy.

        Args:
            registry: Pre-loaded :class:`~mcp_audit.registry.loader.KnownServerRegistry`
                instance used to validate the replacement package name.
                When ``None`` the registry check is skipped (warns on every fix).
            offline: When ``True``, all version-resolution network calls are
                suppressed and the fix is skipped with a warning.
        """
        self._registry = registry
        self._offline = offline
        self.warnings: list[str] = []

    def can_fix(self, finding: Finding) -> bool:
        return finding.id in ("SC-001", "SC-002")

    def apply(self, config: dict, finding: Finding) -> tuple[dict, str]:
        server_dict, root_key = find_server_section(config, finding.server)
        if server_dict is None or root_key is None:
            raise ValueError(
                f"Server {finding.server!r} not found in config; cannot apply fix."
            )

        # Determine the ecosystem from the server command.
        command: str = server_dict.get("command", "")
        is_npm = command in _NPX_LIKE
        is_pypi = command in _PYPI_LIKE

        if not is_npm and not is_pypi:
            raise ValueError(
                f"Server {finding.server!r} uses command {command!r} which is not "
                "a supported package-manager command for SC pinning."
            )

        # Extract the verified (closest known-good) package name from evidence.
        m = _CLOSEST_RE.search(finding.evidence)
        if m is None:
            raise ValueError(
                f"Cannot parse verified package name from SC evidence: "
                f"{finding.evidence!r}"
            )
        verified_pkg = m.group(1)

        # Emit a warning when the replacement isn't in the known-server registry
        # (edge case: registry may have been updated since the finding was generated).
        if self._registry is not None and not self._registry.is_known(verified_pkg):
            self.warnings.append(
                f"Warning: {verified_pkg!r} is not in the mcp-audit known-server "
                "registry. Pinning to latest version anyway — verify this package "
                "is legitimate before committing."
            )

        # Skip version resolution when offline.
        if self._offline:
            self.warnings.append(
                f"Skipping version pin for {finding.server!r} ({verified_pkg}): "
                "--offline flag is active."
            )
            return config, f"Pinning skipped for {finding.server!r} (offline)"

        # Resolve latest version from the appropriate registry.
        if is_npm:
            version = _resolve_npm_version(verified_pkg)
        else:
            version = _resolve_pypi_version(verified_pkg)

        if version is None:
            self.warnings.append(
                f"Skipping version pin for {finding.server!r} ({verified_pkg}): "
                "could not resolve latest version from registry."
            )
            return (
                config,
                f"Pinning skipped for {finding.server!r} (version unresolvable)",
            )

        pinned_arg = f"{verified_pkg}@{version}"

        # Locate the current (typosquatted) package in the args list and replace it.
        args: list[str] = list(server_dict.get("args", []))
        current_pkg = _find_package_arg(args)
        if current_pkg is None:
            raise ValueError(
                f"Cannot locate package arg in args {args!r} for {finding.server!r}."
            )

        # Idempotent: already pinned to the verified package at some version.
        if current_pkg == pinned_arg or current_pkg.startswith(f"{verified_pkg}@"):
            return (
                config,
                f"Package already pinned ({current_pkg}) for "
                f"{finding.server!r} (already fixed)",
            )

        # Replace the old arg (may include existing @wrong-version suffix).
        pkg_base = current_pkg.split("@")[0] if "@" in current_pkg else current_pkg
        new_args = [
            pinned_arg if (a == current_pkg or a.split("@")[0] == pkg_base) else a
            for a in args
        ]

        new_config = copy.deepcopy(config)
        new_config[root_key][finding.server]["args"] = new_args
        return (
            new_config,
            f"Replaced {current_pkg!r} → {pinned_arg!r} in {finding.server!r}",
        )


def _find_package_arg(args: list[str]) -> str | None:
    """Return the first non-flag positional token from an npx/uvx args list.

    Strips any existing ``@version`` suffix so callers get a clean package name
    for comparison, but returns the original arg token (with any existing suffix)
    so the replacement targets the right list element.

    Args:
        args: The ``args`` array from the server config.

    Returns:
        The matching arg token (potentially ``pkg@old-version``), or ``None``.
    """
    skip_next = False
    # Flags whose next token is a value, not a package name.
    _flags_with_value = frozenset(
        {"-p", "--package", "--call", "-c", "--from", "-f", "--python", "--with"}
    )
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in _flags_with_value:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg.startswith(("/", ".", "http://", "https://", "file:")):
            continue
        return arg
    return None
