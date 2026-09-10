"""Fix strategy for pinning a package version into a server's launch args.

Two related but distinct jobs live here (STORY-0070 extended the original
SC-001/002-only strategy to also handle STORY-0069's lock and the existing
vulnerability scanner's unpinned-version finding):

* **SC-001 / SC-002** (typosquat replacement): extract the closest
  known-legitimate package name from the finding evidence, resolve its latest
  version, and replace the typosquatted arg with ``verified-pkg@version``.
* **VULN-UNPINNED / LOCK-004** (exact-version pinning): rewrite a floating
  spec (``npx -y foo``, or a semver range ``foo@^1.2.3``) to an exact
  ``pkg@version`` pin. When a lock file was passed in and has a
  ``resolved_version`` for this server, that version is used with no network
  call — the same version already recorded (and reviewed) at lock time,
  which for LOCK-004 also means the fix formalises the exact version
  mcp-audit approved rather than leaving the config floating and free to
  drift again. Without a lock entry, the latest version is resolved live
  from npm/PyPI, exactly like the SC-001/002 path.

Both paths skip cleanly (never raise, never write a partial pin) when the
version cannot be resolved (offline with no lock, or a network failure), and
are idempotent — re-running after a fix reports "already fixed" with no diff.
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
from mcp_audit.vulnerability.resolver import is_version_range

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


_VERSION_PIN_IDS: frozenset[str] = frozenset({"VULN-UNPINNED", "LOCK-004"})


class PackagePinningStrategy(BaseFixStrategy):
    """Replace typosquatted or floating package specs with an exact pin.

    For each SC-001 / SC-002 finding the strategy:

    1. Parses the closest known-good package name from the finding evidence.
    2. Checks the known-server registry: if the replacement is a registry
       entry, the fix is applied silently; otherwise a warning is emitted but
       the fix still proceeds.
    3. Resolves the latest version from npm (npx) or PyPI (uvx/pipx).
    4. Replaces the typosquatted arg token with ``{verified-pkg}@{version}``.

    For each VULN-UNPINNED / LOCK-004 finding (STORY-0070):

    1. Prefers the version already recorded in ``mcp-lock.json`` for this
       server, when a lock file was passed in — no network call.
    2. Otherwise resolves the latest version live, exactly like SC-001/002.
    3. Replaces the current (possibly floating or range) arg with an exact
       ``pkg@version`` pin.

    When ``offline=True`` (and no lock entry covers this server) or the
    version registry is unreachable, the fix is skipped and a warning is
    added to :attr:`warnings`.  The caller inspects the warnings list after
    :meth:`apply` returns.
    """

    def __init__(
        self,
        registry: KnownServerRegistry | None = None,
        offline: bool = False,
        lock_doc: dict | None = None,
    ) -> None:
        """Initialise the strategy.

        Args:
            registry: Pre-loaded :class:`~mcp_audit.registry.loader.KnownServerRegistry`
                instance used to validate the replacement package name.
                When ``None`` the registry check is skipped (warns on every fix).
            offline: When ``True``, all version-resolution network calls are
                suppressed and the fix is skipped with a warning — unless a
                ``lock_doc`` entry already has a resolved version for the
                server, in which case no network call is needed anyway.
            lock_doc: The raw parsed ``mcp-lock.json`` document (as returned
                by :func:`mcp_audit.lock.writer.load_existing`) for the
                nearest ancestor lock, or ``None`` when no lock file was
                found. Only consulted for VULN-UNPINNED / LOCK-004 fixes.
        """
        self._registry = registry
        self._offline = offline
        self._lock_doc = lock_doc
        self.warnings: list[str] = []

    def can_fix(self, finding: Finding) -> bool:
        return finding.id in ("SC-001", "SC-002") or finding.id in _VERSION_PIN_IDS

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
                "a supported package-manager command for pinning."
            )

        if finding.id in _VERSION_PIN_IDS:
            return self._apply_version_pin(
                config, finding, server_dict, root_key, is_npm=is_npm
            )
        return self._apply_typosquat_pin(
            config, finding, server_dict, root_key, is_npm=is_npm
        )

    def _apply_typosquat_pin(
        self,
        config: dict,
        finding: Finding,
        server_dict: dict,
        root_key: str,
        *,
        is_npm: bool,
    ) -> tuple[dict, str]:
        """Handle SC-001 / SC-002 (unchanged behaviour, factored out of ``apply``)."""
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
        version = (
            _resolve_npm_version(verified_pkg)
            if is_npm
            else _resolve_pypi_version(verified_pkg)
        )

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

    def _lock_entry_for(self, finding: Finding) -> dict | None:
        """Return this finding's server's ``mcp-lock.json`` entry, if any."""
        if not self._lock_doc:
            return None
        key = f"{finding.client}/{finding.server}"
        return (self._lock_doc.get("servers") or {}).get(key)

    def _apply_version_pin(
        self,
        config: dict,
        finding: Finding,
        server_dict: dict,
        root_key: str,
        *,
        is_npm: bool,
    ) -> tuple[dict, str]:
        """Handle VULN-UNPINNED / LOCK-004: pin to an exact version (STORY-0070)."""
        args: list[str] = list(server_dict.get("args", []))
        current_pkg = _find_package_arg(args)
        if current_pkg is None:
            raise ValueError(
                f"Cannot locate package arg in args {args!r} for {finding.server!r}."
            )
        pkg_base = current_pkg.split("@", 1)[0] if "@" in current_pkg else current_pkg
        current_spec = current_pkg.split("@", 1)[1] if "@" in current_pkg else None

        lock_entry = self._lock_entry_for(finding)
        lock_package = (lock_entry or {}).get("package") or {}
        version = lock_package.get("resolved_version")
        from_lock = version is not None

        if from_lock:
            pkg_name = lock_package.get("name") or pkg_base
            was_range = bool(lock_package.get("range_spec"))
        else:
            pkg_name = pkg_base
            was_range = bool(current_spec) and is_version_range(current_spec)
            if self._offline:
                self.warnings.append(
                    f"Skipping version pin for {finding.server!r} ({pkg_name}): "
                    "--offline flag is active."
                )
                return config, f"Pinning skipped for {finding.server!r} (offline)"
            version = (
                _resolve_npm_version(pkg_name)
                if is_npm
                else _resolve_pypi_version(pkg_name)
            )

        if version is None:
            self.warnings.append(
                f"Skipping version pin for {finding.server!r} ({pkg_name}): "
                "could not resolve a version to pin."
            )
            return (
                config,
                f"Pinning skipped for {finding.server!r} (version unresolvable)",
            )

        pinned_arg = f"{pkg_name}@{version}"

        if current_pkg == pinned_arg:
            return (
                config,
                f"Package already pinned ({current_pkg}) for "
                f"{finding.server!r} (already fixed)",
            )

        new_args = [pinned_arg if a == current_pkg else a for a in args]
        new_config = copy.deepcopy(config)
        new_config[root_key][finding.server]["args"] = new_args

        range_note = " (semver range collapsed to an exact pin)" if was_range else ""
        source_note = (
            ""
            if from_lock
            else "; pinned to current registry resolution — run `mcp-audit lock` "
            "to record it"
        )
        return (
            new_config,
            f"Replaced {current_pkg!r} → {pinned_arg!r} in "
            f"{finding.server!r}{range_note}{source_note}",
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
