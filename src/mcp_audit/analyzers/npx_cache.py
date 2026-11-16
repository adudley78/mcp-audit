"""Known-malicious packages that npx downloaded and ran on this machine (SC-011).

STORY-0158.  SC-008 matches OSV ``MAL-*`` records by exact package name, but
only for a package an MCP config launches.  A skill collection installed from
a shell (``npx agentic-awesome-skills``) leaves only the skill files on disk:
the package name is gone, so SC-008 has nothing to match (GAPS.md, SC-008).

npx keeps what it ran.  Since npm 7, ``npx <pkg>`` (``npm exec``) installs
the package into ``<npm cache>/_npx/<hash>/node_modules`` and leaves it there.
Every installed package, including each dependency, has its own
``package.json`` with its exact ``name`` and ``version``.  This module reads
those two fields and matches them against the same bundled mirror SC-008
uses (``registry/known-malicious.json``), with the same exact-name rule, so a
name that is not in a record cannot cause a finding.

**What it reads.**  ``<cache>/_npx/*/node_modules/<name>/package.json`` and
``<cache>/_npx/*/node_modules/@<scope>/<name>/package.json``, top level of
``node_modules`` only (npm installs flat; a nested copy is a duplicate of a
version conflict and is not read).  The cache is ``$npm_config_cache`` when
set, else ``%LocalAppData%\\npm-cache`` on Windows, else ``~/.npm`` (npm
docs, ``cache`` config).  Only regular files are opened, never through a
symlink, at most 64 KiB each, and at most :data:`MAX_INSTALL_DIRS` install
directories and :data:`MAX_PACKAGES` packages per scan.  Nothing is run,
written or sent.

**What it cannot say.**  An empty cache does not prove a clean machine:
``npm cache clean`` and ``npx clear-npx-cache`` delete it, and a cache set in
``.npmrc`` (not the environment) is not read.  The mirror holds only the
records the sync script selects (MCP-named, registry-listed, or agent-stack
names), so other malicious packages in the cache are not reported.  PyPI
caches (uvx, pipx) are not read yet.  See GAPS.md.

Finding:

- **SC-011** (CRITICAL): the cache holds a release that an OSV ``MAL-*``
  record covers.  The package was downloaded by npx on this machine, which
  runs its install scripts and its bin entry.  One finding per package and
  version.

Runs only in a default scan (no explicit path).  :func:`npx_cache_findings`
never raises.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.models import Finding, Severity
from mcp_audit.registry.malicious import (
    KnownMaliciousPackages,
    MaliciousMatch,
    assess,
    load_known_malicious,
)

#: Install directories under ``_npx`` read per scan.
MAX_INSTALL_DIRS = 2_000

#: ``package.json`` files read per scan, across all install directories.
MAX_PACKAGES = 50_000

#: Largest ``package.json`` read (a real one is a few KiB).
MAX_MANIFEST_BYTES = 64 * 1024

#: Client label on SC-011 findings: the source is npx, not an MCP client.
CLIENT = "npx-cache"


def _environ() -> dict[str, str]:
    """The process environment (tests patch this)."""
    return dict(os.environ)


def _home() -> Path:
    """The home directory (tests patch this)."""
    return Path.home()


def npm_cache_dir(
    environ: dict[str, str] | None = None, home: Path | None = None
) -> Path:
    """Return npm's cache directory the way npm resolves its default.

    Args:
        environ: Environment to read (default: the process environment).
        home: Home directory (default: :func:`Path.home`).

    Returns:
        ``$npm_config_cache`` (any case) when set, else
        ``%LocalAppData%\\npm-cache`` on Windows, else ``~/.npm``.
    """
    env = environ if environ is not None else _environ()
    for key, value in env.items():
        if key.lower() == "npm_config_cache" and value:
            return Path(value).expanduser()
    if sys.platform == "win32":
        local = env.get("LOCALAPPDATA")
        if local:
            return Path(local) / "npm-cache"
    return (home if home is not None else _home()) / ".npm"


@dataclass(frozen=True)
class CachedPackage:
    """One package npx installed.

    Attributes:
        name: ``name`` from its ``package.json``.
        version: ``version`` from its ``package.json``.
        manifest: Path of that ``package.json``.
    """

    name: str
    version: str
    manifest: Path


def _is_real_dir(path: Path) -> bool:
    """``True`` for a directory that is not a symlink or a Windows junction."""
    try:
        if not stat.S_ISDIR(path.lstat().st_mode):
            return False
        is_junction = getattr(path, "is_junction", None)  # Python 3.12+
        return not (is_junction is not None and is_junction())
    except OSError:
        return False


def _list_dir(path: Path, errors: list[str]) -> list[Path]:
    """Sorted entries of *path*; a read problem goes to *errors*."""
    try:
        return sorted(path.iterdir())
    except FileNotFoundError:
        return []
    except OSError as exc:
        errors.append(f"npx cache: cannot list {path.name}: {type(exc).__name__}")
        return []


def _read_manifest(path: Path) -> CachedPackage | None:
    """Read ``name`` and ``version`` from one ``package.json``, or ``None``.

    The file must be a regular file reached without a symlink and no larger
    than :data:`MAX_MANIFEST_BYTES`.
    """
    # Windows has no O_NOFOLLOW, so a link is refused by lstat() first there.
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None
    except OSError:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            return None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    name, version = data.get("name"), data.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    name, version = name.strip(), version.strip()
    if not name or not version or len(name) > 214 or len(version) > 256:
        return None
    return CachedPackage(name=name, version=version, manifest=path)


def iter_cached_packages(cache_dir: Path, errors: list[str]) -> Iterator[CachedPackage]:
    """Yield every package in ``<cache_dir>/_npx/*/node_modules``.

    Args:
        cache_dir: npm's cache directory.
        errors: The scan's error list; budget stops and unreadable
            directories are appended here.

    Yields:
        One :class:`CachedPackage` per readable top-level package.
    """
    npx_root = cache_dir / "_npx"
    if not _is_real_dir(npx_root):
        return
    installs = [p for p in _list_dir(npx_root, errors) if _is_real_dir(p)]
    if len(installs) > MAX_INSTALL_DIRS:
        errors.append(
            f"npx cache: {len(installs)} install directories, only the first "
            f"{MAX_INSTALL_DIRS} were read"
        )
        installs = installs[:MAX_INSTALL_DIRS]
    read = 0
    for install in installs:
        modules = install / "node_modules"
        if not _is_real_dir(modules):
            continue
        for entry in _list_dir(modules, errors):
            if entry.name.startswith(".") or not _is_real_dir(entry):
                continue
            if entry.name.startswith("@"):
                candidates = [p for p in _list_dir(entry, errors) if _is_real_dir(p)]
            else:
                candidates = [entry]
            for package_dir in candidates:
                if read >= MAX_PACKAGES:
                    errors.append(f"npx cache: stopped after {MAX_PACKAGES} packages")
                    return
                read += 1
                package = _read_manifest(package_dir / "package.json")
                if package is not None:
                    yield package


def _build_finding(package: CachedPackage, matches: list[MaliciousMatch]) -> Finding:
    """Return the SC-011 finding for one cached package and version."""
    ids = ", ".join(m.record.id for m in matches)
    first = matches[0].record
    aliases = sorted({a for m in matches for a in m.record.aliases})
    notes: list[str] = []
    for m in matches:
        if m.record.note and m.record.note not in notes:
            notes.append(m.record.note)
    description = (
        f"npx downloaded the npm package {package.name!r} version "
        f"{package.version} on this machine, and OSV lists that release as "
        f"malicious ({ids}"
        + (f"; aliases {', '.join(aliases)}" if aliases else "")
        + ")"
        + (f": {first.summary!r}." if first.summary else ".")
        + " npx runs a package's install scripts and its command when it "
        "downloads it, so the code has probably already run. A skill "
        "collection installed this way leaves only its skill files, so this "
        "cache is the one place its package name is still recorded."
        + "".join(f" Note: {n}" for n in notes)
    )
    evidence = (
        f"package: {package.name} | version: {package.version} | "
        f"ecosystem: npm | osv: {ids}"
    )
    if aliases:
        evidence += f" | aliases: {', '.join(aliases)}"
    return Finding(
        id="SC-011",
        severity=Severity.CRITICAL,
        analyzer="supply_chain",
        client=CLIENT,
        server=package.name,
        title=f"Known malicious package in the npx cache: {package.name} ({ids})",
        description=description,
        evidence=evidence,
        remediation=(
            f"Treat this machine as exposed: follow the advisory at {first.link}, "
            "rotate credentials the package could read, and remove anything it "
            "installed (skills, MCP server entries, shell profile changes). Then "
            "delete its install directory under the npm cache's _npx folder."
        ),
        cwe="CWE-506",
        owasp_mcp_top_10=["MCP04"],
        finding_path=str(package.manifest),
    )


def _findings(
    errors: list[str],
    cache_dir: Path | None,
    malicious: KnownMaliciousPackages | None,
) -> list[Finding]:
    cache = cache_dir if cache_dir is not None else npm_cache_dir()
    index = malicious if malicious is not None else load_known_malicious()
    if len(index) == 0:
        return []
    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []
    for package in iter_cached_packages(cache, errors):
        key = (package.name.lower(), package.version)
        if key in seen:
            continue
        seen.add(key)
        records = index.lookup("npm", package.name)
        # The cache records an exact version, so it is assessed as a pin:
        # only a listed release fires.  ``curated=False``: a blanket range on
        # a registry-listed package is taken as stated here, because the
        # release is already on disk and the cost of a miss is a compromise.
        matches = [
            m
            for m in (assess(r, package.version, curated=False) for r in records)
            if m is not None
        ]
        if matches:
            findings.append(_build_finding(package, matches))
    return findings


def npx_cache_findings(
    errors: list[str],
    *,
    cache_dir: Path | None = None,
    malicious: KnownMaliciousPackages | None = None,
) -> list[Finding]:
    """SC-011 for a default scan.  Never raises.

    Args:
        errors: The scan's error list; read problems are appended here.
        cache_dir: npm's cache directory (default: :func:`npm_cache_dir`).
        malicious: The known-malicious index (default: the bundled mirror).

    Returns:
        One finding per cached package and version that an OSV ``MAL-*``
        record covers; empty when there is no npx cache.
    """
    try:
        return _findings(errors, cache_dir, malicious)
    except Exception as exc:  # noqa: BLE001 — a cache check never fails the scan
        errors.append(f"npx cache: check failed: {type(exc).__name__}")
        return []
