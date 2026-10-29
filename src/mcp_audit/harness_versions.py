"""Installed versions of Claude Code, Codex and Gemini CLI, read from files only.

STORY-0132.  Nothing here runs a harness binary or any other program: a version
comes from a ``package.json`` or from the name of a file or directory the
installer wrote.  Everything is best-effort and reports what it skipped.

Layouts read (see ``docs/affected.md``):

* npm global installs: ``<prefix>/lib/node_modules/<pkg>/package.json`` (and
  ``<prefix>/node_modules/<pkg>/package.json`` for Windows' ``%APPDATA%\\npm``)
  for ``@anthropic-ai/claude-code``, ``@openai/codex``, ``@google/gemini-cli``.
  Prefixes: ``npm_config_prefix``, ``~/.nvm/versions/node/*`` (and ``NVM_DIR``),
  ``/opt/homebrew``, ``/usr/local``, ``/usr``, ``~/.npm-global``, ``%APPDATA%\\npm``.
* Claude Code's native installer: version-named entries under
  ``~/.local/share/claude/versions/`` (Anthropic's setup page: the launcher
  ``~/.local/bin/claude`` is a symlink into that directory).  The launcher's
  target is read with ``readlink`` only, never followed or executed.

Which install is first on ``PATH`` cannot be known without executing, so every
install found is returned.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from packaging.version import InvalidVersion, Version

#: Largest ``package.json`` read.
MAX_PACKAGE_JSON_BYTES = 1024 * 1024
#: Most entries read from one directory (versions dir, nvm dir).
MAX_DIR_ENTRIES = 512

#: harness key -> (product name as research records spell it, npm package).
HARNESSES: dict[str, tuple[str, str]] = {
    "claude-code": ("Claude Code", "@anthropic-ai/claude-code"),
    "codex": ("Codex", "@openai/codex"),
    "gemini-cli": ("Gemini CLI", "@google/gemini-cli"),
}

_VERSION_NAME = re.compile(
    r"^\d{1,6}(?:\.\d{1,6}){1,3}(?:[-+.][0-9A-Za-z.\-+]{1,40})?$"
)


@dataclass(frozen=True)
class HarnessInstall:
    """One installed harness found on disk.

    Attributes:
        harness: Key of ``HARNESSES``.
        product: Product name as research records spell it.
        version: The version string as the file states it.
        source: Path of the file or directory it was read from.
        kind: ``npm`` or ``native``.
        launcher_target: ``True`` when ``~/.local/bin/claude`` points here.
    """

    harness: str
    product: str
    version: str
    source: str
    kind: str
    launcher_target: bool = False


@dataclass
class HarnessScan:
    """Installs found plus what was skipped and why."""

    installs: list[HarnessInstall] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def for_product(self, product: str) -> list[HarnessInstall]:
        """Installs whose product name equals *product* (case-insensitive)."""
        want = product.casefold()
        return [i for i in self.installs if i.product.casefold() == want]


def _read_version(pkg_json: Path, expected_name: str, skipped: list[str]) -> str | None:
    """Return a ``package.json``'s ``version``, or ``None`` (reason in *skipped*)."""
    try:
        fd = os.open(pkg_json, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as exc:  # ELOOP, EACCES, ...
        skipped.append(f"{pkg_json}: not readable ({type(exc).__name__})")
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                skipped.append(f"{pkg_json}: not a regular file")
                return None
            raw = fh.read(MAX_PACKAGE_JSON_BYTES + 1)
    except OSError as exc:
        skipped.append(f"{pkg_json}: not readable ({type(exc).__name__})")
        return None
    if len(raw) > MAX_PACKAGE_JSON_BYTES:
        skipped.append(f"{pkg_json}: over {MAX_PACKAGE_JSON_BYTES} bytes")
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        skipped.append(f"{pkg_json}: not valid JSON")
        return None
    if not isinstance(data, dict):
        skipped.append(f"{pkg_json}: not a JSON object")
        return None
    if data.get("name") != expected_name:
        skipped.append(f"{pkg_json}: name is not {expected_name}")
        return None
    version = data.get("version")
    if not isinstance(version, str) or len(version) > 64:
        skipped.append(f"{pkg_json}: version is not a string")
        return None
    try:
        Version(version)
    except InvalidVersion:
        skipped.append(f"{pkg_json}: version {version[:32]!r} does not parse")
        return None
    return version


def _list_dir(path: Path, skipped: list[str]) -> list[Path]:
    """Sorted children of *path* (capped); ``[]`` when it is absent or unreadable."""
    try:
        names = sorted(os.listdir(path))
    except FileNotFoundError:
        return []
    except OSError as exc:
        skipped.append(f"{path}: not readable ({type(exc).__name__})")
        return []
    if len(names) > MAX_DIR_ENTRIES:
        skipped.append(
            f"{path}: {len(names)} entries, read the first {MAX_DIR_ENTRIES}"
        )
        names = names[:MAX_DIR_ENTRIES]
    return [path / n for n in names]


def _node_module_roots(
    home: Path, env: dict[str, str], skipped: list[str]
) -> list[Path]:
    """Every ``node_modules`` directory an npm global install might use."""
    prefixes: list[Path] = []
    for key in ("npm_config_prefix", "NPM_CONFIG_PREFIX"):
        if env.get(key):
            prefixes.append(Path(env[key]))
    nvm_dirs = [home / ".nvm"]
    if env.get("NVM_DIR"):
        nvm_dirs.append(Path(env["NVM_DIR"]))
    for nvm in nvm_dirs:
        prefixes.extend(_list_dir(nvm / "versions" / "node", skipped))
    prefixes += [
        Path("/opt/homebrew"),
        Path("/usr/local"),
        Path("/usr"),
        home / ".npm-global",
    ]
    if env.get("APPDATA"):
        prefixes.append(Path(env["APPDATA"]) / "npm")
    roots: list[Path] = []
    for p in prefixes:
        roots += [p / "lib" / "node_modules", p / "node_modules"]
    return roots


def _native_installs(home: Path, skipped: list[str]) -> list[HarnessInstall]:
    """Claude Code's native installer: version-named entries and the launcher."""
    versions = home / ".local" / "share" / "claude" / "versions"
    target: Path | None = None
    launcher = home / ".local" / "bin" / "claude"
    try:
        target = Path(os.readlink(launcher))
    except OSError:
        target = None  # absent, not a symlink, or unreadable: nothing to say
    if target is not None and not target.is_absolute():
        target = launcher.parent / target
    found: list[HarnessInstall] = []
    for entry in _list_dir(versions, skipped):
        name = entry.name
        if not _VERSION_NAME.match(name):
            continue
        try:
            Version(name)
        except InvalidVersion:
            continue
        pointed = target is not None and os.path.normpath(target) == os.path.normpath(
            entry
        )
        found.append(
            HarnessInstall(
                "claude-code",
                HARNESSES["claude-code"][0],
                name,
                str(entry),
                "native",
                launcher_target=pointed,
            )
        )
    return found


def find_harness_versions(
    home: Path | None = None, env: dict[str, str] | None = None
) -> HarnessScan:
    """Find installed Claude Code, Codex and Gemini CLI versions, reading files only.

    Never executes anything.  A hostile or malformed file is skipped with a
    reason in ``HarnessScan.skipped``; this function does not raise on bad
    input.

    Args:
        home: Home directory (default: the user's).
        env: Environment mapping (default: ``os.environ``).

    Returns:
        Every install found (duplicates by real path removed) and the skips.
    """
    scan = HarnessScan()
    try:
        home_dir = home if home is not None else Path.home()
    except RuntimeError:
        scan.skipped.append("home directory could not be determined")
        return scan
    environ = dict(os.environ) if env is None else env
    seen: set[str] = set()
    for root in _node_module_roots(home_dir, environ, scan.skipped):
        for key, (product, pkg) in HARNESSES.items():
            pkg_json = root / pkg / "package.json"
            version = _read_version(pkg_json, pkg, scan.skipped)
            if version is None:
                continue
            try:
                real = str(pkg_json.resolve())
            except (OSError, RuntimeError):
                real = str(pkg_json)
            if real in seen:
                continue
            seen.add(real)
            scan.installs.append(
                HarnessInstall(key, product, version, str(pkg_json), "npm")
            )
    scan.installs.extend(_native_installs(home_dir, scan.skipped))
    return scan
