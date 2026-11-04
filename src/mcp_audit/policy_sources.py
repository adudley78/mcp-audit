"""Read-only readers for OS-level policy sources (STORY-0144).

Claude Code and the editors mcp-audit knows read administrator policy from
places beyond plain files: the Windows registry and macOS managed preferences.
This module holds the small, injectable readers both
``analyzers/managed_policy.py`` and ``extensions/policy.py`` use, so tests run
on Linux CI with fake readers and no real registry or plist ever.

Invariants:

* **Read-only.** The registry is opened with ``KEY_READ`` only; no ``winreg``
  call that creates, sets or deletes a key or value is ever made, and nothing
  is written to any policy location.
* ``winreg`` is imported lazily and only on Windows (:func:`winreg_reader`).
* Every value read is capped at :data:`MAX_VALUE_BYTES` (1 MiB).
* A plist is read only when it is a regular file that resolves inside the
  managed-preferences root (a symlink out of it is not followed).

Locations are the ones the vendors document, nothing guessed:

* Claude Code: https://code.claude.com/docs/en/managed-settings
  (``HKLM\\SOFTWARE\\Policies\\ClaudeCode`` and the HKCU twin, value
  ``Settings``; macOS ``com.anthropic.claudecode`` managed preferences).
* macOS managed preferences are files the OS writes under
  ``/Library/Managed Preferences`` (``<domain>.plist`` for the device,
  ``<user>/<domain>.plist`` for a user-scoped profile).
"""

from __future__ import annotations

import datetime
import os
import plistlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

MAX_VALUE_BYTES = 1024 * 1024

MACOS_MANAGED_PREFERENCES = Path("/Library/Managed Preferences")


@dataclass(frozen=True)
class RegistryRead:
    """Outcome of reading one registry value.

    Attributes:
        found: The value exists.
        text: Its string content (``REG_SZ`` / ``REG_EXPAND_SZ``), not expanded.
        problem: Why a value that exists could not be used (wrong type, over
            the size cap, access denied); ``None`` otherwise.
        problem_kind: ``malformed`` (not a string / empty: Claude Code refuses
            to start), ``denied`` (the OS refused the read: Claude Code starts
            without the source) or ``unreadable`` (any other failure, or the
            size cap).
    """

    found: bool
    text: str | None = None
    problem: str | None = None
    problem_kind: str = "malformed"


#: ``(hive, subkey, value_name) -> RegistryRead``; hive is ``"HKLM"`` or ``"HKCU"``.
RegistryReader = Callable[[str, str, str], RegistryRead]

NOT_FOUND = RegistryRead(False)


def winreg_reader(hive: str, subkey: str, name: str) -> RegistryRead:
    """Read ``hive\\subkey`` value *name* with ``winreg`` (Windows only).

    Opens the key with ``KEY_READ`` and calls only ``QueryValueEx``.  Returns
    ``NOT_FOUND`` off Windows, for a missing key or value.  Never raises.
    """
    if not sys.platform.startswith("win"):
        return NOT_FOUND
    try:
        import winreg  # noqa: PLC0415 — Windows only
    except ImportError:
        return NOT_FOUND
    root = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}.get(
        hive
    )
    if root is None:
        return NOT_FOUND
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return NOT_FOUND
    except PermissionError as exc:
        return RegistryRead(
            True, None, f"access denied: {type(exc).__name__}", "denied"
        )
    except OSError as exc:
        return RegistryRead(
            True, None, f"cannot read: {type(exc).__name__}", "unreadable"
        )
    if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value, str):
        return RegistryRead(True, None, "value is not REG_SZ or REG_EXPAND_SZ")
    if len(value.encode("utf-8", "replace")) > MAX_VALUE_BYTES:
        return RegistryRead(
            True, None, f"over the {MAX_VALUE_BYTES}-byte limit", "unreadable"
        )
    return RegistryRead(True, value)


#: Most nodes a plist may expand to; a shared-reference (DAG) binary plist can
#: be a few hundred bytes and expand exponentially.
MAX_PLIST_NODES = 100_000


class PlistTooComplexError(ValueError):
    """The plist's expanded size is over :data:`MAX_PLIST_NODES`."""


def _jsonable(
    value: object, memo: dict[int, tuple[object, int]], depth: int = 0
) -> tuple[object, int]:
    """Convert a plist value to a JSON-shaped one: ``(converted, expanded_size)``.

    Bytes, dates and UIDs become strings.  A container reachable twice is
    converted once and the converted object reused (*memo*), but its expanded
    size is counted each time, so a shared-reference plist that would expand to
    millions of nodes (and make ``json.dumps`` or a recursive walk downstream
    explode) raises :class:`PlistTooComplexError` instead.
    """
    if depth > 32:
        raise PlistTooComplexError("nested too deeply")
    if isinstance(value, (dict, list)):
        hit = memo.get(id(value))
        if hit is not None:
            return hit
        size = 1
        out: object
        if isinstance(value, dict):
            conv: dict[str, object] = {}
            for k, v in value.items():
                child, n = _jsonable(v, memo, depth + 1)
                conv[str(k)] = child
                size += n + 1
                if size > MAX_PLIST_NODES:
                    raise PlistTooComplexError("too many nodes")
            out = conv
        else:
            items: list[object] = []
            for v in value:
                child, n = _jsonable(v, memo, depth + 1)
                items.append(child)
                size += n
                if size > MAX_PLIST_NODES:
                    raise PlistTooComplexError("too many nodes")
            out = items
        memo[id(value)] = (out, size)
        return out, size
    if isinstance(value, (bool, int, float, str)) or value is None:
        return value, 1
    if isinstance(value, (bytes, bytearray)):
        return value.hex(), 1
    if isinstance(value, datetime.datetime):
        return value.isoformat(), 1
    return str(value), 1


@dataclass(frozen=True)
class PlistRead:
    """Outcome of reading one plist: ``found`` plus a dict or a ``problem``."""

    found: bool
    data: dict | None = None
    problem: str | None = None
    # malformed: plutil would report it malformed, Claude Code refuses to start;
    # denied: the OS refused the read, Claude Code starts without the source;
    # unreadable: any other failure (or a symlink out of the root, not followed).
    problem_kind: str = "malformed"


def read_plist(path: Path, root: Path) -> PlistRead:
    """Read *path* (a plist under *root*) with ``plistlib``, files only.

    Not followed: a symlink whose target resolves outside *root*.  Capped at
    1 MiB.  A file that is not a plist, or whose top level is not a dictionary,
    comes back with ``problem`` set.  Never raises.
    """
    try:
        if not path.exists() and not path.is_symlink():
            return PlistRead(False)
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
        if not resolved.is_file():
            return PlistRead(False)
    except ValueError:
        return PlistRead(
            True,
            None,
            "symlink leads outside the managed preferences; not followed",
            "unreadable",
        )
    except PermissionError as exc:
        return PlistRead(True, None, f"access denied: {type(exc).__name__}", "denied")
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop (3.12)
        return PlistRead(True, None, f"cannot read: {type(exc).__name__}", "unreadable")
    try:
        with resolved.open("rb") as handle:
            data = handle.read(MAX_VALUE_BYTES + 1)
    except PermissionError as exc:
        return PlistRead(True, None, f"access denied: {type(exc).__name__}", "denied")
    except OSError as exc:
        return PlistRead(True, None, f"cannot read: {type(exc).__name__}", "unreadable")
    if len(data) > MAX_VALUE_BYTES:
        return PlistRead(
            True, None, f"over the {MAX_VALUE_BYTES}-byte limit", "unreadable"
        )
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 — plistlib raises many types
        return PlistRead(True, None, f"not a valid plist: {type(exc).__name__}")
    if not isinstance(parsed, dict):
        return PlistRead(True, None, "plist top level is not a dictionary")
    try:
        jsonable, _ = _jsonable(parsed, {})
    except PlistTooComplexError:
        return PlistRead(True, None, "plist too complex", "unreadable")
    assert isinstance(jsonable, dict)  # noqa: S101 — _jsonable keeps dict shape
    return PlistRead(True, jsonable)


@dataclass(frozen=True)
class PlatformSources:
    """Everything platform-specific a policy read needs, injectable in tests.

    Attributes:
        platform: ``sys.platform`` value (``"darwin"``, ``"win32"``, ``"linux"``).
        registry: Registry reader; ``None`` when there is no registry.
        plist_root: macOS managed-preferences root.
        user: Current user name, for ``<root>/<user>/<domain>.plist``.
    """

    platform: str
    registry: RegistryReader | None
    plist_root: Path
    user: str | None


def _current_user() -> str | None:
    """The effective user's name from the password database, not the environment.

    ``getpass.getuser()`` reads ``LOGNAME``/``USER``, which the caller controls;
    the user-scoped plist path is built from this name.
    """
    try:
        import pwd  # noqa: PLC0415 — POSIX only

        return pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, KeyError, OSError, AttributeError):
        return None


def default_platform_sources() -> PlatformSources:
    """The real machine's readers (patched out in the test suite's conftest)."""
    return PlatformSources(
        platform=sys.platform,
        registry=winreg_reader if sys.platform.startswith("win") else None,
        plist_root=MACOS_MANAGED_PREFERENCES,
        user=_current_user(),
    )
