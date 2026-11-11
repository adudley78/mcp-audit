"""Stdlib-only lock primitives shared by ``lock --verify`` and ``mcp-audit run``.

The launch gate (:mod:`mcp_audit.runtime.gate`) runs on every wrapped
server's start, so it cannot import :mod:`mcp_audit.lock.model` (pydantic and
the advisory package) or :mod:`mcp_audit.lock.identity` (the supply-chain
analyzer). The pieces both sides need live here, with no imports beyond the
standard library; ``model``, ``identity``, ``discovery`` and ``verifier``
re-export them, so there is still exactly one implementation of each.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit._paths import find_git_root as _find_git_root

#: The lock file's name.
LOCK_FILENAME = "mcp-lock.json"

#: The ``lock_version`` this mcp-audit writes. Version 2 (STORY-0116, the
#: ADR-0005 R59/R62 set agreed on #88) adds ``section_digests``, a per-entry
#: ``resolution.resolution_context``, and records a bare spec as ``"*"``.
LOCK_VERSION = 2

#: Every ``lock_version`` this mcp-audit can verify. A version-1 lock is
#: verified exactly as v0.22 verified it; anything newer is refused.
SUPPORTED_LOCK_VERSIONS: frozenset[int] = frozenset({1, 2})

#: Identity of one server for lock-matching purposes: the config file's path
#: relative to the lock root, plus the server's name within that file.
MatchKey = tuple[str, str]


def lock_version_of(doc: dict) -> object:
    """Return *doc*'s ``lock_version`` value as written (may be anything)."""
    return doc.get("lock_version")


def unsupported_version(doc: dict) -> int | None:
    """Return *doc*'s ``lock_version`` when it is newer than this mcp-audit reads.

    Only an integer above the highest supported version counts. A missing or
    odd value is read as version 1, exactly as v0.22 (which never looked at
    ``lock_version``) read it.
    """
    version = lock_version_of(doc)
    if (
        isinstance(version, int)
        and not isinstance(version, bool)
        and version > max(SUPPORTED_LOCK_VERSIONS)
    ):
        return version
    return None


def normalize_config_ref(config: str) -> str:
    """Return the canonical form of a lock entry's ``config`` string.

    Tolerates the two spellings a hand-edited or foreign-producer lock might
    carry for the same file — backslash separators and a leading ``./`` — so
    that matching never fails on punctuation.

    Args:
        config: A relative config path as recorded in a lock entry.

    Returns:
        A forward-slash path with no leading ``./``.
    """
    normalized = config.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def relative_config_path(config_path: Path, root: Path) -> str | None:
    """Return *config_path* expressed relative to *root*, or ``~``-relative.

    This is the exact string recorded as a lock entry's ``config`` field —
    never an absolute, machine-specific path (ADR-0005's "never contains an
    absolute path" invariant).

    Args:
        config_path: Absolute path to a discovered config file.
        root: The lock root (the directory ``mcp-lock.json`` describes).

    Returns:
        A POSIX-style relative path when *config_path* is under *root*;
        ``~/...`` when it is under the user's home directory instead (the
        ``lock --include-user`` dotfiles-repo case); ``None`` when it is
        under neither, meaning this file is outside the lock's scope.
    """
    resolved = config_path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        pass
    try:
        return f"~/{resolved.relative_to(Path.home()).as_posix()}"
    except (ValueError, RuntimeError):
        return None


def match_key(config_path: Path, root: Path, name: str) -> MatchKey | None:
    """Return the lock-matching identity of one discovered server.

    R61: matching is by **(config path relative to the lock root, server
    name)**, not by the ``<client>/<name>`` string used as the entry's key in
    the file. The client label describes which discovery pass found the file,
    not the server: ``lock``'s project walk labels ``.mcp.json``
    ``claude-code``, a bare ``scan``'s cwd discovery labels the same file
    ``claude-code-project``, and ``scan --path <file>`` labels it ``custom``.
    Keying on the label made every server in a correctly locked repo report
    as both LOCK-002 ("not in lock") and LOCK-003 ("locked server missing")
    simultaneously — see ADR-0005's R61 addendum and R60-01.

    The pair is also what makes one server name defined in two configs under
    the same root unambiguous, which ``<client>/<name>`` was not.

    Args:
        config_path: Absolute path to the config file declaring the server.
        root: The lock root.
        name: The server's name as written in that config file.

    Returns:
        The ``(relative_config, name)`` pair, or ``None`` when *config_path*
        is outside the lock's scope — such a server gets no LOCK findings at
        all rather than a spurious one.
    """
    relative = relative_config_path(config_path, root)
    if relative is None:
        return None
    return (normalize_config_ref(relative), name)


def index_locked_entries(
    locked_servers: dict,
) -> dict[MatchKey, tuple[str, dict]]:
    """Index the lock's entries by their ``(config, name)`` match key (R61).

    Args:
        locked_servers: The lock's ``servers`` object.

    Returns:
        A mapping from match key to ``(entry_key, entry)``, where
        ``entry_key`` is the original ``<client>/<name>`` string — still the
        entry's id for every message and for the file's own shape. An entry
        missing either half of the pair keeps its key string as a fallback
        identity so a malformed lock degrades to the old behaviour for that
        one entry rather than silently dropping it.
    """
    indexed: dict[MatchKey, tuple[str, dict]] = {}
    for key, entry in locked_servers.items():
        config = entry.get("config")
        name = entry.get("name") or key.partition("/")[2]
        match: MatchKey = (
            (normalize_config_ref(config), name) if config else (key, name)
        )
        indexed[match] = (key, entry)
    return indexed


def find_lock_for(config_path: Path) -> Path | None:
    """Return the nearest ancestor ``mcp-lock.json`` for *config_path*, if any.

    The walk is bounded by the enclosing git repository root; outside a git
    repository only *config_path*'s own directory is checked (see
    :mod:`mcp_audit.lock.discovery` for the rationale).

    Args:
        config_path: Path to an MCP config file (need not exist on disk —
            only its parent directory is walked).

    Returns:
        The resolved path to the nearest ``mcp-lock.json``, or ``None`` if
        none was found.
    """
    start = config_path.resolve().parent
    git_root = _find_git_root(start)

    if git_root is None:
        candidate = start / LOCK_FILENAME
        return candidate if candidate.exists() else None

    current = start
    while True:
        candidate = current / LOCK_FILENAME
        if candidate.exists():
            return candidate
        if current == git_root:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent
