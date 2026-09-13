"""Pure, exported identity canonicalization for ``mcp-lock.json`` (ADR-0005 §9).

:func:`canonicalize_url` is intentionally a standalone, side-effect-free
function with no dependency on the rest of the ``lock`` package — STORY-0071
(org allowlist interop) imports it directly rather than re-implementing the
platform allowlist ``serverUrl`` matcher semantics a second time.

:func:`match_key` is the single function that decides whether a discovered
server *is* a given lock entry (R61). It deliberately does not consult the
client label: the label is a property of which discovery found the file, not
of the server, and three different entry points produce three different
labels for the same path — see the module's own R61 note on :func:`match_key`.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from mcp_audit.models import ServerConfig

#: Identity of one server for lock-matching purposes: the config file's path
#: relative to the lock root, plus the server's name within that file.
MatchKey = tuple[str, str]

#: Ports considered "default" for their scheme and therefore dropped from
#: the canonical form (a URL with an explicit ``:443`` and one without are
#: the same server).
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def canonicalize_url(url: str) -> str:
    """Return the canonical form of a remote MCP server URL.

    Rules (ADR-0005 §9, mirroring GitHub's ``serverUrl`` matcher semantics):

    - scheme is lowercased.
    - hostname is lowercased.
    - the default port for the scheme (80/http, 443/https) is dropped.
    - a trailing slash on the path is normalised away, except for the bare
      root path (``"/"``), so ``https://host/api`` and ``https://host/api/``
      are the same identity.
    - embedded userinfo (``user:pass@host``) is dropped — it must never
      round-trip into a committed file.
    - the query string and fragment are dropped entirely.  This is the
      credential-redaction step: a remote server's URL may carry a bearer
      token in a query parameter (``?api_key=...``).  A partial, pattern-based
      redaction could miss an unfamiliar token shape; removing the query
      string outright cannot leak one, and server *identity* for drift
      comparison does not need it — two configs pointing at the same
      scheme+host+path are the same server regardless of query string.

    Args:
        url: The raw URL from a remote server's config entry.

    Returns:
        The canonical URL string, safe to commit to a public repository.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    port = parts.port

    if port is not None and _DEFAULT_PORTS.get(scheme) != port:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    path = parts.path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    if not path:
        path = "/"

    # Query and fragment are always dropped — see docstring.
    return urlunsplit((scheme, netloc, path, "", ""))


def build_identity(server: ServerConfig) -> dict[str, str | list[str]]:
    """Return the ``identity`` sub-object for *server* (ADR-0005 §9).

    Args:
        server: A parsed MCP server configuration.

    Returns:
        ``{"url": <canonical>}`` for a remote server, or
        ``{"command": ..., "args": [...]}`` for a stdio server.
    """
    if server.url:
        return {"url": canonicalize_url(server.url)}
    return {"command": server.command or "", "args": list(server.args)}


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
