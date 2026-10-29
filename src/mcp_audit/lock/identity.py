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

from mcp_audit.analyzers.supply_chain import redact_args
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


def _host_port(url: str) -> tuple[str, int | None] | None:
    """Return ``(hostname, effective port)`` of *url*, or ``None`` if unparseable."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    if port is None:
        port = _DEFAULT_PORTS.get(parts.scheme.lower())
    return host, port


def remote_host(url: str | None) -> str | None:
    """Return the lowercase hostname of *url* (never userinfo, port or query)."""
    hp = _host_port(url) if url else None
    return hp[0] if hp else None


def describe_remote_move(old_url: str | None, new_url: str | None) -> str | None:
    """Name a change of a remote server's host or port, or ``None``.

    Only the hostname and port are quoted, so userinfo and query tokens in
    either URL can never reach the text (STORY-0135).  A path-only,
    query-only or userinfo-only change returns ``None``.

    Args:
        old_url: The previously recorded URL (raw or canonical).
        new_url: The URL now configured.

    Returns:
        e.g. ``"remote host changed from a.example to b.example"``, or a
        port sentence when only the port moved, else ``None``.
    """
    if not old_url or not new_url:
        return None
    old, new = _host_port(old_url), _host_port(new_url)
    if old is None or new is None:
        return None
    if old[0] != new[0]:
        return f"remote host changed from {old[0]} to {new[0]}"
    if old[1] != new[1]:
        return f"remote port changed from {old[1]} to {new[1]} on host {old[0]}"
    return None


def build_identity(server: ServerConfig) -> dict[str, str | list[str]]:
    """Return the ``identity`` sub-object for *server* (ADR-0005 §9).

    A stdio launch records its command and arguments verbatim, except that a
    credential in them (``--api-key``, URL userinfo, ``Password=…``, a secret
    header, ``?token=…``; :func:`~mcp_audit.analyzers.supply_chain.redact_args`)
    is replaced by ``[REDACTED]``/``[REDACTED-FLAG]`` before it reaches the
    committed lock (STORY-0118).  A launch without a credential is recorded
    exactly as before, so a lock written by an earlier mcp-audit still verifies.

    Args:
        server: A parsed MCP server configuration.

    Returns:
        ``{"url": <canonical>}`` for a remote server, or
        ``{"command": ..., "args": [...]}`` for a stdio server.
    """
    if server.url:
        return {"url": canonicalize_url(server.url)}
    command, args = redact_launch(server.command or "", list(server.args))
    return {"command": command, "args": args}


def redact_launch(command: str, args: list[str]) -> tuple[str, list[str]]:
    """Return ``(command, args)`` with credentials redacted (STORY-0118)."""
    cleaned = redact_args([command, *[str(a) for a in args]])
    return cleaned[0], cleaned[1:]


def comparable_identity(identity: object) -> object:
    """Return *identity* in the redacted form both sides of a comparison use.

    ``lock --verify`` compares the locked identity with the current one in
    this form.  A lock written before STORY-0118 holds a credential verbatim;
    one written after holds the redacted text; redaction is idempotent, so
    both compare equal to the same launch and neither reports LOCK-001 on an
    untouched config.  The price is that changing only a credential's value
    is not drift (see GAPS.md).
    """
    if not isinstance(identity, dict):
        return identity
    args = identity.get("args")
    command = identity.get("command")
    if isinstance(args, list) and all(isinstance(a, str) for a in args):
        out = dict(identity)
        out["command"], out["args"] = redact_launch(
            command if isinstance(command, str) else "", args
        )
        return out
    return identity


def launch_carries_secret(server: ServerConfig) -> bool:
    """True when *server*'s stdio launch holds a credential the lock redacts."""
    if server.url:
        return False
    command, args = redact_launch(server.command or "", list(server.args))
    return command != (server.command or "") or args != [str(a) for a in server.args]


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
