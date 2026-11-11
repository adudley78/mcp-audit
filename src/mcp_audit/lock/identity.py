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

import contextlib
from urllib.parse import urlsplit, urlunsplit

from mcp_audit.analyzers.supply_chain import redact_args
from mcp_audit.lock.core import (  # noqa: F401 — re-exported; one implementation
    MatchKey,
    match_key,
    normalize_config_ref,
    relative_config_path,
)
from mcp_audit.models import ServerConfig

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
    """Return ``(hostname, effective port)`` of *url*, or ``None`` if unparseable.

    A placeholder host (``${HOST}``) is ``None``: it names no host.
    """
    hp = _scheme_host_port(url)
    return (hp[1], hp[2]) if hp else None


def _scheme_host_port(url: str) -> tuple[str, str, int | None] | None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host or "${" in host or "$" in host:
        return None
    if host.endswith("."):
        host = host[:-1]
    with contextlib.suppress(UnicodeError):
        host = host.encode("idna").decode("ascii")
    scheme = parts.scheme.lower()
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    return scheme, host, port


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
    old, new = _scheme_host_port(old_url), _scheme_host_port(new_url)
    if old is None or new is None:
        return None
    if old[1] != new[1]:
        return f"remote host changed from {old[1]} to {new[1]}"
    if old[0] != new[0]:
        return f"remote scheme changed from {old[0]} to {new[0]} on host {old[1]}"
    if old[2] != new[2] and old[2] is not None and new[2] is not None:
        return f"remote port changed from {old[2]} to {new[2]} on host {old[1]}"
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
