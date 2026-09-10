"""Pure, exported identity canonicalization for ``mcp-lock.json`` (ADR-0005 §9).

:func:`canonicalize_url` is intentionally a standalone, side-effect-free
function with no dependency on the rest of the ``lock`` package — STORY-0071
(org allowlist interop) imports it directly rather than re-implementing the
platform allowlist ``serverUrl`` matcher semantics a second time.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

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
