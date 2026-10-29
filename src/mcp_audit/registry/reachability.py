"""Which advisories can a given server's launch reach? (STORY-0125).

Some advisories only exist on one transport: the MCP Python SDK's Streamable
HTTP session bug is not there when the server speaks stdio.  A registry
``known_vulns`` record can say so with three optional keys:

``affected_transports``
    A list drawn from ``stdio``, ``http``, ``sse``: the transports the
    vulnerable code runs on.
``requires_auth``
    ``true`` or ``false``, only when the advisory states it.  Shown, never
    used to downgrade anything.
``verified_by``
    Who checked the tag and against what (e.g. ``"Adam Dudley 2026-10-29,
    GHSA text"``).  A tag without it is ignored.

The rule is deliberately narrow.  Only a server that is *provably* stdio is
ever downgraded, and only by a tagged advisory that excludes stdio.  An
untagged advisory, an unreadable tag, a remote URL, or a launch that might
select another transport all keep the advisory in force.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mcp_audit.models import ServerConfig, TransportType

TRANSPORTS: frozenset[str] = frozenset({"stdio", "http", "sse"})

#: OpenVEX justification used when a tag clears a server.
JUSTIFICATION = "vulnerable_code_not_in_execute_path"

# Arguments that can switch a server off stdio.
_TRANSPORT_ARG = re.compile(
    r"^(?:-t|--transport|--port|--host|--sse|--http|--streamable[-_]http|--listen|"
    r"--bind)(?:[=:].*)?$",
    re.IGNORECASE,
)
_TRANSPORT_WORDS = frozenset({"sse", "http", "streamable-http", "streamable_http"})
_TRANSPORT_ENV = re.compile(r"(?:^|_)(?:TRANSPORT|PORT|HOST|BIND|LISTEN)(?:_|$)")


@dataclass(frozen=True)
class Tags:
    """A verified transport tag on one advisory."""

    transports: frozenset[str]
    requires_auth: bool | None
    verified_by: str


def tags_of(record: Any) -> Tags | None:
    """The record's tag, or ``None`` when it has none or it is not valid."""
    if not isinstance(record, dict) or "affected_transports" not in record:
        return None
    problems = tag_problems(record)
    if problems:
        return None
    auth = record.get("requires_auth")
    return Tags(
        frozenset(record["affected_transports"]),
        auth if isinstance(auth, bool) else None,
        str(record["verified_by"]).strip(),
    )


def tag_problems(record: dict) -> list[str]:
    """Why a record's reachability keys are not usable (empty when fine)."""
    out: list[str] = []
    has_any = any(
        k in record for k in ("affected_transports", "requires_auth", "verified_by")
    )
    if not has_any:
        return out
    transports = record.get("affected_transports")
    if (
        not isinstance(transports, list)
        or not transports
        or not all(isinstance(t, str) and t in TRANSPORTS for t in transports)
    ):
        out.append(
            "affected_transports must be a non-empty list of "
            f"{', '.join(sorted(TRANSPORTS))}"
        )
    if "requires_auth" in record and not isinstance(record["requires_auth"], bool):
        out.append("requires_auth must be true or false")
    verified = record.get("verified_by")
    if not isinstance(verified, str) or not verified.strip():
        out.append("verified_by must name who checked the tag and the source")
    return out


def provably_stdio(server: ServerConfig) -> bool:
    """True only when nothing in the config can put the server on a network.

    A command launch, no URL, a stdio transport, and no argument or
    environment variable that selects a transport or a listening address.
    """
    if server.transport is not TransportType.STDIO or server.url or not server.command:
        return False
    for arg in server.args:
        text = str(arg)
        if _TRANSPORT_ARG.match(text) or text.lower() in _TRANSPORT_WORDS:
            return False
    return not any(_TRANSPORT_ENV.search(k.upper()) for k in server.env)


def excludes_stdio(record: Any) -> Tags | None:
    """The tag, when it says the advisory does not apply to stdio servers."""
    tags = tags_of(record)
    if tags is not None and "stdio" not in tags.transports:
        return tags
    return None


def not_reachable(record: Any, server: ServerConfig) -> Tags | None:
    """The tag that clears *server* of this advisory, or ``None``."""
    tags = excludes_stdio(record)
    return tags if tags is not None and provably_stdio(server) else None
