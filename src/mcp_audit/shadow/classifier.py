"""Classify MCP servers as ``sanctioned`` or ``shadow``.

Classification is a pure function: given a server and an optional allowlist,
it returns ``"sanctioned"`` when the server appears in the allowlist and
``"shadow"`` otherwise.

Default is **all shadow** — nothing is sanctioned without an explicit allowlist.
This matches the CISO workflow: "everything is shadow until you say otherwise."
The known-server registry is a *trust signal* (reduces supply-chain risk), not
an allowlist; registry membership alone does not promote a server to sanctioned.
"""

from __future__ import annotations

from typing import Literal

from mcp_audit.models import ServerConfig
from mcp_audit.shadow.allowlist import AllowlistServerEntry, ShadowAllowlist

Classification = Literal["sanctioned", "shadow"]


def classify(
    server: ServerConfig,
    allowlist: ShadowAllowlist | None,
) -> Classification:
    """Classify a server as ``'sanctioned'`` or ``'shadow'``.

    Matching is performed against :attr:`~ShadowAllowlist.sanctioned_servers`
    entries in the following order:

    1. **String entry** — matched against (case-insensitively):
       - ``server.name``
       - ``server.command``
       - Any argument in ``server.args`` (catches npm package names like
         ``@modelcontextprotocol/server-filesystem`` in npx invocations)

    2. **Structured entry** — matched when ALL non-``None`` fields match:
       - ``entry.name`` matches ``server.name``
       - ``entry.command`` matches ``server.command``

    Args:
        server: The server configuration to classify.
        allowlist: The operator's allowlist.  ``None`` means no allowlist is
            configured — every server is ``'shadow'``.

    Returns:
        ``'sanctioned'`` if the server matches an allowlist entry, otherwise
        ``'shadow'``.
    """
    if allowlist is None:
        return "shadow"

    for item in allowlist.sanctioned_servers:
        if (isinstance(item, str) and _string_matches_server(item, server)) or (
            isinstance(item, AllowlistServerEntry)
            and _entry_matches_server(item, server)
        ):
            return "sanctioned"

    return "shadow"


# ── Private helpers ───────────────────────────────────────────────────────────


def _string_matches_server(value: str, server: ServerConfig) -> bool:
    """Return True if *value* matches the server by name, command, or any arg."""
    lower = value.lower()

    if lower == server.name.lower():
        return True

    if server.command and lower == server.command.lower():
        return True

    return any(lower == arg.lower() for arg in server.args)


def _entry_matches_server(entry: AllowlistServerEntry, server: ServerConfig) -> bool:
    """Return True if the structured entry matches the server.

    A structured entry with no fields set (both ``name`` and ``command`` are
    ``None``) never matches — it would be a misconfigured entry.
    """
    if entry.name is None and entry.command is None:
        return False

    name_ok = entry.name is None or entry.name.lower() == server.name.lower()
    cmd_ok = entry.command is None or (
        server.command is not None and entry.command.lower() == server.command.lower()
    )

    return name_ok and cmd_ok
