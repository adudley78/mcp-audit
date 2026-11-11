"""RFC 8785 JSON Canonicalization Scheme (JCS) — see :mod:`mcp_audit._jcs`.

The implementation lives in :mod:`mcp_audit._jcs` so the ``mcp-audit run``
launch path can use it without importing this package's feed and signing
code. Every existing ``from mcp_audit.advisory.canonical import ...`` keeps
working and gets the same objects.
"""

from __future__ import annotations

from mcp_audit._jcs import (  # noqa: F401 — re-exported; one implementation
    MAX_DEPTH,
    MAX_NODES,
    CanonicalError,
    canonicalize,
    canonicalize_str,
)

__all__ = ["CanonicalError", "canonicalize", "canonicalize_str"]
