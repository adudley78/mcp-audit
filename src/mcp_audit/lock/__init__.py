"""``mcp-lock.json`` — a committable, reviewable record of approved MCP servers.

See ``docs/decisions/ADR-0005-mcp-audit-lock.md`` for the full design.  This
package is intentionally split the same way the ADR is organised:

- :mod:`mcp_audit.lock.model` — pydantic models, the ownership boundary
  (which top-level sections mcp-audit owns vs. treats as foreign), and the
  owned-section checksum.
- :mod:`mcp_audit.lock.identity` — pure identity canonicalization
  (``canonicalize_url``), exported for STORY-0071.
- :mod:`mcp_audit.lock.resolve` — thin wrappers over
  ``vulnerability.resolver`` / ``attestation.hasher`` for package resolution.
- :mod:`mcp_audit.lock.writer` — writes/regenerates ``mcp-lock.json``.
- :mod:`mcp_audit.lock.verifier` — ``lock --verify``; returns
  ``list[Finding]``.

Nothing in this package executes a package manager, connects to a live MCP
server, or enforces anything at runtime — it is a static, offline-by-default
record and comparator.  ``lock`` (write) may touch the network to resolve a
floating version; ``lock --verify`` never does unless ``--resolve`` is given.
"""

from __future__ import annotations
