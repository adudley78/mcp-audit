"""Package marker for the bundled mcp-audit project signing keys.

Holds no code — ``mcp-audit-feed.pub`` is force-included here by
``pyproject.toml`` so :func:`importlib.resources.files` can locate it inside
an installed wheel the same way ``mcp_audit.registry`` locates
``known-servers.json``. See ``docs/advisory-feed.md`` ("Key custody and
rotation") for what this key is and how it is used.
"""
