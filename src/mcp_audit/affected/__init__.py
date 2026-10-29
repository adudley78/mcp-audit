"""``mcp-audit affected``: "is this advisory here?" (STORY-0121, EPIC-0008).

Pure decision code lives in :mod:`~mcp_audit.affected.query` (what was asked),
:mod:`~mcp_audit.affected.match` (the per-server decision) and
:mod:`~mcp_audit.affected.render` (terminal, JSON, SARIF).  Nothing here runs
a scanned program or ``git``, and nothing touches the network unless the CLI
was given ``--live``.
"""
