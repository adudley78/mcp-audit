"""Runtime wrapper for MCP servers (``credenzo run``, EPIC-0009).

The AI client launches ``credenzo run -- <original command>`` instead of the
server. This package must stay lean: it is on every server's launch path, so
nothing here may import the scanner, analyzers, registry loader, Typer or Rich.
``tests/test_runtime_entry.py`` pins that.
"""
