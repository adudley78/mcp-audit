"""The ``version`` command."""

from __future__ import annotations

from mcp_audit import __version__
from mcp_audit.cli import app, console


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"mcp-audit {__version__}")
