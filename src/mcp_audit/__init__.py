"""mcp-audit — privacy-first security scanner for MCP server configurations."""

from importlib.metadata import PackageNotFoundError, version

try:
    # The PyPI distribution name is ``mcp-audit-scanner`` (the shorter
    # ``mcp-audit`` name was already taken).  The CLI command remains
    # ``mcp-audit`` — only the wheel/sdist distribution carries the longer
    # name.  Looking up the wrong key here silently falls through to the
    # hard-coded fallback, so every release pre-PyPI-publish used to ship
    # with a stale version string embedded in the binary.
    __version__ = version("mcp-audit-scanner")
except PackageNotFoundError:
    __version__ = "0.5.0"
