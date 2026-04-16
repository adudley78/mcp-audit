"""mcp-audit — privacy-first security scanner for MCP server configurations."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-audit")
except PackageNotFoundError:
    __version__ = "0.1.0"
