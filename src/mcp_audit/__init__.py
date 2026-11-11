"""mcp-audit — privacy-first security scanner for MCP server configurations."""

from __future__ import annotations


def __getattr__(name: str) -> str:
    """Resolve ``__version__`` lazily (PEP 562).

    ``importlib.metadata`` costs ~45 ms to import, and ``mcp-audit run`` sits
    on every wrapped server's launch path without ever needing the version,
    so it is only looked up on first access. ``from mcp_audit import
    __version__`` and ``mcp_audit.__version__`` both still work.
    """
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib.metadata import PackageNotFoundError, version

    try:
        # The PyPI distribution name is ``mcp-audit-scanner`` (the shorter
        # ``mcp-audit`` name was already taken).  The CLI command remains
        # ``mcp-audit`` — only the wheel/sdist distribution carries the longer
        # name.  Looking up the wrong key here silently falls through to the
        # hard-coded fallback, so every release pre-PyPI-publish used to ship
        # with a stale version string embedded in the binary.
        value = version("mcp-audit-scanner")
    except PackageNotFoundError:
        value = "0.5.0"
    globals()["__version__"] = value
    return value
