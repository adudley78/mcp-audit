"""Console-script entry point for ``mcp-audit``.

``mcp-audit run`` sits on every wrapped MCP server's launch path, so it is
dispatched here, before the Typer app (and with it the scanner, analyzers and
registry) is imported. Every other subcommand goes to :mod:`mcp_audit.cli`
unchanged.
"""

from __future__ import annotations

import sys


def main() -> None:
    """Dispatch ``run`` to the lean runtime path, everything else to Typer."""
    if sys.argv[1:2] == ["run"]:
        from mcp_audit.runtime.cli import main as run_main

        sys.exit(run_main(sys.argv[2:]))

    from mcp_audit.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
