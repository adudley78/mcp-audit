"""Console-script entry point for ``credenzo`` (and its old name, ``mcp-audit``).

``credenzo run`` sits on every wrapped MCP server's launch path, so it is
dispatched here, before the Typer app (and with it the scanner, analyzers and
registry) is imported. Every other subcommand goes to :mod:`mcp_audit.cli`
unchanged.
"""

from __future__ import annotations

import sys


def _old_name_notice() -> None:
    """Say once, to a person, that the command has a new name.

    Only when the old name was typed and stderr is a terminal: a script, a CI
    job or a hook that calls ``mcp-audit`` sees no change in its output.
    """
    name = sys.argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.startswith("mcp-audit") and sys.stderr.isatty():
        print(
            "mcp-audit is now credenzo. Both commands work; use `credenzo`.",
            file=sys.stderr,
        )


def main() -> None:
    """Dispatch ``run`` to the lean runtime path, everything else to Typer."""
    if sys.argv[1:2] == ["run"]:
        from mcp_audit.runtime.cli import main as run_main

        sys.exit(run_main(sys.argv[2:]))

    _old_name_notice()

    from mcp_audit.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
