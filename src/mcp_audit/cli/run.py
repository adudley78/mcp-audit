"""``mcp-audit run`` as listed in the Typer app's help.

The console script dispatches ``run`` to :mod:`mcp_audit.runtime.cli` before
this app is imported (see :mod:`mcp_audit._entry`), so this command is only
reached when the Typer app is driven directly (for example by tests). It
forwards every argument untouched to the same lean implementation.
"""

from __future__ import annotations

import typer

from mcp_audit.cli import app
from mcp_audit.runtime.cli import DESCRIPTION
from mcp_audit.runtime.cli import main as run_main


@app.command(
    "run",
    help=f"{DESCRIPTION} Usage: mcp-audit run -- <server command> [args...]",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        "help_option_names": [],
    },
    add_help_option=False,
)
def run(ctx: typer.Context) -> None:
    """Launch an MCP server through the mcp-audit stdio relay."""
    # Click consumes the first ``--``; put it back so everything that
    # followed it reaches the server verbatim.
    raise typer.Exit(run_main(["--", *ctx.args]))
