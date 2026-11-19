"""``credenzo guard`` as listed in the Typer app's help.

The console script dispatches ``guard`` to :mod:`mcp_audit.runtime.guard`
before this app is imported (see :mod:`mcp_audit._entry`): it is a Claude Code
hook that runs before every MCP tool call. This command is only reached when
the Typer app is driven directly (for example by tests); it forwards every
argument untouched to the same lean implementation.
"""

from __future__ import annotations

import typer

from mcp_audit.cli import app
from mcp_audit.runtime.guard import DESCRIPTION
from mcp_audit.runtime.guard import main as guard_main


@app.command(
    "guard",
    help=f"{DESCRIPTION} Run `credenzo guard --print-hook` for the settings.",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        "help_option_names": [],
    },
    add_help_option=False,
)
def guard(ctx: typer.Context) -> None:
    """Deny an MCP tool call that mcp-lock.json does not approve."""
    raise typer.Exit(guard_main(list(ctx.args)))
