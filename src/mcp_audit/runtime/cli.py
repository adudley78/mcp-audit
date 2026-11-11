"""Argument parsing for ``mcp-audit run`` (lean path, stdlib only).

``mcp-audit run`` is on every wrapped server's launch path, so it is parsed
with :mod:`argparse` rather than through the Typer app, which imports the
whole scanner. :mod:`mcp_audit._entry` dispatches here before anything heavy
is imported.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from mcp_audit.runtime.relay import mirror_exit, relay

USAGE = "mcp-audit run -- <server command> [args...]"

DESCRIPTION = (
    "Launch an MCP server through mcp-audit. The AI client runs this "
    "instead of the server; stdin, stdout and stderr are relayed unchanged, "
    "and signals and the exit code pass through."
)


def build_parser() -> argparse.ArgumentParser:
    """Return the parser for ``mcp-audit run``."""
    parser = argparse.ArgumentParser(
        prog="mcp-audit run",
        usage=USAGE,
        description=DESCRIPTION,
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="the server's original command and arguments, after --",
    )
    return parser


def parse_command(argv: Sequence[str]) -> list[str] | None:
    """Return the server command from *argv*, or ``None`` for help/usage.

    Everything after the first ``--`` is the server command, verbatim, so a
    server flag such as ``--help`` or ``--version`` is never taken by the
    wrapper.
    """
    args = list(argv)
    if "--" in args:
        split = args.index("--")
        own, command = args[:split], args[split + 1 :]
        build_parser().parse_args(own)  # rejects unknown wrapper flags
        return command
    parsed = build_parser().parse_args(args)
    command = list(parsed.command)
    return command or None


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``mcp-audit run`` and return (or die with) the server's exit status."""
    args = sys.argv[1:] if argv is None else argv
    command = parse_command(args)
    if not command:
        sys.stderr.write(f"usage: {USAGE}\n")
        return 2
    return mirror_exit(relay(command))
