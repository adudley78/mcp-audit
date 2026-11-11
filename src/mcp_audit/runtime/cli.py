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
from pathlib import Path

from mcp_audit.runtime.relay import mirror_exit, relay

USAGE = (
    "mcp-audit run [--config FILE --server NAME [--lock FILE] "
    "[--mode monitor|enforce]] -- <server command> [args...]"
)

DESCRIPTION = (
    "Launch an MCP server through mcp-audit. The AI client runs this "
    "instead of the server; stdin, stdout and stderr are relayed unchanged, "
    "and signals and the exit code pass through. With --config and --server, "
    "the launch is first checked against mcp-lock.json: monitor mode (the "
    "default) reports a problem on stderr and starts the server anyway; "
    "enforce mode refuses to start it. Once it runs, each tools/list answer "
    "is compared with the tool digests in the lock; enforce mode withholds "
    "tools that were added or changed."
)

#: Exit status when enforce mode refuses a launch (sysexits EX_CONFIG).
EXIT_REFUSED = 78
#: Exit status for a usage error.
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    """Return the parser for ``mcp-audit run``."""
    parser = argparse.ArgumentParser(
        prog="mcp-audit run",
        usage=USAGE,
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="the MCP config file that declares this server",
    )
    parser.add_argument(
        "--server",
        help="the server's name in that config file",
    )
    parser.add_argument(
        "--lock",
        type=Path,
        help="mcp-lock.json to check against (default: nearest above --config)",
    )
    parser.add_argument(
        "--mode",
        choices=("monitor", "enforce"),
        default="monitor",
        help="monitor (default): report and start; enforce: refuse to start",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="the server's original command and arguments, after --",
    )
    return parser


def parse(argv: Sequence[str]) -> tuple[argparse.Namespace, list[str]]:
    """Return ``(wrapper options, server command)`` from *argv*.

    Everything after the first ``--`` is the server command, verbatim, so a
    server flag such as ``--help`` or ``--mode`` is never taken by the
    wrapper.
    """
    args = list(argv)
    if "--" in args:
        split = args.index("--")
        options = build_parser().parse_args(args[:split])
        return options, args[split + 1 :]
    options = build_parser().parse_args(args)
    return options, list(options.command)


def parse_command(argv: Sequence[str]) -> list[str] | None:
    """Return the server command from *argv*, or ``None`` when there is none."""
    return parse(argv)[1] or None


def _say(message: str) -> None:
    sys.stderr.write(f"mcp-audit run: {message}\n")
    sys.stderr.flush()


def _gate(
    options: argparse.Namespace, command: list[str]
) -> tuple[int | None, object | None]:
    """Run the launch gate.

    Returns:
        ``(exit status to stop with or None, tool guard or None)``. A guard
        is returned whenever the server's lock entry was found, so the
        relay can compare its live tools with the lock (Story 1.4).
    """
    if options.config is None and options.server is None:
        if options.mode == "enforce":
            _say("--mode enforce needs --config and --server")
            return EXIT_USAGE, None
        return None, None
    if options.config is None or options.server is None:
        _say("--config and --server go together")
        return EXIT_USAGE, None

    from mcp_audit.runtime.gate import check_launch

    result = check_launch(
        command,
        config_path=options.config.expanduser().resolve(),
        server_name=options.server,
        lock_path=options.lock.expanduser().resolve() if options.lock else None,
    )
    if result.ok:
        from mcp_audit.runtime.tools import ToolGuard

        guard = ToolGuard(
            options.server,
            result.tools_record,
            enforce=options.mode == "enforce",
        )
        return None, guard
    if options.mode == "enforce":
        _say(f"refused: {result.finding_id} {result.summary}. Fix: {result.fix}")
        return EXIT_REFUSED, None
    _say(
        f"monitor: {result.finding_id} {result.summary} "
        f"(enforce mode would refuse to start it). Fix: {result.fix}"
    )
    return None, None


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``mcp-audit run`` and return (or die with) the server's exit status."""
    args = sys.argv[1:] if argv is None else argv
    options, command = parse(args)
    if not command:
        sys.stderr.write(f"usage: {USAGE}\n")
        return EXIT_USAGE
    stop, guard = _gate(options, command)
    if stop is not None:
        return stop
    return mirror_exit(relay(command, guard=guard))
