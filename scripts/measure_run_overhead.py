#!/usr/bin/env python3
"""Measure the cold-start overhead ``mcp-audit run`` adds to a server launch.

EPIC-0009 Story 1.1. Times a trivial server (a Python one-liner that reads
one JSON-RPC line and answers it) launched directly and launched through the
wrapper, and prints the median of each and the difference. The result is
published in ``docs/run.md``; CI's runtime job prints it on every PR.

Usage:
    python scripts/measure_run_overhead.py [--runs N] [--wrapper CMD ...]

``--wrapper`` defaults to ``<python> -m mcp_audit._entry`` (the pip install).
Pass a frozen binary path to measure the PyInstaller build instead.
"""

from __future__ import annotations

import argparse
import statistics
import subprocess
import sys
import time

SERVER = [
    sys.executable,
    "-c",
    "import sys; sys.stdin.readline(); "
    'sys.stdout.write(\'{"jsonrpc":"2.0","id":1,"result":{}}\\n\')',
]
REQUEST = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'


def _time_once(argv: list[str]) -> float:
    start = time.perf_counter()
    out = subprocess.run(  # noqa: S603  # nosec B603 — fixed argv, shell=False
        argv, input=REQUEST, capture_output=True, timeout=60, check=True
    )
    elapsed = time.perf_counter() - start
    if b'"id":1' not in out.stdout:
        raise SystemExit(f"unexpected response from {argv[0]}: {out.stdout!r}")
    return elapsed


def main() -> int:
    """Print median direct and wrapped launch times in milliseconds."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=15)
    parser.add_argument(
        "--wrapper",
        nargs="+",
        default=[sys.executable, "-m", "mcp_audit._entry"],
        help="command that invokes mcp-audit (default: this Python's install)",
    )
    args = parser.parse_args()

    wrapped = [*args.wrapper, "run", "--", *SERVER]
    _time_once(SERVER)  # warm the OS file cache for both
    _time_once(wrapped)
    direct_ms = [_time_once(SERVER) * 1000 for _ in range(args.runs)]
    wrapped_ms = [_time_once(wrapped) * 1000 for _ in range(args.runs)]

    d = statistics.median(direct_ms)
    w = statistics.median(wrapped_ms)
    print(f"runs:      {args.runs}")
    print(f"direct:    {d:7.1f} ms (median)")
    print(f"wrapped:   {w:7.1f} ms (median)")
    print(f"overhead:  {w - d:7.1f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
