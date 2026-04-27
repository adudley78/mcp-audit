#!/usr/bin/env python3
"""Sync (or verify) the test-count references in README.md and CLAUDE.md.

The canonical source of truth is ``uv run pytest --collect-only -q``; this
script parses its trailing "NNNN tests collected in X.YYs" line and rewrites
every hand-maintained count reference in the docs to match.

Usage
-----
    ./scripts/update_test_count.py           # rewrite docs in place
    ./scripts/update_test_count.py --check   # exit 1 if any doc is stale

Wire ``--check`` into CI to prevent new drift; run the unflagged form before
tagging a release.

Exit codes
----------
- 0: docs are in sync (or were updated successfully)
- 1: ``--check`` found drift, or pytest output could not be parsed
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (path, regex, replacement-template) — templates may use ``{count}`` (raw int)
# or ``{formatted}`` (comma-separated).  Regexes are crafted to match both the
# current value and any future drift without catching unrelated numbers.
_SUBSTITUTIONS: list[tuple[str, str, str]] = [
    ("CLAUDE.md", r"\b\d{3,6} tests passing\b", "{count} tests passing"),
    ("README.md", r"\b[\d,]+ tests validate\b", "{formatted} tests validate"),
    ("README.md", r"\bRun all [\d,]+ tests\b", "Run all {formatted} tests"),
    # The release-notes template is rendered into every GitHub Release body
    # by `.github/workflows/release.yml` — match the test-count badge line
    # ("**1,308 tests · Apache 2.0 · …**") via its Apache 2.0 suffix so the
    # regex cannot accidentally strike any of the surrounding bullet points.
    (
        ".github/release-notes-template.md",
        r"\b[\d,]+ tests · Apache 2\.0\b",
        "{formatted} tests · Apache 2.0",
    ),
]


def _collect_test_count() -> int:
    """Return the integer count reported by ``pytest --collect-only -q``."""
    # Use the same Python interpreter that is running this script so the count
    # reflects whichever environment the caller activated (uv venv, system pip
    # install, etc.).  Calling ``uv run pytest`` here would spin up a fresh uv
    # venv that omits optional extras, producing a lower count than the
    # environment the tests actually ran in.
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],  # noqa: S603
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    # The final non-empty line is always ``NNNN tests collected in X.YYs``.
    for line in reversed(proc.stdout.strip().splitlines()):
        match = re.match(r"^\s*(\d+)\s+tests?\s+collected\b", line)
        if match:
            return int(match.group(1))
    raise SystemExit(
        "Error: could not parse test count from pytest --collect-only output.\n"
        f"---\n{proc.stdout}\n---"
    )


def _apply(*, check_only: bool) -> int:
    count = _collect_test_count()
    formatted = f"{count:,}"
    print(f"Detected {count} tests ({formatted} formatted).")

    drift_found = False
    for rel, pattern, template in _SUBSTITUTIONS:
        path = ROOT / rel
        if not path.exists():
            print(f"  WARN: {rel} does not exist — skipping", file=sys.stderr)
            continue

        text = path.read_text(encoding="utf-8")
        replacement = template.format(count=count, formatted=formatted)
        new_text, n = re.subn(pattern, replacement, text)

        if n == 0:
            print(
                f"  WARN: no match for /{pattern}/ in {rel} — "
                "doc text may have changed; update this script",
                file=sys.stderr,
            )
            continue

        if new_text == text:
            suffix = "es" if n > 1 else ""
            print(f"  ok: {rel} already in sync ({n} match{suffix})")
            continue

        drift_found = True
        if check_only:
            print(f"  DRIFT: {rel} is stale", file=sys.stderr)
        else:
            path.write_text(new_text, encoding="utf-8")
            print(f"  updated: {rel}")

    if check_only and drift_found:
        print(
            "\nRun `./scripts/update_test_count.py` to fix.",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any doc file is out of sync; do not modify anything.",
    )
    args = parser.parse_args()
    return _apply(check_only=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
