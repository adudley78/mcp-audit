#!/usr/bin/env python3
"""Sync (or verify) count references in README.md and CLAUDE.md.

Canonical sources of truth:
- Test count:       ``uv run pytest --collect-only -q``
- SAST rule count:  individual ``id:`` entries inside ``semgrep-rules/**/*.yml``
- Community rules:  ``*.yml`` files under ``rules/community/``
- Analyzer count:   concrete ``BaseAnalyzer`` subclasses in ``src/mcp_audit/analyzers/``
  (i.e. ``class XxxAnalyzer(BaseAnalyzer)`` in any file except ``base.py``)

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

import yaml

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Substitution table
# ---------------------------------------------------------------------------
# Each entry: (relative_path, search_regex, replacement_template)
# Templates use named placeholders from the kwargs passed to str.format():
#   test-count:    {count}  {formatted}
#   SAST:          {sast_total}  {sast_py}  {sast_ts}
#   community:     {community_count}
#   analyzers:     {analyzer_count}
#
# str.format() silently ignores unused keys, so every entry receives the full
# set of kwargs — only the relevant ones are substituted.
# ---------------------------------------------------------------------------
_SUBSTITUTIONS: list[tuple[str, str, str]] = [
    # --- test count ---
    ("CLAUDE.md", r"\b\d{3,6} tests passing\b", "{count} tests passing"),
    ("README.md", r"\b[\d,]+ tests validate\b", "{formatted} tests validate"),
    ("README.md", r"\bRun all [\d,]+ tests\b", "Run all {formatted} tests"),
    (
        ".github/release-notes-template.md",
        r"\b[\d,]+ tests · Apache 2\.0\b",
        "{formatted} tests · Apache 2.0",
    ),
    # --- SAST rule counts (README.md) ---
    (
        "README.md",
        r"\d+ Semgrep rules \(\d+ Python, \d+ TypeScript\)",
        "{sast_total} Semgrep rules ({sast_py} Python, {sast_ts} TypeScript)",
    ),
    # --- SAST rule counts (CLAUDE.md — two occurrences, same pattern) ---
    (
        "CLAUDE.md",
        r"\d+ Semgrep rules \(\d+ Python, \d+ TypeScript\)",
        "{sast_total} Semgrep rules ({sast_py} Python, {sast_ts} TypeScript)",
    ),
    # --- community rule count (README.md) ---
    (
        "README.md",
        r"\d+ community rules ship bundled",
        "{community_count} community rules ship bundled",
    ),
    # --- community rule count (CLAUDE.md) ---
    (
        "CLAUDE.md",
        r"\d+ community rules ship bundled",
        "{community_count} community rules ship bundled",
    ),
    # --- analyzer count — "N analyzers:" list item (CLAUDE.md) ---
    (
        "CLAUDE.md",
        r"\b\d+ analyzers:",
        "{analyzer_count} analyzers:",
    ),
    # --- analyzer count — "has N analyzers" prose (CLAUDE.md) ---
    (
        "CLAUDE.md",
        r"has \d+ analyzers\b",
        "has {analyzer_count} analyzers",
    ),
]


# ---------------------------------------------------------------------------
# Count collectors
# ---------------------------------------------------------------------------


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


def _collect_sast_counts(rules_dir: Path | None = None) -> tuple[int, int, int]:
    """Return ``(total, python_count, typescript_count)`` for SAST rules.

    Counts individual rule *definitions* (entries in the ``rules:`` list of
    each ``.yml`` file) rather than file count, because a single file may
    contain several rules.  Only files that parse as a valid Semgrep rule file
    (top-level ``rules`` key) are counted; test fixtures that lack this key
    are excluded.
    """
    if rules_dir is None:
        rules_dir = ROOT / "semgrep-rules"
    total = py_count = ts_count = 0
    for yml_file in sorted(rules_dir.rglob("*.yml")):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "rules" not in data:
            continue
        for rule in data["rules"]:
            langs = rule.get("languages", [])
            total += 1
            if "python" in langs:
                py_count += 1
            if "typescript" in langs:
                ts_count += 1
    return total, py_count, ts_count


def _collect_community_rule_count(community_dir: Path | None = None) -> int:
    """Return the number of ``.yml`` files in ``rules/community/``."""
    if community_dir is None:
        community_dir = ROOT / "rules" / "community"
    return sum(1 for _ in community_dir.glob("*.yml"))


def _collect_analyzer_count(analyzers_dir: Path | None = None) -> int:
    """Return the number of concrete ``BaseAnalyzer`` subclasses.

    Scans every ``.py`` file under ``src/mcp_audit/analyzers/`` except
    ``base.py`` for the pattern ``class XxxAnalyzer(BaseAnalyzer``.
    ``attack_paths.py`` does not subclass ``BaseAnalyzer`` so it is naturally
    excluded.  ``rug_pull.py`` and ``toxic_flow.py`` do subclass it and are
    counted even though their primary interface is ``analyze_all()``.
    """
    if analyzers_dir is None:
        analyzers_dir = ROOT / "src" / "mcp_audit" / "analyzers"
    count = 0
    for py_file in sorted(analyzers_dir.glob("*.py")):
        if py_file.name == "base.py":
            continue
        text = py_file.read_text(encoding="utf-8")
        count += len(
            re.findall(r"^class \w+Analyzer\(BaseAnalyzer", text, re.MULTILINE)
        )
    return count


# ---------------------------------------------------------------------------
# Core apply loop
# ---------------------------------------------------------------------------


def _apply(*, check_only: bool) -> int:
    """Apply (or check) all substitutions.  Returns exit code (0 or 1)."""
    test_count = _collect_test_count()
    test_formatted = f"{test_count:,}"
    sast_total, sast_py, sast_ts = _collect_sast_counts()
    community_count = _collect_community_rule_count()
    analyzer_count = _collect_analyzer_count()

    print(f"Detected {test_count} tests ({test_formatted} formatted).")
    print(
        f"Detected {sast_total} SAST rules "
        f"({sast_py} Python, {sast_ts} TypeScript)."
    )
    print(f"Detected {community_count} community rules.")
    print(f"Detected {analyzer_count} concrete analyzers.")

    fmt_kwargs = {
        "count": test_count,
        "formatted": test_formatted,
        "sast_total": sast_total,
        "sast_py": sast_py,
        "sast_ts": sast_ts,
        "community_count": community_count,
        "analyzer_count": analyzer_count,
    }

    drift_found = False
    for rel, pattern, template in _SUBSTITUTIONS:
        path = ROOT / rel
        if not path.exists():
            print(f"  WARN: {rel} does not exist — skipping", file=sys.stderr)
            continue

        text = path.read_text(encoding="utf-8")
        replacement = template.format(**fmt_kwargs)
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
            print(
                f"  DRIFT: {rel} is stale for pattern /{pattern}/",
                file=sys.stderr,
            )
        else:
            path.write_text(new_text, encoding="utf-8")
            print(f"  updated: {rel} ({n} replacement{'s' if n > 1 else ''})")

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
