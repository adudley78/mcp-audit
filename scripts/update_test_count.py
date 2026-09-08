#!/usr/bin/env python3
"""Sync (or verify) count references in README.md and CLAUDE.md.

Canonical sources of truth:
- Test count:       ``uv run pytest --collect-only -q``
- SAST rule count:  individual ``id:`` entries inside ``semgrep-rules/**/*.yml``
- Community rules:  ``*.yml`` files under ``rules/community/`` (includes the
  always-inert ``TEMPLATE.yml``/``COMM-000`` — this is the same total
  ``mcp-audit rule list`` prints, and the same one ``community_count`` below
  has always meant; see the R43 manual-test-matrix baseline for why this is
  the intended convention, not an oversight)
- Community rule ID range: highest numeric ``COMM-NNN`` id among the
  *non-template* files in ``rules/community/`` (independent of
  ``community_count`` — a future reserved/unissued id, like ``COMM-032``
  today, can make these two numbers diverge; see ``PROVENANCE.md``)
- Real (non-template) community rule count: ``community_count`` minus
  ``TEMPLATE.yml`` itself
- Registry entry count: ``entry_count`` field in ``registry/known-servers.json``
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
import json
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
#   community:     {community_count}  {community_max_id:03d}
#   registry:      {registry_count}
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
    # --- community rule total + real-rule count + COMM-NNN range form
    # (CLAUDE.md). This is the phrase that let the R43 drift go unseen: the
    # old regex for "N community rules ship bundled" (above) never matched
    # this sentence, so --check stayed green while this line said 30 and
    # reality said 34.
    (
        "CLAUDE.md",
        r"\d+ bundled community rules total: \d+ real detection rules"
        r" \(`COMM-001` through `COMM-\d+`;",
        "{community_count} bundled community rules total:"
        " {real_community_count} real detection rules"
        " (`COMM-001` through `COMM-{community_max_id:03d}`;",
    ),
    # --- registry entry count — "curated dataset of N known-legitimate MCP
    # servers" prose form (CLAUDE.md) ---
    (
        "CLAUDE.md",
        r"curated dataset of \d+ known-legitimate MCP servers",
        "curated dataset of {registry_count} known-legitimate MCP servers",
    ),
    # --- registry entry count — "N-entry curated dataset" form (CLAUDE.md) ---
    (
        "CLAUDE.md",
        r"\d+-entry curated dataset of legitimate MCP servers",
        "{registry_count}-entry curated dataset of legitimate MCP servers",
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
    """Return the number of ``.yml`` files in ``rules/community/``.

    This intentionally includes ``TEMPLATE.yml`` (loaded as ``COMM-000``) —
    it is the same total ``load_bundled_community_rules()`` returns and
    ``mcp-audit rule list`` prints as "N bundled community rule(s)", and the
    convention every existing "N community rules ship bundled" reference in
    README.md/CLAUDE.md already follows. See
    ``tests/test_manual_test_matrix.py`` for a live assertion that this
    number matches ``docs/manual-test-matrix.md``.
    """
    if community_dir is None:
        community_dir = ROOT / "rules" / "community"
    return sum(1 for _ in community_dir.glob("*.yml"))


def _collect_community_max_id(community_dir: Path | None = None) -> int:
    """Return the highest numeric ``COMM-NNN`` id among *real* community rules.

    Deliberately excludes ``TEMPLATE.yml`` (``COMM-000``) and is computed
    independently of :func:`_collect_community_rule_count` — the two numbers
    coincide today only because exactly one id (``COMM-032``) is reserved and
    unissued (see ``PROVENANCE.md``). A second reserved id in the future
    would make ``community_count`` and ``community_max_id`` diverge; treating
    them as interchangeable would silently reintroduce the R43 drift this
    script exists to close.
    """
    if community_dir is None:
        community_dir = ROOT / "rules" / "community"
    max_id = 0
    for yml_file in sorted(community_dir.glob("*.yml")):
        if yml_file.name == "TEMPLATE.yml":
            continue
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        rule_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(rule_id, str):
            continue
        match = re.match(r"^COMM-(\d+)$", rule_id)
        if match:
            max_id = max(max_id, int(match.group(1)))
    if max_id == 0:
        raise SystemExit(
            f"Error: found no COMM-NNN rule ids under {community_dir} "
            "(excluding TEMPLATE.yml) — is the directory empty or moved?"
        )
    return max_id


def _collect_real_community_rule_count(community_dir: Path | None = None) -> int:
    """Return the count of real (non-template) files in ``rules/community/``.

    Equal to :func:`_collect_community_rule_count` minus ``TEMPLATE.yml``
    itself. Kept as its own collector (rather than ``community_count - 1``
    inline) so a future second non-rule file in the directory fails a count
    mismatch loudly instead of silently going stale by one.
    """
    if community_dir is None:
        community_dir = ROOT / "rules" / "community"
    return sum(1 for p in community_dir.glob("*.yml") if p.name != "TEMPLATE.yml")


def _collect_registry_entry_count(registry_path: Path | None = None) -> int:
    """Return the ``entry_count`` field from ``registry/known-servers.json``.

    Cross-checked against ``len(entries)`` so a hand-edited, out-of-sync
    ``entry_count`` field fails loudly instead of quietly propagating a wrong
    number into every doc this script writes.
    """
    if registry_path is None:
        registry_path = ROOT / "registry" / "known-servers.json"
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    declared = data.get("entry_count")
    actual = len(data.get("entries", []))
    if declared != actual:
        raise SystemExit(
            f"Error: {registry_path} entry_count={declared!r} but "
            f"len(entries)={actual} — the registry file is internally "
            "inconsistent; fix it before trusting either number."
        )
    return actual


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
    community_max_id = _collect_community_max_id()
    real_community_count = _collect_real_community_rule_count()
    registry_count = _collect_registry_entry_count()
    analyzer_count = _collect_analyzer_count()

    print(f"Detected {test_count} tests ({test_formatted} formatted).")
    print(f"Detected {sast_total} SAST rules ({sast_py} Python, {sast_ts} TypeScript).")
    print(
        f"Detected {community_count} community rules "
        f"(COMM-001 through COMM-{community_max_id:03d})."
    )
    print(f"Detected {registry_count} registry entries.")
    print(f"Detected {analyzer_count} concrete analyzers.")

    fmt_kwargs = {
        "count": test_count,
        "formatted": test_formatted,
        "sast_total": sast_total,
        "sast_py": sast_py,
        "sast_ts": sast_ts,
        "community_count": community_count,
        "community_max_id": community_max_id,
        "real_community_count": real_community_count,
        "registry_count": registry_count,
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
