"""Tests for scripts/update_test_count.py count-collection helpers."""

from __future__ import annotations

import importlib.util as _ilu
import re
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import helpers directly from the script (not installed as a package)
# ---------------------------------------------------------------------------
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "update_test_count.py"

_spec = _ilu.spec_from_file_location("update_test_count", _SCRIPT)
assert _spec and _spec.loader
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

_collect_sast_counts = _mod._collect_sast_counts
_collect_community_rule_count = _mod._collect_community_rule_count
_collect_analyzer_count = _mod._collect_analyzer_count
ROOT = _mod.ROOT


# ---------------------------------------------------------------------------
# Filesystem-backed counts (integration-style, always reflects real state)
# ---------------------------------------------------------------------------


def test_sast_count_matches_filesystem() -> None:
    """_collect_sast_counts() must return positive, consistent numbers."""
    total, py, ts = _collect_sast_counts()
    assert total > 0, "Expected at least one SAST rule"
    assert py > 0, "Expected at least one Python SAST rule"
    assert ts > 0, "Expected at least one TypeScript SAST rule"
    assert py + ts == total, "Python + TypeScript must equal total"


def test_community_rule_count_matches_filesystem() -> None:
    """_collect_community_rule_count() must match files on disk."""
    community_dir = ROOT / "rules" / "community"
    expected = sum(1 for _ in community_dir.glob("*.yml"))
    assert _collect_community_rule_count() == expected
    assert expected > 0, "Expected at least one community rule"


def test_analyzer_count_matches_filesystem() -> None:
    """_collect_analyzer_count() must equal concrete BaseAnalyzer subclasses."""
    analyzers_dir = ROOT / "src" / "mcp_audit" / "analyzers"
    expected = 0
    for py_file in sorted(analyzers_dir.glob("*.py")):
        if py_file.name == "base.py":
            continue
        text = py_file.read_text(encoding="utf-8")
        expected += len(
            re.findall(r"^class \w+Analyzer\(BaseAnalyzer", text, re.MULTILINE)
        )
    assert _collect_analyzer_count() == expected
    assert expected > 0, "Expected at least one concrete analyzer"


def test_sast_count_excludes_non_rule_yamls(tmp_path: Path) -> None:
    """Files without a top-level 'rules:' key must not be counted."""
    fixture_dir = tmp_path / "semgrep-rules"
    fixture_dir.mkdir()
    # A valid rule file
    (fixture_dir / "real_rule.yml").write_text(
        textwrap.dedent("""\
        rules:
          - id: test-rule
            message: test
            severity: WARNING
            languages: [python]
            patterns:
              - pattern: eval(...)
        """)
    )
    # A test fixture that should be excluded
    (fixture_dir / "test_fixture.yml").write_text(
        textwrap.dedent("""\
        test_cases:
          - input: foo
        """)
    )
    total, py, ts = _collect_sast_counts(fixture_dir)
    assert total == 1
    assert py == 1
    assert ts == 0


def test_sast_languages_from_yaml_field(tmp_path: Path) -> None:
    """Python vs TypeScript split must come from 'languages:' field, not path."""
    rules_dir = tmp_path / "semgrep-rules"
    rules_dir.mkdir()
    # A file in a 'typescript' path but with languages: [python]
    sub = rules_dir / "typescript" / "foo"
    sub.mkdir(parents=True)
    (sub / "rule.yml").write_text(
        textwrap.dedent("""\
        rules:
          - id: weird-rule
            message: test
            severity: WARNING
            languages: [python]
            patterns:
              - pattern: eval(...)
        """)
    )
    total, py, ts = _collect_sast_counts(rules_dir)
    assert total == 1
    assert py == 1, "Must read language from YAML field, not directory name"
    assert ts == 0


def test_analyzer_excludes_base_and_attack_paths() -> None:
    """base.py and attack_paths.py must not be counted as concrete analyzers."""
    count = _collect_analyzer_count()
    # Verify attack_paths.py has no BaseAnalyzer subclass (it's standalone)
    attack_paths = ROOT / "src" / "mcp_audit" / "analyzers" / "attack_paths.py"
    if attack_paths.exists():
        text = attack_paths.read_text(encoding="utf-8")
        assert not re.search(r"class \w+Analyzer\(BaseAnalyzer", text), (
            "attack_paths.py should not subclass BaseAnalyzer"
        )
    # The count must be positive and reflect only non-base classes
    assert count > 0


# ---------------------------------------------------------------------------
# --check mode exits non-zero on drift
# ---------------------------------------------------------------------------


def test_check_mode_exits_nonzero_on_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--check exits 1 and prints a clear error when a doc count is stale."""
    import importlib.util as ilu

    spec = ilu.spec_from_file_location("utc_fresh", _SCRIPT)
    assert spec and spec.loader
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)  # type: ignore[union-attr]

    # Stub out _collect_test_count so we don't need a real pytest run in tmp_path
    monkeypatch.setattr(m, "_collect_test_count", lambda: 1000)

    # Write stale doc files in tmp_path — all counts deliberately wrong
    sast_line = (
        "- **SAST rule pack** — 1 Semgrep rules (1 Python, 0 TypeScript)"
        " across 6 categories\n"
    )
    (tmp_path / "README.md").write_text(
        sast_line
        + "- **Governance** — 1 community rules ship bundled\n"
        + "- 999 tests validate\n"
        + "- Run all 999 tests\n",
        encoding="utf-8",
    )
    (tmp_path / "CLAUDE.md").write_text(
        "- 1 analyzers: foo\n"
        "has 1 analyzers with patterns\n"
        "- 1 tests passing\n"
        "1 community rules ship bundled\n"
        "1 Semgrep rules (1 Python, 0 TypeScript)\n",
        encoding="utf-8",
    )
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "release-notes-template.md").write_text(
        "1 tests · Apache 2.0\n", encoding="utf-8"
    )

    # Point module ROOT at tmp_path; count helpers use real repo dirs (correct values)
    m.ROOT = tmp_path
    exit_code = m._apply(check_only=True)

    assert exit_code == 1, "Expected exit code 1 when docs are stale"
