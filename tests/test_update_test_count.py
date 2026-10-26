"""Tests for scripts/update_test_count.py count-collection helpers."""

from __future__ import annotations

import importlib.util as _ilu
import json
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
_collect_community_max_id = _mod._collect_community_max_id
_collect_real_community_rule_count = _mod._collect_real_community_rule_count
_collect_registry_entry_count = _mod._collect_registry_entry_count
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


def test_community_max_id_excludes_template_and_matches_filesystem() -> None:
    """_collect_community_max_id() must equal the highest real COMM-NNN id."""
    community_dir = ROOT / "rules" / "community"
    expected = 0
    for yml_file in sorted(community_dir.glob("*.yml")):
        if yml_file.name == "TEMPLATE.yml":
            continue
        import yaml

        data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
        rule_id = data.get("id") if isinstance(data, dict) else None
        if isinstance(rule_id, str):
            m = re.match(r"^COMM-(\d+)$", rule_id)
            if m:
                expected = max(expected, int(m.group(1)))
    assert _collect_community_max_id() == expected
    assert expected > 0, "Expected at least one real COMM-NNN rule id"


def test_real_community_rule_count_excludes_template() -> None:
    """_collect_real_community_rule_count() == total count minus TEMPLATE.yml."""
    assert _collect_real_community_rule_count() == _collect_community_rule_count() - 1


def test_registry_entry_count_matches_declared_field() -> None:
    """_collect_registry_entry_count() must equal the JSON's own entry_count."""
    registry_path = ROOT / "registry" / "known-servers.json"
    import json as _json

    data = _json.loads(registry_path.read_text(encoding="utf-8"))
    assert _collect_registry_entry_count() == data["entry_count"]
    assert _collect_registry_entry_count() == len(data["entries"])


def test_registry_entry_count_raises_on_internal_mismatch(tmp_path: Path) -> None:
    """A registry file whose entry_count disagrees with len(entries) must abort."""
    bad_registry = tmp_path / "known-servers.json"
    bad_registry.write_text(
        json.dumps({"entry_count": 5, "entries": [{"name": "only-one"}]}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit):
        _collect_registry_entry_count(bad_registry)


def test_community_max_id_raises_when_no_real_rules(tmp_path: Path) -> None:
    """An empty (or template-only) community dir must fail loudly, not return 0."""
    empty_dir = tmp_path / "community"
    empty_dir.mkdir()
    (empty_dir / "TEMPLATE.yml").write_text("id: COMM-000\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        _collect_community_max_id(empty_dir)


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

    # _apply() unconditionally calls every collector (including
    # _collect_community_max_id and _collect_registry_entry_count, added in
    # R43) before it ever looks at a substitution pattern, and both of those
    # fail loudly — by design — when their source directory/file is missing
    # rather than silently returning 0 (see their docstrings). Once ROOT is
    # repointed at tmp_path below, both would find nothing and abort the
    # test before it ever reaches the drift-detection assertion this test is
    # actually about. Provide the minimal real inputs those two collectors
    # need so they resolve normally; their specific values are irrelevant
    # here since this test asserts exit-code-on-drift, not any single count.
    community_dir = tmp_path / "rules" / "community"
    community_dir.mkdir(parents=True)
    (community_dir / "COMM-001.yml").write_text(
        "id: COMM-001\nseverity: LOW\n", encoding="utf-8"
    )
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir()
    (registry_dir / "known-servers.json").write_text(
        json.dumps({"entry_count": 1, "entries": [{"name": "test-server"}]}),
        encoding="utf-8",
    )
    # _collect_release_version (STORY-0102) also reads ROOT/pyproject.toml.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "0.21.1"\n', encoding="utf-8"
    )

    # Point module ROOT at tmp_path; count helpers use real repo dirs (correct values)
    m.ROOT = tmp_path
    exit_code = m._apply(check_only=True)

    assert exit_code == 1, "Expected exit code 1 when docs are stale"


# ---------------------------------------------------------------------------
# Release pin (STORY-0102): docs examples name the version pyproject.toml ships
# ---------------------------------------------------------------------------

_PRE_COMMIT_PIN_FILES = _mod._PRE_COMMIT_PIN_FILES
_ACTION_PIN_DOCS = _mod._ACTION_REF_DOCS
_VERSION_INPUT_DOCS = _mod._VERSION_INPUT_DOCS
_PIP_PIN_DOCS = _mod._PIP_PIN_DOCS

# What each pin pattern must match, counted independently of the pattern:
# every occurrence of the thing being pinned. A reshaped example (an extra
# blank line under ``repo:``, a quoted ``version: 'v0.21.1'``, a ``uses:``
# with a different spacing) then fails here instead of silently dropping out
# of --check, which only WARNs on a pattern that matches nothing.
_PIN_ANCHORS = {
    _mod._PRE_COMMIT_REV_PATTERN: (
        r"(?m)^[ \t-]*repo: https://github\.com/adudley78/mcp-audit[ \t]*$"
    ),
    _mod._ACTION_REF_PATTERN: r"uses:\s*adudley78/mcp-audit[/@]",
    _mod._VERSION_INPUT_PATTERN: r"(?m)^[ \t]+version:\s*['\"]?v\d",
    _mod._PIP_PIN_PATTERN: r"mcp-audit-scanner==",
}


def _fresh_module() -> object:
    """Load a private copy of the script so ROOT can be repointed safely."""
    spec = _ilu.spec_from_file_location("utc_pins", _SCRIPT)
    assert spec and spec.loader
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)  # type: ignore[union-attr]
    return m


def _stub_counts(m: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub every count collector so _apply() only exercises the pins."""
    monkeypatch.setattr(m, "_collect_test_count", lambda: 1)
    monkeypatch.setattr(m, "_collect_sast_counts", lambda: (2, 1, 1))
    monkeypatch.setattr(m, "_collect_community_rule_count", lambda: 2)
    monkeypatch.setattr(m, "_collect_community_max_id", lambda: 1)
    monkeypatch.setattr(m, "_collect_real_community_rule_count", lambda: 1)
    monkeypatch.setattr(m, "_collect_registry_entry_count", lambda: 1)
    monkeypatch.setattr(m, "_collect_analyzer_count", lambda: 1)


def test_release_version_is_pyproject_project_version() -> None:
    """The pin source is [project].version, the field release_gate.py tags."""
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert _mod._collect_release_version() == data["project"]["version"]


@pytest.mark.parametrize("version", ["0.22.0.dev1", "0.22", "", None])
def test_release_version_rejects_non_release_versions(
    tmp_path: Path, version: str | None
) -> None:
    """A version no release tag can match must fail loudly, not be written."""
    body = "[project]\n" + (f'version = "{version}"\n' if version is not None else "")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(body, encoding="utf-8")
    with pytest.raises(SystemExit, match="not an X.Y.Z release version"):
        _mod._collect_release_version(pyproject)


def _pin_rows() -> list[tuple[str, str, str]]:
    return [row for row in _mod._SUBSTITUTIONS if "{release_" in row[2]]


def test_pin_rows_cover_exactly_the_pinned_files() -> None:
    by_pattern: dict[str, set[str]] = {}
    for rel, pattern, _ in _pin_rows():
        by_pattern.setdefault(pattern, set()).add(rel)
    assert by_pattern == {
        _mod._PRE_COMMIT_REV_PATTERN: set(_PRE_COMMIT_PIN_FILES),
        _mod._ACTION_REF_PATTERN: set(_ACTION_PIN_DOCS),
        _mod._VERSION_INPUT_PATTERN: set(_VERSION_INPUT_DOCS),
        _mod._PIP_PIN_PATTERN: set(_PIP_PIN_DOCS),
    }


_PATTERN_NAMES = {
    _mod._PRE_COMMIT_REV_PATTERN: "pre-commit-rev",
    _mod._ACTION_REF_PATTERN: "action-uses",
    _mod._VERSION_INPUT_PATTERN: "version-input",
    _mod._PIP_PIN_PATTERN: "pip-pin",
}


@pytest.mark.parametrize(
    ("rel", "pattern"),
    [
        pytest.param(rel, pattern, id=f"{_PATTERN_NAMES[pattern]}:{rel}")
        for rel, pattern, _ in _pin_rows()
    ],
)
def test_every_pinned_example_is_matched(rel: str, pattern: str) -> None:
    """Each pin row matches every occurrence of what it pins, and at least one."""
    text = (ROOT / rel).read_text(encoding="utf-8")
    matched = len(re.findall(pattern, text))
    expected = len(re.findall(_PIN_ANCHORS[pattern], text))
    assert expected > 0, f"{rel} no longer contains anything this row pins"
    assert matched == expected, (
        f"{rel}: pattern matched {matched} of {expected} pinned examples; "
        "an example has a shape the script would not rewrite"
    )


def test_readme_examples_are_pinned_to_the_current_release() -> None:
    """README never tells users to run the action from ``@main`` or a dead tag."""
    tag = f"v{_mod._collect_release_version()}"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "adudley78/mcp-audit@main" not in readme
    assert f"uses: adudley78/mcp-audit@{tag}" in readme
    assert re.search(
        rf"repo: https://github\.com/adudley78/mcp-audit\n\s+rev: {re.escape(tag)}\b",
        readme,
    )


def test_check_flags_stale_pins_and_rewrite_fixes_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A version bump makes --check fail until the same PR rewrites the pins."""
    m = _fresh_module()
    _stub_counts(m, monkeypatch)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "0.22.0"\n', encoding="utf-8"
    )
    pre_commit = (
        "repos:\n"
        "  - repo: https://github.com/adudley78/mcp-audit\n"
        "    rev: v0.21.1  # current release\n"
        "    hooks:\n"
        "      - id: mcp-audit\n"
    )
    other_repo = "  - repo: https://github.com/someone/else\n    rev: v0.21.1\n"
    (tmp_path / "README.md").write_text(
        "        uses: adudley78/mcp-audit@main\n" + pre_commit + other_repo,
        encoding="utf-8",
    )
    for rel in _PRE_COMMIT_PIN_FILES[1:]:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(pre_commit, encoding="utf-8")
    sha_pin = "- uses: adudley78/mcp-audit@" + "32b648a3" * 5 + " # v0.10.0\n"
    action_doc = (
        "- uses: adudley78/mcp-audit@main\n"
        "- uses: adudley78/mcp-audit@v0.3.3  # comment kept\n"
        "- uses: adudley78/mcp-audit/setup-action@v0.10.0\n" + sha_pin
    )
    prose = "Lock verification was added in `adudley78/mcp-audit@v0.17.0`.\n"
    version_input = "      - uses: x/y@v1\n        with:\n          version: v0.21.1\n"
    pip_pin = "pip install mcp-audit-scanner==0.21.1\n"
    assert _ACTION_PIN_DOCS[0] == _VERSION_INPUT_DOCS[0] == "README.md"
    for rel in _ACTION_PIN_DOCS[1:]:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        before = path.read_text(encoding="utf-8") if path.exists() else ""
        path.write_text(action_doc + prose + before, encoding="utf-8")
    for rel in _VERSION_INPUT_DOCS[1:]:
        path = tmp_path / rel
        path.write_text(path.read_text(encoding="utf-8") + version_input, "utf-8")
    for rel in _PIP_PIN_DOCS:
        (tmp_path / rel).write_text(pip_pin, encoding="utf-8")
    monkeypatch.setattr(m, "ROOT", tmp_path)

    assert m._apply(check_only=True) == 1
    assert "@main" in (tmp_path / "README.md").read_text(encoding="utf-8")

    assert m._apply(check_only=False) == 0
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "uses: adudley78/mcp-audit@v0.22.0" in readme
    assert "    rev: v0.22.0  # current release\n" in readme
    assert other_repo in readme, "a different repo's rev must not be touched"
    for rel in _PRE_COMMIT_PIN_FILES[1:]:
        assert "rev: v0.22.0" in (tmp_path / rel).read_text(encoding="utf-8")
    for rel in _ACTION_PIN_DOCS[1:]:
        text = (tmp_path / rel).read_text(encoding="utf-8")
        assert prose in text, f"{rel}: prose citing an old release was rewritten"
        if rel in _VERSION_INPUT_DOCS:
            assert text.endswith("          version: v0.22.0\n"), rel
        assert text.startswith(
            "- uses: adudley78/mcp-audit@v0.22.0\n"
            "- uses: adudley78/mcp-audit@v0.22.0  # comment kept\n"
            "- uses: adudley78/mcp-audit/setup-action@v0.22.0\n" + sha_pin
        ), f"{rel}: tags and @main move; a SHA pin is left alone"
    for rel in _PIP_PIN_DOCS:
        text = (tmp_path / rel).read_text(encoding="utf-8")
        assert text == "pip install mcp-audit-scanner==0.22.0\n"
    assert m._apply(check_only=True) == 0
