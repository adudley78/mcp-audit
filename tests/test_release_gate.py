"""scripts/release_gate.py: when a bump becomes a release, and when a run publishes."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.release_gate import GateError, decide_publish, decide_tag, main

CHANGELOG = (
    "# Changelog\n\n## [Unreleased]\n\n"
    "## [0.22.0] - 2026-10-20\n\n## [0.21.0] - 2026-10-13\n"
)
TAGS = "v0 v0.20.0 v0.21.0"


def test_new_version_with_section_is_due() -> None:
    d = decide_tag("0.22.0", "0.21.0", CHANGELOG, TAGS)
    assert d.go and d.tag == "v0.22.0"


def test_already_tagged_is_a_quiet_noop() -> None:
    d = decide_tag("0.21.0", "0.20.0", CHANGELOG, TAGS)
    assert not d.go


def test_bump_without_changelog_section_fails() -> None:
    with pytest.raises(GateError, match="no '## \\[0.23.0\\]' section"):
        decide_tag("0.23.0", "0.22.0", CHANGELOG, TAGS)


def test_bump_backwards_fails() -> None:
    changelog = CHANGELOG + "\n## [0.20.5] - 2026-10-01\n"
    with pytest.raises(GateError, match="lower than the latest"):
        decide_tag("0.20.5", "0.20.4", changelog, TAGS)


def test_dependabot_edit_never_tags_a_pending_bump() -> None:
    """0.22.0 is bumped but untagged; a later pyproject edit must not tag HEAD."""
    d = decide_tag("0.22.0", "0.22.0", CHANGELOG, TAGS)
    assert not d.go
    assert "did not change" in d.reason


def test_floating_major_tags_are_ignored() -> None:
    assert decide_tag("0.22.0", None, CHANGELOG, "v0 v1").go


def test_unreleased_heading_does_not_count_as_a_section() -> None:
    with pytest.raises(GateError):
        decide_tag("0.22.1", "0.22.0", "## [Unreleased]\n0.22.1\n", TAGS)


@pytest.mark.parametrize(
    ("event", "ref", "publish", "on_main", "expected"),
    [
        ("push", "refs/tags/v0.22.0", "false", True, True),
        ("workflow_dispatch", "refs/tags/v0.22.0", "true", True, True),
        ("workflow_dispatch", "refs/tags/v0.22.0", "false", True, False),
        ("workflow_dispatch", "refs/heads/main", "false", True, False),
        ("workflow_dispatch", "refs/heads/feature", "", False, False),
    ],
)
def test_publish_decisions(event, ref, publish, on_main, expected) -> None:
    assert decide_publish(event, ref, publish, "0.22.0", on_main).go is expected


@pytest.mark.parametrize(
    ("event", "ref", "publish", "on_main", "message"),
    [
        ("workflow_dispatch", "refs/heads/main", "true", True, "needs a vX.Y.Z tag"),
        (
            "workflow_dispatch",
            "refs/tags/v0.22.0-rc1",
            "true",
            True,
            "needs a vX.Y.Z tag",
        ),
        ("workflow_dispatch", "refs/tags/v0.23.0", "true", True, "does not match"),
        ("push", "refs/tags/v0.22.0", "false", False, "not on main"),
        ("workflow_dispatch", "refs/tags/v0.22.0", "true", False, "not on main"),
        ("schedule", "refs/tags/v0.22.0", "true", True, "does not publish"),
    ],
)
def test_publish_refusals_fail_loudly(event, ref, publish, on_main, message) -> None:
    with pytest.raises(GateError, match=message):
        decide_publish(event, ref, publish, "0.22.0", on_main)


def test_cli_writes_github_output(tmp_path: Path, monkeypatch) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\nversion = "0.22.0"\n')
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    code = main(
        [
            "publish",
            "--pyproject",
            str(pyproject),
            "--event",
            "push",
            "--ref",
            "refs/tags/v0.22.0",
            "--on-main",
            "true",
        ]
    )
    assert code == 0
    assert out.read_text() == "publish=true\n"


def test_cli_refusal_exits_one(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\nversion = "0.22.0"\n')
    code = main(
        [
            "publish",
            "--pyproject",
            str(pyproject),
            "--event",
            "workflow_dispatch",
            "--ref",
            "refs/heads/main",
            "--publish",
            "true",
            "--on-main",
            "true",
        ]
    )
    assert code == 1


def test_cli_tag_reads_the_parent_version(tmp_path: Path, monkeypatch) -> None:
    head = tmp_path / "head.toml"
    head.write_text('[project]\nname = "x"\nversion = "0.22.0"\n')
    parent = tmp_path / "parent.toml"
    parent.write_text('[project]\nname = "x"\nversion = "0.22.0"\n')
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG)
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    args = ["tag", "--pyproject", str(head), "--changelog", str(changelog)]
    assert main([*args, "--previous-pyproject", str(parent), "--tags", TAGS]) == 0
    assert "create=false" in out.read_text()
    parent.write_text('[project]\nname = "x"\nversion = "0.21.0"\n')
    out.write_text("")
    assert main([*args, "--previous-pyproject", str(parent), "--tags", TAGS]) == 0
    assert out.read_text() == "create=true\ntag=v0.22.0\n"


def test_version_bump_workflow_shape() -> None:
    """Runs on main pushes, holds only the two scopes it needs, no inline inputs."""
    import yaml

    root = Path(__file__).resolve().parent.parent
    wf = yaml.safe_load(
        (root / ".github/workflows/release-on-version-bump.yml").read_text()
    )
    on = wf[True]  # PyYAML reads the `on:` key as boolean True
    assert on["push"]["branches"] == ["main"]
    assert on["push"]["paths"] == ["pyproject.toml"]
    assert wf["permissions"] == {}
    job = wf["jobs"]["tag-and-dispatch"]
    assert job["permissions"] == {"contents": "write", "actions": "write"}
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "${{" not in runs
    assert "release_gate.py tag" in runs
    assert "--previous-pyproject" in runs
    assert "-f publish=true" in runs
