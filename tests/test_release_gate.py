"""scripts/release_gate.py: when a bump becomes a release, and when a run publishes."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from scripts.release_gate import GateError, decide_publish, decide_tag, main

ROOT = Path(__file__).resolve().parent.parent
BUMP_YML = ROOT / ".github" / "workflows" / "release-on-version-bump.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"

CHANGELOG = (
    "# Changelog\n\n## [Unreleased]\n\n"
    "## [0.22.0] - 2026-10-20\n\n### Added\n\n- A new check.\n\n---\n\n"
    "## [0.21.0] - 2026-10-13\n\n### Added\n\n- Digests.\n"
)
TAGS = "v0 v0.20.0 v0.21.0"


# ── tag: is a release tag due for this commit? ────────────────────────────


def test_new_version_with_notes_is_due() -> None:
    d = decide_tag("0.22.0", "0.21.0", CHANGELOG, TAGS)
    assert d.go and d.tag == "v0.22.0"


def test_already_tagged_is_a_quiet_noop() -> None:
    assert not decide_tag("0.21.0", "0.20.0", CHANGELOG, TAGS).go


def test_dependabot_edit_never_tags_a_pending_bump() -> None:
    """0.22.0 is bumped but untagged; a later pyproject edit must not tag HEAD."""
    d = decide_tag("0.22.0", "0.22.0", CHANGELOG, TAGS)
    assert not d.go
    assert "did not change" in d.reason


def test_bump_without_changelog_section_fails() -> None:
    with pytest.raises(GateError, match=r"no '## \[0.23.0\]' section"):
        decide_tag("0.23.0", "0.22.0", CHANGELOG, TAGS)


def test_bump_with_empty_changelog_section_fails() -> None:
    """The release job would fail on empty notes after PyPI already published."""
    empty = "## [Unreleased]\n\n## [0.23.0] - 2026-10-27\n\n---\n\n## [0.22.0]\n\n- x\n"
    with pytest.raises(GateError, match="is empty"):
        decide_tag("0.23.0", "0.22.0", empty, TAGS)


def test_unreleased_heading_does_not_count_as_a_section() -> None:
    with pytest.raises(GateError):
        decide_tag("0.22.1", "0.22.0", "## [Unreleased]\n0.22.1\n", TAGS)


def test_bump_backwards_fails() -> None:
    changelog = CHANGELOG + "\n## [0.20.5] - 2026-10-01\n\n- Fix.\n"
    with pytest.raises(GateError, match="lower than the latest release tag v0.21.0"):
        decide_tag("0.20.5", "0.20.4", changelog, TAGS)


def test_floating_major_tags_are_ignored() -> None:
    assert decide_tag("0.22.0", None, CHANGELOG, "v0 v1").go


def test_parent_with_a_dev_version_still_counts_as_changed() -> None:
    assert decide_tag("0.22.0", "0.22.0.dev0", CHANGELOG, TAGS).go


# ── publish: may this release.yml run publish? ────────────────────────────


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
    d = decide_publish(event, ref, publish, "0.22.0", on_main, CHANGELOG, TAGS)
    assert d.go is expected


@pytest.mark.parametrize(
    ("event", "ref", "publish", "on_main", "message"),
    [
        ("workflow_dispatch", "refs/heads/main", "true", True, "needs a vX.Y.Z tag"),
        ("workflow_dispatch", "refs/tags/v0.22.0-rc1", "true", True, "vX.Y.Z tag"),
        ("workflow_dispatch", "refs/tags/v0.23.0", "true", True, "does not match"),
        ("push", "refs/tags/v0.22.0", "false", False, "not on main"),
        ("workflow_dispatch", "refs/tags/v0.22.0", "true", False, "not on main"),
        ("schedule", "refs/tags/v0.22.0", "true", True, "does not publish"),
    ],
)
def test_publish_refusals_fail_loudly(event, ref, publish, on_main, message) -> None:
    with pytest.raises(GateError, match=message):
        decide_publish(event, ref, publish, "0.22.0", on_main, CHANGELOG, TAGS)


def test_publish_refuses_a_tag_without_release_notes() -> None:
    """A hand-pushed tag gets the same changelog check as an automated one."""
    with pytest.raises(GateError, match=r"no '## \[0.23.0\]' section"):
        decide_publish("push", "refs/tags/v0.23.0", "", "0.23.0", True, CHANGELOG, TAGS)


def test_publish_refuses_a_tag_behind_the_latest_release() -> None:
    changelog = CHANGELOG + "\n## [0.20.5] - 2026-10-01\n\n- Fix.\n"
    with pytest.raises(GateError, match="lower than the latest release tag v0.21.0"):
        decide_publish(
            "push",
            "refs/tags/v0.20.5",
            "",
            "0.20.5",
            True,
            changelog,
            TAGS + " v0.20.5",
        )


def test_publish_ignores_its_own_tag_when_comparing() -> None:
    d = decide_publish(
        "push", "refs/tags/v0.22.0", "", "0.22.0", True, CHANGELOG, TAGS + " v0.22.0"
    )
    assert d.go


# ── CLI ───────────────────────────────────────────────────────────────────


def _pyproject(path: Path, version: str) -> Path:
    path.write_text(f'[project]\nname = "x"\nversion = "{version}"\n')
    return path


def test_cli_publish_writes_github_output(tmp_path: Path, monkeypatch) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG)
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    args = ["publish", "--pyproject", str(_pyproject(tmp_path / "p.toml", "0.22.0"))]
    args += ["--changelog", str(changelog), "--tags", TAGS, "--event", "push"]
    assert main([*args, "--ref", "refs/tags/v0.22.0", "--on-main", "true"]) == 0
    assert out.read_text() == "publish=true\n"


def test_cli_publish_refusal_exits_one(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG)
    args = ["publish", "--pyproject", str(_pyproject(tmp_path / "p.toml", "0.22.0"))]
    args += ["--changelog", str(changelog), "--event", "workflow_dispatch"]
    args += ["--ref", "refs/heads/main", "--publish", "true", "--on-main", "true"]
    assert main(args) == 1


def test_cli_dry_run_decides_before_reading_the_version(
    tmp_path: Path, monkeypatch
) -> None:
    """A dry-run dispatch from a branch on a dev version must still build."""
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    dev = _pyproject(tmp_path / "p.toml", "0.23.0.dev0")
    args = ["publish", "--pyproject", str(dev), "--changelog", str(tmp_path / "none")]
    args += ["--event", "workflow_dispatch", "--ref", "refs/heads/x"]
    assert main([*args, "--publish", "false", "--on-main", "false"]) == 0
    assert out.read_text() == "publish=false\n"


def test_cli_tag_reads_the_parent_version(tmp_path: Path, monkeypatch) -> None:
    head = _pyproject(tmp_path / "head.toml", "0.22.0")
    parent = _pyproject(tmp_path / "parent.toml", "0.22.0")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG)
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    args = ["tag", "--pyproject", str(head), "--changelog", str(changelog)]
    args += ["--previous-pyproject", str(parent), "--tags", TAGS]
    assert main(args) == 0
    assert out.read_text() == "create=false\ntag=v0.22.0\n"
    _pyproject(parent, "0.21.0")
    out.write_text("")
    assert main(args) == 0
    assert out.read_text() == "create=true\ntag=v0.22.0\n"


# ── workflow wiring ───────────────────────────────────────────────────────


def _steps(job: dict) -> dict[str, dict]:
    return {step.get("name", ""): step for step in job["steps"]}


def test_version_bump_workflow_tags_the_checked_commit_only() -> None:
    wf = yaml.safe_load(BUMP_YML.read_text(encoding="utf-8"))
    on = wf[True]  # PyYAML reads the `on:` key as boolean True
    assert on["push"] == {"branches": ["main"], "paths": ["pyproject.toml"]}
    assert on["workflow_dispatch"]["inputs"]["sha"]["required"] is True
    assert wf["permissions"] == {}
    assert wf["concurrency"]["group"] == (
        "release-on-version-bump-${{ inputs.sha || github.sha }}"
    )
    job = wf["jobs"]["tag-and-dispatch"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["permissions"] == {"contents": "write", "actions": "write"}
    steps = _steps(job)

    resolve = steps["Resolve the commit to release"]
    assert resolve["env"]["INPUT_SHA"] == "${{ inputs.sha }}"
    assert 'SHA="${INPUT_SHA:-$GITHUB_SHA}"' in resolve["run"]
    assert "^[0-9a-f]{40}$" in resolve["run"]
    assert 'git merge-base --is-ancestor "$SHA" FETCH_HEAD' in resolve["run"]
    assert 'git show "$SHA:pyproject.toml"' in resolve["run"]
    assert 'git show "$SHA^:pyproject.toml"' in resolve["run"]

    decide = steps["Decide whether this commit is a release"]
    assert "release_gate.py tag" in decide["run"]
    assert '--previous-pyproject "$RUNNER_TEMP/previous.toml"' in decide["run"]

    create = steps["Create the release tag"]
    assert create["if"] == "steps.decide.outputs.create == 'true'"
    assert create["env"]["SHA"] == "${{ steps.commit.outputs.sha }}"
    assert '-f "ref=refs/tags/$TAG" -f "sha=$SHA"' in create["run"]
    assert "git push" not in create["run"]  # exits 0 on an existing tag

    dispatch = steps["Dispatch release.yml on the tag"]
    assert dispatch["if"] == "steps.decide.outputs.create == 'true'"
    assert '--ref "$TAG" -f publish=true' in dispatch["run"]
    names = list(steps)
    assert names.index("Create the release tag") < names.index(
        "Dispatch release.yml on the tag"
    )

    for step in job["steps"]:
        assert "${{" not in step.get("run", "")  # inputs reach shell via env only


def test_release_gate_job_wiring() -> None:
    wf = yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))
    jobs = wf["jobs"]
    run = _steps(jobs["gate"])["Check the tag, the version, and main"]["run"]
    assert "if git merge-base --is-ancestor HEAD FETCH_HEAD; then" in run
    assert '--on-main "$ON_MAIN"' in run
    assert "--on-main true" not in run
    assert '--ref "$GITHUB_REF"' in run
    assert "--tags \"$(git tag -l 'v*.*.*')\"" in run
    assert jobs["release"]["needs"] == ["build", "gate"]
    assert jobs["publish-pypi"]["needs"] == ["build", "gate"]
    assert jobs["tag-major"]["needs"] == ["build", "gate", "release", "publish-pypi"]
