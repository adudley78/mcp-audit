"""Pins the 2026-11 CI/CD hardening against the year's registry-worm patterns.

TanStack (CVE-2026-45321), IronWorm, Bitwarden CLI and Mini Shai-Hulud all
turned code that ran in CI into a publish or write credential. Each test
below names the property it keeps, so a later edit that drops it fails here
instead of at the next incident.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
BUILD_BINARY = ROOT / ".github" / "actions" / "build-binary" / "action.yml"

# (workflow file, job) pairs whose checkout must keep git credentials because
# the job pushes with git.
PUSHING_JOBS = {
    ("advisory-feed-publish.yml", "publish"),
    ("release.yml", "tag-major"),
}


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(job: dict) -> list[dict]:
    return job.get("steps", [])


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_declares_top_level_permissions(wf: Path) -> None:
    """No workflow inherits the repository's default token scope."""
    assert "permissions" in _load(wf), wf.name


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_checkouts_do_not_persist_credentials(wf: Path) -> None:
    for job_id, job in _load(wf)["jobs"].items():
        for step in _steps(job):
            if not str(step.get("uses", "")).startswith("actions/checkout@"):
                continue
            persist = (step.get("with") or {}).get("persist-credentials")
            if (wf.name, job_id) in PUSHING_JOBS:
                continue
            assert persist is False, f"{wf.name}:{job_id} persists credentials"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_no_pull_request_target(wf: Path) -> None:
    """pull_request_target runs fork code with base-repo trust (TanStack)."""
    on = _load(wf).get(True) or _load(wf).get("on") or {}
    assert "pull_request_target" not in on, wf.name


def test_release_top_level_token_is_read_only() -> None:
    assert _load(RELEASE)["permissions"] == {"contents": "read"}


def test_pypi_oidc_job_runs_no_project_code() -> None:
    """The job holding id-token: write downloads and uploads, nothing else."""
    job = _load(RELEASE)["jobs"]["publish-pypi"]
    assert job["permissions"] == {"id-token": "write"}
    uses = [s.get("uses", "") for s in _steps(job)]
    assert all(u for u in uses), "publish-pypi must have no run: steps"
    assert not any(u.startswith("actions/checkout@") for u in uses)
    assert [u.split("@")[0] for u in uses] == [
        "actions/download-artifact",
        "pypa/gh-action-pypi-publish",
    ]


def test_dist_is_built_without_id_token() -> None:
    job = _load(RELEASE)["jobs"]["build-dist"]
    assert job["permissions"] == {"contents": "read"}
    runs = "\n".join(str(s.get("run", "")) for s in _steps(job))
    assert "uv build" in runs


def test_only_the_jobs_that_must_write_can_write() -> None:
    jobs = _load(RELEASE)["jobs"]
    writers = {
        name
        for name, job in jobs.items()
        if "write" in (job.get("permissions") or {}).values()
    }
    assert writers == {"attest", "release", "publish-pypi", "tag-major"}
    assert jobs["attest"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert not any("run" in s for s in _steps(jobs["attest"]))


def test_binaries_are_attested_before_release() -> None:
    jobs = _load(RELEASE)["jobs"]
    assert "attest" in jobs["release"]["needs"]
    uses = [s.get("uses", "") for s in _steps(jobs["attest"])]
    assert any(u.startswith("actions/attest-build-provenance@") for u in uses)


def test_setup_action_verifies_provenance_after_cache_and_download() -> None:
    steps = _load(ROOT / "setup-action" / "action.yml")["runs"]["steps"]
    names = [s.get("name") for s in steps]
    verify = names.index("Verify build provenance")
    assert verify > names.index("Restore binary from cache")
    assert verify > names.index("Download binary (Windows)")
    assert "if" not in steps[verify], "must run on cache hits too"
    assert "gh attestation verify" in steps[verify]["run"]


def test_release_paths_use_no_actions_cache() -> None:
    """A cache entry is what a less-trusted run can leave for a release run."""
    for doc, steps in (
        (RELEASE.name, [s for j in _load(RELEASE)["jobs"].values() for s in _steps(j)]),
        (BUILD_BINARY.name, _load(BUILD_BINARY)["runs"]["steps"]),
    ):
        for step in steps:
            if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"):
                assert step["with"].get("enable-cache") is False, doc
            assert not str(step.get("uses", "")).startswith("actions/cache"), doc


def test_build_binary_installs_only_locked_dependencies() -> None:
    runs = "\n".join(
        str(s.get("run", "")) for s in _load(BUILD_BINARY)["runs"]["steps"]
    )
    assert "uv sync --all-extras --locked" in runs
    assert "uv pip install" not in runs


@pytest.mark.parametrize(
    "path",
    [BUILD_BINARY, ROOT / "action.yml", ROOT / "setup-action" / "action.yml"],
    ids=lambda p: str(p.relative_to(ROOT)),
)
def test_composite_inputs_never_expand_inside_scripts(path: Path) -> None:
    """`${{ inputs.x }}` in run: is shell injection; pass it through env."""
    for step in _load(path)["runs"]["steps"]:
        assert not re.search(r"\$\{\{\s*inputs\.", str(step.get("run", ""))), step.get(
            "name"
        )


def test_dependabot_version_updates_wait_a_week() -> None:
    cfg = _load(ROOT / ".github" / "dependabot.yml")
    for update in cfg["updates"]:
        assert update.get("cooldown", {}).get("default-days", 0) >= 7


# ── diff/loader.py: git is queried, never trusted ───────────────────────────


class TestDiffGitHardening:
    def test_option_shaped_ref_is_refused_before_git_runs(self) -> None:
        from mcp_audit.diff.loader import _load_from_git_sha  # noqa: PLC0415

        with (
            patch("mcp_audit.diff.loader.subprocess.run") as run,
            pytest.raises(ValueError, match="Not a usable git ref"),
        ):
            _load_from_git_sha("--output=/tmp/pwned")
        run.assert_not_called()

    def test_reads_blobs_with_cat_file_bounded_and_without_fsmonitor(self) -> None:
        from mcp_audit.diff import loader  # noqa: PLC0415

        ok = MagicMock(returncode=0, stdout=b"abc")
        missing = MagicMock(returncode=128, stdout=b"")
        calls: list[tuple[list[str], dict]] = []

        def fake(cmd: list[str], **kw: object) -> MagicMock:
            calls.append((cmd, kw))
            return ok if "rev-parse" in cmd else missing

        with patch("mcp_audit.diff.loader.subprocess.run", side_effect=fake):
            assert loader._load_from_git_sha("HEAD") == []
        for cmd, kw in calls:
            assert cmd[:3] == ["git", "-c", "core.fsmonitor=false"]
            assert "show" not in cmd
            assert kw["timeout"] == loader.GIT_TIMEOUT_SECONDS
        assert any("cat-file" in c for c, _ in calls)

    def test_non_utf8_blob_does_not_crash(self) -> None:
        from mcp_audit.diff import loader  # noqa: PLC0415

        ok = MagicMock(returncode=0, stdout=b"abc")
        blob = MagicMock(returncode=0, stdout=b'{"mcpServers": {}}\xff\xfe')

        def fake(cmd: list[str], **kw: object) -> MagicMock:
            return ok if "rev-parse" in cmd else blob

        with patch("mcp_audit.diff.loader.subprocess.run", side_effect=fake):
            assert loader._load_from_git_sha("HEAD") == []
