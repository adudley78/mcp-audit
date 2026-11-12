"""CRED-005: secrets in permission rules that git history still holds (STORY-0153)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_audit.analyzers import rule_secret_history as hist
from mcp_audit.models import Severity

GIT = shutil.which("git") or "git"
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

# Built from pieces so the repository holds no token-shaped literal.
GH_TOKEN = "gh" + "p_" + "a" * 36
DB_PASSWORD = "hunter2" + "secret"
LEAKY = f"Bash(GITHUB_TOKEN={GH_TOKEN} gh pr list)"
LEAKY_2 = f"Bash(PGPASSWORD={DB_PASSWORD} psql -h db -U app)"
CLEAN = "Bash(npm test *)"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 — git resolved via shutil.which
        [GIT, "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def _repo(tmp_path: Path, name: str = "app") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("x")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _write_settings(
    repo: Path, rules: list[str], name: str = "settings.local.json"
) -> None:
    (repo / ".claude").mkdir(exist_ok=True)
    (repo / ".claude" / name).write_text(json.dumps({"permissions": {"allow": rules}}))


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _scan(start: Path) -> tuple[list, list[str]]:
    errors: list[str] = []
    return hist.scan_repository_history(start, errors), errors


class TestHistory:
    def test_deleted_file_with_secret_is_reported_high(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY, CLEAN])
        _commit(repo, "leak")
        _git(repo, "rm", "-q", ".claude/settings.local.json")
        _commit(repo, "remove")
        findings, errors = _scan(repo)
        assert errors == []
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "CRED-005"
        assert f.severity == Severity.HIGH
        assert "GITHUB_TOKEN=[REDACTED]" in f.evidence
        assert GH_TOKEN not in f.model_dump_json()
        assert Path(f.finding_path).parts[-2:] == (".claude", "settings.local.json")
        assert "1 commit(s)" in f.description

    def test_rule_removed_but_file_kept(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY, LEAKY_2], name="settings.json")
        _commit(repo, "leak")
        _write_settings(repo, [LEAKY_2], name="settings.json")
        _commit(repo, "remove one")
        findings, _ = _scan(repo)
        assert len(findings) == 1
        # LEAKY_2 is still in today's file: CRED-004 reports it, not CRED-005.
        assert "GITHUB_TOKEN=[REDACTED]" in findings[0].evidence
        assert "PGPASSWORD" not in findings[0].evidence

    def test_secret_still_in_the_file_is_left_to_cred_004(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        assert _scan(repo)[0] == []

    def test_never_committed_file_is_silent(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        (repo / ".gitignore").write_text(".claude/settings.local.json\n")
        _commit(repo, "ignore")
        _write_settings(repo, [LEAKY])
        assert _scan(repo)[0] == []

    def test_clean_history_is_silent(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [CLEAN])
        _commit(repo, "ok")
        _git(repo, "rm", "-q", "-r", ".claude")
        _commit(repo, "remove")
        assert _scan(repo)[0] == []

    def test_secret_only_on_another_branch_is_found(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _git(repo, "checkout", "-q", "-b", "feature")
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak on a branch")
        _git(repo, "checkout", "-q", "-")
        findings, _ = _scan(repo)
        assert [f.id for f in findings] == ["CRED-005"]

    def test_packed_history_and_subdirectory_start(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        for i in range(20):
            _write_settings(repo, [CLEAN, f"Bash(echo {i})"])
            _commit(repo, f"c{i}")
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        _write_settings(repo, [CLEAN])
        _commit(repo, "fix")
        _git(repo, "repack", "-adq", "--depth=50")
        (repo / "sub").mkdir()
        findings, _ = _scan(repo / "sub")
        assert len(findings) == 1

    def test_shallow_clone_reports_missing_history(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        for i in range(3):
            (repo / "README.md").write_text(str(i))
            _commit(repo, f"c{i}")
        clone = tmp_path / "clone"
        subprocess.run(  # noqa: S603 — git resolved via shutil.which
            [GIT, "clone", "-q", "--depth", "1", repo.as_uri(), str(clone)],
            check=True,
            capture_output=True,
        )
        findings, errors = _scan(clone)
        assert findings == []
        assert any("shallow clone" in e for e in errors)
        assert not any(str(tmp_path) in e for e in errors)

    def test_sha256_repository_is_skipped_with_an_error(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        with (repo / ".git" / "config").open("a") as fh:
            fh.write("[extensions]\n\tobjectFormat = sha256\n")
        findings, errors = _scan(repo)
        assert findings == []
        assert any("sha256" in e for e in errors)

    def test_corrupt_object_store_is_an_error_not_a_crash(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        head = _git(repo, "rev-parse", "HEAD").strip()
        obj = repo / ".git" / "objects" / head[:2] / head[2:]
        obj.chmod(0o644)
        obj.write_bytes(b"not zlib")
        findings, errors = _scan(repo)
        assert findings == []
        assert errors and all(str(tmp_path) not in e for e in errors)

    def test_outside_a_repository(self, tmp_path: Path) -> None:
        assert _scan(tmp_path) == ([], [])

    def test_linked_worktree_reads_the_shared_store(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        _git(repo, "rm", "-q", ".claude/settings.local.json")
        _commit(repo, "remove")
        wt = tmp_path / "wt"
        _git(repo, "worktree", "add", "-q", str(wt), "HEAD")
        findings, _ = _scan(wt)
        assert len(findings) == 1
        assert Path(findings[0].finding_path).is_relative_to(wt.resolve())


class TestScanWiring:
    def test_default_scan_reports_cred_005(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        _git(repo, "rm", "-q", ".claude/settings.local.json")
        _commit(repo, "remove")
        monkeypatch.chdir(repo)
        result = run_scan()
        ids = [f.id for f in result.findings]
        assert ids.count("CRED-005") == 1
        assert GH_TOKEN not in result.model_dump_json()

    def test_explicit_path_scan_does_not_read_history(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        _git(repo, "rm", "-q", ".claude/settings.local.json")
        _commit(repo, "remove")
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))
        monkeypatch.chdir(repo)
        result = run_scan(extra_paths=[cfg])
        assert "CRED-005" not in [f.id for f in result.findings]


class TestReviewFindings:
    def test_rotated_token_in_history_is_reported(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        old = "gh" + "p_" + "b" * 36
        _write_settings(repo, [f"Bash(GITHUB_TOKEN={old} gh pr list)"])
        _commit(repo, "old token")
        _write_settings(repo, [LEAKY])  # same rule, new token
        _commit(repo, "rotated")
        findings, _ = _scan(repo)
        assert len(findings) == 1
        assert old not in findings[0].model_dump_json()
        assert "1 permission rule value(s)" in findings[0].description

    def test_cited_commit_holds_the_reported_rule(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY_2], name="settings.json")
        _commit(repo, "kept secret")
        for i in range(3):
            (repo / "README.md").write_text(str(i))
            _commit(repo, f"c{i}")
        _write_settings(repo, [LEAKY_2, LEAKY], name="settings.json")
        _commit(repo, "added")
        leak_commit = _git(repo, "rev-parse", "HEAD").strip()
        _write_settings(repo, [LEAKY_2], name="settings.json")
        _commit(repo, "removed")
        findings, _ = _scan(repo)
        assert len(findings) == 1
        assert f"commit {leak_commit[:12]}" in findings[0].evidence
        assert "commits in all" not in findings[0].evidence

    def test_bad_version_is_reported_and_the_walk_goes_on(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        (repo / ".claude").mkdir()
        (repo / ".claude" / "settings.json").write_text("{not json")
        _commit(repo, "broken")
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        _git(repo, "rm", "-q", "-r", ".claude")
        _commit(repo, "remove")
        findings, errors = _scan(repo)
        assert [f.id for f in findings] == ["CRED-005"]
        assert any("not valid JSON" in e for e in errors)

    def test_budget_keeps_what_was_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        _git(repo, "rm", "-q", ".claude/settings.local.json")
        _commit(repo, "remove")
        for i in range(40):
            (repo / "README.md").write_text("x" * 2000 + str(i))
            _commit(repo, f"pad{i}")
        monkeypatch.setattr(hist, "INFLATE_BUDGET", 10_000_000)
        assert len(_scan(repo)[0]) == 1
        monkeypatch.setattr(hist, "INFLATE_BUDGET", 3_000)
        findings, errors = _scan(repo)
        assert any("budget ran out" in e for e in errors)
        assert all(f.id == "CRED-005" for f in findings)

    def test_symlinked_objects_dir_is_not_read(self, tmp_path: Path) -> None:
        other = _repo(tmp_path, "other")
        _write_settings(other, [LEAKY])
        _commit(other, "leak")
        _git(other, "rm", "-q", ".claude/settings.local.json")
        _commit(other, "remove")
        repo = _repo(tmp_path)
        objects = repo / ".git" / "objects"
        objects.rename(
            repo / ".git" / "objects-moved"
        )  # rmtree fails on Windows: git's files are read-only
        try:
            objects.symlink_to(other / ".git" / "objects", target_is_directory=True)
        except OSError:
            pytest.skip("symlinks not available")
        findings, errors = _scan(repo)
        assert findings == []
        assert any("symlink" in e for e in errors)

    def test_project_flag_reads_history_with_or_without_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        repo = _repo(tmp_path)
        _write_settings(repo, [LEAKY])
        _commit(repo, "leak")
        _git(repo, "rm", "-q", ".claude/settings.local.json")
        _commit(repo, "remove")
        cfg = tmp_path / "x.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))
        runner = CliRunner()
        for cwd in (repo, tmp_path):
            monkeypatch.chdir(cwd)
            for extra in ([], ["--path", str(cfg)]):
                out = runner.invoke(
                    app,
                    ["scan", "--project", str(repo), "--format", "json", *extra],
                )
                data = json.loads(out.stdout[out.stdout.index("{") :])
                ids = [f["id"] for f in data["findings"]]
                assert ids.count("CRED-005") == 1, (cwd, extra)
