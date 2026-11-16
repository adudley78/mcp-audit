"""CRED-006: settings files an image or npm package ships (STORY-0157)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit._gitignore import MatchMeter
from mcp_audit.analyzers import shipped_settings as ss
from mcp_audit.models import Severity

# Built from pieces so the repository holds no token-shaped literal.
GH_TOKEN = "gh" + "p_" + "a" * 36
LEAKY = f"Bash(GITHUB_TOKEN={GH_TOKEN} gh pr list)"
CLEAN = "Bash(npm test *)"


def _settings(
    root: Path, rules: list[str], where: str = "", name: str = "settings.local.json"
) -> Path:
    folder = root / where / ".claude" if where else root / ".claude"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(json.dumps({"permissions": {"allow": rules}}))
    return path


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _scan(root: Path) -> tuple[list, list[str]]:
    errors: list[str] = []
    return ss.scan_tree(root, errors), errors


SIMPLE = "FROM python:3.12\nWORKDIR /app\nCOPY . .\n"


# ── .dockerignore semantics ──────────────────────────────────────────────────


class TestDockerignore:
    @pytest.mark.parametrize(
        ("lines", "path", "excluded"),
        [
            (".claude", ".claude/settings.local.json", True),
            (".claude/", ".claude/settings.local.json", True),
            ("./.claude", ".claude/settings.local.json", True),
            ("/.claude", ".claude/settings.local.json", True),
            (".claude", "app/.claude/settings.local.json", False),
            ("**/.claude", "app/.claude/settings.local.json", True),
            ("**/.claude", ".claude/settings.local.json", True),
            ("*/.claude", "app/.claude/settings.local.json", True),
            ("*", ".claude/settings.local.json", True),
            ("*\n!.claude", ".claude/settings.local.json", False),
            (
                ".claude\n!.claude/settings.local.json",
                ".claude/settings.local.json",
                False,
            ),
            ("**/settings.local.json", "a/b/.claude/settings.local.json", True),
            ("# .claude", ".claude/settings.local.json", False),
            ("  .claude  ", ".claude/settings.local.json", True),
            ("node_modules\n.git", ".claude/settings.local.json", False),
        ],
    )
    def test_matching(self, lines: str, path: str, excluded: bool) -> None:
        patterns = ss.parse_dockerignore(lines)
        result = ss.docker_excluded(tuple(path.split("/")), patterns, MatchMeter())
        assert (result is not None) is excluded


_GOLDEN = json.loads(
    (Path(__file__).parent / "golden" / "dockerignore_buildkit.json").read_text()
)["cases"]


@pytest.mark.parametrize(("lines", "path", "excluded"), _GOLDEN)
def test_parity_with_buildkit(lines: str, path: str, excluded: bool) -> None:
    """Same answer as moby/patternmatcher, which BuildKit uses (golden file)."""
    patterns = ss.parse_dockerignore(lines)
    result = ss.docker_excluded(tuple(path.split("/")), patterns, MatchMeter())
    assert (result is not None) is excluded


# ── Dockerfiles ──────────────────────────────────────────────────────────────


class TestDocker:
    def test_copy_all_without_dockerignore_is_high(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "Dockerfile", SIMPLE)
        findings, errors = _scan(tmp_path)
        assert [f.id for f in findings] == ["CRED-006"]
        f = findings[0]
        assert f.severity is Severity.HIGH
        assert f.finding_path == str((tmp_path / "Dockerfile").resolve())
        assert "line 3: COPY . ." in f.evidence
        assert "no .dockerignore" in f.description
        assert "**/.claude/" in f.remediation
        assert GH_TOKEN not in f.model_dump_json()
        assert errors == []

    def test_dockerignore_excludes(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "Dockerfile", SIMPLE)
        _write(tmp_path, ".dockerignore", ".claude/\n")
        assert _scan(tmp_path)[0] == []

    def test_root_only_pattern_misses_nested_folder(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY], where="app")
        _write(tmp_path, "Dockerfile", SIMPLE)
        _write(tmp_path, ".dockerignore", ".claude\n")
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert "app/.claude/settings.local.json" in findings[0].evidence
        assert "matches only the folder at the context root" in findings[0].description

    def test_reinclude_is_reported(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY], name="settings.json")
        _write(tmp_path, "Dockerfile", SIMPLE)
        _write(tmp_path, ".dockerignore", ".claude\n!.claude/settings.json\n")
        assert len(_scan(tmp_path)[0]) == 1

    def test_gitignore_does_not_count(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "Dockerfile", SIMPLE)
        _write(tmp_path, ".gitignore", ".claude/\n")
        assert len(_scan(tmp_path)[0]) == 1

    def test_local_file_without_secret_is_low(self, tmp_path: Path) -> None:
        _settings(tmp_path, [CLEAN])
        _write(tmp_path, "Dockerfile", SIMPLE)
        findings, _ = _scan(tmp_path)
        assert [f.severity for f in findings] == [Severity.LOW]

    def test_shared_file_without_secret_is_silent(self, tmp_path: Path) -> None:
        _settings(tmp_path, [CLEAN], name="settings.json")
        _write(tmp_path, "Dockerfile", SIMPLE)
        assert _scan(tmp_path)[0] == []

    def test_unrelated_source_is_silent(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "Dockerfile", "FROM python:3.12\nCOPY src/ /app/\n")
        assert _scan(tmp_path)[0] == []

    def test_named_folder_and_wildcard_sources(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY], where="app")
        _write(tmp_path, "Dockerfile", "FROM python:3.12\nCOPY app /srv/app\n")
        assert len(_scan(tmp_path)[0]) == 1
        _write(tmp_path, "Dockerfile", "FROM python:3.12\nCOPY * /srv/\n")
        assert len(_scan(tmp_path)[0]) == 1
        _write(tmp_path, "Dockerfile", 'FROM python:3.12\nCOPY ["app", "/srv"]\n')
        assert len(_scan(tmp_path)[0]) == 1

    def test_copy_from_external_image_is_silent(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "Dockerfile", "FROM python:3.12\nCOPY --from=nginx:1 . /x\n")
        assert _scan(tmp_path)[0] == []

    def test_copy_exclude_flag(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(
            tmp_path,
            "Dockerfile",
            "# syntax=docker/dockerfile:1.7-labs\nFROM python:3.12\n"
            "COPY --exclude=.claude . /app\n",
        )
        assert _scan(tmp_path)[0] == []

    def test_builder_stage_only_is_silent(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(
            tmp_path,
            "Dockerfile",
            "FROM node:20 AS build\nWORKDIR /app\nCOPY . .\nRUN npm run build\n"
            "FROM nginx:1\nCOPY --from=build /app/dist /usr/share/nginx/html\n",
        )
        assert _scan(tmp_path)[0] == []

    def test_builder_stage_copied_whole_is_reported(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(
            tmp_path,
            "Dockerfile",
            "FROM node:20 AS build\nWORKDIR /app\nCOPY . .\n"
            "FROM node:20-slim\nCOPY --from=build /app /app\n",
        )
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert "(from stage build)" in findings[0].evidence

    def test_relative_from_source_and_index_ref(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(
            tmp_path,
            "Dockerfile",
            "FROM node:20\nWORKDIR /app\nCOPY . .\n"
            "FROM node:20-slim\nCOPY --from=0 app /srv\n",
        )
        assert len(_scan(tmp_path)[0]) == 1

    def test_final_stage_built_from_a_stage(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(
            tmp_path,
            "Dockerfile",
            "FROM python:3.12 AS base\nCOPY . /app\n"
            "FROM base AS final\nRUN rm -rf /app/.claude\n",
        )
        assert len(_scan(tmp_path)[0]) == 1

    def test_dockerfile_specific_ignore_file_wins(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "Dockerfile", SIMPLE)
        _write(tmp_path, ".dockerignore", ".claude\n")
        _write(tmp_path, "Dockerfile.dockerignore", "node_modules\n")
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert "Dockerfile.dockerignore" in findings[0].description

    def test_named_dockerfile_variants(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "api.Dockerfile", SIMPLE)
        _write(tmp_path, "Containerfile", SIMPLE)
        _write(tmp_path, "Dockerfile.prod", SIMPLE)
        assert len(_scan(tmp_path)[0]) == 3

    def test_continuation_and_heredoc(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(
            tmp_path,
            "Dockerfile",
            "FROM python:3.12\nRUN <<EOF\nCOPY nothing here\nEOF\n"
            "COPY \\\n  # a comment\n  . \\\n  /app\n",
        )
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert "line 5" in findings[0].evidence

    def test_compose_context_one_level_up(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "docker/Dockerfile", SIMPLE)
        _write(
            tmp_path,
            "docker/compose.yaml",
            "services:\n  api:\n    build:\n      context: ..\n"
            "      dockerfile: docker/Dockerfile\n",
        )
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert ".claude/settings.local.json" in findings[0].evidence

    def test_compose_target_picks_the_stage(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(
            tmp_path,
            "Dockerfile",
            "FROM node:20 AS dev\nCOPY . /app\nFROM nginx:1 AS prod\nRUN true\n",
        )
        _write(
            tmp_path,
            "compose.yaml",
            "services:\n  web:\n    build:\n      context: .\n      target: dev\n",
        )
        assert len(_scan(tmp_path)[0]) == 1
        _write(
            tmp_path,
            "compose.yaml",
            "services:\n  web:\n    build:\n      context: .\n      target: prod\n",
        )
        assert _scan(tmp_path)[0] == []

    def test_symlinked_claude_folder_is_skipped(self, tmp_path: Path) -> None:
        # Docker copies a symlink as a link, not the folder it points to.
        real = tmp_path / "elsewhere"
        _settings(real, [LEAKY])
        project = tmp_path / "project"
        project.mkdir()
        try:
            (project / ".claude").symlink_to(real / ".claude", target_is_directory=True)
        except OSError:
            pytest.skip("symlinks not available")
        _write(project, "Dockerfile", SIMPLE)
        assert _scan(project)[0] == []

    def test_bad_compose_is_reported_not_raised(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "compose.yaml", "services: [\n")
        findings, errors = _scan(tmp_path)
        assert findings == []
        assert any(e.startswith("CRED-006:") and "YAML" in e for e in errors)


# ── npm ──────────────────────────────────────────────────────────────────────


class TestNpm:
    def _package(self, root: Path, **extra: object) -> None:
        _write(
            root, "package.json", json.dumps({"name": "x", "version": "1.0.0", **extra})
        )

    def test_npmignore_without_claude_is_reported(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        self._package(tmp_path)
        _write(tmp_path, ".npmignore", "test/\n")
        _write(tmp_path, ".gitignore", ".claude/\n")  # npm ignores it here
        findings, _ = _scan(tmp_path)
        assert [f.severity for f in findings] == [Severity.HIGH]
        assert "no rule in .npmignore" in findings[0].evidence

    def test_gitignore_used_when_no_npmignore(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        self._package(tmp_path)
        _write(tmp_path, ".gitignore", ".claude/settings.local.json\n")
        assert _scan(tmp_path)[0] == []

    def test_no_ignore_file_ships_it(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        self._package(tmp_path)
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert "global excludes file" in findings[0].description

    def test_files_field_limits_the_package(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        self._package(tmp_path, files=["dist"])
        assert _scan(tmp_path)[0] == []

    def test_files_field_that_includes_it(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        self._package(tmp_path, files=[".claude"])
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert '"files" field' in findings[0].description

    def test_private_and_nameless_packages_are_silent(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        self._package(tmp_path, private=True)
        assert _scan(tmp_path)[0] == []
        _write(tmp_path, "package.json", json.dumps({"version": "1.0.0"}))
        assert _scan(tmp_path)[0] == []

    def test_workspace_package_sees_only_its_own_folder(self, tmp_path: Path) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "package.json", json.dumps({"private": True}))
        _write(
            tmp_path,
            "packages/lib/package.json",
            json.dumps({"name": "lib", "version": "1.0.0"}),
        )
        assert _scan(tmp_path)[0] == []
        _settings(tmp_path, [LEAKY], where="packages/lib")
        findings, _ = _scan(tmp_path)
        assert len(findings) == 1
        assert "packages/lib/.claude/settings.local.json" in findings[0].evidence


# ── Scan wiring ──────────────────────────────────────────────────────────────


class TestScanWiring:
    def _repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (repo / ".git" / "objects").mkdir()
        (repo / ".git" / "refs").mkdir()
        _settings(repo, [LEAKY])
        _write(repo, "Dockerfile", SIMPLE)
        return repo

    def test_default_scan_reports_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        repo = self._repo(tmp_path)
        monkeypatch.chdir(repo)
        result = run_scan()
        assert [f.id for f in result.findings].count("CRED-006") == 1
        assert GH_TOKEN not in result.model_dump_json()

    def test_explicit_path_scan_does_not_walk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        repo = self._repo(tmp_path)
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))
        monkeypatch.chdir(repo)
        result = run_scan(extra_paths=[cfg])
        assert "CRED-006" not in [f.id for f in result.findings]

    def test_home_worktree_is_not_walked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = self._repo(tmp_path)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: repo))
        assert ss.scan_cwd_repository(repo, []) == []

    def test_project_flag_reports_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        repo = self._repo(tmp_path)
        runner = CliRunner()
        for cwd in (repo, tmp_path):
            monkeypatch.chdir(cwd)
            out = runner.invoke(
                app, ["scan", "--project", str(repo), "--format", "json"]
            )
            data = json.loads(out.stdout[out.stdout.index("{") :])
            ids = [f["id"] for f in data["findings"]]
            assert ids.count("CRED-006") == 1, cwd

    def test_never_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _settings(tmp_path, [LEAKY])
        _write(tmp_path, "Dockerfile", SIMPLE)

        def boom(*_a: object, **_k: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(ss, "build_stages", boom)
        findings, errors = _scan(tmp_path)
        assert findings == []
        assert any("CRED-006: check failed" in e for e in errors)
