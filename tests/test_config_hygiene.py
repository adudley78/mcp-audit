"""Tests for the ConfigHygieneAnalyzer (analyzers/config_hygiene.py)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.analyzers.config_hygiene import ConfigHygieneAnalyzer
from mcp_audit.models import ServerConfig, Severity, TransportType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(
    config_path: Path,
    env: dict[str, str] | None = None,
    name: str = "test-server",
    client: str = "claude_desktop",
) -> ServerConfig:
    """Build a minimal ServerConfig pointing at *config_path*."""
    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path,
        transport=TransportType.STDIO,
        command="node",
        args=["index.js"],
        env=env or {},
    )


def _finding_ids(findings) -> list[str]:
    return [f.id for f in findings]


# ---------------------------------------------------------------------------
# CFHYG-001 — world-readable file
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cfhyg001_world_readable_fires(tmp_path: Path) -> None:
    """chmod 644 → CFHYG-001 fires."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")
    cfg.chmod(0o644)

    server = _make_server(cfg)
    findings = ConfigHygieneAnalyzer().analyze(server)
    ids = _finding_ids(findings)

    assert "CFHYG-001" in ids
    finding = next(f for f in findings if f.id == "CFHYG-001")
    assert finding.severity == Severity.HIGH
    assert finding.cwe == "CWE-732"
    assert "MCP01" in finding.owasp_mcp_top_10
    assert "chmod 600" in finding.remediation


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cfhyg001_not_world_readable_no_fire(tmp_path: Path) -> None:
    """chmod 600 → CFHYG-001 must NOT fire."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")
    cfg.chmod(0o600)

    server = _make_server(cfg)
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-001" not in _finding_ids(findings)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cfhyg001_mode_640_no_fire(tmp_path: Path) -> None:
    """chmod 640 (group-readable, not other-readable) → CFHYG-001 must NOT fire."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")
    cfg.chmod(0o640)

    server = _make_server(cfg)
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-001" not in _finding_ids(findings)


# ---------------------------------------------------------------------------
# CFHYG-002 — world-writable parent directory
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cfhyg002_world_writable_dir_fires(tmp_path: Path) -> None:
    """A world-writable ancestor → CFHYG-002 fires."""
    # tmp_path is typically under /tmp which is world-writable — but to be
    # deterministic we explicitly set the directory sticky bit off and o+w on.
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")
    cfg.chmod(0o600)

    # Make tmp_path itself world-writable (remove sticky bit if present).
    tmp_path.chmod(0o777)

    server = _make_server(cfg)
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-002" in _finding_ids(findings)
    finding = next(f for f in findings if f.id == "CFHYG-002")
    assert finding.severity == Severity.HIGH
    assert "MCP01" in finding.owasp_mcp_top_10
    assert "MCP09" in finding.owasp_mcp_top_10


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cfhyg002_restricted_dir_no_fire(tmp_path: Path) -> None:
    """A directory with mode 700 → CFHYG-002 must NOT fire."""
    restricted = tmp_path / "secure_dir"
    restricted.mkdir()
    restricted.chmod(0o700)

    cfg = restricted / "mcp.json"
    cfg.write_text("{}")
    cfg.chmod(0o600)

    # Patch Path.home() so the walker stops at restricted's parent (tmp_path),
    # preventing it from walking into system directories that may be world-writable.
    with patch("mcp_audit.analyzers.config_hygiene.Path.home", return_value=tmp_path):
        findings = ConfigHygieneAnalyzer().analyze(_make_server(cfg))

    assert "CFHYG-002" not in _finding_ids(findings)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_cfhyg002_home_dir_boundary_respected(tmp_path: Path) -> None:
    """Walker stops at $HOME — directories above home are not checked."""
    home_dir = tmp_path / "home" / "user"
    home_dir.mkdir(parents=True)
    home_dir.chmod(0o700)

    cfg = home_dir / "mcp.json"
    cfg.write_text("{}")
    cfg.chmod(0o600)

    # The parent of home_dir (tmp_path/home) is NOT world-writable in this
    # test, but we verify the walker doesn't go above home_dir anyway by
    # making the grandparent world-writable.
    (tmp_path / "home").chmod(0o777)

    with patch("mcp_audit.analyzers.config_hygiene.Path.home", return_value=home_dir):
        findings = ConfigHygieneAnalyzer().analyze(_make_server(cfg))

    # The walker should stop at home_dir and NOT see the world-writable parent.
    assert "CFHYG-002" not in _finding_ids(findings)


# ---------------------------------------------------------------------------
# CFHYG-003 — inline plaintext secret
# ---------------------------------------------------------------------------


def test_cfhyg003_plaintext_api_key_fires(tmp_path: Path) -> None:
    """Env var with a plaintext OpenAI key → CFHYG-003 fires."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    env = {"OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"}
    server = _make_server(cfg, env=env)
    findings = ConfigHygieneAnalyzer().analyze(server)

    ids = _finding_ids(findings)
    assert "CFHYG-003" in ids
    finding = next(f for f in findings if f.id == "CFHYG-003")
    assert finding.severity == Severity.HIGH
    assert finding.cwe == "CWE-312"
    assert "MCP01" in finding.owasp_mcp_top_10
    assert "Bitwarden" in finding.description


def test_cfhyg003_github_token_fires(tmp_path: Path) -> None:
    """Env var with a GitHub token → CFHYG-003 fires."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    env = {"GH_TOKEN": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"}
    server = _make_server(cfg, env=env)
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-003" in _finding_ids(findings)


def test_cfhyg003_aws_access_key_fires(tmp_path: Path) -> None:
    """Env var with an AWS access key → CFHYG-003 fires."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    env = {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}
    server = _make_server(cfg, env=env)
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-003" in _finding_ids(findings)


# ---------------------------------------------------------------------------
# CFHYG-004 — env-var references (positive signal)
# ---------------------------------------------------------------------------


def test_cfhyg004_env_var_refs_fires(tmp_path: Path) -> None:
    """Env vars using ${...} references → CFHYG-004 fires (positive)."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    env = {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "DB_PASSWORD": "${DB_PASSWORD}",
    }
    server = _make_server(cfg, env=env)
    findings = ConfigHygieneAnalyzer().analyze(server)

    ids = _finding_ids(findings)
    assert "CFHYG-004" in ids
    assert "CFHYG-003" not in ids
    finding = next(f for f in findings if f.id == "CFHYG-004")
    assert finding.severity == Severity.INFO


def test_cfhyg004_dollar_var_style_fires(tmp_path: Path) -> None:
    """Env vars using $VAR style → CFHYG-004 fires."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    env = {"TOKEN": "$MY_SECRET_TOKEN"}
    server = _make_server(cfg, env=env)
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-004" in _finding_ids(findings)


def test_cfhyg004_python_interp_style_fires(tmp_path: Path) -> None:
    """Env vars using %(VAR)s style → CFHYG-004 fires."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    env = {"TOKEN": "%(SECRET_TOKEN)s"}
    server = _make_server(cfg, env=env)
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-004" in _finding_ids(findings)


def test_cfhyg004_no_env_no_fire(tmp_path: Path) -> None:
    """No env entries → CFHYG-004 must NOT fire."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    server = _make_server(cfg, env={})
    findings = ConfigHygieneAnalyzer().analyze(server)

    assert "CFHYG-004" not in _finding_ids(findings)
    assert "CFHYG-003" not in _finding_ids(findings)


def test_cfhyg004_mixed_literal_and_ref_no_fire(tmp_path: Path) -> None:
    """Mix of env-var ref and plain literal string → CFHYG-004 must NOT fire
    (only fires when ALL non-empty values look like references)."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    env = {
        "GOOD": "${MY_KEY}",
        "BAD": "some-plain-value",  # not a ref, not a secret
    }
    server = _make_server(cfg, env=env)
    findings = ConfigHygieneAnalyzer().analyze(server)

    # Neither CFHYG-003 (no secret pattern) nor CFHYG-004 (not all refs)
    assert "CFHYG-004" not in _finding_ids(findings)
    assert "CFHYG-003" not in _finding_ids(findings)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_file_not_found_returns_empty(tmp_path: Path) -> None:
    """Stat raises FileNotFoundError → analyze() returns [] without raising."""
    cfg = tmp_path / "nonexistent.json"
    server = _make_server(cfg)
    findings = ConfigHygieneAnalyzer().analyze(server)
    assert findings == []


def test_permission_error_on_stat_returns_empty(tmp_path: Path) -> None:
    """Stat raises PermissionError → analyze() returns [] without raising."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")

    with patch.object(Path, "stat", side_effect=PermissionError("denied")):
        findings = ConfigHygieneAnalyzer().analyze(_make_server(cfg))

    assert findings == []


# ---------------------------------------------------------------------------
# Analyzer metadata
# ---------------------------------------------------------------------------


def test_analyzer_name_and_description() -> None:
    """Verify the analyzer exposes the expected name and description."""
    analyzer = ConfigHygieneAnalyzer()
    assert analyzer.name == "config_hygiene"
    assert "hygiene" in analyzer.description.lower()


# ---------------------------------------------------------------------------
# Windows skip — smoke tests to ensure the class is importable on all platforms
# ---------------------------------------------------------------------------


def test_analyze_returns_list_type(tmp_path: Path) -> None:
    """analyze() always returns a list (works on all platforms)."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")
    server = _make_server(cfg)
    result = ConfigHygieneAnalyzer().analyze(server)
    assert isinstance(result, list)
