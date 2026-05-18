"""Tests for `mcp-audit fix` — fixer orchestrator, strategies, and CLI command."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.fixer.fixer import run_fix
from mcp_audit.fixer.strategies.credentials import CredentialsFixStrategy
from mcp_audit.fixer.strategies.pinning import PackagePinningStrategy, _find_package_arg
from mcp_audit.fixer.strategies.transport import TransportFixStrategy
from mcp_audit.models import Finding, ScanResult, ServerConfig, Severity, TransportType

runner = CliRunner()

# Synthetic credential tokens used only as test fixtures — not real secrets.
_GH_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
_SK_TOKEN = "sk-abcdefghijklmnop12345"  # noqa: S105


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_finding(
    finding_id: str = "CRED-001",
    severity: Severity = Severity.HIGH,
    server: str = "my-server",
    evidence: str = "env.GITHUB_TOKEN matches GitHub Token pattern",
    analyzer: str = "credentials",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer=analyzer,
        client="claude-desktop",
        server=server,
        title="Test finding",
        description="A test finding.",
        evidence=evidence,
        remediation="Fix it.",
    )


def _config_with_secret(
    server_name: str = "my-server",
    env_key: str = "GITHUB_TOKEN",
    env_value: str = _GH_TOKEN,
) -> dict:
    return {
        "mcpServers": {
            server_name: {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {env_key: env_value},
            }
        }
    }


def _config_with_http_url(
    server_name: str = "my-server",
    url: str = "http://my-server:8080/mcp",
) -> dict:
    return {"mcpServers": {server_name: {"url": url}}}


def _config_with_typosquat(
    server_name: str = "my-server",
    command: str = "npx",
    # typo: missing final 's'
    pkg: str = "@modelcontextprotocol/server-filesytem",
) -> dict:
    return {
        "mcpServers": {
            server_name: {
                "command": command,
                "args": [pkg],
            }
        }
    }


def _write_config(tmp_path: Path, data: dict, name: str = "config.json") -> Path:
    p = tmp_path / name
    # Use same format as run_fix so idempotent configs produce an empty diff.
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    p.write_text(text, encoding="utf-8")
    return p


def _cred_evidence(key: str = "GITHUB_TOKEN") -> str:
    return f"env.{key} matches GitHub Token pattern"


def _sc_evidence(
    current: str = "@modelcontextprotocol/server-filesytem",
    closest: str = "@modelcontextprotocol/server-filesystem",
) -> str:
    return (
        f"command: npx {current} | "
        f"closest: '{closest}' (maintainer=modelcontextprotocol, verified=True)"
    )


# ── CredentialsFixStrategy unit tests ─────────────────────────────────────────


class TestCredentialFixStrategy:
    def test_can_fix_cred001(self) -> None:
        s = CredentialsFixStrategy()
        assert s.can_fix(_make_finding("CRED-001"))

    def test_can_fix_cred002(self) -> None:
        s = CredentialsFixStrategy()
        assert s.can_fix(_make_finding("CRED-002"))

    def test_cannot_fix_other(self) -> None:
        s = CredentialsFixStrategy()
        assert not s.can_fix(_make_finding("TRANSPORT-001"))

    def test_cred001_replaces_env_value(self) -> None:
        s = CredentialsFixStrategy()
        config = _config_with_secret(env_key="GITHUB_TOKEN", env_value="ghp_abc123xxx")
        finding = _make_finding("CRED-001", evidence=_cred_evidence("GITHUB_TOKEN"))
        new_config, desc = s.apply(config, finding)
        env = new_config["mcpServers"]["my-server"]["env"]
        assert env["GITHUB_TOKEN"] == "${GITHUB_TOKEN}"  # noqa: S105
        assert "GITHUB_TOKEN" in desc
        # Original must be unchanged (strategy must deep-copy)
        orig = config["mcpServers"]["my-server"]["env"]["GITHUB_TOKEN"]
        assert orig == "ghp_abc123xxx"

    def test_cred001_idempotent_placeholder(self) -> None:
        s = CredentialsFixStrategy()
        config = _config_with_secret(env_value="${GITHUB_TOKEN}")  # noqa: S105
        finding = _make_finding("CRED-001", evidence=_cred_evidence())
        new_config, desc = s.apply(config, finding)
        assert new_config is not config or new_config == config
        assert "already fixed" in desc

    def test_cred001_raises_when_server_missing(self) -> None:
        s = CredentialsFixStrategy()
        config: dict = {"mcpServers": {}}
        finding = _make_finding("CRED-001", server="nonexistent")
        with pytest.raises(ValueError, match="not found"):
            s.apply(config, finding)

    def test_cred001_raises_on_bad_evidence(self) -> None:
        s = CredentialsFixStrategy()
        config = _config_with_secret()
        finding = _make_finding("CRED-001", evidence="completely unparseable evidence")
        with pytest.raises(ValueError, match="Cannot parse env key"):
            s.apply(config, finding)

    def test_cred002_redacts_arg(self) -> None:
        s = CredentialsFixStrategy()
        config: dict = {
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": ["server.js", "--token", _GH_TOKEN],
                }
            }
        }
        finding = _make_finding("CRED-002", evidence="args match GitHub Token pattern")
        new_config, desc = s.apply(config, finding)
        args = new_config["mcpServers"]["my-server"]["args"]
        assert not any("ghp_" in a for a in args), "Secret not redacted from args"
        assert any("${REDACTED_SECRET}" in a for a in args)  # noqa: S105
        assert "my-server" in desc

    def test_cred002_no_match_is_already_fixed(self) -> None:
        s = CredentialsFixStrategy()
        config: dict = {
            "mcpServers": {"my-server": {"command": "node", "args": ["clean-arg"]}}
        }
        finding = _make_finding("CRED-002", evidence="args match GitHub Token pattern")
        _, desc = s.apply(config, finding)
        assert "already fixed" in desc


# ── TransportFixStrategy unit tests ───────────────────────────────────────────


class TestTransportFixStrategy:
    def test_can_fix_transport001(self) -> None:
        s = TransportFixStrategy()
        assert s.can_fix(_make_finding("TRANSPORT-001"))

    def test_cannot_fix_other(self) -> None:
        s = TransportFixStrategy()
        assert not s.can_fix(_make_finding("CRED-001"))

    def test_upgrades_http_to_https(self) -> None:
        s = TransportFixStrategy()
        config = _config_with_http_url(url="http://remote-host:8080/mcp")
        finding = _make_finding(
            "TRANSPORT-001", evidence="URL: http://remote-host:8080/mcp"
        )
        new_config, desc = s.apply(config, finding)
        assert (
            new_config["mcpServers"]["my-server"]["url"]
            == "https://remote-host:8080/mcp"
        )
        assert "https://" in desc
        # Deep copy guard
        assert config["mcpServers"]["my-server"]["url"] == "http://remote-host:8080/mcp"

    def test_already_https_is_idempotent(self) -> None:
        s = TransportFixStrategy()
        config = _config_with_http_url(url="https://remote-host:8080/mcp")
        finding = _make_finding(
            "TRANSPORT-001", evidence="URL: https://remote-host:8080/mcp"
        )
        _, desc = s.apply(config, finding)
        assert "already fixed" in desc

    def test_raises_when_no_url(self) -> None:
        s = TransportFixStrategy()
        config: dict = {"mcpServers": {"my-server": {"command": "npx", "args": []}}}
        finding = _make_finding("TRANSPORT-001")
        with pytest.raises(ValueError, match="no 'url' field"):
            s.apply(config, finding)

    def test_raises_when_server_missing(self) -> None:
        s = TransportFixStrategy()
        config: dict = {"mcpServers": {}}
        finding = _make_finding("TRANSPORT-001", server="nonexistent")
        with pytest.raises(ValueError, match="not found"):
            s.apply(config, finding)

    def test_vscode_servers_root_key(self) -> None:
        """Handles VS Code format which uses 'servers' as the root key."""
        s = TransportFixStrategy()
        config: dict = {"servers": {"my-server": {"url": "http://remote:9000/sse"}}}
        finding = _make_finding("TRANSPORT-001")
        new_config, desc = s.apply(config, finding)
        assert new_config["servers"]["my-server"]["url"] == "https://remote:9000/sse"


# ── PackagePinningStrategy unit tests ─────────────────────────────────────────


def _npm_mock(version: str = "1.2.3") -> MagicMock:
    """Return a mock urlopen context manager returning a versioned npm response."""
    resp = MagicMock()
    resp.read.return_value = json.dumps({"version": version}).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _pypi_mock(version: str = "0.9.1") -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps({"info": {"version": version}}).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


_URLOPEN = "mcp_audit.fixer.strategies.pinning.urllib.request.urlopen"


class TestPackagePinningStrategy:
    def _sc_finding(
        self,
        server: str = "my-server",
        current_pkg: str = "@modelcontextprotocol/server-filesytem",
        closest_pkg: str = "@modelcontextprotocol/server-filesystem",
        finding_id: str = "SC-001",
    ) -> Finding:
        return _make_finding(
            finding_id,
            server=server,
            evidence=_sc_evidence(current_pkg, closest_pkg),
            analyzer="supply_chain",
        )

    def test_can_fix_sc001_sc002(self) -> None:
        s = PackagePinningStrategy()
        assert s.can_fix(_make_finding("SC-001"))
        assert s.can_fix(_make_finding("SC-002"))

    def test_cannot_fix_other(self) -> None:
        s = PackagePinningStrategy()
        assert not s.can_fix(_make_finding("CRED-001"))

    def test_apply_with_mocked_npm_registry(self) -> None:
        config = _config_with_typosquat(pkg="@modelcontextprotocol/server-filesytem")
        finding = self._sc_finding()

        with patch(_URLOPEN, return_value=_npm_mock("1.2.3")):
            s = PackagePinningStrategy()
            new_config, desc = s.apply(config, finding)

        args = new_config["mcpServers"]["my-server"]["args"]
        assert args == ["@modelcontextprotocol/server-filesystem@1.2.3"]
        assert "1.2.3" in desc
        assert not s.warnings

    def test_apply_with_mocked_pypi_registry(self) -> None:
        config: dict = {
            "mcpServers": {
                "my-server": {
                    "command": "uvx",
                    "args": ["mcp-server-filesytem"],
                }
            }
        }
        finding = _make_finding(
            "SC-001",
            server="my-server",
            evidence=(
                "command: uvx mcp-server-filesytem | "
                "closest: 'mcp-server-filesystem' "
                "(maintainer=foo, verified=True)"
            ),
            analyzer="supply_chain",
        )

        with patch(_URLOPEN, return_value=_pypi_mock("0.9.1")):
            s = PackagePinningStrategy()
            new_config, desc = s.apply(config, finding)

        assert new_config["mcpServers"]["my-server"]["args"] == [
            "mcp-server-filesystem@0.9.1"
        ]
        assert "0.9.1" in desc

    def test_pinning_skipped_offline(self) -> None:
        config = _config_with_typosquat()
        finding = self._sc_finding()
        s = PackagePinningStrategy(offline=True)
        new_config, desc = s.apply(config, finding)
        assert new_config == config
        assert "offline" in desc.lower()
        assert any("offline" in w.lower() for w in s.warnings)

    def test_pinning_skipped_network_failure(self) -> None:
        """When urlopen raises, fix is skipped but other fixes still apply."""
        import urllib.error

        config = _config_with_typosquat()
        finding = self._sc_finding()

        with patch(_URLOPEN, side_effect=urllib.error.URLError("connection refused")):
            s = PackagePinningStrategy()
            new_config, desc = s.apply(config, finding)

        assert new_config == config
        assert "skipped" in desc.lower()
        assert any("could not resolve" in w.lower() for w in s.warnings)

    def test_already_pinned_is_idempotent(self) -> None:
        config: dict = {
            "mcpServers": {
                "my-server": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-filesystem@1.2.3"],
                }
            }
        }
        finding = self._sc_finding(current_pkg="@modelcontextprotocol/server-filesytem")

        with patch(_URLOPEN, return_value=_npm_mock("1.2.3")):
            s = PackagePinningStrategy()
            _, desc = s.apply(config, finding)

        assert "already fixed" in desc

    def test_warning_emitted_when_replacement_not_in_registry(self) -> None:
        config = _config_with_typosquat()
        finding = self._sc_finding(closest_pkg="unknown-package-xyz")

        mock_registry = MagicMock()
        mock_registry.is_known.return_value = False

        with patch(_URLOPEN, return_value=_npm_mock("1.0.0")):
            s = PackagePinningStrategy(registry=mock_registry)
            s.apply(config, finding)

        assert any(
            "not in the mcp-audit known-server registry" in w for w in s.warnings
        )

    def test_no_warning_when_replacement_in_registry(self) -> None:
        config = _config_with_typosquat()
        finding = self._sc_finding()

        mock_registry = MagicMock()
        mock_registry.is_known.return_value = True

        with patch(_URLOPEN, return_value=_npm_mock("1.0.0")):
            s = PackagePinningStrategy(registry=mock_registry)
            s.apply(config, finding)

        assert not s.warnings

    def test_raises_on_unparseable_evidence(self) -> None:
        config = _config_with_typosquat()
        finding = _make_finding("SC-001", evidence="no closest: here")
        s = PackagePinningStrategy()
        with pytest.raises(ValueError, match="Cannot parse verified package name"):
            s.apply(config, finding)


# ── _find_package_arg helper ──────────────────────────────────────────────────


class TestFindPackageArg:
    def test_plain_package(self) -> None:
        assert _find_package_arg(["some-mcp-server"]) == "some-mcp-server"

    def test_skips_flags(self) -> None:
        result = _find_package_arg(["-y", "--yes", "some-mcp-server"])
        assert result == "some-mcp-server"

    def test_returns_versioned_arg(self) -> None:
        assert _find_package_arg(["some-mcp-server@1.2.3"]) == "some-mcp-server@1.2.3"

    def test_none_when_empty(self) -> None:
        assert _find_package_arg([]) is None

    def test_skips_local_paths(self) -> None:
        assert _find_package_arg(["/usr/local/bin/server"]) is None


# ── run_fix orchestrator tests ────────────────────────────────────────────────


class TestRunFix:
    def test_no_fixable_findings(self, tmp_path: Path) -> None:
        config = _config_with_secret()
        cp = _write_config(tmp_path, config)
        result = run_fix([_make_finding("POISON-001")], cp)
        assert result.no_fixable

    def test_credential_redaction_dry_run(self, tmp_path: Path) -> None:
        config = _config_with_secret(env_key="API_TOKEN", env_value=_SK_TOKEN)
        cp = _write_config(tmp_path, config)
        findings = [
            _make_finding(
                "CRED-001",
                evidence="env.API_TOKEN matches OpenAI API Key pattern",
            )
        ]

        result = run_fix(findings, cp, apply=False)

        assert not result.no_fixable
        assert result.backup_path is None
        assert "${API_TOKEN}" in result.diff  # noqa: S105
        assert "-" in result.diff
        assert "+" in result.diff
        assert "sk-" in cp.read_text(encoding="utf-8")

    def test_credential_redaction_apply(self, tmp_path: Path) -> None:
        config = _config_with_secret(env_key="GITHUB_TOKEN", env_value=_GH_TOKEN)
        cp = _write_config(tmp_path, config)
        findings = [_make_finding("CRED-001", evidence=_cred_evidence())]

        result = run_fix(findings, cp, apply=True)

        assert result.backup_path is not None
        assert result.backup_path.exists()
        bak_data = json.loads(result.backup_path.read_text(encoding="utf-8"))
        bak_token = bak_data["mcpServers"]["my-server"]["env"]["GITHUB_TOKEN"]
        assert bak_token.startswith("ghp_")
        new_data = json.loads(cp.read_text(encoding="utf-8"))
        env_val = new_data["mcpServers"]["my-server"]["env"]["GITHUB_TOKEN"]
        assert env_val == "${GITHUB_TOKEN}"  # noqa: S105

    def test_transport_upgrade(self, tmp_path: Path) -> None:
        config = _config_with_http_url(url="http://remote-mcp:9000/sse")
        cp = _write_config(tmp_path, config)
        findings = [
            _make_finding("TRANSPORT-001", evidence="URL: http://remote-mcp:9000/sse")
        ]

        result = run_fix(findings, cp, apply=True)

        new_data = json.loads(cp.read_text(encoding="utf-8"))
        assert (
            new_data["mcpServers"]["my-server"]["url"] == "https://remote-mcp:9000/sse"
        )
        assert result.backup_path is not None

    def test_multiple_credentials_single_pass(self, tmp_path: Path) -> None:
        """All CRED-001 findings for different servers are redacted in one run."""
        config: dict = {
            "mcpServers": {
                "server-a": {
                    "command": "npx",
                    "args": [],
                    "env": {"KEY_A": _GH_TOKEN},
                },
                "server-b": {
                    "command": "npx",
                    "args": [],
                    "env": {"KEY_B": _SK_TOKEN},
                },
            }
        }
        cp = _write_config(tmp_path, config)
        findings = [
            _make_finding(
                "CRED-001",
                server="server-a",
                evidence="env.KEY_A matches GitHub Token pattern",
            ),
            _make_finding(
                "CRED-001",
                server="server-b",
                evidence="env.KEY_B matches OpenAI API Key pattern",
            ),
        ]

        result = run_fix(findings, cp, apply=True)

        new_data = json.loads(cp.read_text(encoding="utf-8"))
        assert new_data["mcpServers"]["server-a"]["env"]["KEY_A"] == "${KEY_A}"  # noqa: S105
        assert new_data["mcpServers"]["server-b"]["env"]["KEY_B"] == "${KEY_B}"  # noqa: S105
        assert len(result.fixes_applied) == 2

    def test_fix_type_filter_credentials_only(self, tmp_path: Path) -> None:
        """--fix-type credentials skips transport and pinning findings."""
        config: dict = {
            "mcpServers": {
                "my-server": {
                    "command": "npx",
                    "args": [],
                    "env": {"TOKEN": _GH_TOKEN},
                    "url": "http://remote:8080",
                }
            }
        }
        cp = _write_config(tmp_path, config)
        findings = [
            _make_finding(
                "CRED-001", evidence="env.TOKEN matches GitHub Token pattern"
            ),
            _make_finding("TRANSPORT-001", evidence="URL: http://remote:8080"),
        ]

        run_fix(findings, cp, apply=True, fix_types=["credentials"])

        new_data = json.loads(cp.read_text(encoding="utf-8"))
        assert new_data["mcpServers"]["my-server"]["env"]["TOKEN"] == "${TOKEN}"  # noqa: S105
        assert new_data["mcpServers"]["my-server"]["url"] == "http://remote:8080"

    def test_pinning_apply(self, tmp_path: Path) -> None:
        config = _config_with_typosquat(pkg="@modelcontextprotocol/server-filesytem")
        cp = _write_config(tmp_path, config)
        finding = _make_finding(
            "SC-001",
            server="my-server",
            evidence=_sc_evidence(),
            analyzer="supply_chain",
        )

        with patch(_URLOPEN, return_value=_npm_mock("2.0.0")):
            result = run_fix([finding], cp, apply=True)

        new_data = json.loads(cp.read_text(encoding="utf-8"))
        args = new_data["mcpServers"]["my-server"]["args"]
        assert "@modelcontextprotocol/server-filesystem@2.0.0" in args
        assert result.backup_path is not None

    def test_pinning_skipped_when_offline(self, tmp_path: Path) -> None:
        config = _config_with_typosquat()
        cp = _write_config(tmp_path, config)
        finding = _make_finding(
            "SC-001",
            server="my-server",
            evidence=_sc_evidence(),
            analyzer="supply_chain",
        )

        result = run_fix([finding], cp, apply=False, offline=True)

        # Pinning was skipped so the typosquatted arg must remain unchanged.
        import json as _json

        original = _json.loads(cp.read_text(encoding="utf-8"))
        assert original["mcpServers"]["my-server"]["args"] == [
            "@modelcontextprotocol/server-filesytem"
        ]
        assert any("offline" in w.lower() for w in result.skipped)

    def test_input_json_reads_config_path(self, tmp_path: Path) -> None:
        """Config_path is resolved from the scan result when using --input."""
        config = _config_with_secret(env_value=_GH_TOKEN)
        cp = _write_config(tmp_path, config)

        server = ServerConfig(
            name="my-server",
            client="claude-desktop",
            config_path=cp,
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-github"],
            env={"GITHUB_TOKEN": _GH_TOKEN},
        )
        finding = _make_finding("CRED-001", evidence=_cred_evidence())
        scan = ScanResult(servers=[server], findings=[finding])

        result = run_fix(scan.findings, cp, apply=False)
        assert "${GITHUB_TOKEN}" in result.diff  # noqa: S105

    def test_raises_on_missing_config(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            run_fix([], tmp_path / "nonexistent.json")

    def test_raises_on_invalid_json(self, tmp_path: Path) -> None:
        cp = tmp_path / "bad.json"
        cp.write_text("not json at all", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            run_fix([], cp)

    def test_backup_contains_original(self, tmp_path: Path) -> None:
        config = _config_with_secret(env_value=_GH_TOKEN)
        cp = _write_config(tmp_path, config)
        original_text = cp.read_text(encoding="utf-8")
        findings = [_make_finding("CRED-001", evidence=_cred_evidence())]

        result = run_fix(findings, cp, apply=True)

        assert result.backup_path is not None
        assert result.backup_path.read_text(encoding="utf-8") == original_text

    def test_read_only_config_raises_permission_error(self, tmp_path: Path) -> None:
        """Exit 2 with clear message when config is read-only."""
        import os

        config = _config_with_secret()
        cp = _write_config(tmp_path, config)
        findings = [_make_finding("CRED-001", evidence=_cred_evidence())]

        if sys.platform == "win32":
            pytest.skip("chmod semantics differ on Windows")

        original_mode = cp.stat().st_mode
        os.chmod(cp, 0o444)
        try:
            with pytest.raises(PermissionError):
                run_fix(findings, cp, apply=True)
        finally:
            os.chmod(cp, original_mode)

    def test_diff_empty_when_all_already_fixed(self, tmp_path: Path) -> None:
        config = _config_with_secret(env_value="${GITHUB_TOKEN}")  # noqa: S105
        cp = _write_config(tmp_path, config)
        findings = [_make_finding("CRED-001", evidence=_cred_evidence())]

        result = run_fix(findings, cp, apply=False)

        assert result.diff == "" or not result.diff


# ── CLI command integration tests ─────────────────────────────────────────────


class TestFixCLI:
    def _make_scan_result(
        self,
        cp: Path,
        env_key: str = "GITHUB_TOKEN",
        env_val: str = _GH_TOKEN,
    ) -> ScanResult:
        server = ServerConfig(
            name="my-server",
            client="claude-desktop",
            config_path=cp,
            transport=TransportType.STDIO,
            command="npx",
            args=[],
            env={env_key: env_val},
        )
        finding = _make_finding("CRED-001", evidence=_cred_evidence(env_key))
        return ScanResult(servers=[server], findings=[finding])

    def test_dry_run_shows_diff_file_unchanged(self, tmp_path: Path) -> None:
        config = _config_with_secret(env_value=_GH_TOKEN)
        cp = _write_config(tmp_path, config)
        original = cp.read_text(encoding="utf-8")

        with patch("mcp_audit.cli.fix.run_scan") as mock_scan:
            mock_scan.return_value = self._make_scan_result(cp)
            result = runner.invoke(app, ["fix", "--path", str(cp)])

        assert result.exit_code == 0
        assert cp.read_text(encoding="utf-8") == original

    def test_apply_writes_file_and_backup(self, tmp_path: Path) -> None:
        config = _config_with_secret(env_value=_GH_TOKEN)
        cp = _write_config(tmp_path, config)

        with patch("mcp_audit.cli.fix.run_scan") as mock_scan:
            mock_scan.return_value = self._make_scan_result(cp)
            result = runner.invoke(app, ["fix", "--path", str(cp), "--apply"])

        assert result.exit_code == 0
        new_data = json.loads(cp.read_text(encoding="utf-8"))
        env_val = new_data["mcpServers"]["my-server"]["env"]["GITHUB_TOKEN"]
        assert env_val == "${GITHUB_TOKEN}"  # noqa: S105
        bak = cp.with_suffix(cp.suffix + ".bak")
        assert bak.exists()

    def test_no_fixable_exits_0_with_message(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"clean-server": {"command": "npx", "args": []}}}
        cp = _write_config(tmp_path, config)

        with patch("mcp_audit.cli.fix.run_scan") as mock_scan:
            server = ServerConfig(
                name="clean-server",
                client="claude-desktop",
                config_path=cp,
                transport=TransportType.STDIO,
                command="npx",
                args=[],
            )
            mock_scan.return_value = ScanResult(servers=[server], findings=[])
            result = runner.invoke(app, ["fix", "--path", str(cp)])

        assert result.exit_code == 0
        assert "No fixable findings" in result.output

    def test_invalid_fix_type_exits_2(self, tmp_path: Path) -> None:
        config = {"mcpServers": {}}
        cp = _write_config(tmp_path, config)
        result = runner.invoke(app, ["fix", "--path", str(cp), "--fix-type", "bogus"])
        assert result.exit_code == 2

    def test_nonexistent_path_exits_2(self, tmp_path: Path) -> None:
        nonexistent = str(tmp_path / "nonexistent.json")
        result = runner.invoke(app, ["fix", "--path", nonexistent])
        assert result.exit_code == 2

    def test_input_json_flag(self, tmp_path: Path) -> None:
        """--input reads findings from an existing scan JSON file."""
        config = _config_with_secret(env_value=_GH_TOKEN)
        cp = _write_config(tmp_path, config)

        server = ServerConfig(
            name="my-server",
            client="claude-desktop",
            config_path=cp,
            transport=TransportType.STDIO,
            command="npx",
            args=[],
            env={"GITHUB_TOKEN": _GH_TOKEN},
        )
        finding = _make_finding("CRED-001", evidence=_cred_evidence())
        scan = ScanResult(servers=[server], findings=[finding])

        scan_json = tmp_path / "scan.json"
        scan_json.write_text(scan.model_dump_json(), encoding="utf-8")

        result = runner.invoke(app, ["fix", "--input", str(scan_json)])
        assert result.exit_code == 0
        assert "${GITHUB_TOKEN}" in result.output or "Would apply" in result.output  # noqa: S105

    def test_path_and_input_mutually_exclusive(self, tmp_path: Path) -> None:
        cp = _write_config(tmp_path, {"mcpServers": {}})
        scan_json = tmp_path / "scan.json"
        scan_json.write_text("{}", encoding="utf-8")
        result = runner.invoke(
            app, ["fix", "--path", str(cp), "--input", str(scan_json)]
        )
        assert result.exit_code == 2

    def test_offline_flag_skips_pinning(self, tmp_path: Path) -> None:
        config = _config_with_typosquat()
        cp = _write_config(tmp_path, config)

        with patch("mcp_audit.cli.fix.run_scan") as mock_scan:
            server = ServerConfig(
                name="my-server",
                client="claude-desktop",
                config_path=cp,
                transport=TransportType.STDIO,
                command="npx",
                args=["@modelcontextprotocol/server-filesytem"],
            )
            finding = _make_finding(
                "SC-001",
                server="my-server",
                evidence=_sc_evidence(),
                analyzer="supply_chain",
            )
            mock_scan.return_value = ScanResult(servers=[server], findings=[finding])
            result = runner.invoke(app, ["fix", "--path", str(cp), "--offline"])

        assert result.exit_code == 0
        assert "offline" in result.output.lower()


# ── Integration: fix then re-scan reduces finding count ───────────────────────


class TestFixReducesFindings:
    def test_credential_finding_gone_after_fix(self, tmp_path: Path) -> None:
        """After applying CRED-001 fix, a re-scan should find nothing."""
        from mcp_audit.analyzers.credentials import CredentialsAnalyzer

        config = _config_with_secret(env_key="GITHUB_TOKEN", env_value=_GH_TOKEN)
        cp = _write_config(tmp_path, config)

        findings_before = CredentialsAnalyzer().analyze(
            ServerConfig(
                name="my-server",
                client="claude-desktop",
                config_path=cp,
                transport=TransportType.STDIO,
                command="npx",
                args=[],
                env={"GITHUB_TOKEN": _GH_TOKEN},
            )
        )
        assert any(f.id == "CRED-001" for f in findings_before)

        run_fix([_make_finding("CRED-001", evidence=_cred_evidence())], cp, apply=True)

        new_data = json.loads(cp.read_text(encoding="utf-8"))
        findings_after = CredentialsAnalyzer().analyze(
            ServerConfig(
                name="my-server",
                client="claude-desktop",
                config_path=cp,
                transport=TransportType.STDIO,
                command="npx",
                args=[],
                env=new_data["mcpServers"]["my-server"].get("env", {}),
            )
        )
        assert not any(f.id == "CRED-001" for f in findings_after)

    def test_transport_finding_gone_after_fix(self, tmp_path: Path) -> None:
        """After applying TRANSPORT-001 fix, the transport analyzer finds nothing."""
        from mcp_audit.analyzers.transport import TransportAnalyzer

        config = _config_with_http_url(url="http://remote-mcp:9000/sse")
        cp = _write_config(tmp_path, config)

        server_before = ServerConfig(
            name="my-server",
            client="claude-desktop",
            config_path=cp,
            transport=TransportType.SSE,
            url="http://remote-mcp:9000/sse",
        )
        assert any(
            f.id == "TRANSPORT-001" for f in TransportAnalyzer().analyze(server_before)
        )

        run_fix(
            [
                _make_finding(
                    "TRANSPORT-001", evidence="URL: http://remote-mcp:9000/sse"
                )
            ],
            cp,
            apply=True,
        )

        new_data = json.loads(cp.read_text(encoding="utf-8"))
        server_after = ServerConfig(
            name="my-server",
            client="claude-desktop",
            config_path=cp,
            transport=TransportType.SSE,
            url=new_data["mcpServers"]["my-server"]["url"],
        )
        assert not any(
            f.id == "TRANSPORT-001" for f in TransportAnalyzer().analyze(server_after)
        )
