"""Tests for config parsing and security analyzers."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.analyzers.credentials import CredentialsAnalyzer
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.analyzers.transport import TransportAnalyzer
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import ServerConfig, Severity, TransportType

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def clean_config():
    return DiscoveredConfig(
        client_name="test",
        root_key="mcpServers",
        path=FIXTURES / "clean_with_credential.json",
    )


@pytest.fixture
def malicious_config():
    return DiscoveredConfig(
        client_name="test",
        root_key="mcpServers",
        path=FIXTURES / "malicious_config.json",
    )


class TestConfigParser:
    def test_parse_clean_config(self, clean_config):
        servers = parse_config(clean_config)
        assert len(servers) == 2
        assert servers[0].name == "filesystem"
        assert servers[0].transport == TransportType.STDIO
        assert servers[0].command == "npx"

    def test_parse_malicious_config(self, malicious_config):
        servers = parse_config(malicious_config)
        assert len(servers) == 2
        sus_api = next(s for s in servers if s.name == "sus-api")
        assert sus_api.transport == TransportType.SSE
        assert sus_api.url == "http://sketchy-server.evil.com:8080/sse"

    def test_parse_nonexistent_file(self):
        config = DiscoveredConfig(
            client_name="test",
            root_key="mcpServers",
            path=Path("/nonexistent/config.json"),
        )
        with pytest.raises(ValueError, match="Cannot read"):
            parse_config(config)

    def test_parse_vscode_servers_key(self, tmp_path):
        config_file = tmp_path / "mcp.json"
        config_file.write_text(
            '{"servers": {"test-server": {"command": "node", "args": ["server.js"]}}}'
        )
        config = DiscoveredConfig(
            client_name="vscode",
            root_key="servers",
            path=config_file,
        )
        servers = parse_config(config)
        assert len(servers) == 1
        assert servers[0].name == "test-server"


class TestPoisoningAnalyzer:
    def setup_method(self):
        self.analyzer = PoisoningAnalyzer()

    def test_detects_ssh_exfiltration(self, malicious_config):
        servers = parse_config(malicious_config)
        evil_calc = next(s for s in servers if s.name == "evil-calculator")
        findings = self.analyzer.analyze(evil_calc)
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 1
        assert any(
            "ssh" in f.title.lower() or "ssh" in f.evidence.lower()
            for f in critical_findings
        )

    def test_detects_instruction_injection(self, malicious_config):
        servers = parse_config(malicious_config)
        evil_calc = next(s for s in servers if s.name == "evil-calculator")
        findings = self.analyzer.analyze(evil_calc)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 1

    def test_clean_server_no_poisoning(self, clean_config):
        servers = parse_config(clean_config)
        fs_server = next(s for s in servers if s.name == "filesystem")
        findings = self.analyzer.analyze(fs_server)
        # Filesystem server should have no poisoning findings
        poisoning_findings = [f for f in findings if f.analyzer == "poisoning"]
        assert len(poisoning_findings) == 0


class TestCredentialsAnalyzer:
    def setup_method(self):
        self.analyzer = CredentialsAnalyzer()

    def test_detects_github_token(self, clean_config):
        servers = parse_config(clean_config)
        github_server = next(s for s in servers if s.name == "github")
        findings = self.analyzer.analyze(github_server)
        assert len(findings) >= 1
        assert any("GitHub" in f.title for f in findings)

    def test_detects_anthropic_key(self, malicious_config):
        servers = parse_config(malicious_config)
        sus_api = next(s for s in servers if s.name == "sus-api")
        findings = self.analyzer.analyze(sus_api)
        assert len(findings) >= 1

    def test_no_creds_in_clean_server(self, clean_config):
        servers = parse_config(clean_config)
        fs_server = next(s for s in servers if s.name == "filesystem")
        findings = self.analyzer.analyze(fs_server)
        assert len(findings) == 0


class TestCredentialEvidenceNoSecretLeakage:
    """V-02: evidence strings must never contain any portion of the actual secret."""

    def setup_method(self):
        self.analyzer = CredentialsAnalyzer()

    def test_env_evidence_contains_no_secret_value(self):
        secret = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
        server = ServerConfig(
            name="test",
            client="test",
            config_path=Path("/tmp/test.json"),  # noqa: S108
            transport=TransportType.STDIO,
            command="node",
            env={"GITHUB_TOKEN": secret},
        )
        findings = self.analyzer.analyze(server)
        assert len(findings) >= 1
        for f in findings:
            assert secret not in f.evidence
            assert secret[:8] not in f.evidence
            assert secret[-4:] not in f.evidence

    def test_args_evidence_contains_no_secret_value(self):
        secret = "sk-ant-api03-realAnthropicKeyHere1234567890abcdef"  # noqa: S105
        server = ServerConfig(
            name="test",
            client="test",
            config_path=Path("/tmp/test.json"),  # noqa: S108
            transport=TransportType.STDIO,
            command="node",
            args=["--token", secret],
        )
        findings = self.analyzer.analyze(server)
        assert len(findings) >= 1
        for f in findings:
            assert secret not in f.evidence
            assert secret[:12] not in f.evidence


class TestTransportAnalyzer:
    def setup_method(self):
        self.analyzer = TransportAnalyzer()

    def test_detects_unencrypted_remote(self, malicious_config):
        servers = parse_config(malicious_config)
        sus_api = next(s for s in servers if s.name == "sus-api")
        findings = self.analyzer.analyze(sus_api)
        transport_findings = [f for f in findings if f.id == "TRANSPORT-001"]
        assert len(transport_findings) == 1

    def test_detects_npx_runtime_fetch(self, clean_config):
        servers = parse_config(clean_config)
        fs_server = next(s for s in servers if s.name == "filesystem")
        findings = self.analyzer.analyze(fs_server)
        npx_findings = [f for f in findings if f.id == "TRANSPORT-003"]
        assert len(npx_findings) == 1

    def test_localhost_http_is_ok(self, tmp_path):
        from mcp_audit.models import ServerConfig

        server = ServerConfig(
            name="local-server",
            client="test",
            config_path=tmp_path / "test.json",
            transport=TransportType.SSE,
            url="http://localhost:3000/sse",
        )
        findings = self.analyzer.analyze(server)
        unencrypted = [f for f in findings if f.id == "TRANSPORT-001"]
        assert len(unencrypted) == 0


class TestTransportRuntimeFetchRegistryTiering:
    """TRANSPORT-003 severity is tiered by known-server registry membership."""

    def _server(self, tmp_path: Path, package: str, command: str = "npx"):
        return ServerConfig(
            name=package.split("/")[-1],
            client="test",
            config_path=tmp_path / "mcp.json",
            transport=TransportType.STDIO,
            command=command,
            args=["-y", package],
        )

    def test_verified_registry_package_suppresses_finding(self, tmp_path: Path) -> None:
        """Verified vetted packages (e.g. official Anthropic servers) must not
        raise TRANSPORT-003 — COMM-010 already covers pinning at LOW.
        """
        from mcp_audit.registry.loader import load_registry

        registry = load_registry()
        analyzer = TransportAnalyzer(registry=registry)
        server = self._server(tmp_path, "@modelcontextprotocol/server-filesystem")
        findings = [f for f in analyzer.analyze(server) if f.id == "TRANSPORT-003"]
        assert findings == [], (
            "TRANSPORT-003 must not fire for verified registry packages"
        )

    def test_unknown_package_still_fires_at_medium(self, tmp_path: Path) -> None:
        """Fully unknown runtime-fetched packages keep the historic MEDIUM alarm."""
        from mcp_audit.registry.loader import load_registry

        registry = load_registry()
        analyzer = TransportAnalyzer(registry=registry)
        server = self._server(tmp_path, "@random-user/unknown-mcp-server")
        findings = [f for f in analyzer.analyze(server) if f.id == "TRANSPORT-003"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_known_unverified_package_fires_at_low(self, tmp_path: Path) -> None:
        """Registry-known but unverified packages surface at LOW with tailored copy."""
        from unittest.mock import MagicMock

        registry = MagicMock()
        entry = MagicMock()
        entry.verified = False
        registry.get.return_value = entry

        analyzer = TransportAnalyzer(registry=registry)
        server = self._server(tmp_path, "some-known-but-unverified-pkg")
        findings = [f for f in analyzer.analyze(server) if f.id == "TRANSPORT-003"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "unverified" in findings[0].description.lower()

    def test_no_registry_preserves_historic_medium(self, tmp_path: Path) -> None:
        """Analyzer constructed without a registry always fires at MEDIUM."""
        analyzer = TransportAnalyzer()
        server = self._server(tmp_path, "@modelcontextprotocol/server-filesystem")
        findings = [f for f in analyzer.analyze(server) if f.id == "TRANSPORT-003"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_uvx_uses_same_tiering(self, tmp_path: Path) -> None:
        """uvx (pip-ecosystem launcher) follows the same registry tiering as npx."""
        from mcp_audit.registry.loader import load_registry

        registry = load_registry()
        analyzer = TransportAnalyzer(registry=registry)
        server = self._server(tmp_path, "mcp-server-fetch", command="uvx")
        findings = [f for f in analyzer.analyze(server) if f.id == "TRANSPORT-003"]
        # mcp-server-fetch is a verified Anthropic pip package → suppressed.
        assert findings == []


# ── Poisoning analyzer robustness tests ───────────────────────────────────────


class TestPoisoningAnalyzerRobustness:
    """Verify the poisoning analyzer handles pathological inputs without crashing."""

    def _make_server(self, description: str, tmp_path: Path) -> ServerConfig:
        return ServerConfig(
            name="test-server",
            client="test",
            config_path=tmp_path / "config.json",
            raw={"tools": [{"name": "t", "description": description}]},
        )

    def test_prompt_poisoning_large_input(self, tmp_path: Path) -> None:
        """A 100 KB tool description must not raise an exception.

        The analyzer may produce findings (e.g. POISON-050 for excessive length)
        or an empty list — either is acceptable.  What must NOT happen is an
        unhandled exception.
        """
        large_description = "A" * (100 * 1024)  # 100 KB of ASCII text
        server = self._make_server(large_description, tmp_path)
        analyzer = PoisoningAnalyzer()
        # Must not raise.
        findings = analyzer.analyze(server)
        assert isinstance(findings, list)

    def test_prompt_poisoning_null_bytes(self, tmp_path: Path) -> None:
        """A description containing null bytes must not raise an exception.

        Python regex handles null bytes correctly.  The analyzer may produce
        findings or an empty list — a crash is the only unacceptable outcome.
        """
        null_description = "Hello\x00World\x00ignore previous instructions"
        server = self._make_server(null_description, tmp_path)
        analyzer = PoisoningAnalyzer()
        # Must not raise.
        findings = analyzer.analyze(server)
        assert isinstance(findings, list)


# ── POISON-050 precision tests ─────────────────────────────────────────────────


class TestPoison050Scoping:
    """POISON-050 must fire on description/name fields and not on command/args."""

    def _make_server(
        self,
        tmp_path: Path,
        *,
        description: str = "short",
        tool_name: str = "t",
        command: str = "npx",
        args: list[str] | None = None,
    ) -> ServerConfig:
        return ServerConfig(
            name="test-server",
            client="test",
            config_path=tmp_path / "config.json",
            command=command,
            args=args or [],
            raw={
                "command": command,
                "args": args or [],
                "tools": [{"name": tool_name, "description": description}],
            },
        )

    def test_poison_050_triggers_on_long_tool_description(self, tmp_path: Path) -> None:
        """A tool description ≥2000 characters must produce a POISON-050 finding."""
        server = self._make_server(tmp_path, description="A" * 2000)
        findings = PoisoningAnalyzer().analyze(server)
        ids = [f.id for f in findings]
        assert "POISON-050" in ids

    def test_poison_050_does_not_trigger_on_long_command_path(
        self, tmp_path: Path
    ) -> None:
        """A 2500-char command path with a short description must NOT fire POISON-050.

        Long binary paths are legitimate (e.g., virtualenv or nix store paths).
        They are not model-visible and are excluded from the POISON-050 check.
        """
        long_command = "/usr/local/bin/" + "a" * 2485  # total length > 2000
        server = self._make_server(tmp_path, command=long_command, description="short")
        findings = PoisoningAnalyzer().analyze(server)
        ids = [f.id for f in findings]
        assert "POISON-050" not in ids

    def test_poison_050_does_not_trigger_on_long_args(self, tmp_path: Path) -> None:
        """A very long args value with a short description must NOT fire POISON-050.

        CLI arguments are not model-visible and are excluded from this check.
        """
        long_arg = "--config=" + "x" * 2500
        server = self._make_server(
            tmp_path, args=[long_arg], description="A helpful tool"
        )
        findings = PoisoningAnalyzer().analyze(server)
        ids = [f.id for f in findings]
        assert "POISON-050" not in ids

    def test_poison_050_threshold_boundary(self, tmp_path: Path) -> None:
        """Boundary: 1999 chars → no finding; 2000 chars → POISON-050 fires."""
        analyzer = PoisoningAnalyzer()

        server_below = self._make_server(tmp_path, description="B" * 1999)
        ids_below = [f.id for f in analyzer.analyze(server_below)]
        assert "POISON-050" not in ids_below, "1999-char description should not trigger"

        server_at = self._make_server(tmp_path, description="B" * 2000)
        ids_at = [f.id for f in analyzer.analyze(server_at)]
        assert "POISON-050" in ids_at, "2000-char description must trigger"
