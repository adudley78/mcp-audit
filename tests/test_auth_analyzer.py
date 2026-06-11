"""Tests for mcp_audit.analyzers.auth — AUTH-001."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from mcp_audit.analyzers.auth import (
    AuthAnalyzer,
    _classify_host,
)
from mcp_audit.models import Finding, ServerConfig, Severity, TransportType

# ── Fixture helpers ────────────────────────────────────────────────────────────


def _server(
    name: str = "test",
    url: str | None = None,
    transport: TransportType = TransportType.STREAMABLE_HTTP,
    headers: dict | None = None,
    env: dict | None = None,
    raw: dict | None = None,
) -> ServerConfig:
    """Build a minimal ServerConfig for testing."""
    if raw is None:
        raw = {}
    if url is not None:
        raw["url"] = url
    return ServerConfig(
        name=name,
        client="test-client",
        config_path=Path("/tmp/test.json"),  # noqa: S108
        transport=transport,
        url=url,
        headers=headers or {},
        env=env or {},
        raw=raw,
    )


def _stdio_server(name: str = "local") -> ServerConfig:
    return ServerConfig(
        name=name,
        client="test-client",
        config_path=Path("/tmp/test.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command="node",
        args=["server.js"],
        raw={"command": "node", "args": ["server.js"]},
    )


def _find_auth001(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.id == "AUTH-001"]


# ── _classify_host ─────────────────────────────────────────────────────────────


class TestClassifyHost:
    def test_localhost_name(self) -> None:
        assert _classify_host("localhost") == "local"

    def test_127_0_0_1(self) -> None:
        assert _classify_host("127.0.0.1") == "local"

    def test_loopback_other(self) -> None:
        assert _classify_host("127.0.0.2") == "local"

    def test_ipv6_loopback_bare(self) -> None:
        assert _classify_host("::1") == "local"

    def test_ipv6_loopback_bracketed(self) -> None:
        assert _classify_host("[::1]") == "local"

    def test_rfc1918_10_block(self) -> None:
        assert _classify_host("10.0.0.1") == "private"

    def test_rfc1918_172_block(self) -> None:
        assert _classify_host("172.16.0.1") == "private"
        assert _classify_host("172.31.255.255") == "private"

    def test_rfc1918_192_168(self) -> None:
        assert _classify_host("192.168.1.100") == "private"

    def test_link_local(self) -> None:
        assert _classify_host("169.254.0.1") == "private"

    def test_local_mdns(self) -> None:
        assert _classify_host("myserver.local") == "private"

    def test_public_ip(self) -> None:
        assert _classify_host("8.8.8.8") == "public"

    def test_public_hostname(self) -> None:
        assert _classify_host("api.example.com") == "public"

    def test_empty_hostname(self) -> None:
        assert _classify_host("") == "public"

    def test_172_15_is_public(self) -> None:
        # 172.15.x.x is NOT in the 172.16-31 private range.
        assert _classify_host("172.15.0.1") == "public"

    def test_172_32_is_public(self) -> None:
        assert _classify_host("172.32.0.1") == "public"


# ── AUTH-001: acceptance criteria ─────────────────────────────────────────────


class TestAuth001PublicHost:
    """Public-host remote server, no auth material → AUTH-001 HIGH."""

    def test_public_http_no_auth_emits_high(self) -> None:
        server = _server(url="https://api.example.com/mcp")
        findings = AuthAnalyzer().analyze(server)
        auth = _find_auth001(findings)
        assert len(auth) == 1
        assert auth[0].severity == Severity.HIGH

    def test_public_sse_no_auth_emits_high(self) -> None:
        server = _server(
            url="https://mcp.example.com/sse",
            transport=TransportType.SSE,
        )
        findings = AuthAnalyzer().analyze(server)
        auth = _find_auth001(findings)
        assert len(auth) == 1
        assert auth[0].severity == Severity.HIGH

    def test_owasp_code_is_mcp06(self) -> None:
        server = _server(url="https://api.example.com/mcp")
        findings = AuthAnalyzer().analyze(server)
        assert "MCP06" in _find_auth001(findings)[0].owasp_mcp_top_10

    def test_cwe_is_306(self) -> None:
        server = _server(url="https://api.example.com/mcp")
        findings = AuthAnalyzer().analyze(server)
        assert _find_auth001(findings)[0].cwe == "CWE-306"


class TestAuth001Localhost:
    """localhost/127.0.0.1/::1 → no finding."""

    def test_localhost_no_finding(self) -> None:
        server = _server(url="http://localhost:8080/mcp")
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_127_0_0_1_no_finding(self) -> None:
        server = _server(url="http://127.0.0.1:8080/mcp")
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_ipv6_loopback_no_finding(self) -> None:
        server = _server(url="http://[::1]:8080/mcp")
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []


class TestAuth001PrivateHost:
    """Private-range hosts → AUTH-001 MEDIUM."""

    def test_10_x_emits_medium(self) -> None:
        server = _server(url="https://10.0.0.5/mcp")
        findings = _find_auth001(AuthAnalyzer().analyze(server))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_192_168_emits_medium(self) -> None:
        server = _server(url="https://192.168.1.1/mcp")
        findings = _find_auth001(AuthAnalyzer().analyze(server))
        assert findings[0].severity == Severity.MEDIUM

    def test_mdns_local_emits_medium(self) -> None:
        server = _server(url="https://devbox.local/mcp")
        findings = _find_auth001(AuthAnalyzer().analyze(server))
        assert findings[0].severity == Severity.MEDIUM


class TestAuth001AuthSignalSuppression:
    """Any auth signal suppresses AUTH-001."""

    def test_authorization_header_suppresses(self) -> None:
        server = _server(
            url="https://api.example.com/mcp",
            headers={"Authorization": "Bearer ${TOKEN}"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_x_api_key_header_suppresses(self) -> None:
        server = _server(
            url="https://api.example.com/mcp",
            headers={"x-api-key": "${API_KEY}"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_api_key_header_suppresses(self) -> None:
        server = _server(
            url="https://api.example.com/mcp",
            headers={"api-key": "mykey123"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_token_field_in_raw_suppresses(self) -> None:
        server = _server(
            url="https://api.example.com/mcp",
            raw={"url": "https://api.example.com/mcp", "token": "${TOKEN}"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_apikey_field_suppresses(self) -> None:
        server = _server(
            url="https://api.example.com/mcp",
            raw={"url": "https://api.example.com/mcp", "apiKey": "abc123"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_oauth_fields_suppress(self) -> None:
        server = _server(
            url="https://api.example.com/mcp",
            raw={
                "url": "https://api.example.com/mcp",
                "oauth": {
                    "client_id": "my-client",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                },
            },
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_url_userinfo_suppresses(self) -> None:
        server = _server(url="https://token:@api.example.com/mcp")
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_user_password_url_suppresses(self) -> None:
        server = _server(url="https://user:pass@api.example.com/mcp")
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_env_var_placeholder_in_header_suppresses(self) -> None:
        server = _server(
            url="https://api.example.com/mcp",
            headers={"Authorization": "${BEARER_TOKEN}"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_case_insensitive_header_name(self) -> None:
        # 'AUTHORIZATION' in uppercase should still suppress.
        server = _server(
            url="https://api.example.com/mcp",
            headers={"AUTHORIZATION": "Bearer tok"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []


class TestAuth001StdioNeverFires:
    """stdio (command) servers: AUTH-001 never fires."""

    def test_stdio_server_no_finding(self) -> None:
        server = _stdio_server()
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []

    def test_stdio_with_env_no_finding(self) -> None:
        server = ServerConfig(
            name="local-node",
            client="test",
            config_path=Path("/tmp/t.json"),  # noqa: S108
            transport=TransportType.STDIO,
            command="node",
            args=["srv.js"],
            env={"SOME_KEY": "val"},
            raw={"command": "node"},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []


class TestAuth001MalformedURL:
    """Malformed URL: skip without crashing."""

    def test_malformed_url_no_crash(self) -> None:
        # urlparse won't raise but will produce empty hostname.
        server = _server(url="not-a-url", transport=TransportType.STREAMABLE_HTTP)
        # Should not raise; may or may not produce a finding depending on
        # what urlparse returns for this input — just assert no exception.
        AuthAnalyzer().analyze(server)

    def test_no_url_no_finding(self) -> None:
        server = ServerConfig(
            name="no-url",
            client="test",
            config_path=Path("/tmp/t.json"),  # noqa: S108
            transport=TransportType.STREAMABLE_HTTP,
            raw={},
        )
        assert _find_auth001(AuthAnalyzer().analyze(server)) == []


# ── Scanner pipeline integration ──────────────────────────────────────────────


def _patch_no_known_clients():
    return patch("mcp_audit.discovery._get_client_specs", return_value=[])


class TestScannerPipelineIntegration:
    """AUTH-001 surfaces through the full scan pipeline."""

    def test_unauthenticated_remote_server_in_full_scan(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "remote-no-auth": {
                            "url": "https://api.example.com/mcp",
                        }
                    }
                }
            )
        )
        from mcp_audit.scanner import run_scan

        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config],
                skip_rug_pull=True,
            )

        auth_findings = [f for f in result.findings if f.id == "AUTH-001"]
        assert len(auth_findings) >= 1
        assert auth_findings[0].severity == Severity.HIGH

    def test_authenticated_remote_server_no_auth001(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "remote-with-auth": {
                            "url": "https://api.example.com/mcp",
                            "headers": {"Authorization": "Bearer ${TOKEN}"},
                        }
                    }
                }
            )
        )
        from mcp_audit.scanner import run_scan

        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config],
                skip_rug_pull=True,
            )

        auth_findings = [f for f in result.findings if f.id == "AUTH-001"]
        assert auth_findings == []

    def test_auth_analyzer_in_get_default_analyzers(self) -> None:
        from mcp_audit.scanner import get_default_analyzers

        analyzers = get_default_analyzers()
        types = [type(a).__name__ for a in analyzers]
        assert "AuthAnalyzer" in types

    def test_headers_parsed_from_config(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "srv": {
                            "url": "https://api.example.com/mcp",
                            "headers": {"x-api-key": "mykey"},
                        }
                    }
                }
            )
        )
        from mcp_audit.config_parser import parse_config
        from mcp_audit.discovery import DiscoveredConfig

        dc = DiscoveredConfig(path=config, client_name="test", root_key="mcpServers")
        servers = parse_config(dc)
        assert len(servers) == 1
        assert servers[0].headers.get("x-api-key") == "mykey"
