"""Tests for the supply chain attestation module (Layer 1: hash verification).

All network-touching functions are mocked — no real HTTP calls are made.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from mcp_audit.attestation.hasher import (
    HashResult,
    compute_hash_from_file,
    resolve_npm_tarball_url,
    resolve_pip_tarball_url,
)
from mcp_audit.attestation.verifier import (
    extract_version_from_server,
    verify_server_hashes,
)
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig, Severity, TransportType
from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_server(
    name: str = "@modelcontextprotocol/server-filesystem",
    command: str = "npx",
    args: list[str] | None = None,
    client: str = "claude",
    config_path: str = "/tmp/mcp.json",  # noqa: S108
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=Path(config_path),
        transport=TransportType.STDIO,
        command=command,
        args=args or [],
    )


def _make_registry_with_hashes(
    tmp_path: Path,
    entries: list[dict] | None = None,
) -> KnownServerRegistry:
    """Build a KnownServerRegistry backed by a temp JSON file."""
    if entries is None:
        entries = [
            {
                "name": "@modelcontextprotocol/server-filesystem",
                "source": "npm",
                "repo": "https://github.com/modelcontextprotocol/servers",
                "maintainer": "Anthropic",
                "verified": True,
                "last_verified": "2026-04-15",
                "known_versions": ["0.6.2"],
                "tags": ["official"],
                "known_hashes": {"0.6.2": "sha256:abc123def456abc123def456abc123de"},
            }
        ]
    data = {
        "schema_version": "1.0",
        "last_updated": "2026-04-15",
        "entry_count": len(entries),
        "entries": entries,
    }
    reg_file = tmp_path / "registry.json"
    reg_file.write_text(json.dumps(data))
    return KnownServerRegistry(path=reg_file)


# ── TestHashComputation ────────────────────────────────────────────────────────


class TestHashComputation:
    def test_compute_hash_from_file(self, tmp_path: Path) -> None:
        content = b"hello mcp-audit"
        f = tmp_path / "test.bin"
        f.write_bytes(content)
        expected = "sha256:" + hashlib.sha256(content).hexdigest()
        assert compute_hash_from_file(f) == expected

    def test_compute_hash_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = "sha256:" + hashlib.sha256(b"").hexdigest()
        assert compute_hash_from_file(f) == expected

    def test_resolve_npm_tarball_url_scoped(self) -> None:
        url = resolve_npm_tarball_url("@scope/name", "1.2.3")
        assert url == "https://registry.npmjs.org/@scope/name/-/name-1.2.3.tgz"

    def test_resolve_npm_tarball_url_unscoped(self) -> None:
        url = resolve_npm_tarball_url("some-package", "0.5.0")
        assert url == "https://registry.npmjs.org/some-package/-/some-package-0.5.0.tgz"

    def test_resolve_pip_tarball_url(self) -> None:
        url = resolve_pip_tarball_url("mcp", "1.6.0")
        assert url == "https://pypi.org/pypi/mcp/1.6.0/json"


# ── TestVersionExtraction ──────────────────────────────────────────────────────


class TestVersionExtraction:
    def test_extract_version_npx_scoped(self) -> None:
        server = _make_server(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem@0.6.2"],
        )
        assert extract_version_from_server(server) == "0.6.2"

    def test_extract_version_npx_unscoped(self) -> None:
        server = _make_server(
            command="npx",
            args=["some-package@0.5.0"],
        )
        assert extract_version_from_server(server) == "0.5.0"

    def test_extract_version_no_version(self) -> None:
        server = _make_server(
            command="npx",
            args=["some-package"],
        )
        assert extract_version_from_server(server) is None

    def test_extract_version_non_npx(self) -> None:
        server = _make_server(
            command="python",
            args=["-m", "mcp_server_sqlite@1.0.0"],
        )
        assert extract_version_from_server(server) is None


# ── TestRegistryEntryHashField ─────────────────────────────────────────────────


class TestRegistryEntryHashField:
    def test_registry_entry_loads_without_hashes(self) -> None:
        entry = RegistryEntry(
            name="test-pkg",
            source="npm",
            repo=None,
            maintainer="test",
            verified=True,
            last_verified="2026-01-01",
            known_versions=[],
            tags=[],
        )
        assert entry.known_hashes is None

    def test_registry_entry_loads_with_hashes(self) -> None:
        entry = RegistryEntry(
            name="test-pkg",
            source="npm",
            repo=None,
            maintainer="test",
            verified=True,
            last_verified="2026-01-01",
            known_versions=["1.0.0"],
            tags=[],
            known_hashes={"1.0.0": "sha256:abc123"},
        )
        assert entry.known_hashes is not None
        assert entry.known_hashes["1.0.0"] == "sha256:abc123"

    def test_registry_entry_hash_format_preserved(self) -> None:
        hash_val = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        entry = RegistryEntry(
            name="test-pkg",
            source="pip",
            repo=None,
            maintainer="test",
            verified=True,
            last_verified="2026-01-01",
            known_versions=["2.0.0"],
            tags=[],
            known_hashes={"2.0.0": hash_val},
        )
        assert entry.known_hashes["2.0.0"] == hash_val

    def test_existing_entries_backward_compat(self, tmp_path: Path) -> None:
        """Existing registry entries without known_hashes load without error."""
        data = {
            "schema_version": "1.0",
            "last_updated": "2026-04-15",
            "entry_count": 1,
            "entries": [
                {
                    "name": "@modelcontextprotocol/server-filesystem",
                    "source": "npm",
                    "repo": "https://github.com/modelcontextprotocol/servers",
                    "maintainer": "Anthropic",
                    "verified": True,
                    "last_verified": "2026-04-15",
                    "known_versions": [],
                    "tags": ["official"],
                }
            ],
        }
        reg_file = tmp_path / "registry.json"
        reg_file.write_text(json.dumps(data))
        reg = KnownServerRegistry(path=reg_file)
        assert len(reg.entries) == 1
        assert reg.entries[0].known_hashes is None


# ── TestVerifierFindings ───────────────────────────────────────────────────────


class TestVerifierFindings:
    def test_hash_match_no_finding(self, tmp_path: Path) -> None:
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="@modelcontextprotocol/server-filesystem",
            args=["@modelcontextprotocol/server-filesystem@0.6.2"],
        )
        match_result = HashResult(
            package_name="@modelcontextprotocol/server-filesystem",
            version="0.6.2",
            computed_hash="sha256:abc123def456abc123def456abc123de",
            expected_hash="sha256:abc123def456abc123def456abc123de",
            match=True,
            source_url="https://registry.npmjs.org/...",
        )
        with patch(
            "mcp_audit.attestation.verifier.verify_package_hash",
            return_value=match_result,
        ):
            findings = verify_server_hashes([server], reg)
        assert findings == []

    def test_hash_mismatch_critical_finding(self, tmp_path: Path) -> None:
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="@modelcontextprotocol/server-filesystem",
            args=["@modelcontextprotocol/server-filesystem@0.6.2"],
        )
        mismatch_result = HashResult(
            package_name="@modelcontextprotocol/server-filesystem",
            version="0.6.2",
            computed_hash="sha256:deadbeefdeadbeefdeadbeef",
            expected_hash="sha256:abc123def456abc123def456abc123de",
            match=False,
            source_url="https://registry.npmjs.org/...",
        )
        with patch(
            "mcp_audit.attestation.verifier.verify_package_hash",
            return_value=mismatch_result,
        ):
            findings = verify_server_hashes([server], reg)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.analyzer == "attestation"
        assert "@modelcontextprotocol/server-filesystem" in f.title
        assert "0.6.2" in f.title

    def test_network_error_info_finding(self, tmp_path: Path) -> None:
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="@modelcontextprotocol/server-filesystem",
            args=["@modelcontextprotocol/server-filesystem@0.6.2"],
        )
        error_result = HashResult(
            package_name="@modelcontextprotocol/server-filesystem",
            version="0.6.2",
            computed_hash="",
            expected_hash="sha256:abc123def456abc123def456abc123de",
            match=None,
            source_url="Network error: <urlopen error timeout>",
        )
        with patch(
            "mcp_audit.attestation.verifier.verify_package_hash",
            return_value=error_result,
        ):
            findings = verify_server_hashes([server], reg)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.INFO
        assert f.analyzer == "attestation"

    def test_no_hash_pinned_for_version_info_finding(self, tmp_path: Path) -> None:
        """Version exists in server config but has no pinned hash in registry."""
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="@modelcontextprotocol/server-filesystem",
            args=["@modelcontextprotocol/server-filesystem@9.9.9"],
        )
        findings = verify_server_hashes([server], reg)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.INFO
        assert "9.9.9" in f.title

    def test_version_unknown_info_finding(self, tmp_path: Path) -> None:
        """Server config doesn't expose a version — should produce INFO finding."""
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="@modelcontextprotocol/server-filesystem",
            # No version pin in args
            args=["@modelcontextprotocol/server-filesystem"],
        )
        findings = verify_server_hashes([server], reg)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.INFO
        assert "unknown" in f.title.lower() or "cannot" in f.title.lower()

    def test_server_not_in_registry_no_finding(self, tmp_path: Path) -> None:
        """Unrecognized server name → attestation skips it entirely."""
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="totally-unknown-server",
            args=["totally-unknown-server@1.0.0"],
        )
        findings = verify_server_hashes([server], reg)
        assert findings == []

    def test_finding_id_deterministic(self, tmp_path: Path) -> None:
        """Same inputs always produce the same finding id."""
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="@modelcontextprotocol/server-filesystem",
            args=["@modelcontextprotocol/server-filesystem@0.6.2"],
        )
        mismatch_result = HashResult(
            package_name="@modelcontextprotocol/server-filesystem",
            version="0.6.2",
            computed_hash="sha256:bad",
            expected_hash="sha256:abc123def456abc123def456abc123de",
            match=False,
            source_url="https://registry.npmjs.org/...",
        )
        with patch(
            "mcp_audit.attestation.verifier.verify_package_hash",
            return_value=mismatch_result,
        ):
            findings1 = verify_server_hashes([server], reg)
            findings2 = verify_server_hashes([server], reg)
        assert findings1[0].id == findings2[0].id

    def test_mismatch_finding_evidence_fields(self, tmp_path: Path) -> None:
        """CRITICAL mismatch finding evidence contains required fields."""
        reg = _make_registry_with_hashes(tmp_path)
        server = _make_server(
            name="@modelcontextprotocol/server-filesystem",
            args=["@modelcontextprotocol/server-filesystem@0.6.2"],
        )
        mismatch_result = HashResult(
            package_name="@modelcontextprotocol/server-filesystem",
            version="0.6.2",
            computed_hash="sha256:deadbeef",
            expected_hash="sha256:abc123def456abc123def456abc123de",
            match=False,
            source_url="https://registry.npmjs.org/...",
        )
        with patch(
            "mcp_audit.attestation.verifier.verify_package_hash",
            return_value=mismatch_result,
        ):
            findings = verify_server_hashes([server], reg)
        assert len(findings) == 1
        evidence = json.loads(findings[0].evidence)
        assert "package_name" in evidence
        assert "version" in evidence
        assert "expected_hash" in evidence
        assert "computed_hash" in evidence


# ── TestVerifyCLI ──────────────────────────────────────────────────────────────


runner = CliRunner()


class TestVerifyCLI:
    def test_verify_specific_server_pass(self, tmp_path: Path) -> None:
        _make_registry_with_hashes(tmp_path)
        reg_path = tmp_path / "registry.json"

        match_result = HashResult(
            package_name="@modelcontextprotocol/server-filesystem",
            version="0.6.2",
            computed_hash="sha256:abc123def456abc123def456abc123de",
            expected_hash="sha256:abc123def456abc123def456abc123de",
            match=True,
            source_url="https://registry.npmjs.org/...",
        )
        with patch(
            "mcp_audit.attestation.hasher.verify_package_hash",
            return_value=match_result,
        ):
            result = runner.invoke(
                app,
                [
                    "verify",
                    "@modelcontextprotocol/server-filesystem",
                    "--registry",
                    str(reg_path),
                ],
            )
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_specific_server_fail(self, tmp_path: Path) -> None:
        _make_registry_with_hashes(tmp_path)
        reg_path = tmp_path / "registry.json"

        fail_result = HashResult(
            package_name="@modelcontextprotocol/server-filesystem",
            version="0.6.2",
            computed_hash="sha256:deadbeef",
            expected_hash="sha256:abc123def456abc123def456abc123de",
            match=False,
            source_url="https://registry.npmjs.org/...",
        )
        with patch(
            "mcp_audit.attestation.hasher.verify_package_hash",
            return_value=fail_result,
        ):
            result = runner.invoke(
                app,
                [
                    "verify",
                    "@modelcontextprotocol/server-filesystem",
                    "--registry",
                    str(reg_path),
                ],
            )
        assert result.exit_code == 1
        assert "FAIL" in result.output

    def test_verify_unknown_server(self, tmp_path: Path) -> None:
        _make_registry_with_hashes(tmp_path)
        reg_path = tmp_path / "registry.json"

        result = runner.invoke(
            app,
            ["verify", "totally-unknown-server", "--registry", str(reg_path)],
        )
        assert result.exit_code == 0
        assert "not in the registry" in result.output

    def test_verify_all_no_hashes_pinned(self, tmp_path: Path) -> None:
        """--all with no servers that have pinned hashes exits 0."""
        data = {
            "schema_version": "1.0",
            "last_updated": "2026-04-15",
            "entry_count": 1,
            "entries": [
                {
                    "name": "@modelcontextprotocol/server-filesystem",
                    "source": "npm",
                    "repo": None,
                    "maintainer": "Anthropic",
                    "verified": True,
                    "last_verified": "2026-04-15",
                    "known_versions": [],
                    "tags": [],
                    # No known_hashes field
                }
            ],
        }
        reg_file = tmp_path / "registry.json"
        reg_file.write_text(json.dumps(data))

        with patch("mcp_audit.cli.discover_configs", return_value=[]):
            result = runner.invoke(
                app, ["verify", "--all", "--registry", str(reg_file)]
            )
        assert result.exit_code == 0


# ── TestScanWithVerifyHashes ───────────────────────────────────────────────────


class TestScanWithVerifyHashes:
    def test_scan_verify_hashes_flag_triggers_attestation(self, tmp_path: Path) -> None:
        """--verify-hashes causes verify_server_hashes to be called."""
        cfg = tmp_path / "mcp.json"
        cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "@modelcontextprotocol/server-filesystem": {
                            "command": "npx",
                            "args": ["@modelcontextprotocol/server-filesystem@0.6.2"],
                        }
                    }
                }
            )
        )
        reg = _make_registry_with_hashes(tmp_path)
        reg_path = tmp_path / "registry.json"

        with (
            patch(
                "mcp_audit.attestation.verifier.verify_server_hashes",
                return_value=[],
            ) as mock_verify,
            patch(
                "mcp_audit.registry.loader.KnownServerRegistry",
                return_value=reg,
            ),
        ):
            runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(cfg),
                    "--verify-hashes",
                    "--registry",
                    str(reg_path),
                ],
            )
        # The attestation verifier should have been called
        mock_verify.assert_called_once()

    def test_scan_no_verify_hashes_skips_attestation(self, tmp_path: Path) -> None:
        """Default scan (no --verify-hashes) does not call verify_server_hashes."""
        cfg = tmp_path / "mcp.json"
        cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "test-server": {
                            "command": "npx",
                            "args": ["test-server"],
                        }
                    }
                }
            )
        )
        with patch(
            "mcp_audit.attestation.verifier.verify_server_hashes",
        ) as mock_verify:
            runner.invoke(
                app,
                ["scan", "--path", str(cfg)],
            )
        mock_verify.assert_not_called()
