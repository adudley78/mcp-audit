"""Tests for ``mcp-audit vet`` and ``mcp_audit.verdict``."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry
from mcp_audit.verdict import (
    SCHEMA_VERSION,
    badge_url,
    build_verdict,
    name_to_slug,
    verdict_page_url,
)

# Windows does not support POSIX file permission bits — skip mode checks there.
_windows_skip = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows does not support POSIX file permissions",
)

runner = CliRunner()

# ── Fixtures ──────────────────────────────────────────────────────────────────

_VERIFIED_ENTRY = RegistryEntry(
    name="@modelcontextprotocol/server-filesystem",
    source="npm",
    repo="https://github.com/modelcontextprotocol/servers",
    maintainer="Anthropic",
    verified=True,
    last_verified="2026-04-15",
    known_versions=[],
    tags=["official", "filesystem", "local"],
    known_hashes={"2026.1.14": "sha256:abc123"},
    capabilities=["file_read", "file_write"],
    attestation_expected=True,
    known_vulnerabilities=None,
    known_vulns=[],
)

_CVE_ENTRY = RegistryEntry(
    name="mcp-atlassian",
    source="pip",
    repo="https://github.com/sooperset/mcp-atlassian",
    maintainer="sooperset",
    verified=True,
    last_verified="2026-04-15",
    known_versions=["0.9.3"],
    tags=["atlassian", "jira", "confluence"],
    package_ecosystem="pypi",
    known_vulnerabilities=["CVE-2026-27826"],
    known_vulns=[
        {
            "cve": "CVE-2026-27826",
            "cvss": 9.8,
            "description": "Authentication bypass via crafted token",
            "fixed_in": "0.9.4",
        }
    ],
)

_UNVERIFIED_ENTRY = RegistryEntry(
    name="some-mcp-tool",
    source="npm",
    repo=None,
    maintainer="unknown-dev",
    verified=False,
    last_verified="2026-01-01",
    known_versions=[],
    tags=["community"],
    known_vulnerabilities=None,
    known_vulns=[],
)


def _make_registry(entries: list[RegistryEntry] | None = None) -> KnownServerRegistry:
    """Return a KnownServerRegistry populated with synthetic entries."""
    reg = MagicMock(spec=KnownServerRegistry)
    entries = entries or [_VERIFIED_ENTRY]
    reg.entries = entries
    reg.schema_version = "1.0"
    reg.last_updated = "2026-06-13"

    # Wire up the index lookups to match real behaviour.
    name_index = {e.name.lower(): e for e in entries}
    reg.get = lambda name: name_index.get(name.lower())
    reg.is_known = lambda name: name.lower() in name_index

    from mcp_audit.registry.loader import normalize_pypi_name  # noqa: PLC0415

    npm_entries = [e for e in entries if e.package_ecosystem in ("npm", "any")]
    npm_index = {e.name.lower(): e for e in npm_entries}
    reg.get_npm = lambda name: npm_index.get(name.lower())
    reg.is_known_npm = lambda name: name.lower() in npm_index

    pypi_entries = [e for e in entries if e.package_ecosystem in ("pypi", "any")]
    pypi_norm = {normalize_pypi_name(e.name): e for e in pypi_entries}
    reg.get_pypi = lambda name: pypi_norm.get(normalize_pypi_name(name))
    reg.is_known_pypi = lambda name: normalize_pypi_name(name) in pypi_norm

    reg.find_closest = MagicMock(return_value=None)
    reg.find_closest_npm = MagicMock(return_value=None)
    reg.find_closest_pypi = MagicMock(return_value=None)
    return reg


# ── Unit: name_to_slug ─────────────────────────────────────────────────────────


class TestNameToSlug:
    def test_scoped_npm(self) -> None:
        assert name_to_slug("@modelcontextprotocol/server-filesystem") == (
            "at-modelcontextprotocol-server-filesystem"
        )

    def test_scoped_npm_azure(self) -> None:
        assert name_to_slug("@azure/mcp") == "at-azure-mcp"

    def test_plain_name(self) -> None:
        assert name_to_slug("mcp-atlassian") == "mcp-atlassian"

    def test_underscores_replaced(self) -> None:
        assert name_to_slug("mcp_server_git") == "mcp-server-git"

    def test_uppercase_lowercased(self) -> None:
        assert name_to_slug("MyMCPServer") == "mymcpserver"

    def test_roundtrip_scoped(self) -> None:
        # Slug conversion is deterministic and idempotent for the URL builder.
        slug = name_to_slug("@scope/my_pkg")
        assert slug == "at-scope-my-pkg"


# ── Unit: badge_url / verdict_page_url ────────────────────────────────────────


class TestUrls:
    def test_badge_url_npm(self) -> None:
        url = badge_url("npm", "@scope/name")
        assert url == (
            "https://img.shields.io/endpoint?"
            "url=https://mcp-audit.dev/v1/badge/npm/at-scope-name.json"
        )

    def test_verdict_page_url_pypi(self) -> None:
        url = verdict_page_url("pypi", "mcp-atlassian")
        assert url == "https://mcp-audit.dev/v1/verdicts/pypi/mcp-atlassian.json"


# ── Unit: build_verdict ────────────────────────────────────────────────────────


class TestBuildVerdict:
    _PKG = "@modelcontextprotocol/server-filesystem"

    def _reg(self) -> KnownServerRegistry:
        return _make_registry([_VERIFIED_ENTRY])

    def test_schema_version(self) -> None:
        v = build_verdict(self._PKG, "npm", _VERIFIED_ENTRY, None, self._reg())
        assert v["schema_version"] == SCHEMA_VERSION

    def test_required_keys_present(self) -> None:
        v = build_verdict(self._PKG, "npm", _VERIFIED_ENTRY, None, self._reg())
        for key in (
            "schema_version",
            "generated_at",
            "package",
            "registry",
            "known_vulnerabilities",
            "capabilities",
            "attestation",
        ):
            assert key in v, f"Missing required key: {key}"

    def test_known_verified(self) -> None:
        v = build_verdict(self._PKG, "npm", _VERIFIED_ENTRY, None, self._reg())
        assert v["registry"]["listed"] is True
        assert v["registry"]["verified"] is True
        assert v["registry"]["maintainer"] == "Anthropic"
        assert v["known_vulnerabilities"] == []
        assert v["typosquat_of"] is None
        assert "file_read" in v["capabilities"]
        assert v["attestation"]["hash_pins_available"] is True
        assert v["attestation"]["attestation_expected"] is True

    def test_unknown_package(self) -> None:
        v = build_verdict("nonexistent-pkg", "npm", None, None, self._reg())
        assert v["registry"]["listed"] is False
        assert v["registry"]["verified"] is False
        assert v["known_vulnerabilities"] == []
        assert v["typosquat_of"] is None
        assert v["capabilities"] == []

    def test_typosquat_field_populated(self) -> None:
        v = build_verdict(
            "@modelcontextprotocol/server-filesytem",  # typo
            "npm",
            None,
            _VERIFIED_ENTRY,
            self._reg(),
        )
        assert v["typosquat_of"] == "@modelcontextprotocol/server-filesystem"
        assert v["registry"]["listed"] is False

    def test_package_block(self) -> None:
        v = build_verdict("test-pkg", "pypi", None, None, self._reg())
        assert v["package"]["ecosystem"] == "pypi"
        assert v["package"]["name"] == "test-pkg"

    def test_links_verdict_page(self) -> None:
        v = build_verdict("@scope/name", "npm", None, None, self._reg())
        assert "mcp-audit.dev" in v["links"]["verdict_page"]
        assert "at-scope-name" in v["links"]["verdict_page"]

    def test_generated_at_is_iso8601(self) -> None:
        from datetime import datetime  # noqa: PLC0415

        v = build_verdict("pkg", "npm", None, None, self._reg())
        # Should parse without raising.
        datetime.fromisoformat(v["generated_at"])


# ── Unit: CVE normalisation ────────────────────────────────────────────────────


class TestCveNormalisation:
    def test_rich_vulns_take_precedence(self) -> None:
        reg = _make_registry([_CVE_ENTRY])
        v = build_verdict("mcp-atlassian", "pypi", _CVE_ENTRY, None, reg)
        vulns = v["known_vulnerabilities"]
        assert len(vulns) == 1
        cve = vulns[0]
        assert cve["cve"] == "CVE-2026-27826"
        assert cve["cvss"] == 9.8
        assert cve["description"] == "Authentication bypass via crafted token"
        assert cve["fixed_in"] == "0.9.4"
        assert cve["source"] == "NVD"
        assert "nvd.nist.gov" in cve["link"]

    def test_bare_cve_strings_promoted(self) -> None:
        """Entries with only known_vulnerabilities (bare strings) get promoted."""
        bare_entry = RegistryEntry(
            name="bare-pkg",
            source="npm",
            repo=None,
            maintainer="test",
            verified=False,
            last_verified="2026-01-01",
            known_versions=[],
            tags=[],
            known_vulnerabilities=["CVE-2025-0001"],
            known_vulns=[],
        )
        reg = _make_registry([bare_entry])
        v = build_verdict("bare-pkg", "npm", bare_entry, None, reg)
        vulns = v["known_vulnerabilities"]
        assert len(vulns) == 1
        assert vulns[0]["cve"] == "CVE-2025-0001"
        assert vulns[0]["cvss"] is None
        assert vulns[0]["source"] == "NVD"

    def test_deduplication_across_both_fields(self) -> None:
        """CVE in both known_vulns (rich) and known_vulnerabilities appears once."""
        dup_entry = RegistryEntry(
            name="dup-pkg",
            source="npm",
            repo=None,
            maintainer="test",
            verified=False,
            last_verified="2026-01-01",
            known_versions=[],
            tags=[],
            known_vulnerabilities=["CVE-2025-0001"],
            known_vulns=[
                {
                    "cve": "CVE-2025-0001",
                    "cvss": 7.0,
                    "description": "desc",
                    "fixed_in": "1.2.3",
                }
            ],
        )
        reg = _make_registry([dup_entry])
        v = build_verdict("dup-pkg", "npm", dup_entry, None, reg)
        assert len(v["known_vulnerabilities"]) == 1
        assert v["known_vulnerabilities"][0]["cvss"] == 7.0  # rich version wins


# ── JSON schema conformance ────────────────────────────────────────────────────


class TestJsonSchemaConformance:
    """Validate verdict dict against required fields from mcp-audit.dev v1 schema."""

    _REQUIRED_KEYS = {
        "schema_version",
        "generated_at",
        "package",
        "registry",
        "known_vulnerabilities",
        "capabilities",
        "attestation",
    }
    _VULN_REQUIRED = {"cve", "source"}

    def _v(self, entry: RegistryEntry | None = None) -> dict:
        reg = _make_registry([entry] if entry else [])
        return build_verdict("test", "npm", entry, None, reg)

    def test_all_required_keys_present_known(self) -> None:
        v = self._v(_VERIFIED_ENTRY)
        assert self._REQUIRED_KEYS.issubset(v.keys())

    def test_all_required_keys_present_unknown(self) -> None:
        v = self._v(None)
        assert self._REQUIRED_KEYS.issubset(v.keys())

    def test_known_vulns_items_have_required_keys(self) -> None:
        reg = _make_registry([_CVE_ENTRY])
        v = build_verdict("mcp-atlassian", "pypi", _CVE_ENTRY, None, reg)
        for item in v["known_vulnerabilities"]:
            missing = self._VULN_REQUIRED - item.keys()
            assert not missing, f"Item missing required keys: {missing}"

    def test_capabilities_is_list(self) -> None:
        v = self._v(_VERIFIED_ENTRY)
        assert isinstance(v["capabilities"], list)

    def test_known_vulnerabilities_is_list(self) -> None:
        v = self._v(None)
        assert isinstance(v["known_vulnerabilities"], list)

    def test_typosquat_of_is_null_or_string(self) -> None:
        v = self._v(None)
        assert v.get("typosquat_of") is None or isinstance(v["typosquat_of"], str)


# ── CLI: clean path ────────────────────────────────────────────────────────────


class TestVetCliClean:
    def test_exit_0_for_known_verified(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app, ["vet", "@modelcontextprotocol/server-filesystem"]
            )
        assert result.exit_code == 0

    def test_terminal_output_shows_verified(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app, ["vet", "@modelcontextprotocol/server-filesystem"]
            )
        assert "Verified" in result.output or "Listed" in result.output

    def test_no_letter_grade_in_output(self) -> None:
        """Vet output must not contain a letter grade."""
        reg = _make_registry([_VERIFIED_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app, ["vet", "@modelcontextprotocol/server-filesystem"]
            )
        # No letter grade strings like "Grade: A" or "grade A"
        output = result.output.lower()
        assert "grade:" not in output
        assert "grade a" not in output
        assert "grade b" not in output


# ── CLI: CVE path ──────────────────────────────────────────────────────────────


class TestVetCliCve:
    def test_exit_1_for_cve(self) -> None:
        reg = _make_registry([_CVE_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "mcp-atlassian", "--ecosystem", "pypi"])
        assert result.exit_code == 1

    def test_cve_id_in_output(self) -> None:
        reg = _make_registry([_CVE_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "mcp-atlassian", "--ecosystem", "pypi"])
        assert "CVE-2026-27826" in result.output

    def test_nvd_link_in_output(self) -> None:
        reg = _make_registry([_CVE_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "mcp-atlassian", "--ecosystem", "pypi"])
        assert "nvd.nist.gov" in result.output


# ── CLI: typosquat path ────────────────────────────────────────────────────────


class TestVetCliTyposquat:
    def test_exit_1_for_typosquat(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        reg.find_closest_npm = MagicMock(return_value=_VERIFIED_ENTRY)
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app,
                ["vet", "@modelcontextprotocol/server-filesytem"],  # 1-char typo
            )
        assert result.exit_code == 1

    def test_did_you_mean_in_output(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        reg.find_closest_npm = MagicMock(return_value=_VERIFIED_ENTRY)
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app,
                ["vet", "@modelcontextprotocol/server-filesytem"],
            )
        out = result.output.lower()
        assert "typosquat" in out or "did you mean" in out


# ── CLI: unknown path ──────────────────────────────────────────────────────────


class TestVetCliUnknown:
    def test_exit_0_for_unknown_no_strict(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "completely-unknown-package"])
        assert result.exit_code == 0

    def test_exit_1_for_unknown_with_strict(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app, ["vet", "completely-unknown-package", "--strict"]
            )
        assert result.exit_code == 1

    def test_unknown_output_mentions_absence_not_signal(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "completely-unknown-package"])
        assert "NOT a safety signal" in result.output or "not" in result.output.lower()

    def test_unknown_output_suggests_scan(self) -> None:
        reg = _make_registry([_VERIFIED_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "completely-unknown-package"])
        assert "scan" in result.output


# ── CLI: --format json ─────────────────────────────────────────────────────────


class TestVetCliJson:
    def _get_json(self, pkg: str, extra_args: list[str] | None = None) -> dict:
        entries = [_VERIFIED_ENTRY, _CVE_ENTRY]
        reg = _make_registry(entries)
        args = ["vet", pkg, "--format", "json"] + (extra_args or [])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, args)
        return json.loads(result.output)

    def test_json_schema_version(self) -> None:
        v = self._get_json("@modelcontextprotocol/server-filesystem")
        assert v["schema_version"] == SCHEMA_VERSION

    def test_json_all_required_keys(self) -> None:
        v = self._get_json("@modelcontextprotocol/server-filesystem")
        for key in (
            "schema_version",
            "generated_at",
            "package",
            "registry",
            "known_vulnerabilities",
            "capabilities",
            "attestation",
        ):
            assert key in v, f"Missing required key: {key}"

    def test_json_cve_structure(self) -> None:
        v = self._get_json("mcp-atlassian", ["--ecosystem", "pypi"])
        vulns = v["known_vulnerabilities"]
        assert len(vulns) > 0
        assert vulns[0]["cve"] == "CVE-2026-27826"
        assert vulns[0]["source"] == "NVD"
        assert "nvd.nist.gov" in vulns[0]["link"]

    def test_json_no_letter_grade(self) -> None:
        v = self._get_json("@modelcontextprotocol/server-filesystem")
        assert "grade" not in v
        assert "letter_grade" not in v
        # Serialised text also must not contain a standalone grade.
        raw = json.dumps(v)
        assert '"grade"' not in raw

    def test_json_unknown_package(self) -> None:
        v = self._get_json("totally-unknown")
        assert v["registry"]["listed"] is False
        assert v["known_vulnerabilities"] == []
        assert v["typosquat_of"] is None


# ── CLI: --badge ───────────────────────────────────────────────────────────────


class TestVetCliBadge:
    def test_badge_output_contains_shields_url(self) -> None:
        reg = _make_registry()
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app,
                ["vet", "@modelcontextprotocol/server-filesystem", "--badge"],
            )
        assert "img.shields.io" in result.output
        assert "mcp-audit.dev" in result.output

    def test_badge_url_slug_convention(self) -> None:
        reg = _make_registry()
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "@scope/my_pkg", "--badge"])
        assert "at-scope-my-pkg" in result.output

    def test_badge_exit_0(self) -> None:
        reg = _make_registry()
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app,
                ["vet", "@modelcontextprotocol/server-filesystem", "--badge"],
            )
        assert result.exit_code == 0

    def test_badge_markdown_format(self) -> None:
        """Badge output must be a Shields.io Markdown image link."""
        reg = _make_registry()
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "@scope/name", "--badge"])
        assert result.output.strip().startswith("[![")


# ── CLI: PEP 503 normalization ─────────────────────────────────────────────────


class TestPep503:
    def test_underscore_name_finds_hyphen_entry(self) -> None:
        """mcp_atlassian → mcp-atlassian via PEP 503 normalisation."""
        reg = _make_registry([_CVE_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app, ["vet", "mcp_atlassian", "--ecosystem", "pypi", "--format", "json"]
            )
        data = json.loads(result.output)
        assert data["registry"]["listed"] is True

    def test_uppercase_name_normalized(self) -> None:
        """MCP-Atlassian → mcp-atlassian via PEP 503 normalisation."""
        reg = _make_registry([_CVE_ENTRY])
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(
                app, ["vet", "MCP-Atlassian", "--ecosystem", "pypi", "--format", "json"]
            )
        data = json.loads(result.output)
        assert data["registry"]["listed"] is True


# ── CLI: input validation ──────────────────────────────────────────────────────


class TestVetCliValidation:
    def test_empty_name_exit_2(self) -> None:
        reg = _make_registry()
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "   "])
        assert result.exit_code == 2

    def test_invalid_ecosystem_exit_2(self) -> None:
        reg = _make_registry()
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "some-pkg", "--ecosystem", "docker"])
        assert result.exit_code == 2

    def test_invalid_ecosystem_error_message(self) -> None:
        reg = _make_registry()
        with patch("mcp_audit.cli.vet.load_registry", return_value=reg):
            result = runner.invoke(app, ["vet", "some-pkg", "--ecosystem", "docker"])
        assert "Unknown ecosystem" in result.output or "npm" in result.output


# ── CLI: --online mode ─────────────────────────────────────────────────────────


class TestVetCliOnline:
    def test_online_uses_fetched_verdict(self) -> None:
        """When online fetch succeeds, the fetched verdict is emitted."""
        live_verdict = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": "2026-06-13T00:00:00+00:00",
            "package": {"ecosystem": "npm", "name": "@scope/pkg"},
            "registry": {
                "listed": True,
                "verified": True,
                "maintainer": "Test",
                "entry_updated": "2026-01-01",
                "registry_updated": "2026-06-13",
            },
            "known_vulnerabilities": [],
            "capabilities": ["file_read"],
            "attestation": {"hash_pins_available": True, "attestation_expected": False},
            "typosquat_of": None,
            "tags": [],
            "links": {"repo": None, "verdict_page": "https://mcp-audit.dev/..."},
        }
        reg = _make_registry()
        with (
            patch("mcp_audit.cli.vet.load_registry", return_value=reg),
            patch("mcp_audit.cli.vet._fetch_online_verdict", return_value=live_verdict),
        ):
            result = runner.invoke(
                app, ["vet", "@scope/pkg", "--online", "--format", "json"]
            )
        data = json.loads(result.output)
        assert data["registry"]["listed"] is True

    def test_online_fallback_on_network_failure(self) -> None:
        """Network failure falls back to bundled registry (exit 0 for unknown)."""
        reg = _make_registry([_VERIFIED_ENTRY])
        with (
            patch("mcp_audit.cli.vet.load_registry", return_value=reg),
            patch("mcp_audit.cli.vet._fetch_online_verdict", return_value=None),
        ):
            result = runner.invoke(app, ["vet", "completely-unknown-pkg", "--online"])
        assert result.exit_code == 0

    @_windows_skip
    def test_online_cache_written_at_0o600(self, tmp_path: Path) -> None:
        """Verdict cache file must be created with mode 0o600."""
        from mcp_audit.cli.vet import _write_verdict_cache  # noqa: PLC0415

        cache_file = tmp_path / "verdict-cache.json"
        console = MagicMock()

        with patch("mcp_audit.cli.vet._VERDICT_CACHE_PATH", cache_file):
            _write_verdict_cache(
                "npm", "@scope/name", {"schema_version": "1.0.0"}, console
            )

        assert cache_file.exists()
        file_mode = oct(stat.S_IMODE(os.stat(cache_file).st_mode))
        assert file_mode == "0o600", f"Expected 0o600, got {file_mode}"

    def test_online_https_scheme_guard(self) -> None:
        """_fetch_online_verdict must never open a non-HTTPS URL."""
        from mcp_audit.cli.vet import _fetch_online_verdict  # noqa: PLC0415

        console = MagicMock()
        # Patch the base URL to http:// to simulate a tampered constant.
        with patch(
            "mcp_audit.cli.vet._VERDICT_ONLINE_BASE",
            "http://mcp-audit.dev/v1/verdicts",
        ):
            result = _fetch_online_verdict("npm", "@scope/pkg", console)
        assert result is None  # Should refuse and return None


# ── slug round-trip ────────────────────────────────────────────────────────────


class TestSlugRoundTrip:
    @pytest.mark.parametrize(
        "name,expected_slug",
        [
            (
                "@modelcontextprotocol/server-filesystem",
                "at-modelcontextprotocol-server-filesystem",
            ),
            ("@azure/mcp", "at-azure-mcp"),
            ("mcp-atlassian", "mcp-atlassian"),
            ("mcp_server_git", "mcp-server-git"),
            ("MyTool", "mytool"),
            ("@SCOPE/NAME", "at-scope-name"),
        ],
    )
    def test_slug(self, name: str, expected_slug: str) -> None:
        assert name_to_slug(name) == expected_slug
