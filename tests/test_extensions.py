"""Tests for the IDE extension scanner (mcp_audit.extensions)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.extensions.analyzer import (
    STALE_THRESHOLD_DAYS,
    analyze_extensions,
    check_known_vulns,
    check_permissions,
    check_provenance,
    check_sideloaded,
    check_stale,
    check_wildcard_activation,
    classify_extension_capabilities,
    load_vuln_registry,
)
from mcp_audit.extensions.discovery import (
    discover_extensions,
    parse_manifest,
)
from mcp_audit.extensions.models import ExtensionManifest, ExtensionVulnEntry
from mcp_audit.models import Severity

runner = CliRunner()

# ── Shared helpers ─────────────────────────────────────────────────────────────


def _make_manifest(
    extension_id: str = "publisher.name",
    name: str = "name",
    publisher: str = "publisher",
    version: str = "1.0.0",
    client_name: str = "vscode",
    keywords: list[str] | None = None,
    categories: list[str] | None = None,
    description: str | None = None,
    activation_events: list[str] | None = None,
    contributes: dict | None = None,
    install_path: str = "/home/user/.vscode/extensions/publisher.name-1.0.0",
    manifest_path: str = (
        "/home/user/.vscode/extensions/publisher.name-1.0.0/package.json"
    ),
    last_updated: str | None = None,
) -> ExtensionManifest:
    return ExtensionManifest(
        extension_id=extension_id,
        name=name,
        publisher=publisher,
        version=version,
        client_name=client_name,
        keywords=keywords or [],
        categories=categories or [],
        description=description,
        activation_events=activation_events or [],
        contributes=contributes or {},
        install_path=install_path,
        manifest_path=manifest_path,
        last_updated=last_updated,
    )


def _make_vuln_entry(
    extension_id: str = "publisher.name",
    affected_versions: str = "*",
    severity: str = "high",
    cve: str | None = "CVE-2024-0001",
    title: str = "Test Vulnerability",
    description: str = "A test vulnerability.",
    reference: str | None = "https://example.com/advisory",
) -> ExtensionVulnEntry:
    return ExtensionVulnEntry(
        extension_id=extension_id,
        affected_versions=affected_versions,
        severity=severity,
        cve=cve,
        title=title,
        description=description,
        reference=reference,
    )


def _pkg_json(**kwargs: object) -> str:
    """Build a minimal valid package.json string."""
    base = {
        "name": "myext",
        "publisher": "mypublisher",
        "version": "1.2.3",
        "displayName": "My Extension",
        "description": "Does things",
        "engines": {"vscode": "^1.80.0"},
    }
    base.update(kwargs)
    return json.dumps(base)


# ── TestExtensionDiscovery ─────────────────────────────────────────────────────


class TestExtensionDiscovery:
    def test_discover_finds_extensions_in_vscode_dir(self, tmp_path: Path) -> None:
        ext_dir = tmp_path / "vscode" / "extensions" / "publisher.name-1.0.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "package.json").write_text(_pkg_json())

        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {"vscode": [str(tmp_path / "vscode" / "extensions")]},
        ):
            results = discover_extensions(clients=["vscode"])

        assert len(results) == 1
        assert results[0].extension_id == "mypublisher.myext"
        assert results[0].client_name == "vscode"

    def test_discover_skips_missing_dirs(self, tmp_path: Path) -> None:
        nonexistent = str(tmp_path / "does_not_exist")
        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {"vscode": [nonexistent]},
        ):
            results = discover_extensions(clients=["vscode"])
        assert results == []

    def test_discover_skips_invalid_package_json(self, tmp_path: Path) -> None:
        ext_dir = tmp_path / "extensions" / "bad-ext-1.0.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "package.json").write_text("{not valid json")

        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {"vscode": [str(tmp_path / "extensions")]},
        ):
            results = discover_extensions(clients=["vscode"])
        assert results == []

    def test_discover_skips_missing_package_json(self, tmp_path: Path) -> None:
        ext_dir = tmp_path / "extensions" / "no-manifest-1.0.0"
        ext_dir.mkdir(parents=True)
        # No package.json

        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {"vscode": [str(tmp_path / "extensions")]},
        ):
            results = discover_extensions(clients=["vscode"])
        assert results == []

    def test_discover_multiple_clients(self, tmp_path: Path) -> None:
        for client in ("vscode", "cursor"):
            ext_dir = tmp_path / client / "extensions" / f"pub.{client}-ext-1.0.0"
            ext_dir.mkdir(parents=True)
            (ext_dir / "package.json").write_text(
                _pkg_json(name=f"{client}-ext", publisher="pub")
            )

        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {
                "vscode": [str(tmp_path / "vscode" / "extensions")],
                "cursor": [str(tmp_path / "cursor" / "extensions")],
            },
        ):
            results = discover_extensions(clients=["vscode", "cursor"])

        client_names = {r.client_name for r in results}
        assert "vscode" in client_names
        assert "cursor" in client_names
        assert len(results) == 2

    def test_discover_client_filter(self, tmp_path: Path) -> None:
        for client in ("vscode", "cursor"):
            ext_dir = tmp_path / client / "extensions" / f"pub.{client}ext-1.0.0"
            ext_dir.mkdir(parents=True)
            (ext_dir / "package.json").write_text(
                _pkg_json(name=f"{client}ext", publisher="pub")
            )

        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {
                "vscode": [str(tmp_path / "vscode" / "extensions")],
                "cursor": [str(tmp_path / "cursor" / "extensions")],
            },
        ):
            results = discover_extensions(clients=["cursor"])

        assert all(r.client_name == "cursor" for r in results)

    def test_discover_deduplication_same_id_different_clients(
        self, tmp_path: Path
    ) -> None:
        """Same extension installed in two clients → both instances returned."""
        for client in ("vscode", "cursor"):
            ext_dir = tmp_path / client / "extensions" / "pub.shared-1.0.0"
            ext_dir.mkdir(parents=True)
            (ext_dir / "package.json").write_text(
                _pkg_json(name="shared", publisher="pub")
            )

        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {
                "vscode": [str(tmp_path / "vscode" / "extensions")],
                "cursor": [str(tmp_path / "cursor" / "extensions")],
            },
        ):
            results = discover_extensions(clients=["vscode", "cursor"])

        assert len(results) == 2
        assert {r.client_name for r in results} == {"vscode", "cursor"}

    def test_parse_manifest_constructs_extension_id(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(_pkg_json(name="myname", publisher="mypub"))
        result = parse_manifest(pkg, "vscode")
        assert result is not None
        assert result.extension_id == "mypub.myname"

    def test_parse_manifest_returns_none_on_missing_fields(
        self, tmp_path: Path
    ) -> None:
        pkg = tmp_path / "package.json"
        # Missing required "version" field
        pkg.write_text(json.dumps({"name": "x", "publisher": "y"}))
        result = parse_manifest(pkg, "vscode")
        assert result is None


# ── TestKnownVulnCheck ─────────────────────────────────────────────────────────


class TestKnownVulnCheck:
    def test_matches_known_vuln_exact_id(self) -> None:
        ext = _make_manifest(extension_id="foo.bar", version="2.0.0")
        vuln = _make_vuln_entry(extension_id="foo.bar", affected_versions="*")
        findings = check_known_vulns(ext, [vuln])
        assert len(findings) == 1

    def test_no_match_unknown_extension(self) -> None:
        ext = _make_manifest(extension_id="unknown.ext", version="1.0.0")
        vuln = _make_vuln_entry(extension_id="known.ext")
        findings = check_known_vulns(ext, [vuln])
        assert findings == []

    def test_wildcard_version_matches_any(self) -> None:
        ext = _make_manifest(version="99.0.0")
        vuln = _make_vuln_entry(extension_id="publisher.name", affected_versions="*")
        findings = check_known_vulns(ext, [vuln])
        assert len(findings) == 1

    def test_version_prefix_no_match(self) -> None:
        ext = _make_manifest(version="2.0.0")
        vuln = _make_vuln_entry(
            extension_id="publisher.name", affected_versions="<1.0.0"
        )
        findings = check_known_vulns(ext, [vuln])
        assert findings == []

    def test_version_prefix_match(self) -> None:
        ext = _make_manifest(version="0.5.0")
        vuln = _make_vuln_entry(
            extension_id="publisher.name", affected_versions="<1.0.0"
        )
        findings = check_known_vulns(ext, [vuln])
        assert len(findings) == 1

    def test_finding_has_cve_in_evidence(self) -> None:
        ext = _make_manifest()
        vuln = _make_vuln_entry(cve="CVE-2024-9999")
        findings = check_known_vulns(ext, [vuln])
        assert len(findings) == 1
        evidence = json.loads(findings[0].evidence)
        assert evidence["cve"] == "CVE-2024-9999"

    def test_finding_severity_from_registry(self) -> None:
        ext = _make_manifest()
        vuln = _make_vuln_entry(severity="high")
        findings = check_known_vulns(ext, [vuln])
        assert findings[0].severity == Severity.HIGH

    def test_case_insensitive_id_match(self) -> None:
        ext = _make_manifest(extension_id="Foo.Bar")
        vuln = _make_vuln_entry(extension_id="foo.bar")
        findings = check_known_vulns(ext, [vuln])
        assert len(findings) == 1


# ── TestPermissionCheck ────────────────────────────────────────────────────────


class TestPermissionCheck:
    def test_filesystem_plus_network_flagged(self) -> None:
        ext = _make_manifest(
            keywords=["file", "http"],
            description="reads files and makes api requests",
        )
        findings = check_permissions(ext)
        assert any("filesystem" in f.title and "network" in f.title for f in findings)

    def test_terminal_plus_network_flagged(self) -> None:
        ext = _make_manifest(
            keywords=["terminal"],
            description="shell executor with remote api access",
        )
        findings = check_permissions(ext)
        assert any("terminal" in f.title and "network" in f.title for f in findings)

    def test_single_capability_not_flagged(self) -> None:
        ext = _make_manifest(
            keywords=["http", "api", "fetch"],
            description="makes http api requests",
        )
        findings = check_permissions(ext)
        # network only → no combo finding
        assert all(
            "filesystem" not in f.title and "terminal" not in f.title for f in findings
        )

    def test_wildcard_activation_flagged(self) -> None:
        ext = _make_manifest(activation_events=["*"])
        findings = check_wildcard_activation(ext)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_specific_activation_not_flagged(self) -> None:
        ext = _make_manifest(activation_events=["onLanguage:python"])
        findings = check_wildcard_activation(ext)
        assert findings == []


# ── TestCapabilityClassification ──────────────────────────────────────────────


class TestCapabilityClassification:
    def test_ai_related_by_keyword(self) -> None:
        ext = _make_manifest(keywords=["copilot", "ai"])
        caps = classify_extension_capabilities(ext)
        assert "ai_related" in caps

    def test_ai_related_by_name(self) -> None:
        ext = _make_manifest(name="my-assistant", extension_id="pub.my-assistant")
        caps = classify_extension_capabilities(ext)
        assert "ai_related" in caps

    def test_network_by_description(self) -> None:
        ext = _make_manifest(description="calls external api endpoints")
        caps = classify_extension_capabilities(ext)
        assert "network" in caps

    def test_terminal_by_contributes(self) -> None:
        ext = _make_manifest(contributes={"terminal": [{"id": "myterm"}]})
        caps = classify_extension_capabilities(ext)
        assert "terminal" in caps

    def test_debugger_by_contributes(self) -> None:
        ext = _make_manifest(contributes={"debuggers": [{"type": "node"}]})
        caps = classify_extension_capabilities(ext)
        assert "debuggers" in caps

    def test_no_false_capabilities(self) -> None:
        ext = _make_manifest(
            name="plain-theme",
            description="A color theme for VS Code",
            keywords=["theme", "color"],
        )
        caps = classify_extension_capabilities(ext)
        assert "filesystem" not in caps
        assert "network" not in caps
        assert "terminal" not in caps
        assert "debuggers" not in caps
        assert "ai_related" not in caps


# ── TestProvenanceCheck ────────────────────────────────────────────────────────


class TestProvenanceCheck:
    def test_known_publisher_no_finding(self) -> None:
        ext = _make_manifest(
            publisher="microsoft",
            extension_id="microsoft.something",
            keywords=["ai", "copilot"],
        )
        findings = check_provenance(ext)
        assert findings == []

    def test_unknown_publisher_ai_extension_flagged(self) -> None:
        ext = _make_manifest(
            publisher="unknownvendor",
            extension_id="unknownvendor.ai-helper",
            keywords=["ai", "assistant"],
        )
        findings = check_provenance(ext)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_unknown_publisher_non_ai_not_flagged(self) -> None:
        ext = _make_manifest(
            publisher="randompublisher",
            extension_id="randompublisher.json-formatter",
            keywords=["json", "formatter"],
        )
        findings = check_provenance(ext)
        assert findings == []

    def test_sideloaded_flagged(self) -> None:
        ext = _make_manifest(
            install_path="/home/user/downloads/myext.vsix/publisher.name-1.0.0",
        )
        findings = check_sideloaded(ext)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_normal_path_not_sideloaded(self) -> None:
        ext = _make_manifest(
            install_path="/home/user/.vscode/extensions/publisher.name-1.0.0",
        )
        findings = check_sideloaded(ext)
        assert findings == []


# ── TestStaleCheck ─────────────────────────────────────────────────────────────


class TestStaleCheck:
    def _ts(self, days_ago: int) -> str:
        dt = datetime.now(tz=UTC) - timedelta(days=days_ago)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_stale_ai_extension_flagged(self) -> None:
        ext = _make_manifest(
            keywords=["ai", "copilot"],
            last_updated=self._ts(STALE_THRESHOLD_DAYS + 35),
        )
        findings = check_stale(ext)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_stale_non_ai_not_flagged(self) -> None:
        ext = _make_manifest(
            keywords=["formatter"],
            last_updated=self._ts(STALE_THRESHOLD_DAYS + 35),
        )
        findings = check_stale(ext)
        assert findings == []

    def test_fresh_extension_not_flagged(self) -> None:
        ext = _make_manifest(
            keywords=["ai"],
            last_updated=self._ts(30),
        )
        findings = check_stale(ext)
        assert findings == []

    def test_none_last_updated_skipped(self) -> None:
        ext = _make_manifest(keywords=["ai"], last_updated=None)
        findings = check_stale(ext)
        assert findings == []


# ── TestExtensionsCLI ──────────────────────────────────────────────────────────


class TestExtensionsCLI:
    def test_extensions_discover_command(self, tmp_path: Path) -> None:
        ext_dir = tmp_path / "extensions" / "pub.myext-1.0.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "package.json").write_text(_pkg_json(name="myext", publisher="pub"))

        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {"vscode": [str(tmp_path / "extensions")]},
        ):
            result = runner.invoke(app, ["extensions", "discover"])

        assert result.exit_code == 0
        assert "pub.myext" in result.output

    def test_extensions_discover_empty(self, tmp_path: Path) -> None:
        with patch.dict(
            "mcp_audit.extensions.discovery.EXTENSION_PATHS",
            {"vscode": [str(tmp_path / "nonexistent")]},
        ):
            result = runner.invoke(app, ["extensions", "discover"])

        assert result.exit_code == 0
        assert "0" in result.output

    def test_extensions_scan_with_findings(self, tmp_path: Path) -> None:
        ext_dir = tmp_path / "extensions" / "pub.vuln-1.0.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "package.json").write_text(
            _pkg_json(name="vuln", publisher="pub", version="0.9.0")
        )

        vuln = _make_vuln_entry(
            extension_id="pub.vuln", affected_versions="<1.0.0", severity="high"
        )

        with (
            patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
            patch.dict(
                "mcp_audit.extensions.discovery.EXTENSION_PATHS",
                {"vscode": [str(tmp_path / "extensions")]},
            ),
            patch(
                "mcp_audit.extensions.analyzer.load_vuln_registry",
                return_value=[vuln],
            ),
        ):
            result = runner.invoke(app, ["extensions", "scan"])

        assert result.exit_code == 1
        assert "finding" in result.output.lower()

    def test_extensions_scan_no_findings(self, tmp_path: Path) -> None:
        with (
            patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
            patch(
                "mcp_audit.extensions.discovery.discover_extensions",
                return_value=[],
            ),
            patch(
                "mcp_audit.extensions.analyzer.analyze_extensions",
                return_value=[],
            ),
        ):
            result = runner.invoke(app, ["extensions", "scan"])

        assert result.exit_code == 0
        assert "No issues" in result.output

    def test_scan_include_extensions_flag(self, tmp_path: Path) -> None:
        """scan --include-extensions appends extension findings to scan output."""
        from mcp_audit.models import ScanResult  # noqa: PLC0415

        fake_finding = _make_manifest(keywords=["ai"], activation_events=["*"])

        with (
            patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
            patch(
                "mcp_audit.extensions.discovery.discover_extensions",
                return_value=[fake_finding],
            ),
            patch(
                "mcp_audit.extensions.analyzer.analyze_extensions",
                return_value=[],
            ),
            patch("mcp_audit.cli.run_scan", return_value=ScanResult()),
        ):
            result = runner.invoke(app, ["scan", "--include-extensions"])

        assert result.exit_code == 0
        assert "Extension" in result.output


# ── TestExtensionFindingFormat ─────────────────────────────────────────────────


class TestExtensionFindingFormat:
    def test_finding_analyzer_tag(self) -> None:
        ext = _make_manifest()
        vuln = _make_vuln_entry()
        findings = check_known_vulns(ext, [vuln])
        assert all(f.analyzer == "extensions" for f in findings)

    def test_finding_id_deterministic(self) -> None:
        ext = _make_manifest(extension_id="pub.name")
        vuln = _make_vuln_entry(extension_id="pub.name", cve="CVE-2024-1234")
        f1 = check_known_vulns(ext, [vuln])
        f2 = check_known_vulns(ext, [vuln])
        assert f1[0].id == f2[0].id

    def test_sarif_artifact_is_manifest_path(self) -> None:
        """Extension findings include manifest_path as finding_path."""
        mp = "/home/user/.vscode/extensions/pub.name-1.0.0/package.json"
        ext = _make_manifest(manifest_path=mp)
        vuln = _make_vuln_entry()
        findings = check_known_vulns(ext, [vuln])
        assert findings[0].finding_path == mp


# ── TestLoadVulnRegistry ───────────────────────────────────────────────────────


class TestLoadVulnRegistry:
    def test_load_from_explicit_path(self, tmp_path: Path) -> None:
        data = {
            "schema_version": "1",
            "last_updated": "2026-01-01",
            "entries": [
                {
                    "extension_id": "test.ext",
                    "affected_versions": "*",
                    "severity": "high",
                    "title": "Test",
                    "description": "desc",
                }
            ],
        }
        p = tmp_path / "vulns.json"
        p.write_text(json.dumps(data))
        entries = load_vuln_registry(path=p)
        assert len(entries) == 1
        assert entries[0].extension_id == "test.ext"

    def test_returns_empty_on_missing_file(self, tmp_path: Path) -> None:
        entries = load_vuln_registry(path=tmp_path / "nonexistent.json")
        assert entries == []

    def test_returns_empty_on_malformed_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        entries = load_vuln_registry(path=p)
        assert entries == []

    def test_bundled_registry_loads_five_entries(self) -> None:
        """The shipped known-extension-vulns.json has exactly 5 entries."""
        # Resolve from repo root (dev environment)
        repo_root = Path(__file__).parent.parent
        registry_path = repo_root / "registry" / "known-extension-vulns.json"
        entries = load_vuln_registry(path=registry_path)
        assert len(entries) == 5


# ── TestAnalyzeExtensions ──────────────────────────────────────────────────────


class TestAnalyzeExtensions:
    def test_analyze_extensions_empty_list(self) -> None:
        assert analyze_extensions([]) == []

    def test_analyze_extensions_runs_all_layers(self) -> None:
        """A wildcard-activation AI extension from unknown publisher should generate
        multiple findings (wildcard activation + provenance)."""
        ext = _make_manifest(
            publisher="unknownvendor",
            extension_id="unknownvendor.ai-helper",
            keywords=["ai", "assistant"],
            activation_events=["*"],
        )
        findings = analyze_extensions([ext], vuln_registry=[])
        # At minimum: wildcard activation + provenance
        assert len(findings) >= 2
        analyzers = {f.analyzer for f in findings}
        assert analyzers == {"extensions"}
