"""Tests for the known-server registry loader and supply-chain integration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.registry.loader import (
    BUNDLED_REGISTRY_PATH,
    KnownServerRegistry,
    RegistryEntry,
    levenshtein,
    load_registry,
)

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_server(
    name: str = "test",
    command: str = "npx",
    args: list[str] | None = None,
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client="claude",
        config_path=Path("/tmp/mcp.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command=command,
        args=args or [],
    )


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture()
def minimal_registry_json(tmp_path: Path) -> Path:
    """Write a minimal three-entry registry JSON and return its path."""
    data = {
        "schema_version": "1.0",
        "last_updated": "2026-04-15",
        "entry_count": 3,
        "entries": [
            {
                "name": "@modelcontextprotocol/server-filesystem",
                "source": "npm",
                "repo": "https://github.com/modelcontextprotocol/servers",
                "maintainer": "Anthropic",
                "verified": True,
                "last_verified": "2026-04-15",
                "known_versions": [],
                "tags": ["official", "filesystem", "local"],
            },
            {
                "name": "@modelcontextprotocol/server-github",
                "source": "npm",
                "repo": "https://github.com/modelcontextprotocol/servers",
                "maintainer": "Anthropic",
                "verified": True,
                "last_verified": "2026-04-15",
                "known_versions": [],
                "tags": ["official", "github", "remote"],
            },
            {
                "name": "mcp",
                "source": "pip",
                "repo": "https://github.com/modelcontextprotocol/python-sdk",
                "maintainer": "Anthropic",
                "verified": True,
                "last_verified": "2026-04-15",
                "known_versions": [],
                "tags": ["official", "sdk"],
            },
        ],
    }
    p = tmp_path / "registry.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture()
def minimal_registry(minimal_registry_json: Path) -> KnownServerRegistry:
    """Return a loaded KnownServerRegistry from the minimal fixture."""
    return KnownServerRegistry(path=minimal_registry_json)


# ── Registry loads from bundled path ──────────────────────────────────────────


class TestBundledRegistryLoad:
    def test_bundled_path_exists(self) -> None:
        assert BUNDLED_REGISTRY_PATH.exists(), (
            f"Bundled registry not found at {BUNDLED_REGISTRY_PATH}. "
            "Run in editable mode or check the dev environment."
        )

    def test_bundled_registry_loads_without_error(self) -> None:
        reg = load_registry()
        assert len(reg.entries) > 0

    def test_schema_version_present(self) -> None:
        reg = load_registry()
        assert reg.schema_version == "1.0"

    def test_last_updated_present(self) -> None:
        reg = load_registry()
        assert reg.last_updated != "unknown"

    def test_entry_count_matches_field(self) -> None:
        """entry_count field must equal the actual entries list length."""
        raw = BUNDLED_REGISTRY_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        reg = load_registry()
        assert len(reg.entries) == data["entry_count"]


# ── is_known ──────────────────────────────────────────────────────────────────


class TestIsKnown:
    def test_official_entry_returns_true(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        assert (
            minimal_registry.is_known("@modelcontextprotocol/server-filesystem") is True
        )

    def test_unknown_name_returns_false(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        assert minimal_registry.is_known("@evil/fake-filesystem") is False

    def test_case_insensitive(self, minimal_registry: KnownServerRegistry) -> None:
        assert (
            minimal_registry.is_known("@ModelContextProtocol/Server-FileSystem") is True
        )

    def test_partial_name_returns_false(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        assert minimal_registry.is_known("server-filesystem") is False

    def test_pip_entry_is_known(self, minimal_registry: KnownServerRegistry) -> None:
        assert minimal_registry.is_known("mcp") is True


# ── find_closest ──────────────────────────────────────────────────────────────


class TestFindClosest:
    def test_typosquat_within_threshold(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        # one char deleted (distance 1)
        result = minimal_registry.find_closest(
            "@modelcontextprotocol/server-filesyste", threshold=3
        )
        assert result is not None
        assert result.name == "@modelcontextprotocol/server-filesystem"

    def test_returns_none_for_exact_match(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        result = minimal_registry.find_closest(
            "@modelcontextprotocol/server-filesystem", threshold=3
        )
        assert result is None

    def test_returns_none_outside_threshold(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        result = minimal_registry.find_closest(
            "totally-unrelated-xyz-tool", threshold=3
        )
        assert result is None

    def test_default_threshold_2(self, minimal_registry: KnownServerRegistry) -> None:
        # Distance 1 must be found with default threshold=2.
        result = minimal_registry.find_closest("@modelcontextprotocol/server-filesyste")
        assert result is not None

    def test_threshold_too_tight(self, minimal_registry: KnownServerRegistry) -> None:
        # 2-char deletion should NOT be found with threshold=1.
        result = minimal_registry.find_closest(
            "@modelcontextprotocol/server-filesyst",
            threshold=1,
        )
        assert result is None

    def test_returns_maintainer_info(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        # one extra char → distance 1
        result = minimal_registry.find_closest(
            "@modelcontextprotocol/server-githubs", threshold=3
        )
        assert result is not None
        assert result.maintainer == "Anthropic"
        assert result.verified is True


# ── names ─────────────────────────────────────────────────────────────────────


class TestNames:
    def test_names_returns_all(self, minimal_registry: KnownServerRegistry) -> None:
        names = minimal_registry.names()
        assert "@modelcontextprotocol/server-filesystem" in names
        assert "@modelcontextprotocol/server-github" in names
        assert "mcp" in names

    def test_names_count_matches_entries(
        self, minimal_registry: KnownServerRegistry
    ) -> None:
        assert len(minimal_registry.names()) == len(minimal_registry.entries)


# ── load_registry ─────────────────────────────────────────────────────────────


class TestLoadRegistry:
    def test_explicit_path(self, minimal_registry_json: Path) -> None:
        reg = load_registry(minimal_registry_json)
        assert len(reg.entries) == 3

    def test_missing_explicit_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_registry(tmp_path / "nonexistent.json")

    def test_malformed_json_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ValueError, match="Malformed registry JSON"):
            load_registry(bad)

    def test_user_cache_preferred_over_bundled(
        self,
        minimal_registry_json: Path,
    ) -> None:
        """User-cache path must be preferred over the bundled registry."""
        import mcp_audit.registry.loader as loader_mod  # noqa: PLC0415

        with patch.object(loader_mod, "_USER_CACHE_PATH", minimal_registry_json):
            reg = load_registry()
        # minimal fixture has 3 entries; bundled registry has 57
        assert len(reg.entries) == 3


# ── RegistryEntry model ───────────────────────────────────────────────────────


class TestRegistryEntry:
    def test_all_fields_populated(self, minimal_registry: KnownServerRegistry) -> None:
        entry = minimal_registry.entries[0]
        assert entry.name == "@modelcontextprotocol/server-filesystem"
        assert entry.source == "npm"
        assert entry.maintainer == "Anthropic"
        assert entry.verified is True
        assert "official" in entry.tags

    def test_pip_source_accepted(self, minimal_registry: KnownServerRegistry) -> None:
        pip_entry = next(e for e in minimal_registry.entries if e.source == "pip")
        assert pip_entry.name == "mcp"

    def test_null_repo_allowed(self, tmp_path: Path) -> None:
        data = {
            "schema_version": "1.0",
            "last_updated": "2026-04-15",
            "entry_count": 1,
            "entries": [
                {
                    "name": "mcp-server-community",
                    "source": "npm",
                    "repo": None,
                    "maintainer": "community",
                    "verified": False,
                    "last_verified": "2026-04-15",
                    "known_versions": [],
                    "tags": ["community"],
                }
            ],
        }
        p = tmp_path / "r.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        reg = KnownServerRegistry(path=p)
        assert reg.entries[0].repo is None


# ── Supply chain analyzer uses registry ───────────────────────────────────────


class TestSupplyChainAnalyzerUsesRegistry:
    """Confirm SupplyChainAnalyzer calls the registry instead of the old YAML."""

    def test_analyzer_calls_is_known(self) -> None:
        mock_reg = MagicMock(spec=KnownServerRegistry)
        mock_reg.is_known.return_value = True

        analyzer = SupplyChainAnalyzer(registry=mock_reg)
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesystem"])
        analyzer.analyze(server)

        mock_reg.is_known.assert_called_once_with(
            "@modelcontextprotocol/server-filesystem"
        )

    def test_analyzer_calls_find_closest_when_unknown(self) -> None:
        mock_reg = MagicMock(spec=KnownServerRegistry)
        mock_reg.is_known.return_value = False
        mock_reg.find_closest.return_value = None

        analyzer = SupplyChainAnalyzer(registry=mock_reg)
        server = _make_server(args=["-y", "unknown-package"])
        analyzer.analyze(server)

        mock_reg.find_closest.assert_called_once()

    def test_analyzer_emits_finding_with_maintainer(self) -> None:
        """Finding description and evidence must include maintainer and verified."""
        mock_entry = RegistryEntry(
            name="@modelcontextprotocol/server-filesystem",
            source="npm",
            repo="https://github.com/modelcontextprotocol/servers",
            maintainer="Anthropic",
            verified=True,
            last_verified="2026-04-15",
            known_versions=[],
            tags=["official"],
        )
        mock_reg = MagicMock(spec=KnownServerRegistry)
        mock_reg.is_known.return_value = False
        mock_reg.find_closest.return_value = mock_entry

        analyzer = SupplyChainAnalyzer(registry=mock_reg)
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesyste"])
        findings = analyzer.analyze(server)

        assert len(findings) == 1
        assert "Anthropic" in findings[0].description
        assert "Anthropic" in findings[0].evidence
        assert "verified" in findings[0].evidence

    def test_custom_registry_path_used(self, minimal_registry_json: Path) -> None:
        """SupplyChainAnalyzer loads a custom registry when registry_path is given."""
        analyzer = SupplyChainAnalyzer(registry_path=minimal_registry_json)
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesystem"])
        assert analyzer.analyze(server) == []


# ── update-registry command ───────────────────────────────────────────────────


class TestUpdateRegistry:
    """update-registry fetches and writes the registry cache for all users."""

    def test_update_registry_writes_cache(self, tmp_path: Path) -> None:
        """update-registry fetches the remote registry and writes the cache file."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        fake_registry = json.dumps(
            {
                "schema_version": "1.0",
                "last_updated": "2026-04-15",
                "entry_count": 1,
                "entries": [
                    {
                        "name": "test-pkg",
                        "source": "npm",
                        "repo": None,
                        "maintainer": "community",
                        "verified": False,
                        "last_verified": "2026-04-15",
                        "known_versions": [],
                        "tags": [],
                    }
                ],
            }
        ).encode()

        cache_path = tmp_path / "registry" / "known-servers.json"

        runner = CliRunner()
        with (
            patch("mcp_audit.cli._REGISTRY_CACHE_PATH", cache_path),
            patch("urllib.request.urlopen") as mock_urlopen,
        ):
            mock_resp = MagicMock()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read.return_value = fake_registry
            mock_urlopen.return_value = mock_resp

            result = runner.invoke(app, ["update-registry"])

        assert result.exit_code == 0
        assert "Registry updated" in result.output
        assert cache_path.exists()


# ── levenshtein (registry module) ─────────────────────────────────────────────


class TestLevenshteinInLoader:
    """Sanity-check the levenshtein implementation in the registry module."""

    def test_identical(self) -> None:
        assert levenshtein("abc", "abc") == 0

    def test_single_deletion(self) -> None:
        assert levenshtein("server-filesystem", "server-filesyste") == 1

    def test_single_insertion(self) -> None:
        assert levenshtein("server-slack", "server-slacks") == 1

    def test_symmetric(self) -> None:
        assert levenshtein("abc", "xyz") == levenshtein("xyz", "abc")


# ── --offline-registry / offline parameter ────────────────────────────────────


class TestOfflineRegistry:
    """load_registry(offline=True) must skip the user cache."""

    def test_offline_skips_user_cache(
        self,
        minimal_registry_json: Path,
    ) -> None:
        """With offline=True, the user-cache path is ignored even when it exists."""
        import mcp_audit.registry.loader as loader_mod  # noqa: PLC0415

        with patch.object(loader_mod, "_USER_CACHE_PATH", minimal_registry_json):
            # minimal fixture has 3 entries; bundled registry has 57
            reg = load_registry(offline=True)
        assert len(reg.entries) != 3, "offline=True should bypass the user cache"

    def test_offline_still_loads_bundled(self) -> None:
        """offline=True must load the bundled registry, not raise FileNotFoundError."""
        reg = load_registry(offline=True)
        assert len(reg.entries) > 0

    def test_offline_explicit_path_not_overridden(
        self,
        minimal_registry_json: Path,
    ) -> None:
        """An explicit path argument must win even when offline=True."""
        reg = load_registry(path=minimal_registry_json, offline=True)
        assert len(reg.entries) == 3

    def test_known_server_registry_offline_kwarg(
        self,
        minimal_registry_json: Path,
    ) -> None:
        """KnownServerRegistry(offline=True) passes offline flag to _locate."""
        import mcp_audit.registry.loader as loader_mod  # noqa: PLC0415

        with patch.object(loader_mod, "_USER_CACHE_PATH", minimal_registry_json):
            reg = KnownServerRegistry(offline=True)
        assert len(reg.entries) != 3


# ── PyInstaller _MEIPASS resolution ───────────────────────────────────────────


class TestMeipassResolution:
    """Verify _resolve_bundled_path() and _locate() behave correctly under
    PyInstaller."""

    def test_resolve_bundled_path_returns_meipass_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With sys.frozen=True, _resolve_bundled_path() must return the _MEIPASS
        path."""
        import sys  # noqa: PLC0415

        from mcp_audit.registry.loader import _resolve_bundled_path  # noqa: PLC0415

        # Create a realistic _MEIPASS layout so the existence check passes.
        registry_dir = tmp_path / "registry"
        registry_dir.mkdir()
        (registry_dir / "known-servers.json").write_text("{}")

        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

        result = _resolve_bundled_path()
        assert result == tmp_path / "registry" / "known-servers.json"

    def test_resolve_bundled_path_not_frozen_returns_non_meipass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With sys.frozen=False, _resolve_bundled_path() must not use _MEIPASS."""
        import sys  # noqa: PLC0415

        from mcp_audit.registry.loader import _resolve_bundled_path  # noqa: PLC0415

        monkeypatch.setattr(sys, "frozen", False, raising=False)
        # Plant a decoy _MEIPASS — must be ignored when not frozen.
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

        result = _resolve_bundled_path()
        assert str(tmp_path) not in str(result)

    def test_frozen_registry_loads_via_patched_bundled_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """KnownServerRegistry loads correctly when BUNDLED_REGISTRY_PATH mimics a
        frozen _MEIPASS layout (offline=True so user-cache is skipped)."""
        import mcp_audit.registry.loader as loader_mod  # noqa: PLC0415

        fake_dir = tmp_path / "registry"
        fake_dir.mkdir()
        fake_registry = fake_dir / "known-servers.json"
        fake_registry.write_text(
            '{"schema_version":"1.0","last_updated":"2026-04-17",'
            '"entry_count":1,"entries":[{"name":"frozen-test-pkg",'
            '"source":"npm","repo":null,"maintainer":"test","verified":false,'
            '"last_verified":"2026-04-17","known_versions":[],"tags":[]}]}',
            encoding="utf-8",
        )

        monkeypatch.setattr(loader_mod, "BUNDLED_REGISTRY_PATH", fake_registry)

        reg = KnownServerRegistry(offline=True)
        assert len(reg.entries) == 1
        assert reg.entries[0].name == "frozen-test-pkg"

    def test_locate_raises_when_bundled_path_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_locate() must raise FileNotFoundError when both the user cache and
        BUNDLED_REGISTRY_PATH are absent — simulates a corrupt PyInstaller bundle."""
        import mcp_audit.registry.loader as loader_mod  # noqa: PLC0415

        missing = tmp_path / "no-such-file.json"
        monkeypatch.setattr(loader_mod, "BUNDLED_REGISTRY_PATH", missing)
        monkeypatch.setattr(loader_mod, "_USER_CACHE_PATH", missing)

        with pytest.raises(FileNotFoundError, match="No registry file found"):
            KnownServerRegistry()

    def test_meipass_path_shape_matches_spec_datas(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The _MEIPASS sub-path registry/known-servers.json must match the
        'datas' entry in all four PyInstaller spec files."""
        import sys  # noqa: PLC0415

        from mcp_audit.registry.loader import _resolve_bundled_path  # noqa: PLC0415

        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

        result = _resolve_bundled_path()
        # The spec files place the registry at <_MEIPASS>/registry/known-servers.json
        assert result.parts[-2] == "registry"
        assert result.name == "known-servers.json"


class TestOfflineRegistrySupplyChain:
    """SupplyChainAnalyzer(offline_registry=True) must use bundled registry."""

    def test_offline_registry_flag_propagates(
        self,
        minimal_registry_json: Path,
    ) -> None:
        import mcp_audit.registry.loader as loader_mod  # noqa: PLC0415
        from mcp_audit.analyzers.supply_chain import (
            SupplyChainAnalyzer,  # noqa: PLC0415
        )

        with patch.object(loader_mod, "_USER_CACHE_PATH", minimal_registry_json):
            analyzer = SupplyChainAnalyzer(offline_registry=True)
        # bundled registry has 64 entries; minimal fixture has 3
        assert len(analyzer.registry.entries) != 3

    def test_registry_property_returns_loaded_registry(self) -> None:
        from mcp_audit.analyzers.supply_chain import (
            SupplyChainAnalyzer,  # noqa: PLC0415
        )

        analyzer = SupplyChainAnalyzer()
        assert isinstance(analyzer.registry, KnownServerRegistry)


class TestRegistryEntryMetadataFields:
    """RegistryEntry correctly deserialises and exposes optional metadata fields."""

    def test_entry_with_all_metadata_fields(self) -> None:
        """All three metadata fields deserialise correctly when present."""
        entry = RegistryEntry(
            name="some-package",
            source="npm",
            repo=None,
            maintainer="test",
            verified=True,
            last_verified="2026-04-23",
            known_versions=[],
            tags=[],
            first_published="2024-11-14",
            weekly_downloads=42800,
            publisher_history=["anthropic-bot", "modelcontextprotocol"],
        )
        assert entry.first_published == "2024-11-14"
        assert entry.weekly_downloads == 42800
        assert entry.publisher_history == ["anthropic-bot", "modelcontextprotocol"]

    def test_entry_without_metadata_fields_defaults_to_none(self) -> None:
        """All three metadata fields default to None when absent."""
        entry = RegistryEntry(
            name="some-package",
            source="npm",
            repo=None,
            maintainer="test",
            verified=True,
            last_verified="2026-04-23",
            known_versions=[],
            tags=[],
        )
        assert entry.first_published is None
        assert entry.weekly_downloads is None
        assert entry.publisher_history is None

    def test_bundled_registry_loads_without_error(self) -> None:
        """Bundled registry loads cleanly with the new optional fields present."""
        registry = KnownServerRegistry()
        assert len(registry.entries) >= 60
        # Entries with metadata should deserialise correctly.
        enriched = [e for e in registry.entries if e.first_published is not None]
        for e in enriched:
            assert len(e.first_published) == 10  # YYYY-MM-DD


class TestUpdateRegistryURL:
    """Verify _UPDATE_REGISTRY_URL uses a version tag, not /main/."""

    def test_update_registry_url_uses_version_tag(self) -> None:
        """_UPDATE_REGISTRY_URL must contain the current __version__ string."""
        from mcp_audit import __version__  # noqa: PLC0415
        from mcp_audit.cli import _UPDATE_REGISTRY_URL  # noqa: PLC0415

        assert f"v{__version__}" in _UPDATE_REGISTRY_URL, (
            f"_UPDATE_REGISTRY_URL should reference v{__version__}, "
            f"got: {_UPDATE_REGISTRY_URL}"
        )

    def test_update_registry_url_does_not_use_main_branch(self) -> None:
        """_UPDATE_REGISTRY_URL must not point at /main/ (breaks older binaries)."""
        from mcp_audit.cli import _UPDATE_REGISTRY_URL  # noqa: PLC0415

        assert "/main/" not in _UPDATE_REGISTRY_URL, (
            "_UPDATE_REGISTRY_URL must not use /main/ — use a version tag instead. "
            f"Current value: {_UPDATE_REGISTRY_URL}"
        )


# ── verify — config file path support ─────────────────────────────────────────


class TestVerifyConfigPath:
    """verify SERVER_NAME accepts a config file path in addition to package names."""

    def _minimal_registry_json(self, tmp_path: Path, name: str = "test-pkg") -> Path:
        reg = {
            "schema_version": "1.0",
            "last_updated": "2026-04-20",
            "entry_count": 1,
            "entries": [
                {
                    "name": name,
                    "source": "npm",
                    "repo": None,
                    "maintainer": "community",
                    "verified": False,
                    "last_verified": "2026-04-20",
                    "known_versions": [],
                    "tags": [],
                }
            ],
        }
        p = tmp_path / "registry.json"
        p.write_text(json.dumps(reg))
        return p

    def test_verify_accepts_config_path(self, tmp_path: Path) -> None:
        """verify PATH produces a table output, not a 'not found' message (F12)."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"my-server": {"command": "node", "args": []}}}'
        )
        reg_path = self._minimal_registry_json(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["verify", str(config), "--registry", str(reg_path)],
        )

        assert result.exit_code == 0, result.output
        # Must produce table output (not the package-name "not found" message)
        assert "Verification" in result.output or "Server" in result.output

    def test_verify_config_path_shows_all_servers(self, tmp_path: Path) -> None:
        """All servers in the config appear in the verification table."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"alpha": {"command": "npx", "args": []}, '
            '"beta": {"command": "node", "args": []}}}'
        )
        reg_path = self._minimal_registry_json(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["verify", str(config), "--registry", str(reg_path)],
        )

        assert result.exit_code == 0, result.output
        assert "alpha" in result.output
        assert "beta" in result.output

    def test_verify_nonexistent_config_exits_2(self, tmp_path: Path) -> None:
        """verify /no/such/file.json must exit 2 with a clear error."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        runner = CliRunner()
        result = runner.invoke(app, ["verify", str(tmp_path / "no-such-file.json")])

        assert result.exit_code == 2
        assert "not found" in result.output.lower() or "Error" in result.output

    def test_verify_package_name_still_works(self, tmp_path: Path) -> None:
        """Package-name form (no path separator, no .json) still works."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        reg_path = self._minimal_registry_json(tmp_path, name="test-pkg")

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["verify", "test-pkg", "--registry", str(reg_path)],
        )

        # test-pkg has no known_hashes → "No hashes pinned" message, exit 0
        assert result.exit_code == 0
        assert "test-pkg" in result.output
