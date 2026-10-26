"""Tests for mcp_audit.registry.twins (SC-007 unscoped-twin index, STORY-0097)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry, load_registry
from mcp_audit.registry.twins import TwinIndex, fold_name, twin_keys_for_entry


def _entry(name: str, eco: str = "npm", verified: bool = True) -> dict:
    return {
        "name": name,
        "source": "pip" if eco == "pypi" else "npm",
        "package_ecosystem": eco,
        "repo": None,
        "maintainer": "someone",
        "verified": verified,
        "last_verified": "2026-10-25",
        "known_versions": [],
        "tags": [],
    }


def _registry(tmp_path: Path, *entries: dict) -> KnownServerRegistry:
    path = tmp_path / "known-servers.json"
    path.write_text(
        json.dumps(
            {"schema_version": "1.0", "last_updated": "2026-10-25", "entries": entries}
        ),
        encoding="utf-8",
    )
    return KnownServerRegistry(path=path)


@pytest.fixture(scope="module")
def bundled() -> TwinIndex:
    return TwinIndex(load_registry(offline=True))


def _model(name: str) -> RegistryEntry:
    return RegistryEntry.model_validate(_entry(name))


# ── Key derivation, one test per rule ─────────────────────────────────────────


class TestTwinKeysForEntry:
    def test_server_prefix_gives_basename_and_mcp_server_spelling(self) -> None:
        keys = twin_keys_for_entry(_model("@modelcontextprotocol/server-github"))
        assert keys == [
            ("server-github", "basename"),
            ("mcp-server-github", "mcp-server-spelling"),
        ]

    def test_mcp_server_prefix_gives_basename_only(self) -> None:
        keys = twin_keys_for_entry(_model("@supabase/mcp-server-supabase"))
        assert keys == [("mcp-server-supabase", "basename")]

    def test_mcp_server_suffix_gives_mcp_server_spelling_only(self) -> None:
        """MAL-2026-5480 squatted mcp-server-notion; notion-mcp-server is a
        real, unrelated community package (~2,500 weekly downloads), so the
        exact basename is deliberately not a key."""
        keys = twin_keys_for_entry(_model("@notionhq/notion-mcp-server"))
        assert keys == [("mcp-server-notion", "mcp-server-spelling")]

    @pytest.mark.parametrize(
        "name",
        [
            "@upstash/context7-mcp",
            "@azure/mcp",
            "@modelcontextprotocol/sdk",
            "@modelcontextprotocol/inspector",
            "@autoposting.ai/cli",
            "@toolbox-sdk/server",
            "@stripe/agent-toolkit",
            "@shopify/dev-mcp",
        ],
    )
    def test_other_name_shapes_give_no_keys(self, name: str) -> None:
        assert twin_keys_for_entry(_model(name)) == []

    @pytest.mark.parametrize(
        "name", ["@x/server-mcp", "@x/server-", "@x/mcp-server-", "@x/-mcp-server"]
    )
    def test_generic_or_empty_slug_gives_no_keys(self, name: str) -> None:
        assert twin_keys_for_entry(_model(name)) == []

    def test_unscoped_and_pypi_entries_give_no_npm_keys(self) -> None:
        assert twin_keys_for_entry(_model("mcp-server-kubernetes")) == []
        pypi = RegistryEntry.model_validate(_entry("mcp-server-git", eco="pypi"))
        assert twin_keys_for_entry(pypi) == []

    def test_fold_name_matches_pep503(self) -> None:
        assert fold_name("MCP_Server.GitHub") == "mcp-server-github"


# ── Lookups against the shipped registry ──────────────────────────────────────


class TestBundledRegistryTwins:
    @pytest.mark.parametrize(
        ("name", "official", "rule"),
        [
            # MAL-2026-5479 and its siblings: the mcp-server- spelling.
            (
                "mcp-server-github",
                "@modelcontextprotocol/server-github",
                "mcp-server-spelling",
            ),
            (
                "mcp-server-redis",
                "@modelcontextprotocol/server-redis",
                "mcp-server-spelling",
            ),
            (
                "mcp-server-everything",
                "@modelcontextprotocol/server-everything",
                "mcp-server-spelling",
            ),
            # npm took server-github down to a 0.0.1-security placeholder.
            ("server-github", "@modelcontextprotocol/server-github", "basename"),
            ("mcp-server-supabase", "@supabase/mcp-server-supabase", "basename"),
            ("mcp-server-notion", "@notionhq/notion-mcp-server", "mcp-server-spelling"),
            # The ars923 placeholder stubs (registry-audit-2026-08-18.md §3b).
            ("mcp-server-neon", "@neondatabase/mcp-server-neon", "basename"),
        ],
    )
    def test_npm_twins(
        self, bundled: TwinIndex, name: str, official: str, rule: str
    ) -> None:
        twins = bundled.find(name, "npm")
        assert twins, name
        assert twins[0].entry.name == official
        assert twins[0].rule == rule
        assert twins[0].other_ecosystem is False

    @pytest.mark.parametrize(
        "name", ["mcp-server-git", "mcp-server-fetch", "mcp-server-qdrant"]
    )
    def test_npm_name_of_a_pypi_package_is_a_same_name_twin(
        self, bundled: TwinIndex, name: str
    ) -> None:
        """MAL-2026-5476/5478: npm squats of Anthropic's PyPI servers."""
        twins = bundled.find(name, "npm")
        assert [(t.entry.name, t.rule, t.other_ecosystem) for t in twins] == [
            (name, "same-name", True)
        ]

    def test_two_twins_put_the_same_registry_first(self, bundled: TwinIndex) -> None:
        twins = bundled.find("mcp-server-postgres", "npm")
        assert [(t.entry.name, t.rule) for t in twins] == [
            ("@modelcontextprotocol/server-postgres", "mcp-server-spelling"),
            ("mcp-server-postgres", "same-name"),
        ]

    def test_pypi_launch_of_an_npm_official_name(self, bundled: TwinIndex) -> None:
        """PyPI mcp-server-memory is a placeholder with ~450 monthly installs."""
        twins = bundled.find("mcp-server-memory", "pypi")
        assert twins[0].entry.name == "@modelcontextprotocol/server-memory"
        assert twins[0].other_ecosystem is True
        assert "launched from PyPI" in twins[0].explain()

    @pytest.mark.parametrize(
        "name", ["mcp_server_github", "MCP-Server-GitHub", "mcp.server.github"]
    )
    def test_spelling_variants_fold_to_the_same_twin(
        self, bundled: TwinIndex, name: str
    ) -> None:
        """npm treats these as different packages; all are still twins."""
        assert bundled.find(name, "npm")
        assert bundled.find(name, "pypi")

    @pytest.mark.parametrize(
        ("name", "ecosystem"),
        [
            ("@modelcontextprotocol/server-github", "npm"),  # the official package
            ("@evil/server-github", "npm"),  # scoped: SC-001..003's job
            ("notion-mcp-server", "npm"),  # real community package
            ("context7-mcp", "npm"),
            ("mcp", "npm"),
            ("server", "npm"),
            ("inspector", "npm"),
            ("cli", "npm"),
            ("mcp-server-kubernetes", "npm"),  # in the registry itself
            ("mcp-server-git", "pypi"),  # the official PyPI package
            ("mcp-server-postgres", "pypi"),  # in the registry as PyPI
            ("mcp-server-gitt", "npm"),  # near-miss: not a derived key
            ("", "npm"),
        ],
    )
    def test_not_twins(self, bundled: TwinIndex, name: str, ecosystem: str) -> None:
        assert bundled.find(name, ecosystem) == []  # type: ignore[arg-type]

    def test_explanations_name_the_relation(self, bundled: TwinIndex) -> None:
        assert bundled.find("server-github", "npm")[0].explain() == (
            "the name of '@modelcontextprotocol/server-github' without its scope"
        )
        assert bundled.find("mcp-server-git", "npm")[0].explain() == (
            "the name of the PyPI package 'mcp-server-git', launched from npm"
        )


class TestSyntheticRegistry:
    def test_verified_entry_sorts_first(self, tmp_path: Path) -> None:
        reg = _registry(
            tmp_path,
            _entry("@b/server-thing", verified=False),
            _entry("@a/server-thing", verified=True),
        )
        twins = TwinIndex(reg).find("mcp-server-thing", "npm")
        assert [t.entry.name for t in twins] == ["@a/server-thing", "@b/server-thing"]

    def test_empty_registry(self, tmp_path: Path) -> None:
        assert TwinIndex(_registry(tmp_path)).find("mcp-server-x", "npm") == []

    def test_pathological_names_are_linear(self, bundled: TwinIndex) -> None:
        """A config controls the name; lookups must not blow up on it."""
        names = [
            "a" * 200_000,
            "-" * 200_000 + "x",
            "mcp-server-" + "_." * 100_000,
            "server-" + "a-" * 100_000,
        ]
        start = time.monotonic()
        for name in names:
            assert bundled.find(name, "npm") == []
            assert bundled.find(name, "pypi") == []
        assert time.monotonic() - start < 2.0
