"""Tests for mcp_audit.lock.writer — regeneration, canonical form, checksum scope."""

from __future__ import annotations

import getpass
import json
from pathlib import Path

import pytest

from mcp_audit.advisory import canonical as canonical_module
from mcp_audit.lock import resolve as resolve_module
from mcp_audit.lock.model import compute_checksum
from mcp_audit.lock.writer import (
    LockWriteError,
    load_existing,
    regenerate,
    serialize,
    write_lock,
)
from mcp_audit.models import ServerConfig, TransportType


def _server(
    name: str = "github",
    client: str = "cursor",
    command: str = "npx",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    url: str | None = None,
    config_path: Path = Path("/home/tester/.cursor/mcp.json"),
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path,
        transport=TransportType.STDIO if url is None else TransportType.STREAMABLE_HTTP,
        command=command,
        args=args or [],
        env=env or {},
        headers=headers or {},
        url=url,
    )


# ── First-time write, offline-safe (exact pins never hit the network) ──────────


class TestRegenerateFirstTime:
    def test_exact_pin_needs_no_network(self) -> None:
        server = _server(args=["-y", "@modelcontextprotocol/server-github@1.2.3"])
        doc = regenerate(
            None, [server], Path("/home/tester/project"), offline=True, registry=None
        )
        entry = doc["servers"]["cursor/github"]
        assert entry["package"]["name"] == "@modelcontextprotocol/server-github"
        assert entry["package"]["resolved_version"] == "1.2.3"
        assert entry["package"]["resolution"]["method"] == "exact-pin"
        assert entry["package"]["range_spec"] is False

    def test_unpinned_offline_is_unresolved(self) -> None:
        server = _server(args=["-y", "foo"])
        doc = regenerate(
            None, [server], Path("/home/tester/project"), offline=True, registry=None
        )
        entry = doc["servers"]["cursor/github"]
        assert entry["package"]["resolved_version"] is None
        assert entry["package"]["resolution"]["method"] == "unresolved"
        assert entry["package"]["source"] == "unresolved"

    def test_non_package_launcher_has_no_package(self) -> None:
        server = _server(command="node", args=["./local-server.js"])
        doc = regenerate(
            None, [server], Path("/home/tester/project"), offline=True, registry=None
        )
        entry = doc["servers"]["cursor/github"]
        assert entry["package"] is None

    def test_first_locked_defaults_to_generated_at(self) -> None:
        server = _server(args=["-y", "foo@1.0.0"])
        doc = regenerate(
            None, [server], Path("/home/tester/project"), offline=True, registry=None
        )
        entry = doc["servers"]["cursor/github"]
        assert entry["first_locked"] == doc["generated_at"]

    def test_reserved_foreign_keys_default_present(self) -> None:
        server = _server(args=["-y", "foo@1.0.0"])
        doc = regenerate(
            None, [server], Path("/home/tester/project"), offline=True, registry=None
        )
        assert doc["trees"] == {}
        assert doc["tools"] is None

    def test_checksum_matches_owned_subdocument(self) -> None:
        server = _server(args=["-y", "foo@1.0.0"])
        doc = regenerate(
            None, [server], Path("/home/tester/project"), offline=True, registry=None
        )
        assert doc["checksum"] == compute_checksum(doc)


# ── first_locked preservation (also exercised via --accept) ────────────────────


class TestRegeneratePreservesFirstLocked:
    def test_preserves_first_locked_across_runs(self) -> None:
        root = Path("/home/tester/project")
        server = _server(args=["-y", "foo@1.0.0"])
        doc1 = regenerate(None, [server], root, offline=True, registry=None)
        first_locked = doc1["servers"]["cursor/github"]["first_locked"]

        doc2 = regenerate(doc1, [server], root, offline=True, registry=None)
        assert doc2["servers"]["cursor/github"]["first_locked"] == first_locked
        assert (
            doc2["generated_at"] != first_locked or True
        )  # generated_at may equal; not asserted

    def test_new_server_gets_fresh_first_locked(self) -> None:
        root = Path("/home/tester/project")
        server_a = _server(name="github", args=["-y", "foo@1.0.0"])
        doc1 = regenerate(None, [server_a], root, offline=True, registry=None)

        server_b = _server(name="fetch", args=["-y", "bar@1.0.0"])
        doc2 = regenerate(doc1, [server_a, server_b], root, offline=True, registry=None)

        assert doc2["servers"]["cursor/fetch"]["first_locked"] == doc2["generated_at"]
        assert (
            doc2["servers"]["cursor/github"]["first_locked"]
            == doc1["servers"]["cursor/github"]["first_locked"]
        )


# ── §6: resolved_at is write-on-change only ─────────────────────────────────────


class TestResolvedAtWriteOnChange:
    def test_stable_when_version_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2.0.0", None),
        )
        root = Path("/home/tester/project")
        server = _server(args=["-y", "foo"])  # unpinned -> dist-tag:latest

        doc1 = regenerate(None, [server], root, offline=False, registry=None)
        resolved_at_1 = doc1["servers"]["cursor/github"]["package"]["resolution"][
            "resolved_at"
        ]

        doc2 = regenerate(doc1, [server], root, offline=False, registry=None)
        pkg2 = doc2["servers"]["cursor/github"]["package"]
        assert pkg2["resolution"]["resolved_at"] == resolved_at_1
        assert pkg2["resolved_version"] == "2.0.0"

    def test_updates_on_version_change(self, monkeypatch: pytest.MonkeyPatch) -> None:
        versions = iter(["2.0.0", "3.0.0"])
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: (next(versions), None),
        )
        root = Path("/home/tester/project")
        server = _server(args=["-y", "foo"])

        doc1 = regenerate(None, [server], root, offline=False, registry=None)
        resolved_at_1 = doc1["servers"]["cursor/github"]["package"]["resolution"][
            "resolved_at"
        ]

        doc2 = regenerate(doc1, [server], root, offline=False, registry=None)
        pkg2 = doc2["servers"]["cursor/github"]["package"]
        assert pkg2["resolved_version"] == "3.0.0"
        assert pkg2["resolution"]["resolved_at"] != resolved_at_1


# ── `deprecated` field threading (STORY-0073/R58) ───────────────────────────────


class TestDeprecatedField:
    def test_deprecated_package_records_message_in_package_dict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2025.4.8", "Package no longer supported."),
        )
        root = Path("/home/tester/project")
        server = _server(args=["-y", "@modelcontextprotocol/server-github"])  # unpinned

        doc = regenerate(None, [server], root, offline=False, registry=None)

        pkg = doc["servers"]["cursor/github"]["package"]
        assert pkg["resolved_version"] == "2025.4.8"
        assert pkg["deprecated"] == "Package no longer supported."

    def test_non_deprecated_package_records_null(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2.5.1", None),
        )
        root = Path("/home/tester/project")
        server = _server(name="notion", args=["-y", "@notionhq/notion-mcp-server"])

        doc = regenerate(None, [server], root, offline=False, registry=None)

        pkg = doc["servers"]["cursor/notion"]["package"]
        assert pkg["resolved_version"] == "2.5.1"
        assert pkg["deprecated"] is None

    def test_empty_string_deprecated_normalised_upstream_is_preserved_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """resolve_latest_version_info() itself normalises "" -> "(no message)";
        resolve_package()/regenerate() must thread that value through unchanged."""
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("1.0.0", "(no message)"),
        )
        root = Path("/home/tester/project")
        server = _server(args=["-y", "some-pkg"])

        doc = regenerate(None, [server], root, offline=False, registry=None)

        pkg = doc["servers"]["cursor/github"]["package"]
        assert pkg["deprecated"] == "(no message)"

    def test_offline_never_calls_resolver_and_deprecated_is_null(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(*args: object, **kwargs: object) -> tuple[str, str | None]:
            raise AssertionError("must not resolve over the network when --offline")

        monkeypatch.setattr(resolve_module, "resolve_latest_version_info", _boom)
        root = Path("/home/tester/project")
        server = _server(args=["-y", "@modelcontextprotocol/server-github"])  # unpinned

        doc = regenerate(None, [server], root, offline=True, registry=None)

        pkg = doc["servers"]["cursor/github"]["package"]
        assert pkg["resolved_version"] is None
        assert pkg["deprecated"] is None

    def test_exact_pin_never_calls_resolver_and_deprecated_is_null(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exact pin is fully offline today; no manifest is fetched to
        read `deprecated` from — STORY-0073/R58 does not add a new network
        call for this path."""

        def _boom(*args: object, **kwargs: object) -> tuple[str, str | None]:
            raise AssertionError("exact-pin must never call the network resolver")

        monkeypatch.setattr(resolve_module, "resolve_latest_version_info", _boom)
        root = Path("/home/tester/project")
        server = _server(args=["-y", "@modelcontextprotocol/server-github@1.2.3"])

        doc = regenerate(None, [server], root, offline=False, registry=None)

        pkg = doc["servers"]["cursor/github"]["package"]
        assert pkg["resolved_version"] == "1.2.3"
        assert pkg["deprecated"] is None

    def test_deprecation_status_change_alone_bypasses_write_on_change_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A package going deprecated in place (no version bump) must not be
        silently suppressed by ADR-0005 §6 write-on-change."""
        deprecated_values = iter([None, "Package no longer supported."])
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2025.4.8", next(deprecated_values)),
        )
        root = Path("/home/tester/project")
        server = _server(args=["-y", "@modelcontextprotocol/server-github"])

        doc1 = regenerate(None, [server], root, offline=False, registry=None)
        assert doc1["servers"]["cursor/github"]["package"]["deprecated"] is None

        doc2 = regenerate(doc1, [server], root, offline=False, registry=None)
        pkg2 = doc2["servers"]["cursor/github"]["package"]
        assert pkg2["resolved_version"] == "2025.4.8"
        assert pkg2["deprecated"] == "Package no longer supported."


# ── Ownership-scoped checksum, integrated through regenerate() ─────────────────


class TestChecksumOwnershipScope:
    def test_unaffected_by_a_foreign_trees_edit_between_runs(self) -> None:
        root = Path("/home/tester/project")
        server = _server(args=["-y", "foo@1.0.0"])
        doc1 = regenerate(None, [server], root, offline=True, registry=None)

        # Simulate a foreign tool (the #88 generator) rewriting `trees` only,
        # between two mcp-audit `lock` runs — servers are unchanged.
        doc1_with_trees = dict(doc1)
        doc1_with_trees["trees"] = {
            "_producer": "mcp-lock-tree-gen",
            "_schema_version": 1,
            "servers": {"github": {"deps": ["a", "b"]}},
        }

        doc2 = regenerate(doc1_with_trees, [server], root, offline=True, registry=None)
        assert doc2["checksum"] == doc1["checksum"]
        assert doc2["trees"] == doc1_with_trees["trees"]


# ── Byte/canonical preservation of foreign sections ─────────────────────────────


class TestForeignSectionPreservation:
    def test_unknown_section_canonical_form_preserved(self) -> None:
        """Non-ASCII key, mixed order, a trailing-zero float — RFC 8785 territory."""
        root = Path("/home/tester/project")
        server = _server(args=["-y", "foo@1.0.0"])
        existing = regenerate(None, [server], root, offline=True, registry=None)
        existing["café"] = {"z": 1, "a": 1.20, "m": "café"}

        regenerated = regenerate(existing, [server], root, offline=True, registry=None)
        from mcp_audit.advisory.canonical import canonicalize

        assert canonicalize(regenerated["café"]) == canonicalize(existing["café"])

    def test_oversized_foreign_section_fails_cleanly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = Path("/home/tester/project")
        server = _server(args=["-y", "foo@1.0.0"])
        # Build with the real (large) bound first, so the single-server owned
        # subdocument's own checksum computation is unaffected by the patch
        # applied below — only the oversized `trees` section should fail.
        existing = regenerate(None, [server], root, offline=True, registry=None)
        existing["trees"] = {f"key{i}": {"nested": i} for i in range(40)}

        monkeypatch.setattr(canonical_module, "MAX_NODES", 50)
        regenerated = regenerate(existing, [server], root, offline=True, registry=None)
        with pytest.raises(LockWriteError, match="trees"):
            serialize(regenerated)


# ── Serialization / atomic write ────────────────────────────────────────────────


class TestSerializeAndWrite:
    def test_write_lock_round_trips(self, tmp_path: Path) -> None:
        root = tmp_path
        server = _server(args=["-y", "foo@1.0.0"], config_path=tmp_path / "mcp.json")
        doc = regenerate(None, [server], root, offline=True, registry=None)

        lock_path = tmp_path / "mcp-lock.json"
        write_lock(lock_path, doc)

        reloaded = load_existing(lock_path)
        assert reloaded == doc

    def test_two_no_op_runs_differ_only_by_generated_at(self, tmp_path: Path) -> None:
        root = tmp_path
        server = _server(args=["-y", "foo@1.0.0"], config_path=tmp_path / "mcp.json")

        doc1 = regenerate(None, [server], root, offline=True, registry=None)
        doc2 = regenerate(doc1, [server], root, offline=True, registry=None)

        doc1_no_ts = {
            k: v for k, v in doc1.items() if k not in ("generated_at", "checksum")
        }
        doc2_no_ts = {
            k: v for k, v in doc2.items() if k not in ("generated_at", "checksum")
        }
        assert doc1_no_ts == doc2_no_ts
        assert doc1["checksum"] == doc2["checksum"]

    def test_no_absolute_paths_home_username_or_secrets_in_output(
        self, tmp_path: Path
    ) -> None:
        home = str(Path.home())
        username = getpass.getuser()
        server = _server(
            args=["-y", "@modelcontextprotocol/server-github@1.2.3"],
            env={"GITHUB_TOKEN": "ghp_shouldneverappearinlock1234567890"},  # noqa: S106
            config_path=Path.home() / ".cursor" / "mcp.json",
        )
        doc = regenerate(None, [server], Path.home(), offline=True, registry=None)
        data = serialize(doc).decode("utf-8")

        assert home not in data
        assert username not in data
        assert "ghp_shouldneverappearinlock1234567890" not in data
        assert "GITHUB_TOKEN" in data  # the key name is fine to record


# ── load_existing ────────────────────────────────────────────────────────────────


class TestLoadExisting:
    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert load_existing(tmp_path / "nope.json") is None

    def test_corrupt_json_returns_none(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp-lock.json"
        path.write_text("{not valid json", encoding="utf-8")
        assert load_existing(path) is None

    def test_valid_file_round_trips(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp-lock.json"
        path.write_text(json.dumps({"a": 1}), encoding="utf-8")
        assert load_existing(path) == {"a": 1}
