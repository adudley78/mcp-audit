"""Tests for the rug-pull detection analyzer."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.analyzers.rug_pull import (
    _STATE_DIR,
    DEFAULT_STATE_PATH,
    RugPullAnalyzer,
    build_state_entry,
    compute_hashes,
    derive_state_path,
    load_state,
    save_state,
    server_key,
)
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import ServerConfig, Severity, TransportType

# ── Fixtures ───────────────────────────────────────────────────────────────────


def _make_server(
    name: str = "filesystem-server",
    client: str = "cursor",
    command: str = "npx",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    config_path: Path | None = None,
    raw: dict | None = None,
) -> ServerConfig:
    resolved_args = args or ["-y", "@modelcontextprotocol/server-filesystem"]
    resolved_env = env or {}
    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path or Path("/tmp/mcp.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command=command,
        args=resolved_args,
        env=resolved_env,
        raw=raw if raw is not None else {"command": command, "args": resolved_args},
    )


@pytest.fixture()
def state_file(tmp_path: Path) -> Path:
    """Return a path inside tmp_path for the state file (does not yet exist)."""
    return tmp_path / ".mcp-audit" / "state.json"


@pytest.fixture()
def analyzer(state_file: Path) -> RugPullAnalyzer:
    return RugPullAnalyzer(state_path=state_file)


# ── compute_hashes ────────────────────────────────────────────────────────────


class TestComputeHashes:
    def test_returns_four_keys(self) -> None:
        hashes = compute_hashes(_make_server())
        assert set(hashes) == {"command", "args", "env_keys", "raw"}

    def test_all_values_are_hex_strings(self) -> None:
        hashes = compute_hashes(_make_server())
        for v in hashes.values():
            assert len(v) == 64
            int(v, 16)  # raises if not valid hex

    def test_same_server_same_hashes(self) -> None:
        srv = _make_server()
        assert compute_hashes(srv) == compute_hashes(srv)

    def test_different_command_different_hash(self) -> None:
        a = compute_hashes(_make_server(command="npx"))
        b = compute_hashes(_make_server(command="bunx"))
        assert a["command"] != b["command"]
        assert a["raw"] != b["raw"]

    def test_different_args_different_hash(self) -> None:
        a = compute_hashes(_make_server(args=["-y", "pkg-a"]))
        b = compute_hashes(_make_server(args=["-y", "pkg-b"]))
        assert a["args"] != b["args"]

    def test_env_keys_hashed_sorted(self) -> None:
        a = compute_hashes(_make_server(env={"B": "2", "A": "1"}))
        b = compute_hashes(_make_server(env={"A": "1", "B": "2"}))
        assert a["env_keys"] == b["env_keys"]

    def test_env_values_not_included_in_env_keys_hash(self) -> None:
        """env_keys hash captures key names only, not values."""
        a = compute_hashes(_make_server(env={"KEY": "value1"}))
        b = compute_hashes(_make_server(env={"KEY": "value2"}))
        assert a["env_keys"] == b["env_keys"]


# ── server_key ────────────────────────────────────────────────────────────────


class TestServerKey:
    def test_format(self) -> None:
        srv = _make_server(name="fs", client="claude")
        assert server_key(srv) == "claude/fs"

    def test_slash_separated(self) -> None:
        assert "/" in server_key(_make_server())


# ── load_state / save_state ───────────────────────────────────────────────────


class TestStateIO:
    def test_load_missing_file_returns_empty_state(self, tmp_path: Path) -> None:
        state = load_state(tmp_path / "nonexistent.json")
        assert state["version"] == 1
        assert state["servers"] == {}

    def test_load_corrupt_file_returns_empty_state(self, tmp_path: Path) -> None:
        bad = tmp_path / "state.json"
        bad.write_text("not json")
        state = load_state(bad)
        assert state["servers"] == {}

    def test_load_non_object_returns_empty_state(self, tmp_path: Path) -> None:
        bad = tmp_path / "state.json"
        bad.write_text("[1, 2, 3]")
        state = load_state(bad)
        assert state["servers"] == {}

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "state.json"
        save_state({"version": 1, "servers": {}}, nested)
        assert nested.exists()

    def test_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        original = {"version": 1, "servers": {"cursor/fs": {"hashes": {"raw": "abc"}}}}
        save_state(original, path)
        loaded = load_state(path)
        assert loaded == original


# ── build_state_entry ─────────────────────────────────────────────────────────


class TestBuildStateEntry:
    def test_contains_required_keys(self) -> None:
        entry = build_state_entry(_make_server())
        assert {"config_path", "first_seen", "last_seen", "hashes"}.issubset(entry)

    def test_hashes_present(self) -> None:
        entry = build_state_entry(_make_server())
        assert set(entry["hashes"]) == {"command", "args", "env_keys", "raw"}

    def test_first_seen_preserved_when_provided(self) -> None:
        ts = "2026-01-01T00:00:00+00:00"
        entry = build_state_entry(_make_server(), first_seen=ts)
        assert entry["first_seen"] == ts


# ── RugPullAnalyzer.analyze (single-server no-op) ─────────────────────────────


class TestAnalyzeSingleServer:
    def test_returns_empty_list(self, analyzer: RugPullAnalyzer) -> None:
        assert analyzer.analyze(_make_server()) == []


# ── First scan (no state file) ────────────────────────────────────────────────


class TestFirstScan:
    def test_emits_info_finding_per_server(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        servers = [_make_server("fs"), _make_server("gh", args=["-y", "pkg"])]
        findings = analyzer.analyze_all(servers)
        info = [f for f in findings if f.id == "RUGPULL-000"]
        assert len(info) == 2

    def test_severity_is_info(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        findings = analyzer.analyze_all([_make_server()])
        assert all(f.severity == Severity.INFO for f in findings)

    def test_state_file_created(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        analyzer.analyze_all([_make_server()])
        assert state_file.exists()

    def test_state_file_contains_server(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        srv = _make_server()
        analyzer.analyze_all([srv])
        state = json.loads(state_file.read_text())
        assert server_key(srv) in state["servers"]

    def test_state_file_hashes_are_correct(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        srv = _make_server()
        analyzer.analyze_all([srv])
        state = json.loads(state_file.read_text())
        stored_hashes = state["servers"][server_key(srv)]["hashes"]
        assert stored_hashes == compute_hashes(srv)

    def test_no_high_findings_on_first_scan(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        findings = analyzer.analyze_all([_make_server()])
        assert not any(f.severity == Severity.HIGH for f in findings)


# ── Unchanged config (second scan, no changes) ────────────────────────────────


class TestUnchangedConfig:
    def test_no_high_findings_when_config_unchanged(
        self, analyzer: RugPullAnalyzer
    ) -> None:
        srv = _make_server()
        analyzer.analyze_all([srv])  # first scan
        findings = analyzer.analyze_all([srv])  # second scan, unchanged
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 0

    def test_no_rugpull_001_when_unchanged(self, analyzer: RugPullAnalyzer) -> None:
        srv = _make_server()
        analyzer.analyze_all([srv])
        findings = analyzer.analyze_all([srv])
        assert not any(f.id == "RUGPULL-001" for f in findings)

    def test_no_rugpull_002_for_known_server(self, analyzer: RugPullAnalyzer) -> None:
        srv = _make_server()
        analyzer.analyze_all([srv])
        findings = analyzer.analyze_all([srv])
        assert not any(f.id == "RUGPULL-002" for f in findings)


# ── Changed config → RUGPULL-001 ──────────────────────────────────────────────


class TestChangedConfig:
    def test_changed_raw_emits_rugpull_001(self, analyzer: RugPullAnalyzer) -> None:
        srv_original = _make_server(
            args=["-y", "@modelcontextprotocol/server-filesystem"]
        )
        analyzer.analyze_all([srv_original])

        srv_modified = _make_server(args=["-y", "@modelcontextprotocol/server-evil"])
        findings = analyzer.analyze_all([srv_modified])

        assert any(f.id == "RUGPULL-001" for f in findings)

    def test_severity_is_high(self, analyzer: RugPullAnalyzer) -> None:
        analyzer.analyze_all([_make_server(args=["-y", "pkg-a"])])
        findings = analyzer.analyze_all([_make_server(args=["-y", "pkg-b"])])
        rugpull = [f for f in findings if f.id == "RUGPULL-001"]
        assert rugpull[0].severity == Severity.HIGH

    def test_finding_cwe_is_set(self, analyzer: RugPullAnalyzer) -> None:
        analyzer.analyze_all([_make_server(args=["-y", "pkg-a"])])
        findings = analyzer.analyze_all([_make_server(args=["-y", "pkg-b"])])
        rugpull = next(f for f in findings if f.id == "RUGPULL-001")
        assert rugpull.cwe == "CWE-494"

    def test_evidence_lists_changed_fields(self, analyzer: RugPullAnalyzer) -> None:
        analyzer.analyze_all([_make_server(args=["-y", "pkg-a"])])
        findings = analyzer.analyze_all([_make_server(args=["-y", "pkg-b"])])
        rugpull = next(f for f in findings if f.id == "RUGPULL-001")
        assert "args" in rugpull.evidence

    def test_state_updated_after_change(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        analyzer.analyze_all([_make_server(args=["-y", "pkg-a"])])
        new_srv = _make_server(args=["-y", "pkg-b"])
        analyzer.analyze_all([new_srv])
        state = json.loads(state_file.read_text())
        stored = state["servers"][server_key(new_srv)]["hashes"]
        assert stored == compute_hashes(new_srv)

    def test_command_change_triggers_001(self, analyzer: RugPullAnalyzer) -> None:
        analyzer.analyze_all([_make_server(command="npx")])
        findings = analyzer.analyze_all([_make_server(command="bunx")])
        assert any(f.id == "RUGPULL-001" for f in findings)

    def test_env_key_addition_triggers_001(self, analyzer: RugPullAnalyzer) -> None:
        srv1 = _make_server(
            env={},
            raw={"command": "npx", "env": {}},
        )
        analyzer.analyze_all([srv1])
        srv2 = _make_server(
            env={"NEW_KEY": "value"},
            raw={"command": "npx", "env": {"NEW_KEY": "value"}},
        )
        findings = analyzer.analyze_all([srv2])
        assert any(f.id == "RUGPULL-001" for f in findings)


# ── New server → RUGPULL-002 ──────────────────────────────────────────────────


class TestNewServer:
    def test_new_server_emits_rugpull_002(self, analyzer: RugPullAnalyzer) -> None:
        existing = _make_server("fs")
        analyzer.analyze_all([existing])  # baseline with only "fs"

        new_srv = _make_server("github", args=["-y", "pkg"])
        findings = analyzer.analyze_all([existing, new_srv])
        assert any(f.id == "RUGPULL-002" for f in findings)

    def test_new_server_severity_is_info(self, analyzer: RugPullAnalyzer) -> None:
        analyzer.analyze_all([_make_server("fs")])
        findings = analyzer.analyze_all(
            [_make_server("fs"), _make_server("github", args=["-y", "p"])]
        )
        rp002 = [f for f in findings if f.id == "RUGPULL-002"]
        assert rp002[0].severity == Severity.INFO

    def test_new_server_recorded_in_state(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        analyzer.analyze_all([_make_server("fs")])
        new_srv = _make_server("github", args=["-y", "p"])
        analyzer.analyze_all([_make_server("fs"), new_srv])
        state = json.loads(state_file.read_text())
        assert server_key(new_srv) in state["servers"]


# ── Removed server → RUGPULL-003 ─────────────────────────────────────────────


class TestRemovedServer:
    def test_removed_server_emits_rugpull_003(self, analyzer: RugPullAnalyzer) -> None:
        srv_a = _make_server("fs")
        srv_b = _make_server("github", args=["-y", "pkg"])
        analyzer.analyze_all([srv_a, srv_b])  # baseline with both

        findings = analyzer.analyze_all([srv_a])  # srv_b removed
        assert any(f.id == "RUGPULL-003" for f in findings)

    def test_removed_server_severity_is_info(self, analyzer: RugPullAnalyzer) -> None:
        srv_a = _make_server("fs")
        srv_b = _make_server("github", args=["-y", "pkg"])
        analyzer.analyze_all([srv_a, srv_b])
        findings = analyzer.analyze_all([srv_a])
        rp003 = [f for f in findings if f.id == "RUGPULL-003"]
        assert rp003[0].severity == Severity.INFO

    def test_removed_server_not_added_back_to_state(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        srv_a = _make_server("fs")
        srv_b = _make_server("github", args=["-y", "pkg"])
        analyzer.analyze_all([srv_a, srv_b])
        analyzer.analyze_all([srv_a])  # srv_b removed
        state = json.loads(state_file.read_text())
        # srv_a (still present) must remain in state
        assert server_key(srv_a) in state["servers"]


# ── Combination scenarios ─────────────────────────────────────────────────────


class TestCombinationScenarios:
    def test_simultaneous_change_new_and_removed(
        self, analyzer: RugPullAnalyzer
    ) -> None:
        srv_a = _make_server("fs", args=["-y", "pkg-a"])
        srv_b = _make_server("github", args=["-y", "pkg-b"])
        analyzer.analyze_all([srv_a, srv_b])

        # Modify srv_a, remove srv_b, add srv_c
        srv_a_modified = _make_server("fs", args=["-y", "pkg-evil"])
        srv_c = _make_server("slack", args=["-y", "pkg-c"])

        findings = analyzer.analyze_all([srv_a_modified, srv_c])

        ids = {f.id for f in findings}
        assert "RUGPULL-001" in ids  # srv_a changed
        assert "RUGPULL-002" in ids  # srv_c new
        assert "RUGPULL-003" in ids  # srv_b removed

    def test_empty_server_list_no_crash(self, analyzer: RugPullAnalyzer) -> None:
        # First scan with servers, then scan with empty list
        analyzer.analyze_all([_make_server()])
        findings = analyzer.analyze_all([])
        # All previously tracked servers should appear as RUGPULL-003
        assert all(f.id == "RUGPULL-003" for f in findings)

    def test_first_scan_empty_list_no_findings(self, analyzer: RugPullAnalyzer) -> None:
        findings = analyzer.analyze_all([])
        assert findings == []

    def test_finding_path_populated(self, analyzer: RugPullAnalyzer) -> None:
        srv = _make_server(config_path=Path("/home/user/.cursor/mcp.json"))
        findings = analyzer.analyze_all([srv])
        for f in findings:
            assert f.finding_path == "/home/user/.cursor/mcp.json"


# ── State persistence across analyzer instances ───────────────────────────────


class TestStatePersistence:
    def test_second_instance_reads_first_scan(self, state_file: Path) -> None:
        """Two RugPullAnalyzer instances sharing a state file behave correctly."""
        srv = _make_server()
        RugPullAnalyzer(state_path=state_file).analyze_all([srv])

        # Second instance: should detect change, not treat as first scan
        srv_modified = _make_server(args=["-y", "evil-pkg"])
        findings = RugPullAnalyzer(state_path=state_file).analyze_all([srv_modified])
        assert any(f.id == "RUGPULL-001" for f in findings)

    def test_first_seen_preserved_across_scans(
        self, analyzer: RugPullAnalyzer, state_file: Path
    ) -> None:
        srv = _make_server()
        analyzer.analyze_all([srv])
        state_after_first = json.loads(state_file.read_text())
        first_seen_1 = state_after_first["servers"][server_key(srv)]["first_seen"]

        analyzer.analyze_all([srv])  # second scan, unchanged
        state_after_second = json.loads(state_file.read_text())
        first_seen_2 = state_after_second["servers"][server_key(srv)]["first_seen"]

        assert first_seen_1 == first_seen_2


# ── derive_state_path ─────────────────────────────────────────────────────────


def _discovered(path: str) -> DiscoveredConfig:
    return DiscoveredConfig(
        client_name="custom", root_key="mcpServers", path=Path(path)
    )


class TestStateFilePermissions:
    """V-05: state files must be created with restrictive permissions (0o600)."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_state_file_has_restricted_permissions(self, tmp_path: Path) -> None:
        state_path = tmp_path / "secure" / "state.json"
        save_state({"version": 1, "servers": {}}, state_path)
        mode = os.stat(state_path).st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_state_dir_has_restricted_permissions(self, tmp_path: Path) -> None:
        state_path = tmp_path / "secure_dir" / "state.json"
        save_state({"version": 1, "servers": {}}, state_path)
        dir_mode = os.stat(state_path.parent).st_mode & 0o777
        assert dir_mode == 0o700, f"Expected 0o700, got {oct(dir_mode)}"

    def test_round_trip_still_works_with_permissions(self, tmp_path: Path) -> None:
        state_path = tmp_path / "perm_test" / "state.json"
        original = {"version": 1, "servers": {"k": {"hashes": {"raw": "abc"}}}}
        save_state(original, state_path)
        loaded = load_state(state_path)
        assert loaded == original


class TestDeriveStatePath:
    def test_empty_configs_returns_default_path(self) -> None:
        result = derive_state_path([])
        assert result == DEFAULT_STATE_PATH

    def test_returns_path_in_mcp_audit_dir(self) -> None:
        configs = [_discovered("/tmp/mcp.json")]  # noqa: S108
        result = derive_state_path(configs)
        assert result.parent == DEFAULT_STATE_PATH.parent
        assert result.name.startswith("state_")
        assert result.name.endswith(".json")

    def test_hash_suffix_is_eight_chars(self) -> None:
        configs = [_discovered("/tmp/mcp.json")]  # noqa: S108
        result = derive_state_path(configs)
        suffix = result.stem.removeprefix("state_")
        assert len(suffix) == 8

    def test_deterministic_same_configs(self) -> None:
        configs = [_discovered("/a/mcp.json"), _discovered("/b/mcp.json")]
        assert derive_state_path(configs) == derive_state_path(configs)

    def test_order_independent(self) -> None:
        """Sorting means [A, B] and [B, A] produce the same path."""
        ab = [_discovered("/a/mcp.json"), _discovered("/b/mcp.json")]
        ba = [_discovered("/b/mcp.json"), _discovered("/a/mcp.json")]
        assert derive_state_path(ab) == derive_state_path(ba)

    def test_different_configs_different_paths(self) -> None:
        demo = [_discovered("/demo/configs/a.json")]
        real = [_discovered("/home/user/.cursor/mcp.json")]
        assert derive_state_path(demo) != derive_state_path(real)

    def test_superset_produces_different_path(self) -> None:
        """Adding one more config file changes the derived path."""
        one = [_discovered("/a.json")]
        two = [_discovered("/a.json"), _discovered("/b.json")]
        assert derive_state_path(one) != derive_state_path(two)

    def test_result_is_not_default_state_path(self) -> None:
        configs = [_discovered("/some/mcp.json")]
        result = derive_state_path(configs)
        assert result != DEFAULT_STATE_PATH


# ── platformdirs integration ──────────────────────────────────────────────────


class TestStateDirUsesPlatformdirs:
    def test_state_dir_resolves_under_user_config_dir(self) -> None:
        """_STATE_DIR must live under user_config_dir('mcp-audit'), not Path.home()."""
        from platformdirs import user_config_dir

        expected_parent = Path(user_config_dir("mcp-audit"))
        assert expected_parent / "state" == _STATE_DIR
        assert str(Path.home() / ".mcp-audit") not in str(_STATE_DIR)

    def test_state_dir_is_child_of_user_config_dir(self) -> None:
        """_STATE_DIR must be a child of user_config_dir('mcp-audit'), not a sibling."""
        from platformdirs import user_config_dir

        config_base = Path(user_config_dir("mcp-audit"))
        # _STATE_DIR should be directly inside the config base, not elsewhere.
        assert _STATE_DIR.parent == config_base

    def test_migration_noop_when_legacy_dir_absent(self, tmp_path: Path) -> None:
        """_migrate_legacy_state() must not crash when ~/.mcp-audit does not exist."""
        import mcp_audit.analyzers.rug_pull as rp_module

        absent = tmp_path / "nonexistent_legacy"
        with (
            patch.object(rp_module, "_LEGACY_STATE_DIR", absent),
            patch.object(rp_module, "_migration_done", False),
        ):
            rp_module._migrate_legacy_state()  # must not raise
