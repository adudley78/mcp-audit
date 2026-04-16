"""Tests for the baseline snapshot and drift detection system."""

from __future__ import annotations

import json
import stat
import warnings
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.baselines.manager import (
    BaselineManager,
    DriftType,
)
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig, Severity, TransportType

# ── Fixtures ───────────────────────────────────────────────────────────────────


def _make_server(
    name: str = "filesystem",
    client: str = "claude-desktop",
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
def storage(tmp_path: Path) -> Path:
    """Return a temporary baseline storage directory."""
    return tmp_path / "baselines"


@pytest.fixture()
def mgr(storage: Path) -> BaselineManager:
    return BaselineManager(storage_dir=storage)


@pytest.fixture()
def servers() -> list[ServerConfig]:
    return [
        _make_server("filesystem", "claude-desktop"),
        _make_server("fetch", "cursor", command="uvx", args=["mcp-server-fetch"]),
    ]


# ── Storage directory ─────────────────────────────────────────────────────────


def test_storage_dir_created_with_0o700(tmp_path: Path) -> None:
    """Storage directory must be created with 0o700 permissions."""
    storage = tmp_path / "baselines"
    assert not storage.exists()
    BaselineManager(storage_dir=storage)
    assert storage.exists()
    mode = stat.S_IMODE(storage.stat().st_mode)
    assert mode == 0o700


# ── save() ────────────────────────────────────────────────────────────────────


def test_save_returns_baseline_with_correct_fields(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    bl = mgr.save(servers, config_paths=["/tmp/mcp.json"], name="test-bl")  # noqa: S108
    assert bl.name == "test-bl"
    assert bl.server_count == 2
    assert bl.scanner_version == "0.1.0"
    assert len(bl.servers) == 2
    assert bl.config_paths == ["/tmp/mcp.json"]  # noqa: S108


def test_save_creates_json_file(
    mgr: BaselineManager, storage: Path, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="mybl")
    assert (storage / "mybl.json").exists()


def test_save_file_permissions_are_0o600(
    mgr: BaselineManager, storage: Path, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="permtest")
    path = storage / "permtest.json"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_save_autogenerates_name_from_timestamp(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    bl = mgr.save(servers, config_paths=[])
    assert bl.name.startswith("baseline-")
    assert len(bl.name) == len("baseline-20260416-120000")


def test_save_env_stores_keys_only_not_values(
    mgr: BaselineManager,
) -> None:
    """Env values must NEVER be persisted to disk — only key names."""
    server = _make_server(env={"OPENAI_API_KEY": "sk-secret-123", "DEBUG": "true"})
    bl = mgr.save([server], config_paths=[])

    # Check in the model
    assert set(bl.servers[0].env.keys()) == {"OPENAI_API_KEY", "DEBUG"}
    for v in bl.servers[0].env.values():
        assert v == "", f"Expected empty string, got {v!r}"

    # Check the persisted JSON — values must not appear
    raw_json = (mgr._storage_dir / f"{bl.name}.json").read_text()
    assert "sk-secret-123" not in raw_json
    assert "true" not in raw_json or '"true"' not in raw_json


# ── list() ────────────────────────────────────────────────────────────────────


def test_list_returns_empty_when_no_baselines(mgr: BaselineManager) -> None:
    assert mgr.list() == []


def test_list_returns_newest_first(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="first")
    mgr.save(servers, config_paths=[], name="second")
    mgr.save(servers, config_paths=[], name="third")

    results = mgr.list()
    assert len(results) == 3
    # Should be sorted newest first — verify names are all present
    names = [bl.name for bl in results]
    assert "first" in names and "second" in names and "third" in names
    # created_at should be descending
    for i in range(len(results) - 1):
        assert results[i].created_at >= results[i + 1].created_at


def test_list_skips_malformed_files_without_crash(
    mgr: BaselineManager, storage: Path, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="good-bl")
    bad = storage / "corrupt.json"
    bad.write_text("{ this is not json }", encoding="utf-8")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        results = mgr.list()

    assert len(results) == 1
    assert results[0].name == "good-bl"
    assert any("corrupt.json" in str(warning.message) for warning in w)


# ── load() ────────────────────────────────────────────────────────────────────


def test_load_round_trips_cleanly(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    saved = mgr.save(servers, config_paths=["/a.json"], name="rt-test")
    loaded = mgr.load("rt-test")
    assert loaded.name == saved.name
    assert loaded.server_count == saved.server_count
    assert loaded.scanner_version == saved.scanner_version
    assert len(loaded.servers) == len(saved.servers)
    assert loaded.config_paths == saved.config_paths


def test_load_with_json_extension(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="ext-test")
    bl = mgr.load("ext-test.json")
    assert bl.name == "ext-test"


def test_load_raises_file_not_found_for_missing(mgr: BaselineManager) -> None:
    with pytest.raises(FileNotFoundError, match="nonexistent"):
        mgr.load("nonexistent")


# ── load_latest() ─────────────────────────────────────────────────────────────


def test_load_latest_returns_none_when_no_baselines(mgr: BaselineManager) -> None:
    assert mgr.load_latest() is None


def test_load_latest_returns_most_recent(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="older")
    mgr.save(servers, config_paths=[], name="newer")
    latest = mgr.load_latest()
    assert latest is not None
    assert latest.name == "newer"


# ── delete() ─────────────────────────────────────────────────────────────────


def test_delete_removes_file(
    mgr: BaselineManager, storage: Path, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="to-delete")
    assert (storage / "to-delete.json").exists()
    mgr.delete("to-delete")
    assert not (storage / "to-delete.json").exists()


def test_delete_raises_for_missing(mgr: BaselineManager) -> None:
    with pytest.raises(ValueError, match="nonexistent"):
        mgr.delete("nonexistent")


# ── export() ─────────────────────────────────────────────────────────────────


def test_export_returns_valid_json_string(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    mgr.save(servers, config_paths=[], name="export-test")
    raw = mgr.export("export-test")
    data = json.loads(raw)
    assert data["name"] == "export-test"
    assert data["server_count"] == 2


def test_export_raises_for_missing(mgr: BaselineManager) -> None:
    with pytest.raises(FileNotFoundError, match="missing-bl"):
        mgr.export("missing-bl")


# ── compare() — identical state ───────────────────────────────────────────────


def test_compare_no_drift_when_identical(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    bl = mgr.save(servers, config_paths=[])
    drift = mgr.compare(bl, servers)
    assert drift == []


# ── compare() — server_added ─────────────────────────────────────────────────


def test_compare_detects_server_added(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    bl = mgr.save(servers, config_paths=[])
    new_server = _make_server(
        "github",
        "claude-desktop",
        command="npx",
        args=["@modelcontextprotocol/server-github"],
    )
    drift = mgr.compare(bl, [*servers, new_server])

    added = [d for d in drift if d.drift_type == DriftType.SERVER_ADDED]
    assert len(added) == 1
    assert added[0].server_name == "github"
    assert added[0].severity == Severity.MEDIUM


def test_compare_empty_baseline_all_servers_added(mgr: BaselineManager) -> None:
    """When baseline has no servers, every current server is 'added'."""
    bl = mgr.save([], config_paths=[])
    servers = [_make_server("fs", "claude-desktop"), _make_server("fetch", "cursor")]
    drift = mgr.compare(bl, servers)
    added = [d for d in drift if d.drift_type == DriftType.SERVER_ADDED]
    assert len(added) == 2


# ── compare() — server_removed ────────────────────────────────────────────────


def test_compare_detects_server_removed(
    mgr: BaselineManager, servers: list[ServerConfig]
) -> None:
    bl = mgr.save(servers, config_paths=[])
    drift = mgr.compare(bl, servers[:1])  # remove the second

    removed = [d for d in drift if d.drift_type == DriftType.SERVER_REMOVED]
    assert len(removed) == 1
    assert removed[0].server_name == "fetch"
    assert removed[0].severity == Severity.INFO


def test_compare_empty_current_state_all_servers_removed(mgr: BaselineManager) -> None:
    """When no servers are currently present, all baseline servers are 'removed'."""
    servers = [_make_server("fs", "claude-desktop"), _make_server("fetch", "cursor")]
    bl = mgr.save(servers, config_paths=[])
    drift = mgr.compare(bl, [])
    removed = [d for d in drift if d.drift_type == DriftType.SERVER_REMOVED]
    assert len(removed) == 2


# ── compare() — hash_changed ─────────────────────────────────────────────────


def test_compare_detects_hash_changed(
    mgr: BaselineManager,
) -> None:
    original = _make_server(raw={"command": "npx", "args": ["-y", "server"]})
    bl = mgr.save([original], config_paths=[])

    modified = _make_server(
        raw={"command": "npx", "args": ["-y", "server"], "extra": "injected"}
    )
    drift = mgr.compare(bl, [modified])

    hc = [d for d in drift if d.drift_type == DriftType.HASH_CHANGED]
    assert len(hc) == 1
    assert hc[0].severity == Severity.HIGH


# ── compare() — command_changed ──────────────────────────────────────────────


def test_compare_detects_command_changed(mgr: BaselineManager) -> None:
    original = _make_server(command="npx")
    bl = mgr.save([original], config_paths=[])

    modified = _make_server(command="bunx")
    drift = mgr.compare(bl, [modified])

    cc = [d for d in drift if d.drift_type == DriftType.COMMAND_CHANGED]
    assert len(cc) == 1
    assert cc[0].baseline_value == "npx"
    assert cc[0].current_value == "bunx"
    assert cc[0].severity == Severity.HIGH


# ── compare() — args_changed ─────────────────────────────────────────────────


def test_compare_detects_args_changed(mgr: BaselineManager) -> None:
    original = _make_server(args=["-y", "@modelcontextprotocol/server-filesystem"])
    bl = mgr.save([original], config_paths=[])

    modified = _make_server(args=["-y", "@evil/server-filesystem"])
    drift = mgr.compare(bl, [modified])

    ac = [d for d in drift if d.drift_type == DriftType.ARGS_CHANGED]
    assert len(ac) == 1
    assert ac[0].severity == Severity.MEDIUM


# ── compare() — env_changed ───────────────────────────────────────────────────


def test_compare_detects_env_changed(mgr: BaselineManager) -> None:
    original = _make_server(env={"API_KEY": "secret"})
    bl = mgr.save([original], config_paths=[])

    # New server has different env keys
    modified = _make_server(env={"API_KEY": "secret", "NEW_TOKEN": "x"})
    drift = mgr.compare(bl, [modified])

    ec = [d for d in drift if d.drift_type == DriftType.ENV_CHANGED]
    assert len(ec) == 1
    assert ec[0].severity == Severity.MEDIUM
    assert "NEW_TOKEN" in (ec[0].current_value or "")


# ── compare() — multi-client disambiguation ───────────────────────────────────


def test_compare_distinguishes_same_name_different_clients(
    mgr: BaselineManager,
) -> None:
    """Servers with same name on different clients must not be confused."""
    claude_fs = _make_server("filesystem", "claude-desktop", command="npx")
    cursor_fs = _make_server("filesystem", "cursor", command="uvx")

    bl = mgr.save([claude_fs, cursor_fs], config_paths=[])

    # Modify only the cursor one
    cursor_fs_modified = _make_server(
        "filesystem",
        "cursor",
        command="bunx",
        raw={
            "command": "bunx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem"],
        },
    )
    drift = mgr.compare(bl, [claude_fs, cursor_fs_modified])

    cc = [d for d in drift if d.drift_type == DriftType.COMMAND_CHANGED]
    assert len(cc) == 1
    assert cc[0].client == "cursor"


# ── compare() — multiple findings per server ─────────────────────────────────


def test_compare_multiple_findings_for_same_server(mgr: BaselineManager) -> None:
    """A single server produces hash_changed + command_changed simultaneously."""
    original = _make_server(command="npx", raw={"command": "npx", "args": []})
    bl = mgr.save([original], config_paths=[])

    modified = _make_server(command="bunx", raw={"command": "bunx", "args": []})
    drift = mgr.compare(bl, [modified])

    types = {d.drift_type for d in drift}
    assert DriftType.HASH_CHANGED in types
    assert DriftType.COMMAND_CHANGED in types


# ── compare() — sort order ────────────────────────────────────────────────────


def test_compare_sorted_by_severity_descending(mgr: BaselineManager) -> None:
    """Result must be sorted highest severity first."""
    # server_removed = INFO, command_changed = HIGH
    original = _make_server("alpha", "claude-desktop", command="npx")
    extra = _make_server("beta", "claude-desktop")
    bl = mgr.save([original, extra], config_paths=[])

    modified_alpha = _make_server(
        "alpha",
        "claude-desktop",
        command="bunx",
        raw={
            "command": "bunx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem"],
        },
    )
    drift = mgr.compare(bl, [modified_alpha])  # beta removed, alpha changed

    severities = [d.severity for d in drift]
    sev_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    indices = [sev_order.index(s) for s in severities]
    assert indices == sorted(indices), "Findings are not sorted by severity descending"


# ── CLI integration ───────────────────────────────────────────────────────────


runner = CliRunner()


def test_baseline_list_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.baselines.manager as _bm_mod

    monkeypatch.setattr(_bm_mod, "_DEFAULT_STORAGE_DIR", tmp_path / "baselines")
    result = runner.invoke(app, ["baseline", "list"])
    assert result.exit_code == 0
    assert "No baselines saved" in result.output


def test_baseline_save_and_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import patch

    import mcp_audit.baselines.manager as _bm_mod
    from mcp_audit.discovery import DiscoveredConfig

    monkeypatch.setattr(_bm_mod, "_DEFAULT_STORAGE_DIR", tmp_path / "baselines")

    fake_config_path = tmp_path / "mcp.json"
    fake_config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "test-srv": {"command": "npx", "args": ["-y", "test-server"]}
                }
            }
        ),
        encoding="utf-8",
    )

    with patch(
        "mcp_audit.cli.discover_configs",
        return_value=[
            DiscoveredConfig(
                client_name="claude-desktop",
                root_key="mcpServers",
                path=fake_config_path,
            )
        ],
    ):
        save_result = runner.invoke(app, ["baseline", "save", "ci-baseline"])
        assert save_result.exit_code == 0
        assert "ci-baseline" in save_result.output

    list_result = runner.invoke(app, ["baseline", "list"])
    assert list_result.exit_code == 0
    assert "ci-baseline" in list_result.output


def test_baseline_export_outputs_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import patch

    import mcp_audit.baselines.manager as _bm_mod
    from mcp_audit.discovery import DiscoveredConfig

    monkeypatch.setattr(_bm_mod, "_DEFAULT_STORAGE_DIR", tmp_path / "baselines")
    fake_config_path = tmp_path / "mcp.json"
    fake_config_path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

    with patch(
        "mcp_audit.cli.discover_configs",
        return_value=[
            DiscoveredConfig(
                client_name="cursor", root_key="mcpServers", path=fake_config_path
            )
        ],
    ):
        runner.invoke(app, ["baseline", "save", "export-bl"])
        result = runner.invoke(app, ["baseline", "export", "export-bl"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "export-bl"


def test_scan_baseline_latest_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--baseline latest loads the most recent baseline and appends drift findings."""
    from unittest.mock import patch

    import mcp_audit.baselines.manager as _bm_mod

    storage = tmp_path / "baselines"
    monkeypatch.setattr(_bm_mod, "_DEFAULT_STORAGE_DIR", storage)

    mgr = BaselineManager(storage_dir=storage)
    server = _make_server("fs", "claude-desktop", command="npx")
    mgr.save([server], config_paths=[], name="base-latest")

    # Scan result with a different server (so drift is detected)
    from mcp_audit.models import ScanResult

    fake_result = ScanResult()
    fake_result.servers = [_make_server("new-server", "claude-desktop", command="uvx")]

    with patch("mcp_audit.cli.run_scan", return_value=fake_result):
        result = runner.invoke(
            app,
            ["scan", "--baseline", "latest", "--format", "json"],
        )

    assert result.exit_code in (0, 1)
    output_data = json.loads(result.output)
    drift_findings = [f for f in output_data["findings"] if f["analyzer"] == "baseline"]
    assert len(drift_findings) > 0


def test_scan_baseline_drift_in_json_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drift findings must appear in JSON scan output when --baseline is used."""
    from unittest.mock import patch

    import mcp_audit.baselines.manager as _bm_mod

    storage = tmp_path / "baselines"
    monkeypatch.setattr(_bm_mod, "_DEFAULT_STORAGE_DIR", storage)

    mgr = BaselineManager(storage_dir=storage)
    original = _make_server("fs", "claude-desktop", command="npx")
    mgr.save([original], config_paths=[], name="drift-test")

    from mcp_audit.models import ScanResult

    fake_result = ScanResult()
    fake_result.servers = [
        _make_server(
            "fs",
            "claude-desktop",
            command="bunx",
            raw={
                "command": "bunx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            },
        )
    ]

    with patch("mcp_audit.cli.run_scan", return_value=fake_result):
        result = runner.invoke(
            app,
            ["scan", "--baseline", "drift-test", "--format", "json"],
        )

    output_data = json.loads(result.output)
    analyzers = {f["analyzer"] for f in output_data["findings"]}
    assert "baseline" in analyzers
    titles = [
        f["title"] for f in output_data["findings"] if f["analyzer"] == "baseline"
    ]
    assert any("command_changed" in t or "hash_changed" in t for t in titles)
