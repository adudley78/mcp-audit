"""Tests for mcp_audit.lock.auto_verify — shared check/scan lock verification."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.lock.auto_verify import auto_verify
from mcp_audit.lock.writer import regenerate, write_lock
from mcp_audit.models import ServerConfig, TransportType


def _server(
    name: str = "github",
    client: str = "cursor",
    args: list[str] | None = None,
    config_path: Path = Path("/x/.cursor/mcp.json"),
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path,
        transport=TransportType.STDIO,
        command="npx",
        args=args or ["-y", "foo@1.0.0"],
    )


def _write_lock_for(lock_dir: Path, servers: list[ServerConfig]) -> Path:
    doc = regenerate(None, servers, lock_dir, offline=True, registry=None)
    lock_path = lock_dir / "mcp-lock.json"
    write_lock(lock_path, doc)
    return lock_path


class TestAutoVerify:
    def test_no_lock_anywhere_returns_absent_status(self, tmp_path: Path) -> None:
        server = _server(config_path=tmp_path / ".mcp.json")
        findings, status = auto_verify([server])
        assert findings == []
        assert status.present is False
        assert status.verified is False
        assert status.findings == 0

    def test_clean_lock_reports_verified(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config_path = tmp_path / ".mcp.json"
        server = _server(config_path=config_path)
        lock_path = _write_lock_for(tmp_path, [server])

        findings, status = auto_verify([server])

        assert findings == []
        assert status.present is True
        assert status.verified is True
        assert status.checked_servers == 1
        assert status.lock_paths == [str(lock_path.resolve())]
        # trees/tools are always-present reserved-foreign stub sections
        # (ADR-0005 §1/§4/§11) — never claimed as verified, same as
        # `lock --verify`'s own terminal summary line.
        assert status.unverified_sections == ["tools", "trees"]

    def test_drifted_lock_reports_findings_and_unverified(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config_path = tmp_path / ".mcp.json"
        server = _server(config_path=config_path)
        _write_lock_for(tmp_path, [server])

        drifted = _server(config_path=config_path, args=["-y", "foo@2.0.0"])
        findings, status = auto_verify([drifted])

        # Changing the pinned version changes the owned-section checksum too,
        # so this surfaces as LOCK-001 (identity/config drift), not LOCK-004
        # (LOCK-004 is version drift *without* a checksum mismatch).
        assert len(findings) == 1
        assert findings[0].id == "LOCK-001"
        assert status.present is True
        assert status.verified is False
        assert status.findings == 1

    def test_monorepo_uses_nearest_ancestor_lock_per_server(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".git").mkdir()
        svc_a = tmp_path / "packages" / "svc-a"
        svc_a.mkdir(parents=True)
        server_a = _server(
            name="a-server", config_path=svc_a / ".mcp.json", args=["-y", "a@1.0.0"]
        )
        _write_lock_for(svc_a, [server_a])

        svc_b = tmp_path / "packages" / "svc-b"
        svc_b.mkdir(parents=True)
        server_b = _server(
            name="b-server", config_path=svc_b / ".mcp.json", args=["-y", "b@1.0.0"]
        )
        _write_lock_for(svc_b, [server_b])

        findings, status = auto_verify([server_a, server_b])

        assert findings == []
        assert status.present is True
        assert status.verified is True
        assert status.checked_servers == 2
        assert len(status.lock_paths) == 2
