"""Tests for mcp_audit.lock.verifier — LOCK-001..005, offline vs. --resolve."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.lock import resolve as resolve_module
from mcp_audit.lock.verifier import verify
from mcp_audit.lock.writer import regenerate, write_lock
from mcp_audit.models import ServerConfig, TransportType


def _server(
    name: str = "github",
    client: str = "cursor",
    command: str = "npx",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    config_path: Path = Path("/home/tester/.cursor/mcp.json"),
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path,
        transport=TransportType.STDIO,
        command=command,
        args=args or [],
        env=env or {},
    )


def _write_lock_for(tmp_path: Path, servers: list[ServerConfig]) -> Path:
    doc = regenerate(None, servers, tmp_path, offline=True, registry=None)
    lock_path = tmp_path / "mcp-lock.json"
    write_lock(lock_path, doc)
    return lock_path


class TestMissingLock:
    def test_missing_lock_exits_2(self, tmp_path: Path) -> None:
        result = verify(tmp_path / "mcp-lock.json", [], resolve=False, registry=None)
        assert result.lock_missing is True
        assert result.exit_code == 2


class TestCleanVerify:
    def test_no_drift_exits_0(self, tmp_path: Path) -> None:
        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])
        result = verify(lock_path, [server], resolve=False, registry=None)
        assert result.findings == []
        assert result.exit_code == 0
        assert result.checked_servers == 1


class TestLock001Drift:
    def test_identity_change_flags_lock_001(self, tmp_path: Path) -> None:
        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        drifted = _server(args=["-y", "foo@1.0.0", "--extra-flag"])
        result = verify(lock_path, [drifted], resolve=False, registry=None)

        assert result.exit_code == 1
        assert [f.id for f in result.findings] == ["LOCK-001"]

    def test_new_env_key_flags_lock_001(self, tmp_path: Path) -> None:
        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        drifted = _server(args=["-y", "foo@1.0.0"], env={"NEW_TOKEN": "x"})
        result = verify(lock_path, [drifted], resolve=False, registry=None)

        assert result.exit_code == 1
        assert [f.id for f in result.findings] == ["LOCK-001"]


class TestLock002UnlockedServer:
    def test_new_server_flags_lock_002(self, tmp_path: Path) -> None:
        server_a = _server(name="github", args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server_a])

        server_b = _server(name="fetch", args=["-y", "bar@1.0.0"])
        result = verify(lock_path, [server_a, server_b], resolve=False, registry=None)

        assert result.exit_code == 1
        ids = [f.id for f in result.findings]
        assert ids == ["LOCK-002"]
        assert result.findings[0].server == "fetch"


class TestLock003MissingServer:
    def test_removed_server_flags_lock_003_but_exits_0(self, tmp_path: Path) -> None:
        server_a = _server(name="github", args=["-y", "foo@1.0.0"])
        server_b = _server(name="fetch", args=["-y", "bar@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server_a, server_b])

        result = verify(lock_path, [server_a], resolve=False, registry=None)

        assert result.exit_code == 0
        ids = [f.id for f in result.findings]
        assert ids == ["LOCK-003"]
        assert result.findings[0].server == "fetch"


class TestLock005Tampered:
    def test_hand_edited_checksum_short_circuits(self, tmp_path: Path) -> None:
        import json

        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        doc["servers"]["cursor/github"]["hashes"]["command"] = "sha256:tampered"
        lock_path.write_text(json.dumps(doc), encoding="utf-8")

        result = verify(lock_path, [server], resolve=False, registry=None)

        assert result.exit_code == 2
        assert result.tampered is True
        assert [f.id for f in result.findings] == ["LOCK-005"]

    def test_foreign_trees_edit_never_trips_lock_005(self, tmp_path: Path) -> None:
        """The checkpoint-review fix: regenerating `trees` is not tampering."""
        import json

        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        doc["trees"] = {
            "_producer": "mcp-lock-tree-gen",
            "_schema_version": 1,
            "servers": {"github": {"deps": ["a", "b", "c"]}},
        }
        lock_path.write_text(json.dumps(doc), encoding="utf-8")

        result = verify(lock_path, [server], resolve=False, registry=None)

        # R56: a genuinely populated foreign section now fails the exit code
        # on its own (unverified, not LOCK-005) — the point of this test is
        # that it is LOCK-005 (tampering) that never fires, not that the run
        # is silently clean.
        assert result.exit_code == 1
        assert result.findings == []
        assert "trees" in result.unverified_sections


class TestUnverifiedSectionsGeneric:
    def test_names_trees_and_a_synthetic_foreign_key(self, tmp_path: Path) -> None:
        import json

        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        doc["resolutions"] = {"_producer": "some-other-tool"}
        lock_path.write_text(json.dumps(doc), encoding="utf-8")

        result = verify(lock_path, [server], resolve=False, registry=None)

        assert set(result.unverified_sections) >= {"trees", "resolutions"}


class TestR56UnverifiedExitCode:
    """R56 Part 1: exit code now reflects unverified state, not just findings.

    STEP 1's regression proof: both cases below were pinned at ``exit_code
    == 0`` against the *unmodified* ``verify()`` (confirmed passing — see the
    R56 PR description for the pre-fix run), then inverted in place once the
    fix landed, so the same test now pins the corrected behaviour and would
    catch a regression back to the old bug.
    """

    def test_unresolved_entry_now_fails_exit_code(self, tmp_path: Path) -> None:
        server = _server(args=["-y", "foo"])  # unpinned, offline=True at write time
        lock_path = _write_lock_for(tmp_path, [server])

        result = verify(lock_path, [server], resolve=False, registry=None)

        assert result.exit_code == 1  # was 0 before R56 — CI now sees this
        assert result.unresolved_entries == ["cursor/github"]
        assert result.waived is False
        assert [item.name for item in result.unverified] == ["cursor/github"]

    def test_populated_foreign_trees_now_fails_exit_code(self, tmp_path: Path) -> None:
        import json

        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        doc["trees"] = {
            "_producer": "mcp-lock-tree-gen",
            "_schema_version": 1,
            "servers": {"github": {"deps": ["a", "b", "c"]}},
        }
        lock_path.write_text(json.dumps(doc), encoding="utf-8")

        result = verify(lock_path, [server], resolve=False, registry=None)

        assert result.exit_code == 1  # was 0 before R56 — CI now sees this
        assert "trees" in result.unverified_sections
        assert [item.name for item in result.unverified] == ["trees"]

    def test_default_empty_trees_and_null_tools_stub_never_fails(
        self, tmp_path: Path
    ) -> None:
        """ADR-0005 §4's MUST holds: mcp-audit's own stub is not "foreign"."""
        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        result = verify(lock_path, [server], resolve=False, registry=None)

        assert result.exit_code == 0
        assert result.unverified_sections == ["tools", "trees"]  # reported...
        assert result.unverified == []  # ...but never fails the exit code


class TestAllowUnverifiedWaiver:
    def test_allow_unverified_restores_exit_0_for_unresolved_entry(
        self, tmp_path: Path
    ) -> None:
        server = _server(args=["-y", "foo"])  # unpinned, offline at write time
        lock_path = _write_lock_for(tmp_path, [server])

        result = verify(
            lock_path, [server], resolve=False, registry=None, allow_unverified=True
        )

        assert result.exit_code == 0
        assert result.waived is True
        assert [item.name for item in result.unverified] == ["cursor/github"]

    def test_allow_unverified_restores_exit_0_for_populated_foreign_section(
        self, tmp_path: Path
    ) -> None:
        import json

        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        doc["trees"] = {"_producer": "mcp-lock-tree-gen", "_schema_version": 1}
        lock_path.write_text(json.dumps(doc), encoding="utf-8")

        result = verify(
            lock_path, [server], resolve=False, registry=None, allow_unverified=True
        )

        assert result.exit_code == 0
        assert result.waived is True

    def test_allow_unverified_does_not_waive_real_drift(self, tmp_path: Path) -> None:
        """The waiver must not hide an actual LOCK-001/002/004 finding."""
        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        drifted = _server(args=["-y", "foo@1.0.0", "--extra-flag"])
        result = verify(
            lock_path, [drifted], resolve=False, registry=None, allow_unverified=True
        )

        assert result.exit_code == 1
        assert [f.id for f in result.findings] == ["LOCK-001"]
        assert result.waived is False  # nothing to waive; drift is not waivable

    def test_allow_unverified_is_a_no_op_when_nothing_is_unverified(
        self, tmp_path: Path
    ) -> None:
        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        result = verify(
            lock_path, [server], resolve=False, registry=None, allow_unverified=True
        )

        assert result.exit_code == 0
        assert result.waived is False  # nothing was actually waived


class TestUnresolvedEntriesWarned:
    def test_unresolved_entry_is_reported_not_silently_verified(
        self, tmp_path: Path
    ) -> None:
        server = _server(args=["-y", "foo"])  # unpinned, offline=True at write time
        lock_path = _write_lock_for(tmp_path, [server])

        result = verify(lock_path, [server], resolve=False, registry=None)

        assert result.unresolved_entries == ["cursor/github"]


class TestResolveOptIn:
    def test_no_resolve_flag_never_calls_network_resolver(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(*args: object, **kwargs: object) -> str:
            raise AssertionError(
                "resolve_latest_version_info must not be called without --resolve"
            )

        monkeypatch.setattr(resolve_module, "resolve_latest_version_info", _boom)
        server = _server(args=["-y", "foo@1.0.0"])
        lock_path = _write_lock_for(tmp_path, [server])

        result = verify(lock_path, [server], resolve=False, registry=None)
        assert result.exit_code == 0

    def test_resolve_flag_flags_lock_004_on_version_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("9.9.9", None),
        )
        server = _server(args=["-y", "foo"])  # unpinned
        # Write offline so the lock records resolved_version=None (unresolved).
        doc = regenerate(None, [server], tmp_path, offline=True, registry=None)
        lock_path = tmp_path / "mcp-lock.json"
        write_lock(lock_path, doc)

        result = verify(lock_path, [server], resolve=True, registry=None)

        assert result.exit_code == 1
        assert [f.id for f in result.findings] == ["LOCK-004"]

    def test_resolve_flag_flags_lock_004_critical_on_same_version_different_hash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = _server(args=["-y", "@modelcontextprotocol/server-github@1.2.3"])
        lock_path = _write_lock_for(tmp_path, [server])

        def _fake_resolve_package(srv, *, offline, registry, existing):  # noqa: ANN001
            return {
                "ecosystem": "npm",
                "name": "@modelcontextprotocol/server-github",
                "spec_as_written": "1.2.3",
                "range_spec": False,
                "resolved_version": "1.2.3",
                "resolution": {
                    "method": "exact-pin",
                    "resolved_at": "2026-01-01T00:00:00Z",
                },
                "integrity": "sha256:different",
                "source": "registry",
            }

        monkeypatch.setattr(
            "mcp_audit.lock.verifier.resolve_package", _fake_resolve_package
        )
        # Force the locked entry to carry a *different* integrity than the fake
        # fresh one, recomputing mcp-audit's own checksum so this edit reads as
        # a legitimate re-lock rather than tampering (LOCK-005).
        import json

        from mcp_audit.lock.model import compute_checksum

        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        doc["servers"]["cursor/github"]["package"]["integrity"] = "sha256:original"
        doc["checksum"] = compute_checksum(doc)
        lock_path.write_text(json.dumps(doc), encoding="utf-8")

        result = verify(lock_path, [server], resolve=True, registry=None)

        assert result.exit_code == 1
        assert [f.id for f in result.findings] == ["LOCK-004"]
        from mcp_audit.models import Severity

        assert result.findings[0].severity == Severity.CRITICAL
