"""`scan`/`check` auto-verify must agree with `lock --verify` (R60-01, R61).

These tests exist because `tests/test_lock_auto_verify.py` and
`tests/test_scan_lock_integration.py` both build their fixture lock from the
*scan's own* ``ServerConfig`` list, so the client label is identical on both
sides of the comparison by construction. The shipped defect only appears when
the lock is written by the real ``mcp-audit lock`` command and then read by
``scan``/``check``, because each entry point runs a different discovery whose
client label differs for the same file:

- ``lock``'s project walk labels ``.mcp.json`` ``claude-code``
- bare ``scan``'s cwd discovery labels the same file ``claude-code-project``
- ``scan --path <file>`` labels it ``custom``

The lock key is ``<client>/<name>``, so nothing matched and every server came
back as both ``LOCK-002`` ("not in lock") and ``LOCK-003`` ("locked server
missing") at once — `mcp-audit check` graded a correctly locked repo D and
exited 1 (R60-01, launch-blocking against v0.18.1).

Every test here therefore drives the real CLI end to end. Matching is by
**(config path relative to the lock root, server name)**; the ``client/name``
string remains the entry key in the file and in messages, but it is not part
of identity. See ``docs/decisions/ADR-0005-mcp-audit-lock.md`` (R61 addendum).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()


def _patch_no_known_clients():
    """Patch discovery so only the fixture's own configs are ever found."""
    return patch("mcp_audit.discovery._get_client_specs", return_value=[])


@contextmanager
def _in_repo(root: Path) -> Iterator[None]:
    """Run inside *root* as cwd with host client discovery suppressed."""
    import os

    previous = Path.cwd()
    os.chdir(root)
    try:
        with _patch_no_known_clients():
            yield
    finally:
        os.chdir(previous)


def _repo(tmp_path: Path) -> Path:
    """Create a git-rooted scratch repo (the lock walk is repo-bounded)."""
    (tmp_path / ".git").mkdir()
    return tmp_path


def _write_config(root: Path, relative: str, servers: dict) -> Path:
    """Write an MCP config at *relative* under *root* and return its path."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    root_key = "servers" if relative.endswith(".vscode/mcp.json") else "mcpServers"
    path.write_text(json.dumps({root_key: servers}), encoding="utf-8")
    return path


def _one_server(version: str = "1.0.0", name: str = "github") -> dict:
    return {name: {"command": "npx", "args": ["-y", f"foo@{version}"]}}


def _lock(root: Path) -> None:
    """Run the real `mcp-audit lock` (offline) against *root*."""
    result = runner.invoke(app, ["lock", str(root), "--offline"])
    assert result.exit_code == 0, result.output


def _verify(root: Path) -> int:
    result = runner.invoke(app, ["lock", str(root), "--verify"])
    return result.exit_code


def _scan_json(*args: str) -> dict:
    """Invoke `scan --format json` and return the parsed ScanResult."""
    result = runner.invoke(app, ["scan", *args, "--format", "json"])
    start = result.output.find("{")
    assert start != -1, f"no JSON in scan output:\n{result.output}"
    return json.loads(result.output[start:])


def _lock_ids(doc: dict) -> list[str]:
    """Return every LOCK-* finding id in a ScanResult document, in order."""
    return [f["id"] for f in doc.get("findings", []) if f["id"].startswith("LOCK-")]


def _check_grade(*args: str) -> str:
    """Invoke `check --json` and return the letter grade."""
    result = runner.invoke(app, ["check", *args, "--json"])
    start = result.output.find("{")
    assert start != -1, f"no JSON in check output:\n{result.output}"
    return json.loads(result.output[start:])["score"]["grade"]


# Every project-level config shape `lock`'s own walk discovers, each of which
# gets a *different* client label from `scan`'s discovery than from `lock`'s.
_PROJECT_CONFIGS = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
]


class TestLockedRepoIsCleanUnderScanAndCheck:
    """(a)/(b) — a correctly locked repo must produce zero LOCK-* findings."""

    @pytest.mark.parametrize("relative", _PROJECT_CONFIGS)
    def test_lock_verify_is_clean(self, tmp_path: Path, relative: str) -> None:
        root = _repo(tmp_path)
        _write_config(root, relative, _one_server())
        _lock(root)
        assert _verify(root) == 0

    @pytest.mark.parametrize("relative", _PROJECT_CONFIGS)
    def test_bare_scan_has_no_lock_findings(
        self, tmp_path: Path, relative: str
    ) -> None:
        root = _repo(tmp_path)
        _write_config(root, relative, _one_server())
        _lock(root)
        with _in_repo(root):
            doc = _scan_json()
        assert _lock_ids(doc) == []

    @pytest.mark.parametrize("relative", _PROJECT_CONFIGS)
    def test_scan_explicit_config_path_has_no_lock_findings(
        self, tmp_path: Path, relative: str
    ) -> None:
        root = _repo(tmp_path)
        config = _write_config(root, relative, _one_server())
        _lock(root)
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(config))
        assert _lock_ids(doc) == []

    @pytest.mark.parametrize("relative", _PROJECT_CONFIGS)
    def test_check_grade_matches_no_lock_grade(
        self, tmp_path: Path, relative: str
    ) -> None:
        """The headline R60-01 symptom: `check` graded a clean repo lower."""
        root = _repo(tmp_path)
        config = _write_config(root, relative, _one_server())
        _lock(root)
        with _patch_no_known_clients():
            with_lock = _check_grade("--path", str(config))
            without_lock = _check_grade("--path", str(config), "--no-lock")
        assert with_lock == without_lock

    def test_scan_project_has_no_lock_findings(self, tmp_path: Path) -> None:
        """`scan --project` uses a third label again (claude-code-project)."""
        root = _repo(tmp_path)
        _write_config(root, ".mcp.json", _one_server())
        _lock(root)
        with _patch_no_known_clients():
            doc = _scan_json("--project", str(root))
        assert _lock_ids(doc) == []


class TestDriftIsStillDetected:
    """(c) — fixing the false positives must not blind the real signal."""

    def test_drift_reports_exactly_one_lock_001(self, tmp_path: Path) -> None:
        root = _repo(tmp_path)
        config = _write_config(root, ".mcp.json", _one_server("1.0.0"))
        _lock(root)
        _write_config(root, ".mcp.json", _one_server("2.0.0"))
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(config))
        assert _lock_ids(doc) == ["LOCK-001"]

    def test_added_server_reports_exactly_one_lock_002(self, tmp_path: Path) -> None:
        root = _repo(tmp_path)
        config = _write_config(root, ".mcp.json", _one_server())
        _lock(root)
        _write_config(
            root,
            ".mcp.json",
            {**_one_server(), "extra": {"command": "node", "args": ["s.js"]}},
        )
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(config))
        ids = _lock_ids(doc)
        assert ids == ["LOCK-002"], ids
        added = next(f for f in doc["findings"] if f["id"] == "LOCK-002")
        assert added["server"] == "extra"

    def test_removed_server_reports_lock_003_without_failing(
        self, tmp_path: Path
    ) -> None:
        root = _repo(tmp_path)
        config = _write_config(
            root,
            ".mcp.json",
            {**_one_server(), "extra": {"command": "node", "args": ["s.js"]}},
        )
        _lock(root)
        _write_config(root, ".mcp.json", _one_server())
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(config))
        ids = _lock_ids(doc)
        assert ids == ["LOCK-003"], ids
        removed = next(f for f in doc["findings"] if f["id"] == "LOCK-003")
        assert removed["server"] == "extra"
        # LOCK-003 alone never changes the exit code (ADR-0005 §8).
        assert _verify(root) == 0


class TestMonorepo:
    """(d) — nearest-ancestor lock per config; outside a lock root is a skip."""

    def test_each_config_verifies_against_its_nearest_lock(
        self, tmp_path: Path
    ) -> None:
        root = _repo(tmp_path)
        app_a = root / "apps" / "a"
        app_b = root / "apps" / "b"
        _write_config(app_a, ".mcp.json", _one_server(name="a-server"))
        _write_config(app_b, ".mcp.json", _one_server(name="b-server"))
        _lock(app_a)
        _lock(app_b)
        assert (app_a / "mcp-lock.json").exists()
        assert (app_b / "mcp-lock.json").exists()

        with _patch_no_known_clients():
            doc = _scan_json("--path", str(app_a / ".mcp.json"))
        assert _lock_ids(doc) == []
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(app_b / ".mcp.json"))
        assert _lock_ids(doc) == []

    def test_config_outside_any_lock_root_gets_no_lock_findings(
        self, tmp_path: Path
    ) -> None:
        """A config with no lock above it must not be judged by a sibling's."""
        root = _repo(tmp_path)
        locked = root / "apps" / "locked"
        _write_config(locked, ".mcp.json", _one_server(name="locked-server"))
        _lock(locked)

        unlocked_config = _write_config(
            root / "apps" / "unlocked", ".mcp.json", _one_server(name="free-server")
        )
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(unlocked_config))
        assert _lock_ids(doc) == []


class TestLockFileIsNeverAConfig:
    """(e) — mcp-lock.json must never be ingested as an MCP config."""

    def test_discover_does_not_report_mcp_lock_json(self, tmp_path: Path) -> None:
        root = _repo(tmp_path)
        _write_config(root, ".mcp.json", _one_server())
        _lock(root)
        with _patch_no_known_clients():
            result = runner.invoke(app, ["discover", "--path", str(root)])
        assert result.exit_code == 0
        assert "mcp-lock.json" not in result.output

    def test_explicit_directory_scan_ignores_the_lock_file(
        self, tmp_path: Path
    ) -> None:
        root = _repo(tmp_path)
        _write_config(root, ".mcp.json", _one_server())
        _lock(root)
        # Put a copy where the explicit-directory *.json glob would find it.
        (root / "mcp-lock.json").replace(root / "mcp-lock.json")
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(root))
        names = [s["name"] for s in doc.get("servers", [])]
        assert not any("/" in n for n in names), names
        assert _lock_ids(doc) == []

    def test_any_json_with_lock_version_is_skipped(self, tmp_path: Path) -> None:
        """A renamed lock (or a tree generator's output) is still not a config."""
        root = _repo(tmp_path)
        _write_config(root, "real.json", _one_server())
        (root / "renamed-lock.json").write_text(
            json.dumps(
                {
                    "lock_version": 1,
                    "servers": {"cursor/ghost": {"name": "ghost", "client": "cursor"}},
                }
            ),
            encoding="utf-8",
        )
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(root))
        names = [s["name"] for s in doc.get("servers", [])]
        assert "ghost" not in names, names


class TestSameNameInTwoConfigs:
    """(f) — the pair key disambiguates one name defined in two configs."""

    def test_two_configs_same_server_name_both_verify_clean(
        self, tmp_path: Path
    ) -> None:
        root = _repo(tmp_path)
        # Both files are visible to lock's project walk *and* to a bare
        # scan's cwd discovery (which finds `.mcp.json` and `.vscode/mcp.json`
        # but not `.cursor/mcp.json` — that one is --project / lock only).
        _write_config(root, ".mcp.json", _one_server("1.0.0"))
        _write_config(root, ".vscode/mcp.json", _one_server("2.0.0"))
        _lock(root)

        doc = json.loads((root / "mcp-lock.json").read_text(encoding="utf-8"))
        assert len(doc["servers"]) == 2, list(doc["servers"])

        assert _verify(root) == 0
        with _in_repo(root):
            scanned = _scan_json()
        assert _lock_ids(scanned) == []


class TestOutsideLockRoot:
    """A config not under the lock root is skipped, never LOCK-002/003."""

    def test_verify_skips_outside_root_with_no_lock_findings(
        self, tmp_path: Path
    ) -> None:
        from mcp_audit.lock.verifier import verify
        from mcp_audit.models import ServerConfig

        root = _repo(tmp_path)
        _write_config(root, ".mcp.json", _one_server())
        _lock(root)

        outsider = tmp_path.parent / f"r61-outside-{tmp_path.name}.json"
        outsider.write_text(
            json.dumps(
                {"mcpServers": {"stranger": {"command": "node", "args": ["s.js"]}}}
            ),
            encoding="utf-8",
        )
        locked_config = root / ".mcp.json"
        try:
            result = verify(
                root / "mcp-lock.json",
                [
                    ServerConfig(
                        client="custom",
                        name="github",
                        command="npx",
                        args=["-y", "foo@1.0.0"],
                        config_path=locked_config,
                    ),
                    ServerConfig(
                        client="custom",
                        name="stranger",
                        command="node",
                        args=["s.js"],
                        config_path=outsider,
                    ),
                ],
                root=root,
            )
        finally:
            outsider.unlink(missing_ok=True)

        named = result.outside_root
        assert any(str(outsider) in p or outsider.name in p for p in named)
        assert [f.id for f in result.findings] == []


class TestRemediationHintsAreOpposite:
    """LOCK-002 and LOCK-003 must not prescribe the same command (R61 STEP 4)."""

    def test_lock_002_and_003_remediations_differ(self, tmp_path: Path) -> None:
        root = _repo(tmp_path)
        config = _write_config(root, ".mcp.json", _one_server())
        _lock(root)
        _write_config(
            root,
            ".mcp.json",
            {
                "extra": {"command": "node", "args": ["s.js"]},
            },
        )
        with _patch_no_known_clients():
            doc = _scan_json("--path", str(config))
        by_id = {f["id"]: f for f in doc["findings"] if f["id"].startswith("LOCK-")}
        assert "LOCK-002" in by_id and "LOCK-003" in by_id
        r2 = by_id["LOCK-002"]["remediation"]
        r3 = by_id["LOCK-003"]["remediation"]
        assert "mcp-audit lock" in r2
        assert "lock --accept" in r3
        assert r2 != r3
        # Opposite states must not share a single prescribed command.
        assert not (
            "mcp-audit lock`" in r2
            and "mcp-audit lock`" in r3
            and "accept" not in r2
            and "accept" not in r3
        )
