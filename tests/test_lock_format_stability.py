"""The promises of docs/lock-format.md, checked against a lock that 0.34.0 wrote.

`tests/fixtures/lock_v2_frozen/mcp-lock.json` is never rewritten. It was
written by Credenzo 0.34.0 over the project of `tests/fixtures/lock_v1_corpus`
with that corpus's mocked registry. If a change makes one of these tests
fail, the change breaks a promise: fix the change, not the fixture.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit._jcs import canonicalize
from mcp_audit.cli import app
from mcp_audit.lock.core import (
    LOCK_VERSION,
    SUPPORTED_LOCK_VERSIONS,
    index_locked_entries,
)

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "tests" / "fixtures" / "lock_v2_frozen" / "mcp-lock.json"
DOC = (ROOT / "docs" / "lock-format.md").read_text(encoding="utf-8")
CORPUS = ROOT / "tests" / "fixtures" / "lock_v1_corpus"

_spec = importlib.util.spec_from_file_location("lock_v1_corpus", CORPUS / "generate.py")
corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus)
runner = CliRunner()

#: The names docs/lock-format.md freezes, by where they are in the file.
FROZEN_NAMES: dict[str, set[str]] = {
    "top": {
        "lock_version",
        "generated_by",
        "generated_at",
        "servers",
        "trees",
        "tools",
        "section_digests",
        "checksum",
    },
    "entry": {
        "client",
        "name",
        "config",
        "identity",
        "package",
        "env_keys",
        "header_keys",
        "capabilities",
        "first_locked",
        "hashes",
    },
    "identity": {"command", "args", "url"},
    "package": {
        "ecosystem",
        "name",
        "spec_as_written",
        "range_spec",
        "resolved_version",
        "resolution",
        "integrity",
        "source",
        "deprecated",
    },
    "resolution": {"method", "resolved_at", "resolution_context"},
    "hashes": {"command", "args", "env_keys", "raw"},
}


def _names(doc: dict) -> dict[str, set[str]]:
    entries = list(doc["servers"].values())
    packages = [e["package"] for e in entries if e.get("package")]
    return {
        "top": set(doc),
        "entry": {k for e in entries for k in e},
        "identity": {k for e in entries for k in e.get("identity") or {}},
        "package": {k for p in packages for k in p},
        "resolution": {k for p in packages for k in p["resolution"]},
        "hashes": {k for e in entries for k in e.get("hashes") or {}},
    }


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = corpus.copy_project(tmp_path)
    shutil.copyfile(FROZEN, root / "mcp-lock.json")
    return root


def _verify(root: Path) -> tuple[int, dict]:
    result = runner.invoke(app, ["lock", str(root), "--verify", "--format", "json"])
    return result.exit_code, json.loads(result.stdout[result.stdout.index("{") :])


def test_the_fixture_is_the_lock_that_0_34_0_wrote() -> None:
    doc = json.loads(FROZEN.read_text(encoding="utf-8"))
    assert (doc["lock_version"], doc["generated_by"]) == (2, "mcp-audit/0.34.0")
    assert len(doc["servers"]) == 25
    assert _names(doc) == FROZEN_NAMES


def test_promise_1_the_frozen_lock_still_verifies(project: Path) -> None:
    code, payload = _verify(project)
    assert code == 0
    assert payload["checked_servers"] == 25
    assert payload["findings"] == []
    assert payload["unverified"] == []


def test_promise_1_no_supported_version_is_dropped() -> None:
    assert {1, 2} <= SUPPORTED_LOCK_VERSIONS
    assert LOCK_VERSION in SUPPORTED_LOCK_VERSIONS


def test_promise_2_and_3_the_current_code_writes_every_frozen_name(
    tmp_path: Path,
) -> None:
    root = corpus.copy_project(tmp_path)
    with corpus.patched_registry("locked"):
        assert runner.invoke(app, ["lock", str(root)]).exit_code == 0
    written = _names(json.loads((root / "mcp-lock.json").read_text(encoding="utf-8")))
    for where, names in FROZEN_NAMES.items():
        assert sorted(names - written[where]) == [], where


def test_promise_3_a_relock_keeps_what_was_approved(project: Path) -> None:
    """`lock --accept` on an unchanged project changes no approval record."""
    before = json.loads(FROZEN.read_text(encoding="utf-8"))["servers"]
    with corpus.patched_registry("locked"):
        assert runner.invoke(app, ["lock", str(project), "--accept"]).exit_code == 0
    after = json.loads((project / "mcp-lock.json").read_text(encoding="utf-8"))
    assert set(after["servers"]) == set(before)
    for key, entry in before.items():
        now = after["servers"][key]
        for name in ("identity", "env_keys", "header_keys", "first_locked", "hashes"):
            assert now[name] == entry[name], (key, name)
        if entry.get("package"):
            for name in ("ecosystem", "name", "resolved_version", "integrity"):
                assert now["package"][name] == entry["package"][name], (key, name)


def test_promise_5_the_frozen_file_is_canonical_json() -> None:
    raw = FROZEN.read_bytes()
    assert canonicalize(json.loads(raw)) == raw


def test_promise_6_the_digests_are_recomputed_the_same_way() -> None:
    doc = json.loads(FROZEN.read_text(encoding="utf-8"))

    def digest(value: object) -> str:
        return "sha256:" + hashlib.sha256(canonicalize(value)).hexdigest()

    owned = {k: doc[k] for k in ("lock_version", "generated_by", "servers")}
    assert doc["checksum"] == digest(owned)
    assert doc["section_digests"] == {"servers": digest(doc["servers"])}


def test_promise_8_a_changed_server_is_exit_1_and_a_damaged_lock_is_exit_2(
    project: Path,
) -> None:
    config = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
    config["mcpServers"]["added-after-the-lock"] = {"command": "node", "args": ["x"]}
    (project / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    code, payload = _verify(project)
    assert code == 1
    assert [f["id"] for f in payload["findings"]] == ["LOCK-002"]

    lock = project / "mcp-lock.json"
    lock.write_bytes(lock.read_bytes().replace(b'"npx"', b'"npy"', 1))
    code, payload = _verify(project)
    assert code == 2
    assert [f["id"] for f in payload["findings"]] == ["LOCK-005"]


def test_promise_9_the_reader_of_run_and_guard_reads_the_frozen_lock() -> None:
    doc = json.loads(FROZEN.read_text(encoding="utf-8"))
    assert len(index_locked_entries(doc["servers"])) == 25


def test_the_page_names_every_frozen_name() -> None:
    for names in FROZEN_NAMES.values():
        for name in names:
            assert f"`{name}`" in DOC, name


def test_the_lock_page_no_longer_says_experimental() -> None:
    lock_page = (ROOT / "docs" / "lock.md").read_text(encoding="utf-8")
    assert "EXPERIMENTAL" not in lock_page
    assert "lock-format.md" in lock_page
    gaps = (ROOT / "GAPS.md").read_text(encoding="utf-8")
    assert "digest field name is provisional" not in gaps
    assert "may be renamed before release" not in gaps
