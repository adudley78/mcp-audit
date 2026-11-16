"""Tests for scripts/drift_compare.py (the weekly drift index record)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "drift_compare.py"
SNAPSHOT_SCRIPT = Path(__file__).parent.parent / "scripts" / "drift_snapshot.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load(SCRIPT, "drift_compare")
ds = _load(SNAPSHOT_SCRIPT, "drift_snapshot")


def _dig(contract: str, definition: str) -> dict[str, str]:
    return {"contract": f"sha256:{contract}", "definition": f"sha256:{definition}"}


def _row(package: str, version: str, digests: dict | None, kind: str = "npm") -> dict:
    return {
        "type": kind,
        "package": package,
        "version": version,
        "connected": bool(digests),
        "error": None if digests else "install failed",
        "tool_count": len(digests or {}),
        "digests": digests or {},
    }


def _snap(label: str, rows: list[dict]) -> dict:
    return {"label": label, "pairs": len(rows), "tool": "mcp-audit 0.0.0", "rows": rows}


def test_unchanged_server_with_same_version_is_not_a_change() -> None:
    tools = {"read": _dig("a", "b")}
    out = dc.compare(
        _snap("d1", [_row("p", "1.0", tools)]), _snap("d2", [_row("p", "1.0", tools)])
    )
    assert (out["compared"], out["changed"], out["bumped"]) == (1, 0, 0)
    assert out["rows"] == []


def test_added_removed_text_and_contract_changes_are_told_apart() -> None:
    old = _snap(
        "d1",
        [
            _row("adds", "1.0", {"a": _dig("1", "1")}),
            _row("removes", "1.0", {"a": _dig("1", "1"), "b": _dig("2", "2")}),
            _row("text", "1.0", {"a": _dig("1", "1")}),
            _row("schema", "1.0", {"a": _dig("1", "1")}),
            _row("quiet-bump", "1.0", {"a": _dig("1", "1")}),
        ],
    )
    new = _snap(
        "d2",
        [
            _row("adds", "1.1", {"a": _dig("1", "1"), "b": _dig("2", "2")}),
            _row("removes", "1.1", {"a": _dig("1", "1")}),
            _row("text", "1.0", {"a": _dig("1", "9")}),
            _row("schema", "2.0", {"a": _dig("9", "9")}),
            _row("quiet-bump", "1.1", {"a": _dig("1", "1")}),
        ],
    )
    out = dc.compare(old, new)
    rows = {r["package"]: r for r in out["rows"]}
    assert rows["adds"]["added"] == ["b"] and rows["removes"]["removed"] == ["b"]
    assert rows["text"]["definition_changed"] == ["a"]
    assert rows["text"]["contract_changed"] == []
    assert rows["schema"]["contract_changed"] == ["a"]
    assert (
        rows["quiet-bump"]["changed"] is False and rows["quiet-bump"]["bumped"] is True
    )
    assert out["compared"] == 5 and out["changed"] == 4 and out["changed_pct"] == 80.0
    assert out["changed_with_bump"] == 3 and out["changed_without_bump"] == 1
    assert out["bumped_unchanged"] == 1
    assert out["tool_added_or_removed"] == 2 and out["text_only"] == 1


def test_a_server_that_did_not_connect_on_both_dates_is_not_compared() -> None:
    tools = {"a": _dig("1", "1")}
    old = _snap(
        "d1",
        [
            _row("gone", "1.0", tools),
            _row("new", "1.0", None),
            _row("pkg", "1", tools, "pypi"),
        ],
    )
    new = _snap(
        "d2",
        [
            _row("gone", "1.1", None),
            _row("new", "1.0", tools),
            _row("pkg", "1", tools, "npm"),
        ],
    )
    out = dc.compare(old, new)
    assert out["compared"] == 0 and out["changed_pct"] is None
    assert (out["connected_from"], out["connected_to"]) == (2, 2)


def test_same_name_in_two_registries_is_two_servers() -> None:
    old = _snap(
        "d1",
        [
            _row("x", "1", {"a": _dig("1", "1")}),
            _row("x", "1", {"a": _dig("1", "1")}, "pypi"),
        ],
    )
    new = _snap(
        "d2",
        [
            _row("x", "1", {"a": _dig("1", "1")}),
            _row("x", "2", {"a": _dig("1", "2")}, "pypi"),
        ],
    )
    out = dc.compare(old, new)
    assert (
        out["by_type"]["npm"]["changed"] == 0 and out["by_type"]["pypi"]["changed"] == 1
    )


def test_cli_writes_the_record_and_fails_a_run_that_compared_too_few(
    tmp_path: Path,
) -> None:
    tools = {"a": _dig("1", "1")}
    older, newer, out = (
        tmp_path / "o.json",
        tmp_path / "n.json",
        tmp_path / "idx" / "r.json",
    )
    older.write_text(json.dumps({"rows": [_row("p", "1", tools)]}))
    newer.write_text(
        json.dumps(_snap("2026-11-23", [_row("p", "2", {"a": _dig("1", "2")})]))
    )
    assert (
        dc.main(
            [str(older), str(newer), "--out", str(out), "--from-label", "2026-11-16"]
        )
        == 0
    )
    record = json.loads(out.read_text())
    assert (record["from"], record["to"], record["changed"]) == (
        "2026-11-16",
        "2026-11-23",
        1,
    )
    assert (
        dc.main([str(older), str(newer), "--out", str(out), "--min-compared", "5"]) == 1
    )
    older.write_text("[]")
    assert dc.main([str(older), str(newer), "--out", str(out)]) == 2


@pytest.mark.parametrize(
    ("kind", "name", "version", "ok"),
    [
        ("npm", "@scope/pkg-name", "1.2.3", True),
        ("npm", "chrome-devtools-mcp", "1.13.0-beta.1", True),
        ("pypi", "mcp_server.fetch", "2026.11.11", True),
        ("npm", "--registry=http://evil", "1.0.0", False),
        ("npm", "pkg", "-rf", False),
        ("npm", "../../etc", "1.0.0", False),
        ("npm", "Pkg", "1.0.0", False),
        ("pypi", "pkg; rm -rf /", "1.0", False),
        ("pypi", "pkg", "1.0 --index-url=http://evil", False),
        ("gem", "pkg", "1.0", False),
    ],
)
def test_snapshot_accepts_only_plain_registry_names(
    kind: str, name: str, version: str, ok: bool
) -> None:
    assert ds.valid_pair(kind, name, version) is ok


def test_snapshot_slug_never_holds_a_path_separator() -> None:
    assert "/" not in ds.slug("npm", "@scope/name", "1.0.0")
