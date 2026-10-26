"""Tests for mcp_audit.registry.malicious (SC-008 data, STORY-0097). No network."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

import mcp_audit.registry.malicious as mal_mod
from mcp_audit.registry.malicious import (
    KnownMaliciousPackages,
    MaliciousRecord,
    assess,
    load_known_malicious,
)

ROOT = Path(__file__).resolve().parent.parent
BUNDLED = ROOT / "registry" / "known-malicious.json"


def _write(tmp_path: Path, entries: list, **extra: object) -> Path:
    path = tmp_path / "known-malicious.json"
    doc = {"schema_version": "1.0", "last_updated": "2026-10-25", "entries": entries}
    doc.update(extra)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _raw(
    rid: str = "MAL-2026-1",
    name: str = "evil-mcp",
    eco: str = "npm",
    versions: list[str] | None = None,
    ranges: list[list[dict]] | None = None,
    **extra: object,
) -> dict:
    entry: dict = {
        "id": rid,
        "ecosystem": eco,
        "name": name,
        "aliases": [],
        "summary": f"Malicious code in {name} ({eco})",
        "published": "2026-06-09T00:00:00Z",
        "versions": versions or [],
        "ranges": [{"type": "SEMVER", "events": ev} for ev in (ranges or [])],
    }
    entry.update(extra)
    return entry


def _record(**kwargs: object) -> MaliciousRecord:
    rec = mal_mod._parse_record(_raw(**kwargs))  # type: ignore[arg-type]
    assert rec is not None
    return rec


# ── The shipped file ──────────────────────────────────────────────────────────


class TestBundledFile:
    def test_loads_with_records_and_no_error(self) -> None:
        index = load_known_malicious()
        assert index.load_error is None
        assert len(index) > 200
        assert index.last_updated

    def test_resolves_to_the_repo_file_in_a_dev_checkout(self) -> None:
        assert load_known_malicious().source == BUNDLED.resolve()

    def test_mal_2026_5479_recorded_as_osv_states_it_with_the_canary_note(
        self,
    ) -> None:
        records = load_known_malicious().lookup("npm", "mcp-server-github")
        assert [r.id for r in records] == ["MAL-2026-5479"]
        rec = records[0]
        assert rec.aliases == ("GHSA-95pj-hrh5-27gq",)
        assert rec.summary == "Malicious code in mcp-server-github (npm)"
        assert rec.versions == ("0.0.1", "0.0.2")
        assert rec.ranges == ((("introduced", "0"),),)
        assert rec.note and "npx-canary" in rec.note
        assert "OSV states it" in rec.note

    def test_frozen_binary_layout_resolves(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PyInstaller puts the file at _MEIPASS/registry/known-malicious.json."""
        (tmp_path / "registry").mkdir()
        target = tmp_path / "registry" / "known-malicious.json"
        target.write_text(BUNDLED.read_text(encoding="utf-8"), encoding="utf-8")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
        assert mal_mod._resolve_bundled_path() == target


# ── Loader robustness ─────────────────────────────────────────────────────────


class TestLoader:
    def test_missing_file_is_empty_with_error(self, tmp_path: Path) -> None:
        index = load_known_malicious(tmp_path / "nope.json")
        assert len(index) == 0
        assert index.load_error

    def test_malformed_json_is_empty_with_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        index = load_known_malicious(path)
        assert len(index) == 0 and index.load_error

    @pytest.mark.parametrize("doc", ["[]", '{"entries": {}}', '{"x": 1}', "null"])
    def test_wrong_shape_is_empty_with_error(self, tmp_path: Path, doc: str) -> None:
        path = tmp_path / "bad.json"
        path.write_text(doc, encoding="utf-8")
        index = load_known_malicious(path)
        assert len(index) == 0 and index.load_error

    def test_bad_and_withdrawn_entries_are_skipped(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            [
                _raw("MAL-1", "a-mcp"),
                _raw("MAL-2", "b-mcp", withdrawn="2026-01-01T00:00:00Z"),
                {"id": "MAL-3"},  # no name
                _raw("MAL-4", "c-mcp", eco="Go"),  # ecosystem we don't match
                "not a dict",
                {"id": 7, "name": "x", "ecosystem": "npm"},
            ],
        )
        index = load_known_malicious(path)
        assert [r.id for r in index.records] == ["MAL-1"]
        assert index.load_error is None

    def test_oversized_file_is_refused_and_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(tmp_path, [_raw()])
        monkeypatch.setattr(mal_mod, "MAX_FILE_BYTES", 10)
        index = load_known_malicious(path)
        assert len(index) == 0
        assert "cap" in (index.load_error or "")

    def test_too_many_entries_loads_the_cap_and_reports(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(tmp_path, [_raw(f"MAL-{i}", f"m{i}-mcp") for i in range(5)])
        monkeypatch.setattr(mal_mod, "MAX_ENTRIES", 3)
        index = load_known_malicious(path)
        assert len(index) == 3
        assert "5 entries" in (index.load_error or "")

    @pytest.mark.parametrize("method", ["read_text", "stat"])
    def test_permission_error_does_not_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
    ) -> None:
        path = _write(tmp_path, [_raw()])

        def denied(self: Path, *a: object, **k: object) -> object:
            raise PermissionError(13, "Permission denied", str(self))

        monkeypatch.setattr(Path, method, denied)
        index = load_known_malicious(path)
        assert len(index) == 0
        assert "Permission denied" in (index.load_error or "")

    def test_resolve_failure_does_not_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def loop(self: Path, *a: object, **k: object) -> Path:
            raise RuntimeError("Symlink loop")

        monkeypatch.setattr(Path, "resolve", loop)
        index = load_known_malicious(tmp_path / "x.json")
        assert len(index) == 0 and index.load_error == "Symlink loop"

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privilege")
    def test_symlinked_file_is_read(self, tmp_path: Path) -> None:
        real = _write(tmp_path, [_raw()])
        link = tmp_path / "link.json"
        link.symlink_to(real)
        assert len(load_known_malicious(link)) == 1


# ── Lookup ────────────────────────────────────────────────────────────────────


class TestLookup:
    def test_ecosystems_never_cross(self) -> None:
        index = KnownMaliciousPackages(records=[_record(name="mcp-server-git")])
        assert index.lookup("npm", "mcp-server-git")
        assert index.lookup("pypi", "mcp-server-git") == []

    def test_npm_is_case_insensitive_but_not_separator_folded(self) -> None:
        index = KnownMaliciousPackages(records=[_record(name="mcp-server-git")])
        assert index.lookup("npm", "MCP-Server-Git")
        assert index.lookup("npm", "mcp_server_git") == []

    def test_pypi_uses_pep503(self) -> None:
        index = KnownMaliciousPackages(records=[_record(name="Time_MCP", eco="PyPI")])
        assert index.lookup("pypi", "time-mcp")
        assert index.lookup("pypi", "TIME.MCP")

    def test_huge_name_is_fast(self) -> None:
        index = load_known_malicious()
        start = time.monotonic()
        assert index.lookup("npm", "a" * 500_000) == []
        assert index.lookup("pypi", "-_." * 200_000) == []
        assert time.monotonic() - start < 1.0


# ── Version assessment ────────────────────────────────────────────────────────


class TestAssess:
    def test_blanket_range_covers_everything(self) -> None:
        rec = _record(versions=["0.0.1"], ranges=[[{"introduced": "0"}]])
        unpinned = assess(rec, None, curated=False)
        assert unpinned and unpinned.latest_affected and unpinned.affects_this_launch
        pinned = assess(rec, "9.9.9", curated=False)
        assert pinned and pinned.affects_this_launch
        # Even an unparsable version (npm's security placeholder).
        assert assess(rec, "0.0.1-security", curated=False)

    def test_open_range_from_a_version(self) -> None:
        """postmark-mcp: malicious from 1.0.16 on (MAL-2025-47604)."""
        rec = _record(ranges=[[{"introduced": "1.0.16"}]])
        assert assess(rec, "1.0.15", curated=False) is None
        hit = assess(rec, "1.0.16", curated=False)
        assert hit and hit.pinned == "1.0.16"
        assert assess(rec, "2.0.0", curated=False)
        unpinned = assess(rec, None, curated=False)
        assert unpinned and unpinned.latest_affected

    def test_bounded_ranges(self) -> None:
        fixed = _record(ranges=[[{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]])
        assert assess(fixed, "1.1.9", curated=False)
        assert assess(fixed, "1.2.0", curated=False) is None
        assert assess(fixed, "0.9.0", curated=False) is None
        last = _record(ranges=[[{"introduced": "0"}, {"last_affected": "1.2.0"}]])
        assert assess(last, "1.2.0", curated=False)
        assert assess(last, "1.2.1", curated=False) is None
        unpinned = assess(fixed, None, curated=False)
        assert unpinned and not unpinned.latest_affected

    def test_explicit_versions_only(self) -> None:
        """mcp-use: two compromised releases (MAL-2025-190923)."""
        rec = _record(versions=["1.4.2", "1.4.3"])
        assert assess(rec, "1.4.2", curated=False)
        assert assess(rec, "1.4.4", curated=False) is None
        unpinned = assess(rec, None, curated=False)
        assert unpinned and not unpinned.latest_affected
        assert not unpinned.affects_this_launch

    def test_pypi_version_equality_is_pep440(self) -> None:
        rec = _record(eco="PyPI", versions=["1.0"])
        assert assess(rec, "1.0.0", curated=False)

    def test_unparsable_pinned_version_is_treated_as_covered(self) -> None:
        rec = _record(ranges=[[{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]])
        assert assess(rec, "not.a.version!", curated=False)

    def test_curated_package_drops_a_blanket_range_beside_a_version_list(
        self,
    ) -> None:
        """@browserbasehq/mcp: GHSA's blanket range next to versions ['2.1.1']."""
        rec = _record(versions=["2.1.1"], ranges=[[{"introduced": "0"}]])
        unpinned = assess(rec, None, curated=True)
        assert unpinned and not unpinned.latest_affected
        assert unpinned.blanket_range_ignored
        assert assess(rec, "2.1.1", curated=True)
        assert assess(rec, "3.0.0", curated=True) is None
        # Not curated: OSV's statement stands.
        assert assess(rec, "3.0.0", curated=False)

    def test_curated_package_keeps_a_blanket_range_with_no_version_list(
        self,
    ) -> None:
        rec = _record(ranges=[[{"introduced": "0"}]])
        hit = assess(rec, "3.0.0", curated=True)
        assert hit and not hit.blanket_range_ignored

    def test_record_with_no_affected_data_matches_nothing(self) -> None:
        rec = _record()
        assert assess(rec, None, curated=False) is None
        assert assess(rec, "1.0.0", curated=False) is None

    def test_link(self) -> None:
        assert _record(rid="MAL-2026-5479").link == (
            "https://osv.dev/vulnerability/MAL-2026-5479"
        )
