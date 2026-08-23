"""Tests for scripts/feed_diff.py.

R31: this is no longer a publish gate (R30's version skipped the commit when
unchanged, which froze `expires` and let the published feed expire). It now
only classifies *what kind* of publish this is, for the commit message.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import feed_diff  # noqa: E402

_RECORD_A_V1 = {
    "id": "x_MCPSA-aaaaaaaaaaaa",
    "schema_version": "1.6.0",
    "published": "2026-08-09T14:00:00Z",
    "modified": "2026-08-09T14:00:00Z",
    "summary": "Hardcoded secret",
    "affected": [{"package": {"ecosystem": "npm", "name": "example"}}],
}

_RECORD_A_V2_SAME_CONTENT = {
    **_RECORD_A_V1,
    "published": "2026-08-16T14:00:00Z",
    "modified": "2026-08-16T14:00:00Z",
}

_RECORD_A_V3_DIFFERENT_CONTENT = {
    **_RECORD_A_V1,
    "published": "2026-08-16T14:00:00Z",
    "modified": "2026-08-16T14:00:00Z",
    "summary": "Hardcoded secret (updated remediation)",
}

_RECORD_B = {
    "id": "x_MCPSA-bbbbbbbbbbbb",
    "schema_version": "1.6.0",
    "published": "2026-08-09T14:00:00Z",
    "modified": "2026-08-09T14:00:00Z",
    "summary": "Typosquat package",
    "affected": [{"package": {"ecosystem": "npm", "name": "other"}}],
}


def _write_feed(root: Path, records: list[dict], *, snapshot_version: int = 1) -> Path:
    feed_dir = root / "feed"
    advisories_dir = feed_dir / "advisories"
    advisories_dir.mkdir(parents=True)
    for record in records:
        (advisories_dir / f"{record['id']}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
    (feed_dir / "index.json").write_text(
        json.dumps({"snapshot_version": snapshot_version, "count": len(records)}),
        encoding="utf-8",
    )
    return feed_dir


class TestLoadAdvisoryFingerprints:
    def test_missing_directory_returns_empty(self, tmp_path: Path) -> None:
        assert feed_diff.load_advisory_fingerprints(tmp_path / "nope") == {}

    def test_strips_published_and_modified(self, tmp_path: Path) -> None:
        feed = _write_feed(tmp_path, [_RECORD_A_V1])
        fingerprints = feed_diff.load_advisory_fingerprints(feed)
        record = fingerprints["x_MCPSA-aaaaaaaaaaaa"]
        assert "published" not in record
        assert "modified" not in record
        assert record["summary"] == "Hardcoded secret"

    def test_keys_by_advisory_id(self, tmp_path: Path) -> None:
        feed = _write_feed(tmp_path, [_RECORD_A_V1, _RECORD_B])
        fingerprints = feed_diff.load_advisory_fingerprints(feed)
        assert set(fingerprints) == {"x_MCPSA-aaaaaaaaaaaa", "x_MCPSA-bbbbbbbbbbbb"}


class TestFeedsChanged:
    def test_identical_content_under_new_timestamps_is_not_a_change(
        self, tmp_path: Path
    ) -> None:
        old = _write_feed(
            tmp_path / "old", [_RECORD_A_V1, _RECORD_B], snapshot_version=3
        )
        new = _write_feed(
            tmp_path / "new",
            [_RECORD_A_V2_SAME_CONTENT, _RECORD_B],
            snapshot_version=4,
        )
        assert feed_diff.feeds_changed(old, new) is False

    def test_a_changed_field_is_a_change(self, tmp_path: Path) -> None:
        old = _write_feed(tmp_path / "old", [_RECORD_A_V1])
        new = _write_feed(tmp_path / "new", [_RECORD_A_V3_DIFFERENT_CONTENT])
        assert feed_diff.feeds_changed(old, new) is True

    def test_an_added_advisory_is_a_change(self, tmp_path: Path) -> None:
        old = _write_feed(tmp_path / "old", [_RECORD_A_V1])
        new = _write_feed(tmp_path / "new", [_RECORD_A_V2_SAME_CONTENT, _RECORD_B])
        assert feed_diff.feeds_changed(old, new) is True

    def test_a_removed_advisory_is_a_change(self, tmp_path: Path) -> None:
        old = _write_feed(tmp_path / "old", [_RECORD_A_V1, _RECORD_B])
        new = _write_feed(tmp_path / "new", [_RECORD_A_V2_SAME_CONTENT])
        assert feed_diff.feeds_changed(old, new) is True

    def test_no_previous_feed_is_a_change(self, tmp_path: Path) -> None:
        new = _write_feed(tmp_path / "new", [_RECORD_A_V1])
        assert feed_diff.feeds_changed(tmp_path / "no-such-dir", new) is True

    def test_empty_feed_to_empty_feed_is_not_a_change(self, tmp_path: Path) -> None:
        old = _write_feed(tmp_path / "old", [])
        new = _write_feed(tmp_path / "new", [], snapshot_version=2)
        assert feed_diff.feeds_changed(old, new) is False


class TestDiffSummary:
    def test_identical_content_has_all_zero_counts(self, tmp_path: Path) -> None:
        old = _write_feed(tmp_path / "old", [_RECORD_A_V1, _RECORD_B])
        new = _write_feed(tmp_path / "new", [_RECORD_A_V2_SAME_CONTENT, _RECORD_B])
        summary = feed_diff.diff_summary(old, new)
        assert (summary.added, summary.removed, summary.modified) == (0, 0, 0)
        assert summary.changed_count == 0
        assert summary.changed is False

    def test_added_removed_modified_are_counted_independently(
        self, tmp_path: Path
    ) -> None:
        old = _write_feed(tmp_path / "old", [_RECORD_A_V1, _RECORD_B])
        record_c = {**_RECORD_B, "id": "x_MCPSA-cccccccccccc"}
        new = _write_feed(tmp_path / "new", [_RECORD_A_V3_DIFFERENT_CONTENT, record_c])
        summary = feed_diff.diff_summary(old, new)
        assert summary.added == 1  # record_c
        assert summary.removed == 1  # _RECORD_B dropped
        assert summary.modified == 1  # _RECORD_A changed content
        assert summary.changed_count == 3
        assert summary.changed is True

    def test_no_previous_feed_counts_everything_as_added(self, tmp_path: Path) -> None:
        new = _write_feed(tmp_path / "new", [_RECORD_A_V1, _RECORD_B])
        summary = feed_diff.diff_summary(tmp_path / "no-such-dir", new)
        assert (summary.added, summary.removed, summary.modified) == (2, 0, 0)


class TestBuildCommitMessage:
    def test_no_content_change_wording(self) -> None:
        message = feed_diff.build_commit_message(
            snapshot_version=4, count=23, changed_count=0
        )
        assert (
            message
            == "feed: refresh expiry (snapshot 4, 23 advisories, no content change)"
        )

    def test_content_changed_wording(self) -> None:
        message = feed_diff.build_commit_message(
            snapshot_version=5, count=25, changed_count=2
        )
        assert message == "feed: 2 advisories changed (snapshot 5, 25 advisories)"


class TestReadIndex:
    def test_missing_index_returns_empty_dict(self, tmp_path: Path) -> None:
        assert feed_diff.read_index(tmp_path / "nope") == {}

    def test_reads_existing_index(self, tmp_path: Path) -> None:
        feed = _write_feed(tmp_path, [_RECORD_A_V1], snapshot_version=7)
        assert feed_diff.read_index(feed)["snapshot_version"] == 7


class TestMain:
    def test_exit_code_is_always_zero(self, tmp_path: Path) -> None:
        old = _write_feed(tmp_path / "old", [_RECORD_A_V1])
        new = _write_feed(tmp_path / "new", [_RECORD_A_V2_SAME_CONTENT])
        assert feed_diff.main(["--old", str(old), "--new", str(new)]) == 0

    def test_missing_new_index_is_an_error(self, tmp_path: Path, capsys) -> None:
        (tmp_path / "new").mkdir()
        assert (
            feed_diff.main(
                ["--old", str(tmp_path / "old"), "--new", str(tmp_path / "new")]
            )
            == 2
        )

    def test_writes_github_output_when_unchanged(self, tmp_path: Path, capsys) -> None:
        old = _write_feed(tmp_path / "old", [_RECORD_A_V1], snapshot_version=3)
        new = _write_feed(
            tmp_path / "new", [_RECORD_A_V2_SAME_CONTENT], snapshot_version=4
        )
        output_file = tmp_path / "github_output"
        output_file.write_text("", encoding="utf-8")
        feed_diff.main(
            [
                "--old",
                str(old),
                "--new",
                str(new),
                "--github-output",
                str(output_file),
            ]
        )
        contents = output_file.read_text(encoding="utf-8")
        assert "changed=false" in contents
        assert "changed_count=0" in contents
        assert "snapshot_version=4" in contents
        assert "count=1" in contents
        assert (
            "commit_message=feed: refresh expiry (snapshot 4, 1 advisories, "
            "no content change)"
        ) in contents
        assert capsys.readouterr().out.strip() == (
            "feed: refresh expiry (snapshot 4, 1 advisories, no content change)"
        )

    def test_writes_github_output_when_changed(self, tmp_path: Path, capsys) -> None:
        new = _write_feed(tmp_path / "new", [_RECORD_A_V1], snapshot_version=1)
        output_file = tmp_path / "github_output"
        output_file.write_text("", encoding="utf-8")
        feed_diff.main(
            [
                "--old",
                str(tmp_path / "no-such-dir"),
                "--new",
                str(new),
                "--github-output",
                str(output_file),
            ]
        )
        contents = output_file.read_text(encoding="utf-8")
        assert "changed=true" in contents
        assert "changed_count=1" in contents
        assert (
            "commit_message=feed: 1 advisories changed (snapshot 1, 1 advisories)"
            in contents
        )
        assert capsys.readouterr().out.strip() == (
            "feed: 1 advisories changed (snapshot 1, 1 advisories)"
        )
