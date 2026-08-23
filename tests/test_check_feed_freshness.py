"""Tests for scripts/check_feed_freshness.py (R31 STEP 4 canary).

No network: ``check()`` is pure and takes an injected ``now``; ``main()``
tests monkeypatch ``fetch_index`` rather than hitting the real URL.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_feed_freshness as canary  # noqa: E402


class TestCheck:
    def test_fresh_feed_passes(self) -> None:
        index = {"expires": "2026-09-06T15:05:12Z", "snapshot_version": 4}
        now = datetime(2026, 8, 23, 15, 5, 12, tzinfo=UTC)  # 14 days of headroom
        assert canary.check(index, now=now, margin_days=7) is None

    def test_less_than_one_interval_of_headroom_fails(self) -> None:
        index = {"expires": "2026-09-06T15:05:12Z", "snapshot_version": 4}
        now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=UTC)  # ~5.6 days left
        failure = canary.check(index, now=now, margin_days=7)
        assert failure is not None
        assert "2026-09-06T15:05:12Z" in failure
        assert "publish interval" in failure

    def test_exactly_one_interval_of_headroom_passes(self) -> None:
        # The spec is "less than one interval away" fails; exactly one
        # interval is still fine — it is the instant the next scheduled
        # publish is due, not yet overdue.
        index = {"expires": "2026-09-06T00:00:00Z", "snapshot_version": 1}
        now = datetime(2026, 8, 30, 0, 0, 0, tzinfo=UTC)  # exactly 7 days
        assert canary.check(index, now=now, margin_days=7) is None

    def test_just_under_one_interval_of_headroom_fails(self) -> None:
        index = {"expires": "2026-09-06T00:00:00Z", "snapshot_version": 1}
        now = datetime(2026, 8, 30, 0, 0, 1, tzinfo=UTC)  # 7 days minus 1 second
        assert canary.check(index, now=now, margin_days=7) is not None

    def test_already_expired_fails(self) -> None:
        index = {"expires": "2026-08-09T00:00:00Z", "snapshot_version": 1}
        now = datetime(2026, 8, 23, 0, 0, 0, tzinfo=UTC)
        failure = canary.check(index, now=now, margin_days=7)
        assert failure is not None

    def test_missing_expires_fails(self) -> None:
        failure = canary.check(
            {"snapshot_version": 1}, now=datetime.now(UTC), margin_days=7
        )
        assert failure is not None
        assert "no expires field" in failure

    def test_unparseable_expires_fails(self) -> None:
        failure = canary.check(
            {"expires": "not-a-date"}, now=datetime.now(UTC), margin_days=7
        )
        assert failure is not None
        assert "not RFC 3339" in failure

    def test_custom_margin_is_honoured(self) -> None:
        index = {"expires": "2026-09-06T00:00:00Z", "snapshot_version": 1}
        now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=UTC)  # 5 days left
        assert canary.check(index, now=now, margin_days=3) is None
        assert canary.check(index, now=now, margin_days=7) is not None


class TestMain:
    def test_ok_returns_zero(self, monkeypatch) -> None:
        monkeypatch.setattr(
            canary,
            "fetch_index",
            lambda url: {"expires": "2026-09-06T00:00:00Z", "snapshot_version": 4},
        )
        monkeypatch.setattr(
            canary, "_now", lambda: datetime(2026, 8, 23, 0, 0, 0, tzinfo=UTC)
        )
        assert canary.main([]) == 0

    def test_stale_returns_one(self, monkeypatch) -> None:
        monkeypatch.setattr(
            canary,
            "fetch_index",
            lambda url: {"expires": "2026-08-09T00:00:00Z", "snapshot_version": 1},
        )
        monkeypatch.setattr(
            canary, "_now", lambda: datetime(2026, 8, 23, 0, 0, 0, tzinfo=UTC)
        )
        assert canary.main([]) == 1

    def test_rejects_non_raw_githubusercontent_url(self) -> None:
        assert canary.main(["--url", "https://mcp-audit.dev/feed/index.json"]) == 2

    def test_rejects_non_https_scheme(self) -> None:
        assert (
            canary.main(
                [
                    "--url",
                    "http://raw.githubusercontent.com/adudley78/mcp-audit/feed/index.json",
                ]
            )
            == 2
        )
