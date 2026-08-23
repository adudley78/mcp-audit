"""Adversarial tests for advisory-feed freshness (rollback + expiry)."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

from mcp_audit.advisory.feed import FEED_VERSION, build_advisories, write_feed
from mcp_audit.advisory.freshness import (
    FreshnessError,
    check_expiry,
    identity_key,
    load_seen,
    parse_freshness,
)
from mcp_audit.advisory.sign import (
    SigningConfig,
    SigningError,
    canonical_bytes_for,
    sign_feed,
    verify_feed,
)
from mcp_audit.cli import app
from mcp_audit.cli.scan import _apply_advisory_feed
from mcp_audit.models import ScanResult
from tests.test_advisory_feed import FIXED_NOW, _scan_result

HAS_MINISIGN = shutil.which("minisign") is not None
needs_minisign = pytest.mark.skipif(
    not HAS_MINISIGN, reason="minisign is not installed"
)

FAR_FUTURE = "2099-01-01T00:00:00Z"
NOW = datetime(2026, 2, 1, tzinfo=UTC)

runner = CliRunner()


@pytest.fixture(scope="module")
def minisign_keys(tmp_path_factory) -> tuple[Path, Path]:
    directory = tmp_path_factory.mktemp("freshness-minisign")
    private, public = directory / "ms.key", directory / "ms.pub"
    subprocess.run(  # noqa: S603
        [shutil.which("minisign"), "-G", "-W", "-p", str(public), "-s", str(private)],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return private, public


@pytest.fixture
def minisign_config(minisign_keys) -> SigningConfig:
    private, public = minisign_keys
    return SigningConfig(backend="minisign", private_key=private, public_key=public)


@pytest.fixture(autouse=True)
def _isolate_feed_seen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mcp_audit.advisory.freshness.default_seen_path",
        lambda: tmp_path / "feed-seen.json",
    )


def _advisories():
    return build_advisories(_scan_result(), now=FIXED_NOW).advisories


def _write(
    path: Path,
    *,
    snapshot_version: int = 1,
    expires: str = FAR_FUTURE,
    published_at: str = FIXED_NOW,
) -> Path:
    write_feed(
        _advisories(),
        path,
        published_at=published_at,
        snapshot_version=snapshot_version,
        expires=expires,
    )
    return path


class TestIndexFreshnessFields:
    def test_feed_version_is_1_1(self) -> None:
        assert FEED_VERSION == "1.1"

    def test_freshness_fields_live_on_the_index_only(self, tmp_path: Path) -> None:
        manifest_dir = _write(tmp_path / "feed")
        index = json.loads((manifest_dir / "index.json").read_text(encoding="utf-8"))
        assert index["snapshot_version"] == 1
        assert index["published_at"] == FIXED_NOW
        assert index["expires"] == FAR_FUTURE
        advisory = json.loads(
            next((manifest_dir / "advisories").glob("*.json")).read_text(
                encoding="utf-8"
            )
        )
        assert "snapshot_version" not in advisory
        assert "expires" not in advisory
        assert "published_at" not in advisory


class TestParseFreshnessFailClosed:
    def test_missing_snapshot_version_is_refused(self) -> None:
        with pytest.raises(FreshnessError, match="snapshot_version"):
            parse_freshness({"expires": FAR_FUTURE, "published_at": FIXED_NOW})

    def test_missing_expires_is_refused(self) -> None:
        with pytest.raises(FreshnessError, match="expires"):
            parse_freshness({"snapshot_version": 1, "published_at": FIXED_NOW})

    def test_garbage_snapshot_version_is_refused(self) -> None:
        with pytest.raises(FreshnessError, match="snapshot_version"):
            parse_freshness(
                {
                    "snapshot_version": "1",
                    "expires": FAR_FUTURE,
                    "published_at": FIXED_NOW,
                }
            )


class TestExpiryMessageIncludesClientClock:
    def test_message_prints_expiry_and_now(self) -> None:
        freshness = parse_freshness(
            {
                "snapshot_version": 1,
                "published_at": "2026-01-18T00:00:00Z",
                "expires": "2026-02-01T00:00:00Z",
            }
        )
        with pytest.raises(
            FreshnessError, match="current time is 2026-02-02T00:00:00Z"
        ):
            check_expiry(freshness, datetime(2026, 2, 2, tzinfo=UTC))
        try:
            check_expiry(freshness, datetime(2026, 2, 2, tzinfo=UTC))
        except FreshnessError as exc:
            assert "this feed expired on 2026-02-01T00:00:00Z" in str(exc)


@needs_minisign
class TestVerifyFreshness:
    def test_first_run_with_no_state_is_accepted_and_recorded(
        self, tmp_path: Path, minisign_config: SigningConfig
    ) -> None:
        feed = _write(tmp_path / "feed")
        sign_feed(feed, minisign_config)
        seen = tmp_path / "seen.json"
        report = verify_feed(feed, minisign_config, now=NOW, state_path=seen)
        assert report.ok
        key = identity_key(
            json.loads((feed / "index.json").read_text(encoding="utf-8"))
        )
        assert load_seen(seen)[key] == 1

    def test_replay_of_an_older_version_is_refused(
        self, tmp_path: Path, minisign_config: SigningConfig
    ) -> None:
        seen = tmp_path / "seen.json"
        newer = _write(tmp_path / "new", snapshot_version=2)
        older = _write(tmp_path / "old", snapshot_version=1)
        sign_feed(newer, minisign_config)
        sign_feed(older, minisign_config)
        assert verify_feed(newer, minisign_config, now=NOW, state_path=seen).ok
        report = verify_feed(older, minisign_config, now=NOW, state_path=seen)
        assert not report.ok
        assert any(
            "older than one you have already seen" in failure
            for failure in report.failures
        )

    def test_signed_but_expired_is_refused_with_clock(
        self, tmp_path: Path, minisign_config: SigningConfig
    ) -> None:
        feed = _write(
            tmp_path / "feed",
            published_at="2026-01-18T00:00:00Z",
            expires="2026-02-01T00:00:00Z",
        )
        sign_feed(feed, minisign_config)
        later = datetime(2026, 2, 2, tzinfo=UTC)
        report = verify_feed(
            feed, minisign_config, now=later, state_path=tmp_path / "seen.json"
        )
        assert not report.ok
        blob = " ".join(report.failures)
        assert "this feed expired on 2026-02-01T00:00:00Z" in blob
        assert "current time is 2026-02-02T00:00:00Z" in blob

    def test_counter_without_expires_is_refused(
        self, tmp_path: Path, minisign_config: SigningConfig
    ) -> None:
        feed = _write(tmp_path / "feed")
        sign_feed(feed, minisign_config)
        index_path = feed / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        del index["expires"]
        index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        report = verify_feed(
            feed, minisign_config, now=NOW, state_path=tmp_path / "seen.json"
        )
        assert not report.ok
        assert any("expires" in failure for failure in report.failures)

    def test_expires_without_counter_is_refused(
        self, tmp_path: Path, minisign_config: SigningConfig
    ) -> None:
        feed = _write(tmp_path / "feed")
        sign_feed(feed, minisign_config)
        index_path = feed / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        del index["snapshot_version"]
        index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        report = verify_feed(
            feed, minisign_config, now=NOW, state_path=tmp_path / "seen.json"
        )
        assert not report.ok
        assert any("snapshot_version" in failure for failure in report.failures)

    def test_stateless_client_accepts_stale_but_unexpired_snapshot(
        self, tmp_path: Path, minisign_config: SigningConfig
    ) -> None:
        """Residual gap: no prior state + unexpired signed snapshot is accepted.

        A client that has never verified this identity will take last week's
        still-unexpired snapshot. TTL is the only lever. Documented in
        docs/advisory-feed.md in these words.
        """
        feed = _write(
            tmp_path / "feed",
            published_at="2026-01-20T00:00:00Z",
            expires="2026-02-03T00:00:00Z",
            snapshot_version=1,
        )
        sign_feed(feed, minisign_config)
        report = verify_feed(
            feed,
            minisign_config,
            now=datetime(2026, 2, 1, tzinfo=UTC),
            state_path=tmp_path / "unseen.json",
        )
        assert report.ok
        assert report.age_days == 12


class TestNestedJsonRefusesCleanly:
    def test_canonical_bytes_for_deeply_nested_document(self, tmp_path: Path) -> None:
        bomb: dict = {}
        cursor = bomb
        for _ in range(80):
            cursor["n"] = {}
            cursor = cursor["n"]
        path = tmp_path / "hostile.json"
        path.write_text(json.dumps(bomb), encoding="utf-8")
        with pytest.raises(SigningError, match="nested too deeply"):
            canonical_bytes_for(path)

    def test_feed_verify_cli_does_not_traceback(self, tmp_path: Path) -> None:
        feed = _write(tmp_path / "feed")
        target = next((feed / "advisories").glob("*.json"))
        record = json.loads(target.read_text(encoding="utf-8"))
        bomb: dict = {}
        cursor = bomb
        for _ in range(80):
            cursor["n"] = {}
            cursor = cursor["n"]
        record["bomb"] = bomb
        target.write_text(json.dumps(record), encoding="utf-8")
        result = runner.invoke(app, ["feed", "verify", str(feed)])
        assert result.exit_code == 1
        assert "Traceback" not in result.output
        assert "nested too deeply" in result.output


class TestScanDoesNotFailOnExpiredFeed:
    def test_apply_skips_matching_and_sets_expired(self, tmp_path: Path) -> None:
        feed = _write(
            tmp_path / "feed",
            published_at="2026-01-01T00:00:00Z",
            expires="2026-01-15T00:00:00Z",
        )
        buf = io.StringIO()
        result = _apply_advisory_feed(
            ScanResult(), feed, Console(file=buf, force_terminal=True)
        )
        assert result.feed_status.state == "expired"
        text = " ".join(buf.getvalue().split())
        assert "known-CVE matching was skipped" in text

    def test_scan_cli_completes_with_expired_feed_status(self, tmp_path: Path) -> None:
        feed = _write(
            tmp_path / "feed",
            published_at="2026-01-01T00:00:00Z",
            expires="2026-01-15T00:00:00Z",
        )
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        out = tmp_path / "scan.json"
        with patch("mcp_audit.cli.run_scan", return_value=ScanResult()):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--advisory-feed",
                    str(feed),
                    "--format",
                    "json",
                    "--output-file",
                    str(out),
                ],
            )
        assert result.exit_code in {0, 1}
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["feed_status"]["state"] == "expired"

    def test_missing_feed_directory_exits_2(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with patch("mcp_audit.cli.run_scan", return_value=ScanResult()):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--advisory-feed",
                    str(tmp_path / "absent"),
                ],
            )
        assert result.exit_code == 2
        assert "Advisory feed not found" in result.output
