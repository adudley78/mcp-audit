"""Tests for `mcp-audit advise` and `mcp-audit feed verify`."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.advisory.validate import validate_osv
from mcp_audit.cli import app
from mcp_audit.cli.advise import ENV_SOURCE_DATE_EPOCH, _resolve_now

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "fixtures" / "vulnerable-servers"

# 2026-01-31T00:00:00Z — pinned so every assertion below is reproducible.
EPOCH = "1769817600"
EPOCH_ISO = "2026-01-31T00:00:00Z"

HAS_MINISIGN = shutil.which("minisign") is not None
needs_minisign = pytest.mark.skipif(
    not HAS_MINISIGN, reason="minisign is not installed"
)


@pytest.fixture
def minisign_keys(tmp_path_factory) -> tuple[Path, Path]:
    directory = tmp_path_factory.mktemp("cli-minisign")
    private, public = directory / "ms.key", directory / "ms.pub"
    subprocess.run(  # noqa: S603
        [shutil.which("minisign"), "-G", "-W", "-p", str(public), "-s", str(private)],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return private, public


def _advise(*args: str, env: dict[str, str] | None = None):
    return runner.invoke(
        app,
        ["advise", *args],
        env={ENV_SOURCE_DATE_EPOCH: EPOCH, **(env or {})},
    )


# ── Timestamp resolution ──────────────────────────────────────────────────────


class TestTimestampResolution:
    def test_explicit_timestamp_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_SOURCE_DATE_EPOCH, EPOCH)
        assert _resolve_now("2030-06-01T09:30:00Z") == "2030-06-01T09:30:00Z"

    def test_source_date_epoch_is_honoured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reproducible-builds convention: rebuild the feed, get the same bytes."""
        monkeypatch.setenv(ENV_SOURCE_DATE_EPOCH, EPOCH)
        assert _resolve_now(None) == EPOCH_ISO

    def test_falls_back_to_wall_clock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV_SOURCE_DATE_EPOCH, raising=False)
        assert _resolve_now(None).endswith("Z")

    def test_malformed_timestamp_is_rejected(self) -> None:
        result = _advise(str(FIXTURES), "--published-at", "yesterday", "--no-sign")
        assert result.exit_code != 0

    def test_malformed_epoch_is_rejected(self) -> None:
        result = _advise(
            str(FIXTURES), "--no-sign", env={ENV_SOURCE_DATE_EPOCH: "soon"}
        )
        assert result.exit_code != 0


# ── advise ────────────────────────────────────────────────────────────────────


class TestAdvise:
    def test_writes_a_feed_from_the_fixture_servers(self, tmp_path: Path) -> None:
        result = _advise(str(FIXTURES), "--out", str(tmp_path / "feed"), "--no-sign")
        assert result.exit_code == 0, result.output

        feed = tmp_path / "feed"
        assert (feed / "index.json").is_file()
        assert (feed / "osv" / "all.json").is_file()
        assert (feed / "osv" / "all.zip").is_file()
        assert list((feed / "advisories").glob("*.json"))

    def test_every_published_record_validates_against_osv(self, tmp_path: Path) -> None:
        _advise(str(FIXTURES), "--out", str(tmp_path / "feed"), "--no-sign")
        for path in (tmp_path / "feed" / "advisories").glob("*.json"):
            validate_osv(json.loads(path.read_text(encoding="utf-8")))

    def test_covers_the_three_remediable_finding_classes(self, tmp_path: Path) -> None:
        """The fixtures exist to prove each `fix` class produces a real advisory."""
        _advise(str(FIXTURES), "--out", str(tmp_path / "feed"), "--no-sign")
        classes = {
            json.loads(p.read_text(encoding="utf-8"))["affected"][0][
                "database_specific"
            ]["finding_class"]
            for p in (tmp_path / "feed" / "advisories").glob("*.json")
        }
        assert {"hardcoded-secret", "command-injection", "excessive-scope"} <= classes

    def test_flags_the_typosquatted_package(self, tmp_path: Path) -> None:
        _advise(str(FIXTURES), "--out", str(tmp_path / "feed"), "--no-sign")
        records = json.loads(
            (tmp_path / "feed" / "osv" / "all.json").read_text(encoding="utf-8")
        )
        typosquats = [
            r
            for r in records
            if r["affected"][0]["database_specific"]["finding_class"] == "typosquat"
        ]
        assert typosquats
        assert typosquats[0]["affected"][0]["package"]["name"].endswith("filesytem")

    def test_is_reproducible_across_runs(self, tmp_path: Path) -> None:
        for name in ("first", "second"):
            _advise(str(FIXTURES), "--out", str(tmp_path / name), "--no-sign")
        for path in sorted((tmp_path / "first").rglob("*")):
            if path.is_file():
                mirror = tmp_path / "second" / path.relative_to(tmp_path / "first")
                assert path.read_bytes() == mirror.read_bytes(), path.name

    def test_severity_threshold_narrows_the_feed(self, tmp_path: Path) -> None:
        _advise(
            str(FIXTURES),
            "--out",
            str(tmp_path / "all"),
            "--no-sign",
            "--severity-threshold",
            "info",
        )
        _advise(
            str(FIXTURES),
            "--out",
            str(tmp_path / "crit"),
            "--no-sign",
            "--severity-threshold",
            "critical",
        )
        assert _count(tmp_path / "crit") < _count(tmp_path / "all")

    def test_observation_filter_selects_package_defects(self, tmp_path: Path) -> None:
        _advise(
            str(FIXTURES),
            "--out",
            str(tmp_path / "feed"),
            "--no-sign",
            "--observation",
            "package-intrinsic",
        )
        records = json.loads(
            (tmp_path / "feed" / "osv" / "all.json").read_text(encoding="utf-8")
        )
        assert records
        assert all(
            r["affected"][0]["database_specific"]["observation"] == "package-intrinsic"
            for r in records
        )

    def test_reads_an_existing_scan_result(self, tmp_path: Path) -> None:
        scan_path = tmp_path / "scan.json"
        scan = runner.invoke(
            app, ["scan", str(FIXTURES), "--format", "json", "-o", str(scan_path)]
        )
        assert scan_path.is_file(), scan.output

        result = _advise(
            "--input", str(scan_path), "--out", str(tmp_path / "feed"), "--no-sign"
        )
        assert result.exit_code == 0, result.output
        assert _count(tmp_path / "feed") > 0

    def test_unsigned_feed_names_the_guarantee_it_does_not_carry(
        self, tmp_path: Path
    ) -> None:
        result = _advise(str(FIXTURES), "--out", str(tmp_path / "feed"), "--no-sign")
        flat = _flat(result.output)
        assert "carries no signatures" in flat
        assert "nothing attests to who produced it" in flat

    def test_signing_without_a_key_exits_2_and_says_what_is_missing(
        self, tmp_path: Path
    ) -> None:
        """A feed is signed with a project key; there is no keyless fallback."""
        result = _advise(str(FIXTURES), "--out", str(tmp_path / "feed"), "--sign")
        assert result.exit_code == 2
        flat = _flat(result.output)
        assert "needs a project key" in flat
        assert "--key" in flat

    def test_the_unsigned_feed_survives_a_signing_failure(self, tmp_path: Path) -> None:
        out = tmp_path / "feed"
        result = _advise(str(FIXTURES), "--out", str(out), "--sign")
        assert result.exit_code == 2
        assert (out / "index.json").is_file()

    def test_summary_reports_findings_it_could_not_publish(
        self, tmp_path: Path
    ) -> None:
        result = _advise(
            str(FIXTURES),
            "--out",
            str(tmp_path / "feed"),
            "--no-sign",
            "--severity-threshold",
            "info",
        )
        assert "Skipped:" in result.output


class TestAdviseArgumentErrors:
    def test_missing_target_exits_2(self, tmp_path: Path) -> None:
        result = _advise(str(tmp_path / "absent"), "--no-sign")
        assert result.exit_code == 2
        assert "Path not found" in result.output

    def test_missing_input_scan_exits_2(self, tmp_path: Path) -> None:
        result = _advise("--input", str(tmp_path / "absent.json"), "--no-sign")
        assert result.exit_code == 2
        assert "Scan file not found" in result.output

    def test_malformed_input_scan_exits_2(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        result = _advise("--input", str(bad), "--no-sign")
        assert result.exit_code == 2
        assert "not an mcp-audit JSON scan result" in _flat(result.output)

    def test_unknown_backend_exits_2(self, tmp_path: Path) -> None:
        result = _advise(str(FIXTURES), "--key-alt", "pgp")
        assert result.exit_code == 2
        assert "Unknown backend" in result.output

    def test_unknown_severity_exits_2(self, tmp_path: Path) -> None:
        result = _advise(str(FIXTURES), "--severity-threshold", "spicy", "--no-sign")
        assert result.exit_code == 2
        assert "Unknown severity" in result.output

    def test_unknown_observation_exits_2(self, tmp_path: Path) -> None:
        result = _advise(str(FIXTURES), "--observation", "vibes", "--no-sign")
        assert result.exit_code == 2
        assert "Unknown --observation" in result.output


# ── feed verify ───────────────────────────────────────────────────────────────


@needs_minisign
class TestFeedVerify:
    @pytest.fixture
    def signed_feed(self, tmp_path: Path, minisign_keys) -> Path:
        private, _ = minisign_keys
        feed = tmp_path / "feed"
        result = _advise(
            str(FIXTURES),
            "--out",
            str(feed),
            "--key-alt",
            "minisign",
            "--key",
            str(private),
        )
        assert result.exit_code == 0, result.output
        return feed

    def test_signing_reports_what_it_signed(
        self, tmp_path: Path, minisign_keys
    ) -> None:
        private, _ = minisign_keys
        result = _advise(
            str(FIXTURES),
            "--out",
            str(tmp_path / "feed"),
            "--key-alt",
            "minisign",
            "--key",
            str(private),
        )
        assert "Signed" in result.output

    def test_verify_passes_and_exits_0(self, signed_feed: Path, minisign_keys) -> None:
        _, public = minisign_keys
        result = runner.invoke(
            app,
            [
                "feed",
                "verify",
                str(signed_feed),
                "--key-alt",
                "minisign",
                "--public-key",
                str(public),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "verified" in result.output

    def test_a_mutated_advisory_fails_and_exits_1(
        self, signed_feed: Path, minisign_keys
    ) -> None:
        _, public = minisign_keys
        target = next(
            p
            for p in sorted((signed_feed / "advisories").glob("*.json"))
            if not p.name.endswith((".sig", ".sigstore.json"))
        )
        record = json.loads(target.read_text(encoding="utf-8"))
        record["summary"] = "nothing to see here"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

        result = runner.invoke(
            app,
            [
                "feed",
                "verify",
                str(signed_feed),
                "--key-alt",
                "minisign",
                "--public-key",
                str(public),
            ],
        )
        assert result.exit_code == 1
        assert "FAILED" in result.output

    def test_missing_directory_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["feed", "verify", str(tmp_path / "absent")])
        assert result.exit_code == 2
        assert "Feed directory not found" in result.output

    def test_unknown_backend_exits_2(self, signed_feed: Path) -> None:
        result = runner.invoke(
            app, ["feed", "verify", str(signed_feed), "--key-alt", "pgp"]
        )
        assert result.exit_code == 2
        assert "Unknown backend" in result.output


def _count(feed_dir: Path) -> int:
    index = json.loads((feed_dir / "index.json").read_text(encoding="utf-8"))
    return int(index["count"])


def _flat(text: str) -> str:
    """Collapse Rich's console wrapping so messages can be matched as written."""
    return " ".join(text.split())
