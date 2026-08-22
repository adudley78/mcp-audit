"""Tests for scripts/check_registry_drift.py (CI gate, no network, no stamp)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_registry_drift as drift  # noqa: E402


def _result(
    name: str,
    *,
    bucket: str = "OK",
    ecosystem: list[str] | None = None,
    attestation_expected: bool = False,
    provenance: str = "NOT_CHECKED",
) -> dict[str, Any]:
    return {
        "name": name,
        "declared_ecosystem": ecosystem or ["npm"],
        "declared_source": "npm",
        "bucket": bucket,
        "declared_attestation_expected": attestation_expected,
        "provenance": provenance,
        "declared_last_verified": "2026-04-15",
    }


class TestCollectFailures:
    def test_missing_is_a_failure(self) -> None:
        failures = drift.collect_failures(
            [_result("gone-pkg", bucket="MISSING", ecosystem=["pypi"])]
        )
        assert len(failures) == 1
        assert failures[0]["condition"] == "MISSING"
        assert failures[0]["name"] == "gone-pkg"
        assert failures[0]["ecosystem"] == "pypi"

    def test_no_provenance_while_flagged_is_a_failure(self) -> None:
        failures = drift.collect_failures(
            [
                _result(
                    "@scope/pkg",
                    attestation_expected=True,
                    provenance="NO_PROVENANCE",
                )
            ]
        )
        assert len(failures) == 1
        assert failures[0]["condition"] == "attestation_expected+NO_PROVENANCE"

    def test_thin_is_not_a_failure(self) -> None:
        assert drift.collect_failures([_result("@playwright/mcp", bucket="THIN")]) == []

    def test_stale_last_verified_on_ok_is_not_a_failure(self) -> None:
        assert drift.collect_failures([_result("ok-pkg", bucket="OK")]) == []

    def test_has_provenance_is_not_a_failure(self) -> None:
        assert (
            drift.collect_failures(
                [
                    _result(
                        "pinned",
                        attestation_expected=True,
                        provenance="HAS_PROVENANCE",
                    )
                ]
            )
            == []
        )

    def test_unchecked_provenance_is_not_a_failure(self) -> None:
        assert (
            drift.collect_failures(
                [
                    _result(
                        "maybe",
                        attestation_expected=True,
                        provenance="UNCHECKED",
                    )
                ]
            )
            == []
        )

    def test_unclaimable_mismatch_is_not_a_failure(self) -> None:
        assert (
            drift.collect_failures([_result("moved", bucket="UNCLAIMABLE_MISMATCH")])
            == []
        )


class TestReportAndMessage:
    def test_report_counts(self) -> None:
        report = drift.build_report(
            [
                _result("ok", bucket="OK"),
                _result("thin", bucket="THIN"),
                _result(
                    "flagged-ok",
                    attestation_expected=True,
                    provenance="HAS_PROVENANCE",
                ),
            ],
            "2026-08-22",
        )
        assert report["run_date"] == "2026-08-22"
        assert report["total_entries"] == 3
        assert report["buckets"]["OK"] == 2
        assert report["buckets"]["THIN"] == 1
        assert report["buckets"]["MISSING"] == 0
        assert report["attestation_expected"]["flagged"] == 1
        assert report["attestation_expected"]["HAS_PROVENANCE"] == 1
        assert report["failures"] == []

    def test_failure_message_names_entry_and_commands(self) -> None:
        failures = drift.collect_failures(
            [_result("gone-pkg", bucket="MISSING", ecosystem=["npm"])]
        )
        msg = drift.format_failure_message(failures)
        assert "MISSING fired" in msg
        assert "gone-pkg" in msg
        assert "npm" in msg
        assert "python scripts/audit_registry.py" in msg
        assert "--stamp" in msg
        assert "THIN" in msg


class TestCli:
    def test_cli_writes_report_and_exits_1_on_missing(self, tmp_path: Path) -> None:
        raw = tmp_path / "raw.json"
        raw.write_text(
            json.dumps([_result("gone-pkg", bucket="MISSING")]),
            encoding="utf-8",
        )
        report = tmp_path / "report.json"
        rc = drift.main(
            ["--raw", str(raw), "--report", str(report), "--run-date", "2026-08-22"]
        )
        assert rc == 1
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["failures"][0]["name"] == "gone-pkg"

    def test_cli_exits_0_when_clean(self, tmp_path: Path) -> None:
        raw = tmp_path / "raw.json"
        raw.write_text(json.dumps([_result("ok-pkg")]), encoding="utf-8")
        report = tmp_path / "report.json"
        rc = drift.main(
            ["--raw", str(raw), "--report", str(report), "--run-date", "2026-08-22"]
        )
        assert rc == 0
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["failures"] == []
        assert data["total_entries"] == 1
