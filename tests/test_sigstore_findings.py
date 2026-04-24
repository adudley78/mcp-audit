"""Tests for AttestationResult → Finding translation."""

import pytest

pytest.importorskip(
    "sigstore",
    reason="sigstore not installed; install mcp-audit-scanner[attestation]",
)

from pathlib import Path  # noqa: E402, I001
from mcp_audit.attestation.sigstore_client import AttestationResult  # noqa: E402
from mcp_audit.attestation.sigstore_findings import _attestation_result_to_finding  # noqa: E402
from mcp_audit.models import ServerConfig, Severity, TransportType  # noqa: E402


def _server(tmp_path: Path) -> ServerConfig:
    return ServerConfig(
        name="test-pkg",
        client="test",
        config_path=tmp_path / "t.json",
        transport=TransportType.STDIO,
        command="npx",
        args=["-y", "test-pkg@1.0.0"],
    )


def _result(**kwargs: object) -> AttestationResult:
    defaults: dict[str, object] = {
        "package_name": "test-pkg",
        "version": "1.0.0",
        "source": "npm",
        "status": "absent",
        "oidc_issuer": None,
        "oidc_subject": None,
        "signing_repo": None,
        "expected_repo": "org/repo",
        "error": None,
    }
    defaults.update(kwargs)
    return AttestationResult(**defaults)  # type: ignore[arg-type]


class TestAttestationResultToFinding:
    def test_valid_match_is_info(self, tmp_path: Path) -> None:
        result = _result(status="valid_match", signing_repo="org/repo")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert finding.id == "ATTEST-010"
        assert finding.severity == Severity.INFO
        assert finding.analyzer == "attestation"

    def test_valid_match_description_contains_repo(self, tmp_path: Path) -> None:
        result = _result(status="valid_match", signing_repo="org/repo")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert "org/repo" in finding.description

    def test_valid_mismatch_is_high(self, tmp_path: Path) -> None:
        result = _result(status="valid_mismatch", signing_repo="attacker/fork")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert finding.id == "ATTEST-011"
        assert finding.severity == Severity.HIGH
        assert finding.cwe == "CWE-494"

    def test_valid_mismatch_description_contains_repos(self, tmp_path: Path) -> None:
        result = _result(status="valid_mismatch", signing_repo="attacker/fork")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert "attacker/fork" in finding.description
        assert "org/repo" in finding.description

    def test_invalid_is_critical(self, tmp_path: Path) -> None:
        result = _result(status="invalid", error="bad signature")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert finding.id == "ATTEST-012"
        assert finding.severity == Severity.CRITICAL
        assert finding.cwe == "CWE-494"

    def test_invalid_description_contains_error(self, tmp_path: Path) -> None:
        result = _result(status="invalid", error="bad signature")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert "bad signature" in finding.description

    def test_absent_expected_is_medium(self, tmp_path: Path) -> None:
        result = _result(status="absent")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=True
        )
        assert finding is not None
        assert finding.id == "ATTEST-013"
        assert finding.severity == Severity.MEDIUM

    def test_absent_not_expected_is_info_by_default(self, tmp_path: Path) -> None:
        result = _result(status="absent")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert finding.id == "ATTEST-014"
        assert finding.severity == Severity.INFO

    def test_absent_not_expected_is_medium_with_strict(self, tmp_path: Path) -> None:
        result = _result(status="absent")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=True, attestation_expected=False
        )
        assert finding is not None
        assert finding.id == "ATTEST-014"
        assert finding.severity == Severity.MEDIUM

    def test_error_is_info(self, tmp_path: Path) -> None:
        result = _result(status="error", error="timeout")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert finding.id == "ATTEST-015"
        assert finding.severity == Severity.INFO

    def test_error_description_is_error_message(self, tmp_path: Path) -> None:
        result = _result(status="error", error="connection refused")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert "connection refused" in finding.description

    def test_finding_path_is_set(self, tmp_path: Path) -> None:
        result = _result(status="absent")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        assert finding.finding_path is not None
        assert "t.json" in finding.finding_path

    def test_evidence_is_valid_json(self, tmp_path: Path) -> None:
        import json

        result = _result(status="absent")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=False, attestation_expected=False
        )
        assert finding is not None
        evidence = json.loads(finding.evidence)
        assert evidence["status"] == "absent"
        assert evidence["package_name"] == "test-pkg"

    def test_absent_expected_takes_precedence_over_strict(self, tmp_path: Path) -> None:
        # attestation_expected=True should produce ATTEST-013, not ATTEST-014.
        result = _result(status="absent")
        finding = _attestation_result_to_finding(
            result, _server(tmp_path), strict=True, attestation_expected=True
        )
        assert finding is not None
        assert finding.id == "ATTEST-013"
        assert finding.severity == Severity.MEDIUM
