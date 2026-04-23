"""Verify the smoke-test fixture produces the expected findings.

This test ensures the fixture used in the binary smoke test (scripts/smoke_test.py)
actually generates the findings the smoke test asserts. If this test fails after
a pattern change, the smoke test fixture needs updating.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.scanner import run_scan

SMOKE_FIXTURE = Path(__file__).parent / "fixtures" / "smoke_test_config.json"


class TestSmokeTestFixture:
    def test_fixture_exists(self) -> None:
        assert SMOKE_FIXTURE.exists(), (
            "smoke_test_config.json must exist — it is used by scripts/smoke_test.py"
        )

    def test_fixture_produces_poison_001(self) -> None:
        """Smoke fixture must produce POISON-001 (SSH exfiltration)."""
        result = run_scan(extra_paths=[SMOKE_FIXTURE], skip_rug_pull=True)
        ids = {f.id for f in result.findings}
        assert "POISON-001" in ids, (
            "Smoke fixture must trigger POISON-001; "
            "check that the poisoned-server tool description is intact"
        )

    def test_fixture_produces_credential_finding(self) -> None:
        """Smoke fixture must produce a credential finding."""
        result = run_scan(extra_paths=[SMOKE_FIXTURE], skip_rug_pull=True)
        cred_findings = [f for f in result.findings if f.analyzer == "credentials"]
        assert cred_findings, (
            "Smoke fixture must trigger at least one credential finding; "
            "check that the credential-server env value is a realistic API key pattern"
        )

    def test_fixture_exit_code_would_be_1(self) -> None:
        """Smoke fixture must produce findings (non-zero exit in CLI)."""
        result = run_scan(extra_paths=[SMOKE_FIXTURE], skip_rug_pull=True)
        assert result.findings, "Smoke fixture must produce at least one finding"
