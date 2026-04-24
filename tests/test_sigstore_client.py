"""Tests for sigstore_client — all network calls mocked."""

import pytest

pytest.importorskip(
    "sigstore",
    reason="sigstore not installed; install mcp-audit-scanner[attestation]",
)

from unittest.mock import patch  # noqa: E402

from mcp_audit.attestation.sigstore_client import (  # noqa: E402
    AttestationResult,
    NetworkError,
    _extract_signing_repo_from_subject,
    _normalise_repo,
    verify_attestation,
)


class TestNormaliseRepo:
    def test_full_github_url(self) -> None:
        assert _normalise_repo("https://github.com/org/repo") == "org/repo"

    def test_trailing_slash(self) -> None:
        assert _normalise_repo("https://github.com/org/repo/") == "org/repo"

    def test_git_suffix(self) -> None:
        assert _normalise_repo("https://github.com/org/repo.git") == "org/repo"

    def test_non_github_url(self) -> None:
        assert _normalise_repo("https://gitlab.com/org/repo") is None

    def test_none_input(self) -> None:
        assert _normalise_repo(None) is None

    def test_bare_github_prefix(self) -> None:
        assert _normalise_repo("github.com/org/repo") == "org/repo"

    def test_http_github_url(self) -> None:
        assert _normalise_repo("http://github.com/org/repo") == "org/repo"

    def test_url_with_extra_path_segments(self) -> None:
        # Only org/repo should be extracted; trailing segments ignored.
        assert _normalise_repo("https://github.com/org/repo/tree/main") == "org/repo"


class TestExtractSigningRepo:
    def test_github_actions_uri(self) -> None:
        uri = (
            "https://github.com/modelcontextprotocol/servers"
            "/.github/workflows/publish.yml@refs/heads/main"
        )
        assert _extract_signing_repo_from_subject(uri) == "modelcontextprotocol/servers"

    def test_none_input(self) -> None:
        assert _extract_signing_repo_from_subject(None) is None

    def test_non_github_uri(self) -> None:
        assert _extract_signing_repo_from_subject("https://gitlab.com/org/repo") is None

    def test_http_github_uri(self) -> None:
        uri = "http://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"
        assert _extract_signing_repo_from_subject(uri) == "org/repo"

    def test_plain_github_uri_without_path(self) -> None:
        # Should still extract org/repo from a URI that happens to be minimal.
        uri = "https://github.com/org/repo"
        assert _extract_signing_repo_from_subject(uri) == "org/repo"


class TestVerifyAttestationAbsent:
    def test_npm_none_returns_absent(self) -> None:
        with patch(
            "mcp_audit.attestation.sigstore_client.fetch_npm_attestation_bundle"
        ) as mock:
            mock.return_value = None
            result = verify_attestation("some-pkg", "1.0.0", "npm", "org/repo")
        assert result.status == "absent"
        assert result.error is None

    def test_pip_none_returns_absent(self) -> None:
        with patch(
            "mcp_audit.attestation.sigstore_client.fetch_pypi_attestation_bundle"
        ) as mock:
            mock.return_value = None
            result = verify_attestation("some-pkg", "1.0.0", "pip", "org/repo")
        assert result.status == "absent"
        assert result.error is None

    def test_absent_preserves_expected_repo(self) -> None:
        with patch(
            "mcp_audit.attestation.sigstore_client.fetch_npm_attestation_bundle"
        ) as mock:
            mock.return_value = None
            result = verify_attestation("some-pkg", "1.0.0", "npm", "org/repo")
        assert result.expected_repo == "org/repo"
        assert result.package_name == "some-pkg"
        assert result.version == "1.0.0"
        assert result.source == "npm"


class TestVerifyAttestationNetworkError:
    def test_network_error_returns_error_status(self) -> None:
        with patch(
            "mcp_audit.attestation.sigstore_client.fetch_npm_attestation_bundle"
        ) as mock:
            mock.side_effect = NetworkError("connection refused")
            result = verify_attestation("some-pkg", "1.0.0", "npm", "org/repo")
        assert result.status == "error"
        assert result.error is not None
        assert "connection refused" in result.error

    def test_network_error_pip_returns_error_status(self) -> None:
        with patch(
            "mcp_audit.attestation.sigstore_client.fetch_pypi_attestation_bundle"
        ) as mock:
            mock.side_effect = NetworkError("timeout")
            result = verify_attestation("some-pkg", "1.0.0", "pip", "org/repo")
        assert result.status == "error"
        assert "timeout" in (result.error or "")


class TestVerifyAttestationInvalid:
    def test_bad_bundle_returns_invalid(self) -> None:
        """A bundle dict that fails sigstore parsing produces 'invalid' status."""
        with patch(
            "mcp_audit.attestation.sigstore_client.fetch_npm_attestation_bundle"
        ) as mock:
            # Return a non-None dict that will fail Bundle.from_json parsing.
            mock.return_value = {"mediaType": "invalid", "bad": "data"}
            result = verify_attestation("some-pkg", "1.0.0", "npm", "org/repo")
        assert result.status == "invalid"
        assert result.error is not None


class TestAttestationResultDataclass:
    def test_fields_populated(self) -> None:
        r = AttestationResult(
            package_name="foo",
            version="1.0.0",
            source="npm",
            status="absent",
            oidc_issuer=None,
            oidc_subject=None,
            signing_repo=None,
            expected_repo="org/repo",
            error=None,
        )
        assert r.package_name == "foo"
        assert r.source == "npm"
        assert r.status == "absent"
        assert r.expected_repo == "org/repo"
