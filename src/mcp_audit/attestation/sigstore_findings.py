"""AttestationResult → Finding translation for Layer 2 Sigstore verification."""

from __future__ import annotations

import json

from mcp_audit.attestation.sigstore_client import AttestationResult
from mcp_audit.attestation.verifier import extract_version_from_server
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import KnownServerRegistry

# Finding IDs — rule/category codes (per Opus design doc)
_ATTEST_VALID_MATCH = "ATTEST-010"  # INFO positive signal
_ATTEST_VALID_MISMATCH = "ATTEST-011"  # HIGH — someone else is signing this package
_ATTEST_INVALID = "ATTEST-012"  # CRITICAL — forged or tampered signature
_ATTEST_EXPECTED_ABSENT = (
    "ATTEST-013"  # MEDIUM — should-be-signed package lost provenance  # noqa: E501
)
_ATTEST_ABSENT = "ATTEST-014"  # INFO (MEDIUM with --strict-signatures)
_ATTEST_ERROR = "ATTEST-015"  # INFO — unverifiable


def _attestation_result_to_finding(
    result: AttestationResult,
    server: ServerConfig,
    strict: bool,
    attestation_expected: bool,
) -> Finding | None:
    """Convert an :class:`AttestationResult` to a :class:`Finding`, or ``None``.

    Args:
        result: Sigstore verification outcome.
        server: The server config that triggered verification.
        strict: When ``True``, raises absent-but-not-expected from INFO to MEDIUM.
        attestation_expected: Whether this package is known to use provenance.

    Returns:
        A :class:`Finding` for all non-absent/non-error results, plus for
        absent results depending on ``attestation_expected`` and ``strict``
        mode.  Returns ``None`` only for ``"valid_match"`` when callers
        explicitly suppress INFO-level positives — currently always returns
        a Finding.
    """
    evidence = json.dumps(
        {
            "package_name": result.package_name,
            "version": result.version,
            "source": result.source,
            "status": result.status,
            "oidc_issuer": result.oidc_issuer,
            "oidc_subject": result.oidc_subject,
            "signing_repo": result.signing_repo,
            "expected_repo": result.expected_repo,
        }
    )

    if result.status == "valid_match":
        return Finding(
            id=_ATTEST_VALID_MATCH,
            severity=Severity.INFO,
            analyzer="attestation",
            client=server.client,
            server=server.name,
            title=(
                f"Sigstore provenance verified: {result.package_name}@{result.version}"
            ),
            description=(
                f"Package has a valid Sigstore attestation. OIDC subject matches "
                f"the expected repository ({result.signing_repo})."
            ),
            evidence=evidence,
            remediation="No action required.",
            finding_path=str(server.config_path),
        )

    if result.status == "valid_mismatch":
        return Finding(
            id=_ATTEST_VALID_MISMATCH,
            severity=Severity.HIGH,
            analyzer="attestation",
            client=server.client,
            server=server.name,
            title=(
                f"Sigstore attestation from unexpected publisher: "
                f"{result.package_name}@{result.version}"
            ),
            description=(
                f"The cryptographic signature is valid, but the OIDC subject "
                f"'{result.signing_repo}' does not match the expected repository "
                f"'{result.expected_repo}'. This may indicate a supply chain attack "
                "or a legitimate repository migration — investigate before trusting."
            ),
            evidence=evidence,
            remediation=(
                "Verify that the current publishing identity is authorised. "
                "If the repo has changed, update registry/known-servers.json."
            ),
            cwe="CWE-494",
            finding_path=str(server.config_path),
        )

    if result.status == "invalid":
        return Finding(
            id=_ATTEST_INVALID,
            severity=Severity.CRITICAL,
            analyzer="attestation",
            client=server.client,
            server=server.name,
            title=(
                f"Invalid Sigstore signature: {result.package_name}@{result.version}"
            ),
            description=(
                "A Sigstore provenance attestation was found but the cryptographic "
                "signature is invalid. This is a strong indicator of tampering or a "
                f"forged attestation. Error: {result.error}"
            ),
            evidence=evidence,
            remediation=(
                "Do not use this package. Verify the package on the npm/PyPI registry "
                "and contact the maintainer immediately."
            ),
            cwe="CWE-494",
            finding_path=str(server.config_path),
        )

    if result.status == "absent":
        if attestation_expected:
            return Finding(
                id=_ATTEST_EXPECTED_ABSENT,
                severity=Severity.MEDIUM,
                analyzer="attestation",
                client=server.client,
                server=server.name,
                title=(
                    f"Expected Sigstore attestation missing: "
                    f"{result.package_name}@{result.version}"
                ),
                description=(
                    f"{result.package_name} is a known package that publishes with "
                    "Sigstore provenance, but no attestation was found for this "
                    "version. This may indicate a compromised publish pipeline."
                ),
                evidence=evidence,
                remediation=(
                    "Check the package's publish history and CI configuration. "
                    "If attestation was intentionally removed, update the registry."
                ),
                cwe="CWE-494",
                finding_path=str(server.config_path),
            )
        absent_severity = Severity.MEDIUM if strict else Severity.INFO
        return Finding(
            id=_ATTEST_ABSENT,
            severity=absent_severity,
            analyzer="attestation",
            client=server.client,
            server=server.name,
            title=(f"No Sigstore attestation: {result.package_name}@{result.version}"),
            description=(
                f"{result.package_name}@{result.version} has no Sigstore provenance "
                "attestation. This is common for packages not yet using Trusted "
                "Publishing."
            ),
            evidence=evidence,
            remediation=(
                "Consider requesting that the package maintainer enable Trusted "
                "Publishing to provide provenance attestations."
            ),
            finding_path=str(server.config_path),
        )

    # status == "error"
    return Finding(
        id=_ATTEST_ERROR,
        severity=Severity.INFO,
        analyzer="attestation",
        client=server.client,
        server=server.name,
        title=(
            f"Could not verify Sigstore attestation: "
            f"{result.package_name}@{result.version}"
        ),
        description=(
            result.error or "Attestation verification could not be completed."
        ),
        evidence=evidence,
        remediation=(
            "Ensure network access is available and re-run with --verify-signatures."
        ),
        finding_path=str(server.config_path),
    )


def verify_server_signatures(
    servers: list[ServerConfig],
    registry: KnownServerRegistry,
    strict: bool = False,
) -> list[Finding]:
    """Verify Sigstore provenance for all registry-known servers.

    Skips servers not in the registry (no expected repo to validate against)
    and servers whose version cannot be determined from the config.

    Args:
        servers: All discovered server configs.
        registry: Loaded :class:`~mcp_audit.registry.loader.KnownServerRegistry`.
        strict: When ``True``, ``"absent"`` findings are raised to MEDIUM
            severity for packages that do not have ``attestation_expected``.

    Returns:
        List of :class:`~mcp_audit.models.Finding` objects.  An empty list
        means all verifiable packages were clean or skipped.
    """
    from mcp_audit.attestation.sigstore_client import (  # noqa: PLC0415
        _normalise_repo,
        verify_attestation,
    )

    findings: list[Finding] = []

    for server in servers:
        entry = registry.get(server.name)
        if entry is None:
            continue  # not in registry; supply-chain analyzer handles unknowns

        version = extract_version_from_server(server)
        if version is None:
            continue  # can't verify without a pinned version

        expected_repo = _normalise_repo(entry.repo)
        result = verify_attestation(
            package_name=entry.name,
            version=version,
            source=entry.source,  # type: ignore[arg-type]
            expected_repo=expected_repo,
        )

        finding = _attestation_result_to_finding(
            result,
            server,
            strict=strict,
            attestation_expected=entry.attestation_expected,
        )
        if finding is not None:
            findings.append(finding)

    return findings
