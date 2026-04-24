"""Sigstore provenance bundle fetching and verification (Layer 2 attestation).

Uses the npm and PyPI registry APIs as the primary bundle discovery path.
Verification is performed with the ``sigstore`` Python library, which handles
Fulcio certificate chain validation, SCT verification, and Rekor inclusion
proof checking against TUF-managed trust roots.

Network calls are made only when the caller explicitly opts in via
``--verify-signatures``.  All functions raise ``NetworkError`` (not ``urllib``
errors) so callers can catch a single exception type.

.. note::
    **Binary size flag — rebuild required.**  The pre-sigstore binaries were
    20 MB (darwin) and 22 MB (linux).  Adding ``sigstore>=3.0`` pulls in
    ``betterproto``, ``tuf``, ``rfc3161-client``, ``securesystemslib``,
    ``sigstore-protobuf-specs``, and related deps, which are expected to push
    the rebuilt binary above 22 MB.  Run ``python build.py`` after merging
    this change, measure the output of ``ls -lh dist/mcp-audit-*``, and decide
    whether to (a) accept the larger binary, (b) move ``sigstore`` to an
    optional install group (e.g. ``pip install mcp-audit[sigstore]``), or
    (c) replace the sigstore library with a minimal custom TUF + Rekor client.
    Flag for follow-up before the next release cut.

Sigstore library API notes (sigstore>=3.0):
- ``Bundle.from_json(raw)`` — parses a bundle from JSON bytes or str.
- ``Verifier.production()`` — creates a verifier against the public Sigstore
  trust root (Fulcio + Rekor).
- ``Verifier.verify_dsse(bundle, policy)`` — verifies a DSSE-enveloped bundle
  (used for SLSA provenance on npm); raises ``VerificationError`` on failure.
- Certificate OIDC fields are accessed via X.509 extension OIDs defined in the
  Sigstore spec (``1.3.6.1.4.1.57264.*``).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Literal


class NetworkError(Exception):
    """Wraps any network failure during bundle fetching."""


VerificationStatus = Literal[
    "valid_match",  # signature valid; OIDC subject matches RegistryEntry.repo
    "valid_mismatch",  # signature valid; OIDC subject does NOT match expected repo
    "invalid",  # signature present but cryptographically invalid
    "absent",  # no attestation found for this package+version
    "error",  # network or API error; could not determine status
]


@dataclass
class AttestationResult:
    """Result of a Sigstore provenance verification attempt."""

    package_name: str
    version: str
    source: Literal["npm", "pip"]
    status: VerificationStatus
    oidc_issuer: str | None  # e.g. "https://token.actions.githubusercontent.com"
    oidc_subject: str | None  # full workflow URI
    signing_repo: str | None  # normalised "org/repo" extracted from oidc_subject
    expected_repo: str | None  # from RegistryEntry.repo, normalised
    error: str | None  # only populated when status == "error" or "invalid"


def _normalise_repo(repo_url: str | None) -> str | None:
    """Extract 'org/repo' from a GitHub URL like 'https://github.com/org/repo'.

    Returns None if the URL is None, non-GitHub, or cannot be parsed.

    Args:
        repo_url: Full GitHub repository URL.

    Returns:
        Normalised ``"org/repo"`` string, or ``None``.
    """
    if not repo_url:
        return None
    # Strip trailing slashes and .git suffix before parsing.
    repo_url = repo_url.rstrip("/").removesuffix(".git")
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if repo_url.startswith(prefix):
            tail = repo_url[len(prefix) :]
            parts = tail.split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
    return None


def _extract_signing_repo_from_subject(oidc_subject: str | None) -> str | None:
    """Extract 'org/repo' from a GitHub Actions workflow URI.

    Example input::

        "https://github.com/modelcontextprotocol/servers/.github/workflows/publish.yml@refs/heads/main"

    Example output::

        "modelcontextprotocol/servers"

    Args:
        oidc_subject: Full OIDC subject URI from the Sigstore bundle certificate.

    Returns:
        Normalised ``"org/repo"`` string, or ``None``.
    """
    if not oidc_subject:
        return None
    for prefix in ("https://github.com/", "http://github.com/"):
        if oidc_subject.startswith(prefix):
            tail = oidc_subject[len(prefix) :]
            parts = tail.split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
    return None


def fetch_npm_attestation_bundle(package_name: str, version: str) -> dict | None:
    """Fetch the Sigstore provenance bundle for an npm package from the registry API.

    Args:
        package_name: Full npm package name (scoped or unscoped).
        version: Exact version string.

    Returns:
        The inner Sigstore bundle dict for the first SLSA provenance attestation,
        or ``None`` if no attestation is present.

    Raises:
        NetworkError: On any network failure.
    """
    encoded = package_name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/-/npm/v1/attestations/{encoded}@{version}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310  # nosec B310 — URL is always https://registry.npmjs.org/…
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # no attestation for this package+version
        raise NetworkError(
            f"npm attestation API error {exc.code}: {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise NetworkError(f"npm attestation network error: {exc.reason}") from exc

    attestations = data.get("attestations", [])
    slsa = [
        a
        for a in attestations
        if a.get("predicateType", "").startswith("https://slsa.dev/provenance/")
    ]
    if not slsa:
        return None
    # The "bundle" key inside each attestation entry is the Sigstore bundle.
    return slsa[0].get("bundle")


def fetch_pypi_attestation_bundle(
    package_name: str, version: str, filename: str
) -> dict | None:
    """Fetch the PEP 740 provenance attestation for a PyPI distribution file.

    Args:
        package_name: PyPI package name.
        version: Exact version string.
        filename: The distribution filename (e.g. ``"mcp-1.6.0.tar.gz"``).

    Returns:
        The inner Sigstore bundle dict from the first attestation, or ``None``
        if absent.

    Raises:
        NetworkError: On any network failure.
    """
    url = f"https://pypi.org/integrity/{package_name}/{version}/{filename}/provenance"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310  # nosec B310 — URL is always https://pypi.org/…
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise NetworkError(
            f"PyPI provenance API error {exc.code}: {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise NetworkError(f"PyPI provenance network error: {exc.reason}") from exc

    bundles = data.get("attestation_bundles", [])
    if not bundles:
        return None
    # Each bundle group has a list of individual attestation bundles.
    attestations = bundles[0].get("attestations", [])
    return attestations[0] if attestations else None


def _extract_oidc_fields(
    cert: object,
) -> tuple[str | None, str | None]:
    """Extract OIDC issuer and subject URI from a Sigstore signing certificate.

    Attempts to read the OIDC Issuer extension (OID 1.3.6.1.4.1.57264.1.1 and
    its V2 sibling 1.3.6.1.4.1.57264.1.8) and the SubjectAlternativeName URI
    value from a ``cryptography`` X.509 certificate object.

    Args:
        cert: A ``cryptography.x509.Certificate`` instance (typed as ``object``
            to avoid importing cryptography at module level).

    Returns:
        Tuple of ``(oidc_issuer, oidc_subject)``; either may be ``None``.
    """
    from cryptography.x509 import (  # noqa: PLC0415
        ExtensionNotFound,
        SubjectAlternativeName,
        UniformResourceIdentifier,
    )
    from cryptography.x509.oid import ObjectIdentifier  # noqa: PLC0415

    oidc_issuer_oid = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
    oidc_issuer_v2_oid = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")

    oidc_issuer: str | None = None
    # Try the original issuer extension first, then the V2 DER-encoded form.
    for oid in (oidc_issuer_oid, oidc_issuer_v2_oid):
        try:
            raw_ext = cert.extensions.get_extension_for_oid(oid).value  # type: ignore[union-attr]
            raw_bytes: bytes = raw_ext.value  # type: ignore[attr-defined]
            # V2 extension value is DER-encoded UTF8String; strip the tag+length
            # bytes (0x0C len) when present — a plain UTF-8 decode handles both.
            try:
                oidc_issuer = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                # DER-wrapped: skip the 2-byte header (tag 0x0C + length byte)
                if len(raw_bytes) > 2:
                    oidc_issuer = raw_bytes[2:].decode("utf-8", errors="replace")
            break
        except ExtensionNotFound:
            continue
        except Exception:  # noqa: BLE001, S112
            continue

    oidc_subject: str | None = None
    try:
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName).value  # type: ignore[union-attr]
        uris = san_ext.get_values_for_type(UniformResourceIdentifier)
        oidc_subject = uris[0] if uris else None
    except Exception:  # noqa: BLE001, S110
        pass

    return oidc_issuer, oidc_subject


def verify_attestation(
    package_name: str,
    version: str,
    source: Literal["npm", "pip"],
    expected_repo: str | None,
) -> AttestationResult:
    """Fetch and verify a Sigstore provenance attestation for a package.

    Verification pipeline:

    1. Fetch the bundle from the npm/PyPI registry API.
    2. Parse the bundle with ``sigstore.models.Bundle.from_json()``.
    3. Verify the cryptographic signature using ``Verifier.verify_dsse()``
       against Sigstore's production TUF-managed trust root (Fulcio + Rekor).
    4. Extract the OIDC issuer and subject from the verified signing certificate.
    5. Compare the signing repo against ``expected_repo``.

    Args:
        package_name: Package name (npm or PyPI).
        version: Exact version string.
        source: Ecosystem — ``"npm"`` or ``"pip"``.
        expected_repo: Normalised ``"org/repo"`` from ``RegistryEntry.repo``.

    Returns:
        :class:`AttestationResult` with status, OIDC fields, and
        signing/expected repos.
    """
    try:
        # ── 1. Fetch bundle ───────────────────────────────────────────────────
        if source == "npm":
            bundle_dict = fetch_npm_attestation_bundle(package_name, version)
        else:
            # PyPI requires a filename; use the standard sdist pattern.
            safe_name = package_name.replace("-", "_")
            filename = f"{safe_name}-{version}.tar.gz"
            bundle_dict = fetch_pypi_attestation_bundle(package_name, version, filename)

        if bundle_dict is None:
            return AttestationResult(
                package_name=package_name,
                version=version,
                source=source,
                status="absent",
                oidc_issuer=None,
                oidc_subject=None,
                signing_repo=None,
                expected_repo=expected_repo,
                error=None,
            )

        # ── 2. Parse and verify the bundle ────────────────────────────────────
        try:
            from sigstore.models import Bundle  # noqa: PLC0415
            from sigstore.verify import Verifier  # noqa: PLC0415
            from sigstore.verify.policy import UnsafeNoOp  # noqa: PLC0415
        except ImportError as _import_err:
            raise ImportError(
                "sigstore is not installed. "
                "Enable Sigstore signature verification with: "
                "pip install 'mcp-audit-scanner[attestation]'"
            ) from _import_err

        try:
            bundle = Bundle.from_json(json.dumps(bundle_dict))
            verifier = Verifier.production()
            # verify_dsse validates: Fulcio cert chain, Rekor inclusion proof,
            # and DSSE envelope signature.  UnsafeNoOp defers identity checking
            # to our own repo comparison below — the crypto proof is still full.
            verifier.verify_dsse(bundle, UnsafeNoOp())
        except Exception as exc:  # sigstore VerificationError or parse error
            return AttestationResult(
                package_name=package_name,
                version=version,
                source=source,
                status="invalid",
                oidc_issuer=None,
                oidc_subject=None,
                signing_repo=None,
                expected_repo=expected_repo,
                error=str(exc),
            )

        # ── 3. Extract OIDC fields ────────────────────────────────────────────
        cert = bundle.signing_certificate
        oidc_issuer, oidc_subject = _extract_oidc_fields(cert)

        # ── 4. Compare repos ──────────────────────────────────────────────────
        signing_repo = _extract_signing_repo_from_subject(oidc_subject)
        if expected_repo is None or signing_repo is None:
            # No expected repo to compare against — treat as a match.
            status: VerificationStatus = "valid_match"
        elif signing_repo == expected_repo:
            status = "valid_match"
        else:
            status = "valid_mismatch"

        return AttestationResult(
            package_name=package_name,
            version=version,
            source=source,
            status=status,
            oidc_issuer=oidc_issuer,
            oidc_subject=oidc_subject,
            signing_repo=signing_repo,
            expected_repo=expected_repo,
            error=None,
        )

    except NetworkError as exc:
        return AttestationResult(
            package_name=package_name,
            version=version,
            source=source,
            status="error",
            oidc_issuer=None,
            oidc_subject=None,
            signing_repo=None,
            expected_repo=expected_repo,
            error=str(exc),
        )
