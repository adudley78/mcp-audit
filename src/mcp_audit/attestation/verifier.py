"""High-level attestation verifier: bridges registry hashes, hasher, and findings.

Translates :class:`~mcp_audit.attestation.hasher.HashResult` objects into
:class:`~mcp_audit.models.Finding` objects that flow through all standard
output formatters automatically.
"""

from __future__ import annotations

import hashlib
import json
import re

from mcp_audit.attestation.hasher import HashResult, verify_package_hash
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import KnownServerRegistry

# Pattern: npx [flags] package[@version] [args...]
# Captures the version suffix after the last '@' in an npx argument token.
_NPX_VERSION_RE = re.compile(r"(?:^|[\s/])([^\s@]+)@([^\s]+)")


def extract_version_from_server(server: ServerConfig) -> str | None:
    """Best-effort version extraction from a server config.

    Inspects the command and its args for an ``@version`` suffix in npm-style
    package specifiers (e.g. ``npx @scope/pkg@1.2.3``).

    Args:
        server: Parsed MCP server configuration.

    Returns:
        Version string when found, otherwise ``None``.
    """
    if server.command != "npx":
        return None

    # Search through args for a token containing '@' that looks like pkg@version.
    for arg in server.args:
        # Skip flags (--flag)
        if arg.startswith("-"):
            continue
        # Scoped: @scope/name@version  →  the version is after the second '@'
        if arg.startswith("@"):
            # e.g. "@modelcontextprotocol/server-filesystem@0.6.2"
            # split at '/', then check the right side for '@version'
            parts = arg.split("/", 1)
            if len(parts) == 2 and "@" in parts[1]:
                version = parts[1].rsplit("@", 1)[1]
                if version:
                    return version
        elif "@" in arg:
            # Unscoped: "some-package@0.5.0"
            version = arg.rsplit("@", 1)[1]
            if version:
                return version

    return None


def _deterministic_id(package_name: str, version: str, kind: str) -> str:
    """Return a short deterministic finding ID based on the input tuple.

    Args:
        package_name: Package name string.
        version: Version string.
        kind: Discriminator such as ``"hash_mismatch"`` or ``"unverifiable"``.

    Returns:
        ``"ATT-<8-hex-chars>"`` string.
    """
    raw = f"{package_name}:{version}:{kind}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"ATT-{digest}"


def _hash_result_to_finding(
    result: HashResult,
    server: ServerConfig,
    package_name: str,
    version: str,
) -> Finding | None:
    """Convert a :class:`HashResult` to a :class:`Finding`, or ``None`` if clean.

    Args:
        result: Hash verification outcome.
        server: The server config that triggered this verification.
        package_name: Package name from the registry.
        version: Version string that was verified.

    Returns:
        A :class:`Finding` on mismatch or unverifiable; ``None`` when clean.
    """
    if result.match is True:
        return None

    if result.match is False:
        evidence = json.dumps(
            {
                "package_name": package_name,
                "version": version,
                "expected_hash": result.expected_hash,
                "computed_hash": result.computed_hash,
                "source_url": result.source_url,
            }
        )
        return Finding(
            id=_deterministic_id(package_name, version, "hash_mismatch"),
            severity=Severity.CRITICAL,
            analyzer="attestation",
            client=server.client,
            server=server.name,
            title=f"Package hash mismatch: {package_name}@{version}",
            description=(
                f"Expected {result.expected_hash}, got {result.computed_hash}. "
                "Package may have been tampered with."
            ),
            evidence=evidence,
            remediation=(
                "Do not use this package until the integrity issue is resolved. "
                "Verify the package on the registry, compare with a known-good "
                "installation, and contact the package maintainer."
            ),
            cwe="CWE-494",
            finding_path=str(server.config_path),
        )

    # match is None — could not verify
    evidence = json.dumps(
        {
            "package_name": package_name,
            "version": version,
            "expected_hash": result.expected_hash,
            "computed_hash": result.computed_hash or None,
            "source_url": result.source_url,
        }
    )
    return Finding(
        id=_deterministic_id(package_name, version, "unverifiable"),
        severity=Severity.INFO,
        analyzer="attestation",
        client=server.client,
        server=server.name,
        title=f"Could not verify package hash: {package_name}@{version}",
        description=result.source_url or "Hash verification could not be completed.",
        evidence=evidence,
        remediation=(
            "Ensure network access is available and re-run with --verify-hashes."
        ),
        finding_path=str(server.config_path),
    )


def verify_server_hashes(
    servers: list[ServerConfig],
    registry: KnownServerRegistry,
) -> list[Finding]:
    """Verify package hashes for all servers that have pinned hashes in the registry.

    For each server:

    1. Look up its registry entry via the server name.
    2. Skip if no entry or entry has no ``known_hashes``.
    3. Extract the installed version from the server config.
    4. Look up the expected hash for that version.
    5. Call :func:`~mcp_audit.attestation.hasher.verify_package_hash`.
    6. Produce findings based on outcome.

    Args:
        servers: All discovered server configurations.
        registry: Loaded :class:`~mcp_audit.registry.loader.KnownServerRegistry`.

    Returns:
        List of :class:`~mcp_audit.models.Finding` objects (CRITICAL or INFO).
        An empty list means every verifiable package was clean.
    """
    findings: list[Finding] = []

    for server in servers:
        entry = registry.get(server.name)
        if entry is None or not entry.known_hashes:
            continue

        version = extract_version_from_server(server)

        if version is None:
            findings.append(
                Finding(
                    id=_deterministic_id(entry.name, "unknown", "no_version"),
                    severity=Severity.INFO,
                    analyzer="attestation",
                    client=server.client,
                    server=server.name,
                    title=f"Version unknown — cannot verify hash: {entry.name}",
                    description=(
                        f"A hash is pinned for {entry.name} in the registry but the "
                        "installed version could not be determined from the server "
                        "configuration."
                    ),
                    evidence=json.dumps(
                        {
                            "package_name": entry.name,
                            "version": None,
                            "pinned_versions": list(entry.known_hashes.keys()),
                        }
                    ),
                    remediation=(
                        "Pin the package version explicitly in the npx command "
                        f"(e.g. npx {entry.name}@<version>)."
                    ),
                    finding_path=str(server.config_path),
                )
            )
            continue

        expected_hash = entry.known_hashes.get(version)

        if expected_hash is None:
            findings.append(
                Finding(
                    id=_deterministic_id(entry.name, version, "no_hash_pinned"),
                    severity=Severity.INFO,
                    analyzer="attestation",
                    client=server.client,
                    server=server.name,
                    title=f"No hash pinned for {entry.name}@{version}",
                    description=(
                        f"Version {version!r} is not in the registry's known_hashes "
                        f"for {entry.name}. Integrity cannot be verified."
                    ),
                    evidence=json.dumps(
                        {
                            "package_name": entry.name,
                            "version": version,
                            "pinned_versions": list(entry.known_hashes.keys()),
                        }
                    ),
                    remediation=(
                        "Consider contributing the hash for this version to the "
                        "mcp-audit registry, or pin a version that has a known hash."
                    ),
                    finding_path=str(server.config_path),
                )
            )
            continue

        result = verify_package_hash(
            package_name=entry.name,
            version=version,
            source=entry.source,
            expected_hash=expected_hash,
        )

        finding = _hash_result_to_finding(result, server, entry.name, version)
        if finding is not None:
            findings.append(finding)

    return findings
