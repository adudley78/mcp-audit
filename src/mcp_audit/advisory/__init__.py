"""Signed, OSV-compatible security advisories for MCP server packages.

There is no CVE/OSV/NVD equivalent for MCP servers. This subsystem turns mcp-audit
scan findings into advisory records that any osv-scanner-compatible tool can already
consume, carrying MCP-specific and OWASP MCP Top 10 metadata under the
``affected[].database_specific`` extension point OSV reserves for exactly this.

Module map:

``schema``     the :class:`~mcp_audit.advisory.schema.Advisory` model and OSV export
``classify``   finding ID → vulnerability class, observation kind, and CVSS vector
``canonical``  RFC 8785 (JCS) canonicalization, the input to every signature
``freshness``  snapshot_version / expires / published_at on index.json only
``feed``       building advisories from findings and writing the feed to disk
``sign``       cosign / minisign signing and ``mcp-audit feed verify``

The vendored OSV 1.6.0 JSON schema lives in ``osv_schema/`` so validation works
offline and in the PyInstaller binary.

OWASP MCP Top 10 codes are **not** redefined here. :mod:`mcp_audit.owasp_mcp` is the
repo's single source of truth for that taxonomy, and the feed publishes the same bare
``MCP01``..``MCP10`` codes that SARIF output and ``docs/owasp-mapping.json`` use.
"""

from __future__ import annotations

from .feed import (
    BuildReport,
    FeedManifest,
    build_advisories,
    build_advisory,
    write_feed,
)
from .schema import (
    SCHEMA_VERSION,
    Advisory,
    Package,
    Reference,
    Severity,
    VerifiedPatch,
)
from .sign import SigningConfig, SigningError, VerifyReport, sign_feed, verify_feed

__all__ = [
    "SCHEMA_VERSION",
    "Advisory",
    "BuildReport",
    "FeedManifest",
    "Package",
    "Reference",
    "Severity",
    "SigningConfig",
    "SigningError",
    "VerifiedPatch",
    "VerifyReport",
    "build_advisories",
    "build_advisory",
    "sign_feed",
    "verify_feed",
    "write_feed",
]
