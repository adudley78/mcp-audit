"""SARIF 2.1.0 output formatter.

Produces a Static Analysis Results Interchange Format (SARIF) document that
GitHub, VS Code, and other SAST platforms consume natively.  Upload the
resulting file to GitHub via the code-scanning API or the ``upload-sarif``
action to surface findings as Security tab alerts and pull-request annotations.

Schema reference:
  https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.owasp_mcp import (
    OWASP_MCP_TOP_10,
    OWASP_MCP_TOP_10_URI,
    OWASP_MCP_TOP_10_VERSION,
)

_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main"
    "/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
_VERSION = "2.1.0"
_TOOL_NAME = "mcp-audit"
_TOOL_VERSION = __version__
_TOOL_URI = "https://github.com/adudley78/mcp-audit"
_HELP_URI = "https://github.com/adudley78/mcp-audit#what-it-detects"

# Maps our severity enum to SARIF result levels.
# SARIF levels: "error" | "warning" | "note" | "none"
_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _build_owasp_mcp_taxonomy() -> dict:
    """Build the SARIF toolComponent that defines the OWASP MCP Top 10."""
    return {
        "name": "OWASP-MCP-Top-10",
        "version": OWASP_MCP_TOP_10_VERSION,
        "informationUri": OWASP_MCP_TOP_10_URI,
        "guid": "f1a3c4d5-9e6b-4a7d-8b2c-1f9e0a3d5c7e",  # stable, mcp-audit-issued
        "isComprehensive": True,
        "shortDescription": {
            "text": "OWASP MCP Top 10 risk categories (2025 beta).",
        },
        "taxa": [
            {
                "id": code,
                "name": name,
                "shortDescription": {"text": name},
            }
            for code, name in OWASP_MCP_TOP_10.items()
        ],
    }


def _finding_to_file_uri(finding_path: str | None) -> str:
    """Convert a finding_path string to a SARIF-compliant file URI.

    When ``uriBaseId`` is ``"%SRCROOT%"`` in the artifact location, GitHub's
    uploader resolves the URI relative to the repository root.  A relative
    sentinel ``"unknown"`` renders as a non-linkable result rather than
    triggering a rejection — ``file:///unknown`` is not a valid artifact URI
    when ``uriBaseId`` is set and causes GitHub to discard the result.

    Args:
        finding_path: Absolute path string, or ``None``.

    Returns:
        A ``file://`` URI string, or the sentinel ``"unknown"`` for missing paths.
    """
    if not finding_path:
        # Relative sentinel — GitHub accepts this and renders as "unknown location."
        return "unknown"
    try:
        return Path(finding_path).as_uri()
    except ValueError:
        return f"file://{finding_path}"


def _rule_name_from_title(title: str) -> str:
    """Convert a human title to a camelCase SARIF rule name.

    Strips punctuation, title-cases each word, and joins without spaces.

    Args:
        title: The finding's ``title`` field.

    Returns:
        A compact camelCase identifier, e.g. ``"SshKeyExfiltration"``.
    """
    words = "".join(c if c.isalnum() or c.isspace() else " " for c in title).split()
    if not words:
        return "UnknownRule"
    return words[0].capitalize() + "".join(w.capitalize() for w in words[1:])


def _build_rule(finding: Finding) -> dict:
    """Build a SARIF ``reportingDescriptor`` (rule) object for a finding.

    Args:
        finding: A representative finding for this rule ID.

    Returns:
        A dict conforming to the SARIF ``reportingDescriptor`` schema.
    """
    tags = ["security", "mcp"]

    # Derive a subcategory tag from the analyzer name.
    analyzer_tags: dict[str, str] = {
        "poisoning": "tool-poisoning",
        "credentials": "credentials",
        "transport": "transport-security",
        "supply_chain": "supply-chain",
        "rug_pull": "rug-pull",
        "governance": "governance-policy",
    }
    if finding.analyzer in analyzer_tags:
        tags.append(analyzer_tags[finding.analyzer])

    # CWE tag in GitHub's expected format.
    if finding.cwe:
        cwe_num = finding.cwe.upper().replace("CWE-", "")
        tags.append(f"external/cwe/cwe-{cwe_num.lower()}")

    rule: dict = {
        "id": finding.id,
        "name": _rule_name_from_title(finding.title),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        # SARIF 2.1.0 §3.49.11: `help` carries free-text remediation advice.
        # This is the correct home for actionable guidance; the `fixes` field
        # (§3.55) is reserved for structured byte-level code patches only.
        "help": {"text": finding.remediation},
        "helpUri": _HELP_URI,
        "defaultConfiguration": {"level": _LEVEL_MAP[finding.severity]},
        "properties": {"tags": tags},
    }

    if finding.owasp_mcp_top_10:
        # Belt-and-braces: embed codes in the properties bag for consumers
        # that don't process the taxonomies/relationships machinery.
        rule["properties"]["owasp-mcp-top-10"] = finding.owasp_mcp_top_10

        # SARIF 2.1.0 §3.52: relationships link this rule to taxonomy taxa.
        rule["relationships"] = [
            {
                "target": {
                    "id": code,
                    "toolComponent": {"name": "OWASP-MCP-Top-10"},
                },
                "kinds": ["relevant"],
            }
            for code in finding.owasp_mcp_top_10
        ]

    if finding.cve:
        rule["properties"]["cve"] = finding.cve

    return rule


def _build_result(finding: Finding, rule_index: int) -> dict:
    """Build a SARIF ``result`` object for a finding.

    Args:
        finding: The finding to serialise.
        rule_index: The index of this finding's rule in ``tool.driver.rules``.

    Returns:
        A dict conforming to the SARIF ``result`` schema.
    """
    message_text = (
        f"{finding.title} detected in {finding.client}/{finding.server}. "
        f"{finding.description}"
    )
    # Governance findings use the policy file as the artifact location.
    if finding.analyzer == "governance":
        uri = (
            _finding_to_file_uri(finding.finding_path)
            if finding.finding_path
            else "policy"
        )
    else:
        uri = _finding_to_file_uri(finding.finding_path)

    result: dict = {
        "ruleId": finding.id,
        "ruleIndex": rule_index,
        "level": _LEVEL_MAP[finding.severity],
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        ],
    }

    return result


def format_sarif(
    result: ScanResult,
    asset_prefix: str | None = None,
) -> str:
    """Format a ScanResult as a SARIF 2.1.0 JSON string.

    Rules are deduplicated — if multiple findings share the same ``id``, only
    the first occurrence creates a rule entry; subsequent findings reference it
    by ``ruleIndex``.

    Machine identity is recorded in ``runs[0].invocations[0]`` using the SARIF
    ``machine``, ``account``, and ``operatingSystem`` properties.  *asset_prefix*
    overrides the ``machine`` property when supplied (mirrors Nucleus behaviour).

    Args:
        result: The completed scan result to format.
        asset_prefix: Override the hostname in the invocation ``machine``
            property.  Useful when the hostname is not meaningful.

    Returns:
        Pretty-printed JSON string conforming to the SARIF 2.1.0 schema.
    """
    # ── Build deduplicated rule index ─────────────────────────────────────────
    # Preserves insertion order (first finding wins for the rule definition).
    rule_index_map: dict[str, int] = {}
    rules: list[dict] = []

    for finding in result.findings:
        if finding.id not in rule_index_map:
            rule_index_map[finding.id] = len(rules)
            rules.append(_build_rule(finding))

    # ── Build results ─────────────────────────────────────────────────────────
    sarif_results = [_build_result(f, rule_index_map[f.id]) for f in result.findings]

    effective_machine = (
        asset_prefix if asset_prefix is not None else result.machine.hostname
    )

    # SARIF 2.1.0 §3.20 declares `invocation` with `additionalProperties: false`,
    # so custom fields must go inside the `properties` (propertyBag) key.
    invocation = {
        "executionSuccessful": True,
        "properties": {
            "machine": effective_machine,
            "account": result.machine.username,
            "operatingSystem": (
                f"{result.machine.os} {result.machine.os_version}".strip()
            ),
        },
    }

    run: dict = {
        "tool": {
            "driver": {
                "name": _TOOL_NAME,
                "version": _TOOL_VERSION,
                "informationUri": _TOOL_URI,
                "rules": rules,
            }
        },
        # GitHub uses automationDetails.id to deduplicate uploads from the same
        # tool across multiple workflow runs; without it, re-uploading produces
        # duplicate alerts in the Security tab.
        "automationDetails": {
            "id": f"mcp-audit/{result.machine.hostname or 'scan'}",
        },
        # Required by SARIF 2.1.0 §3.14.14: any uriBaseId token used in
        # artifactLocation entries must be declared here so consumers can
        # resolve relative paths.  GitHub's uploader uses this to anchor
        # %SRCROOT% at the repository root.
        "originalUriBaseIds": {
            "%SRCROOT%": {
                "uri": "file:///",
                "description": {
                    "text": "The root directory of the scanned repository."
                },
            }
        },
        "invocations": [invocation],
        "results": sarif_results,
        "taxonomies": [_build_owasp_mcp_taxonomy()],
    }

    if result.score is not None:
        run["properties"] = {
            "mcp-audit/grade": result.score.grade,
            "mcp-audit/numericScore": result.score.numeric_score,
            "mcp-audit/positiveSignals": result.score.positive_signals,
            "mcp-audit/deductions": result.score.deductions,
        }

    document = {
        "$schema": _SCHEMA,
        "version": _VERSION,
        "runs": [run],
    }

    return json.dumps(document, indent=2)
