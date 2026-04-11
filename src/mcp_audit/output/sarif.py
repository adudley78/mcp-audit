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

from mcp_audit.models import Finding, ScanResult, Severity

_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main"
    "/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
_VERSION = "2.1.0"
_TOOL_NAME = "mcp-audit"
_TOOL_VERSION = "0.1.0"
_TOOL_URI = "https://github.com/yourusername/mcp-audit"
_HELP_URI = "https://github.com/yourusername/mcp-audit#what-it-detects"

# Maps our severity enum to SARIF result levels.
# SARIF levels: "error" | "warning" | "note" | "none"
_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _finding_to_file_uri(finding_path: str | None) -> str:
    """Convert a finding_path string to a SARIF-compliant file URI.

    Args:
        finding_path: Absolute path string, or ``None``.

    Returns:
        A ``file://`` URI string.  Returns ``file:///unknown`` for missing paths.
    """
    if not finding_path:
        return "file:///unknown"
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
    }
    if finding.analyzer in analyzer_tags:
        tags.append(analyzer_tags[finding.analyzer])

    # CWE tag in GitHub's expected format.
    if finding.cwe:
        cwe_num = finding.cwe.upper().replace("CWE-", "")
        tags.append(f"external/cwe/cwe-{cwe_num.lower()}")

    return {
        "id": finding.id,
        "name": _rule_name_from_title(finding.title),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "helpUri": _HELP_URI,
        "defaultConfiguration": {"level": _LEVEL_MAP[finding.severity]},
        "properties": {"tags": tags},
    }


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
        "fixes": [
            {"description": {"text": finding.remediation}}
        ],
    }

    return result


def format_sarif(result: ScanResult) -> str:
    """Format a ScanResult as a SARIF 2.1.0 JSON string.

    Rules are deduplicated — if multiple findings share the same ``id``, only
    the first occurrence creates a rule entry; subsequent findings reference it
    by ``ruleIndex``.

    Args:
        result: The completed scan result to format.

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
    sarif_results = [
        _build_result(f, rule_index_map[f.id]) for f in result.findings
    ]

    document = {
        "$schema": _SCHEMA,
        "version": _VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(document, indent=2)
