"""OWASP MCP Top 10 (2025 beta) — category codes, names, and metadata.

Source: https://owasp.org/www-project-mcp-top-10/

The OWASP MCP Top 10 is an MCP-specific risk framework, parallel to the
broader OWASP Agentic Top 10 (ASI01–ASI10). mcp-audit findings are mapped
to BOTH frameworks: the Agentic Top 10 mapping lives in docs/severity-
framework.md; the MCP Top 10 mapping lives in this module and on each
Finding via the ``owasp_mcp_top_10`` field.
"""

from __future__ import annotations

from typing import Final

# Category code → human-readable name.
OWASP_MCP_TOP_10: Final[dict[str, str]] = {
    "MCP01": "Token Mismanagement and Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks",
    "MCP05": "Command Injection and Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication and Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection and Over-sharing",
}

OWASP_MCP_TOP_10_VERSION: Final[str] = "2025-beta"
OWASP_MCP_TOP_10_URI: Final[str] = "https://owasp.org/www-project-mcp-top-10/"


def category_name(code: str) -> str | None:
    """Return the human-readable name for a category code, or None if unknown."""
    return OWASP_MCP_TOP_10.get(code)


def is_valid_code(code: str) -> bool:
    """Return True if ``code`` is a recognised OWASP MCP Top 10 category."""
    return code in OWASP_MCP_TOP_10
