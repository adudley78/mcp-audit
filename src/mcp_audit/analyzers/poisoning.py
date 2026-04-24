"""Detect tool description poisoning in MCP server configurations.

Tool poisoning embeds malicious instructions in MCP tool descriptions that
are visible to the LLM but hidden from users in client UIs. This analyzer
uses regex pattern matching to detect common poisoning patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity


@dataclass
class DetectionPattern:
    """A single detection pattern with metadata."""

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    remediation: str
    cwe: str | None = None
    description_only: bool = False


# fmt: off
PATTERNS: list[DetectionPattern] = [
    # CRITICAL: File exfiltration
    DetectionPattern(
        id="POISON-001",
        name="SSH key exfiltration",
        pattern=re.compile(
            r"(\.ssh[/\\]|id_rsa|id_ed25519|authorized_keys)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Tool description references SSH key files,"
            " suggesting data exfiltration"
        ),
        remediation="Remove this MCP server immediately and rotate SSH keys",
        cwe="CWE-200",
    ),
    DetectionPattern(
        id="POISON-002",
        name="Cloud credential exfiltration",
        pattern=re.compile(
            r"(\.aws[/\\]credentials|\.azure[/\\]|\.gcloud[/\\]|\.kube[/\\]config)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="Tool description references cloud credential files",
        remediation="Remove this MCP server and rotate cloud credentials",
        cwe="CWE-200",
    ),
    DetectionPattern(
        id="POISON-003",
        name="Environment file exfiltration",
        pattern=re.compile(
            r"(read|access|cat|contents?\s+of)\s+.*\.env\b",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="Tool description instructs reading .env files containing secrets",
        remediation="Remove this MCP server and rotate any exposed secrets",
        cwe="CWE-200",
    ),

    # HIGH: Instruction injection markers
    DetectionPattern(
        id="POISON-010",
        name="XML instruction injection",
        pattern=re.compile(
            r"<(IMPORTANT|SYSTEM|INSTRUCTION|OVERRIDE|PRIORITY)>",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Tool description contains XML-style"
            " instruction injection markers"
        ),
        remediation=(
            "Remove this MCP server; these markers"
            " are used to hijack agent behavior"
        ),
        cwe="CWE-74",
    ),
    DetectionPattern(
        id="POISON-011",
        name="LLM prompt injection markers",
        pattern=re.compile(
            r"(\[INST\]|<<SYS>>|<\|im_start\|>|<\|system\|>)",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Tool description contains LLM prompt format injection markers",
        remediation="Remove this MCP server; these exploit LLM instruction parsing",
        cwe="CWE-74",
    ),
    DetectionPattern(
        id="POISON-012",
        name="Behavioral override instructions",
        pattern=re.compile(
            r"(ignore\s+(previous|prior|all)\s+instructions|"
            r"do\s+not\s+(mention|tell|reveal|say|inform)|"
            r"override\s+(previous|prior|default)|"
            r"disregard\s+(previous|prior|all|any))",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Tool description attempts to override agent behavior",
        remediation="Remove this MCP server; it contains behavioral manipulation",
        cwe="CWE-74",
    ),

    # HIGH: Data exfiltration language
    DetectionPattern(
        id="POISON-020",
        name="Data exfiltration via encoding",
        pattern=re.compile(
            r"(encode\s+(in|as|to)\s+base64|"
            r"convert\s+to\s+base64|"
            r"base64[\.\s]+encode|"
            r"append\s+to\s+(url|query|parameter)|"
            r"send\s+to\s+(endpoint|server|url|webhook))",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Tool description contains data exfiltration language",
        remediation=(
            "Remove this MCP server;"
            " it may exfiltrate data via encoded channels"
        ),
        cwe="CWE-200",
    ),
    DetectionPattern(
        id="POISON-021",
        name="Hidden parameter exfiltration",
        pattern=re.compile(
            r"(pass\s+(content|data|value|result|output)\s+(as|in|via)\s+['\"]?\w+['\"]?|"
            r"include\s+(content|data)\s+in\s+(the\s+)?(request|response|header|parameter))",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Tool description instructs passing data through hidden parameters",
        remediation="Remove this MCP server; it channels data through side channels",
        cwe="CWE-200",
    ),

    # MEDIUM: Cross-tool manipulation
    DetectionPattern(
        id="POISON-030",
        name="Cross-tool manipulation",
        pattern=re.compile(
            r"(before\s+using\s+this\s+tool|"
            r"first\s+call|"
            r"instead\s+(of\s+)?(use|using|call)|"
            r"after\s+(calling|using)\s+this)",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        description="Tool description attempts to influence usage of other tools",
        remediation=(
            "Review this MCP server; cross-tool instructions"
            " may indicate tool shadowing"
        ),
        cwe="CWE-441",
    ),

    # MEDIUM: Stealth techniques
    DetectionPattern(
        id="POISON-040",
        name="Zero-width Unicode characters",
        pattern=re.compile(r"[\u200b\u200c\u200d\ufeff\u2060\u00ad\u034f]"),
        severity=Severity.MEDIUM,
        description=(
            "Tool description contains invisible Unicode"
            " characters used for stealth"
        ),
        remediation=(
            "Investigate this MCP server;"
            " zero-width chars hide malicious instructions"
        ),
        cwe="CWE-116",
    ),

    # HIGH: Unicode homoglyph substitution
    DetectionPattern(
        id="POISON-060",
        name="Unicode homoglyph substitution",
        pattern=re.compile(
            # Cyrillic (U+0400–U+04FF) and Greek (U+0370–U+03FF) code-points
            # are visually identical to many ASCII letters and are the dominant
            # script families used in homoglyph attacks against Latin text.
            r"[\u0370-\u03FF\u0400-\u04FF]"
        ),
        severity=Severity.HIGH,
        description=(
            "Tool description contains Unicode characters from Cyrillic or Greek"
            " blocks that are visually identical to ASCII letters (homoglyphs)."
            " Attackers use this technique to hide malicious instructions from"
            " human reviewers while keeping them readable to language models."
        ),
        remediation=(
            "Review the full tool description for hidden instructions."
            " Remove any non-ASCII characters that are not legitimately required."
        ),
        cwe="CWE-116",
    ),

    # LOW: Suspicious signals
    DetectionPattern(
        id="POISON-050",
        name="Excessive description length",
        pattern=re.compile(r".{2000,}", re.DOTALL),
        severity=Severity.LOW,
        description=(
            "Tool description contains an unusually long string (≥2000 characters)."
            " Oversized tool descriptions can be used to inject hidden instructions"
            " into the AI model's context window."
            " Note: only tool name and description fields are checked —"
            " long command paths or arguments are not flagged by this rule."
        ),
        remediation="Review the full tool description for hidden instructions",
        description_only=True,
    ),
]
# fmt: on


class PoisoningAnalyzer(BaseAnalyzer):
    """Detect tool description poisoning in MCP server configurations."""

    @property
    def name(self) -> str:
        return "poisoning"

    @property
    def description(self) -> str:
        return "Detect malicious instructions in tool descriptions"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Analyze a server's tool descriptions for poisoning patterns.

        For static config analysis, this checks the raw config data for
        tool-like structures. Full tool enumeration via MCP protocol
        connection will be added in a future version.

        Patterns marked ``description_only=True`` (currently POISON-050) are
        applied only to ``name`` and ``description`` keys in the config — the
        fields an AI model reads when deciding whether to invoke a tool.
        Fields such as ``command``, ``args``, and env values are not
        model-visible and are excluded from those checks.
        """
        findings: list[Finding] = []

        general_patterns = [p for p in PATTERNS if not p.description_only]
        description_only_patterns = [p for p in PATTERNS if p.description_only]

        # All string values — used for patterns that cover every field.
        all_texts = self._extract_text_fields(server.raw)
        for text in all_texts:
            for pattern in general_patterns:
                match = pattern.pattern.search(text)
                if match:
                    findings.append(
                        Finding(
                            id=pattern.id,
                            severity=pattern.severity,
                            analyzer=self.name,
                            client=server.client,
                            server=server.name,
                            title=pattern.name,
                            description=pattern.description,
                            evidence=f"Matched: {match.group()[:100]}",
                            remediation=pattern.remediation,
                            cwe=pattern.cwe,
                        )
                    )

        # Only description/name values — used for patterns whose threat model
        # is specifically about oversized or manipulated tool descriptions.
        if description_only_patterns:
            description_texts = self._extract_description_fields(server.raw)
            for text in description_texts:
                for pattern in description_only_patterns:
                    match = pattern.pattern.search(text)
                    if match:
                        findings.append(
                            Finding(
                                id=pattern.id,
                                severity=pattern.severity,
                                analyzer=self.name,
                                client=server.client,
                                server=server.name,
                                title=pattern.name,
                                description=pattern.description,
                                evidence=f"Matched: {match.group()[:100]}",
                                remediation=pattern.remediation,
                                cwe=pattern.cwe,
                            )
                        )

        return findings

    def _extract_text_fields(
        self,
        data: dict | list | str,
        depth: int = 0,
    ) -> list[str]:
        """Recursively extract all string values from a nested structure."""
        if depth > 50:
            return []

        texts: list[str] = []
        if isinstance(data, str):
            texts.append(data)
        elif isinstance(data, dict):
            for value in data.values():
                texts.extend(self._extract_text_fields(value, depth + 1))
        elif isinstance(data, list):
            for item in data:
                texts.extend(self._extract_text_fields(item, depth + 1))
        return texts

    def _extract_description_fields(
        self,
        data: dict | list | str,
        depth: int = 0,
    ) -> list[str]:
        """Extract only ``name`` and ``description`` values from a nested structure.

        These are the fields an AI model reads when deciding whether to call a
        tool.  Command paths, argument lists, and environment variable values
        are intentionally excluded because they are not model-visible and do
        not constitute an attack surface for tool description padding.
        """
        if depth > 50:
            return []

        texts: list[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ("description", "name"):
                    if isinstance(value, str):
                        texts.append(value)
                    # Non-string description/name values are not collected.
                else:
                    texts.extend(self._extract_description_fields(value, depth + 1))
        elif isinstance(data, list):
            for item in data:
                texts.extend(self._extract_description_fields(item, depth + 1))
        return texts
