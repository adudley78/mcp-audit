"""Detect exposed secrets and credentials in MCP server configurations."""

from __future__ import annotations

import re

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity

# Patterns for common API key formats
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS"),
    ("AWS Secret Key", re.compile(r"(?i)(aws_secret|secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"), "AWS"),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "GitHub"),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI"),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic"),
    ("Stripe Key", re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}"), "Stripe"),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack"),
    ("Generic Secret", re.compile(r"(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*['\"][^'\"]{8,}['\"]"), "Generic"),
    ("Database URL with creds", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://\w+:[^@]+@"), "Database"),
]


class CredentialsAnalyzer(BaseAnalyzer):
    """Detect secrets and API keys exposed in MCP server configs."""

    @property
    def name(self) -> str:
        return "credentials"

    @property
    def description(self) -> str:
        return "Detect exposed secrets and credentials in configurations"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        findings: list[Finding] = []

        # Check environment variables
        for key, value in server.env.items():
            for secret_name, pattern, provider in SECRET_PATTERNS:
                if pattern.search(value):
                    findings.append(Finding(
                        id="CRED-001",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title=f"{provider} credential in environment",
                        description=f"{secret_name} found in env var '{key}'",
                        evidence=f"env.{key} matches {secret_name} pattern",
                        remediation="Use a credential manager, keychain, or vault reference instead of inline secrets",
                        cwe="CWE-798",
                    ))
                    break  # One finding per env var

        # Check command args for secrets
        args_str = " ".join(server.args)
        for secret_name, pattern, provider in SECRET_PATTERNS:
            match = pattern.search(args_str)
            if match:
                findings.append(Finding(
                    id="CRED-002",
                    severity=Severity.HIGH,
                    analyzer=self.name,
                    client=server.client,
                    server=server.name,
                    title=f"{provider} credential in command arguments",
                    description=f"{secret_name} found in server args",
                    evidence=f"args match {secret_name} pattern",
                    remediation="Pass secrets via environment variables or credential manager, not command args",
                    cwe="CWE-798",
                ))

        return findings
