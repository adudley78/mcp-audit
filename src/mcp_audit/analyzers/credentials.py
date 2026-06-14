"""Detect exposed secrets and credentials in MCP server configurations."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity

# Patterns for common API key formats.
# EVASION-KNOWN (see GAPS.md "Known detection evasions"):
#   High-entropy tokens with no recognised prefix and not matching the generic
#   "password|secret|token|api_key" =/: quoted form are not caught (no
#   entropy-based detector — same class as the "Pattern coverage is thin" note).
#   Closing it needs a Shannon-entropy check + allow-list.
# fmt: off
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key",
     re.compile(r"AKIA[0-9A-Z]{16}"), "AWS"),
    ("AWS Secret Key",
     re.compile(r"(?i)(aws_secret|secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"), "AWS"),
    ("GitHub Token",
     re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "GitHub"),
    ("GitHub Fine-Grained PAT",
     re.compile(r"github_pat_[A-Za-z0-9_]{82}"), "GitHub"),
    ("OpenAI API Key",
     re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI"),
    ("Anthropic API Key",
     re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic"),
    ("Stripe Key",
     re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}"), "Stripe"),
    ("Slack Token",
     re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack"),
    ("GCP Service Account Key",
     re.compile(r'"private_key"\s*:\s*"-----BEGIN'), "GCP"),
    ("Azure SAS Token",
     re.compile(r"sv=\d{4}-\d{2}-\d{2}[^\s\"']{0,200}&sig=[A-Za-z0-9+/=]+"), "Azure"),
    ("DigitalOcean Token",
     re.compile(r"dop_v1_[a-f0-9]{64}"), "DigitalOcean"),
    ("Vercel Token",
     re.compile(r"vercel_[a-zA-Z0-9]{20,}"), "Vercel"),
    ("PEM Private Key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "PEM"),
    ("HashiCorp Vault Service Token",
     re.compile(r"hvs\.[A-Za-z0-9_-]{90,}"), "Vault"),
    ("HashiCorp Vault Batch Token",
     re.compile(r"hvb\.[A-Za-z0-9_-]{90,}"), "Vault"),
    ("Generic Secret",
     re.compile(
         r"(?i)(password|secret|token|api_key|apikey)"
         r"\s*[=:]\s*['\"][^'\"]{8,}['\"]"
     ), "Generic"),
    ("Database URL with creds",
     re.compile(r"(?i)(postgres|mysql|mongodb|redis)://\w+:[^@]+@"), "Database"),
]
# fmt: on

# Env-var reference forms that must NOT be flagged as literal credentials:
#   ${VAR}  /  $VAR  /  %VAR%   (POSIX and Windows substitution syntaxes)
_ENV_REF_RE: re.Pattern[str] = re.compile(
    r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z0-9_]+%"
)


def _is_env_reference(value: str) -> bool:
    """Return True if *value* is an environment-variable reference, not a literal."""
    return bool(_ENV_REF_RE.search(value))


def _redact_url_password(url: str, password: str) -> str:
    """Return *url* with the userinfo password replaced by ``***``.

    Uses a single literal replacement of ``:<password>@`` so the rest of the URL
    (scheme, username, host, port, path) is preserved exactly for the evidence
    string — the analyst sees the real URL shape without the secret.
    """
    return url.replace(f":{password}@", ":***@", 1)


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
                    findings.append(
                        Finding(
                            id="CRED-001",
                            severity=Severity.HIGH,
                            analyzer=self.name,
                            client=server.client,
                            server=server.name,
                            title=f"{provider} credential in environment",
                            description=f"{secret_name} found in env var '{key}'",
                            evidence=f"env.{key} matches {secret_name} pattern",
                            remediation=(
                                "Use a credential manager, keychain, or vault"
                                " reference instead of inline secrets"
                            ),
                            cwe="CWE-798",
                            owasp_mcp_top_10=["MCP01"],
                        )
                    )
                    break  # One finding per env var

        # Check command args for secrets
        args_str = " ".join(server.args)
        for secret_name, pattern, provider in SECRET_PATTERNS:
            match = pattern.search(args_str)
            if match:
                findings.append(
                    Finding(
                        id="CRED-002",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title=f"{provider} credential in command arguments",
                        description=f"{secret_name} found in server args",
                        evidence=f"args match {secret_name} pattern",
                        remediation=(
                            "Pass secrets via environment variables"
                            " or credential manager, not command args"
                        ),
                        cwe="CWE-798",
                        owasp_mcp_top_10=["MCP01"],
                    )
                )

        # Check the server URL for credentials embedded in the userinfo field
        # ("https://user:password@host").  Env-var references ("${PASSWORD}")
        # are intentionally ignored — only literal embedded secrets are flagged.
        if server.url:
            try:
                parsed = urlparse(server.url)
            except ValueError:
                parsed = None
            if (
                parsed is not None
                and parsed.password
                and not _is_env_reference(parsed.password)
            ):
                redacted = _redact_url_password(server.url, parsed.password)
                findings.append(
                    Finding(
                        id="CRED-001",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title="Credential embedded in server URL",
                        description=(
                            "The server URL embeds a plaintext credential in its"
                            " userinfo component. Credentials in URLs are logged by"
                            " proxies, shells, and history files, and are visible to"
                            " anyone who can read the configuration."
                        ),
                        evidence=f"URL: {redacted}",
                        remediation=(
                            "Move the credential to an environment variable or"
                            " credential manager and reference it (e.g."
                            " Authorization header via ${TOKEN}); never embed"
                            " secrets in the URL."
                        ),
                        cwe="CWE-798",
                        owasp_mcp_top_10=["MCP01"],
                    )
                )

        return findings
