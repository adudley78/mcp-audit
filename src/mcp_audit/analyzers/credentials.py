"""Detect exposed secrets and credentials in MCP server configurations."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from mcp_audit.analyzers.auth import AUTH_HEADER_NAMES
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


# ── CRED-003: literal secrets in authentication headers ───────────────────────
#
# CRED-003 is *key-driven*, not value-driven, and deliberately does not reuse
# SECRET_PATTERNS as its primary rule. SECRET_PATTERNS is provider-shaped
# (`AKIA…`, `ghp_…`, `sk-…`) plus one "Generic Secret" pattern that requires a
# quoted `key: "value"` shape — a bearer token or raw JWT
# (`Bearer eyJhbGciOi…`) matches none of it. For `headers`, the *key* already
# tells you the value is a credential (this is exactly why AUTH_HEADER_NAMES
# suppresses AUTH-001), so CRED-003 fires on any literal value under a
# recognised auth-header key, independent of its shape. SECRET_PATTERNS is
# still consulted as a supplement for header keys *not* in AUTH_HEADER_NAMES
# (e.g. a custom `X-Custom-Thing: ghp_…`), where the value itself is the only
# available signal.

# Authentication scheme prefixes that may precede the credential in a header
# value (RFC 7235 / RFC 6750). Matched case-insensitively; the captured prefix
# (including trailing whitespace) is preserved verbatim when synthesising a
# fix.
_SCHEME_PREFIX_RE: re.Pattern[str] = re.compile(r"(?i)^(bearer|basic|token)\s+")

# A *full-string* match of an env-var reference — deliberately not
# ``_ENV_REF_RE.search()``, which would wave through
# ``"Bearer sk-live-abc$FOO"`` because it merely *contains* ``$FOO``. The
# correct header value is a scheme prefix followed *entirely* by a single env
# reference; anything else left over after stripping the prefix is live
# material.
_ENV_REF_FULL_RE: re.Pattern[str] = re.compile(
    r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z0-9_]+%)$"
)

# Obvious placeholder/template values. Firing HIGH on a freshly-copied example
# config is the false positive that gets a rule switched off wholesale, and
# template configs are the most-copied configs in the ecosystem — so these
# fire INFO at most rather than being suppressed outright (the header is
# still not wired to an env var, which is worth a nudge before real use).
_PLACEHOLDER_RE: re.Pattern[str] = re.compile(
    r"(?i)^\s*$"  # empty / whitespace-only
    r"|^<[^>]*>$"  # <your-token>, <API_KEY>, ...
    r"|^(your[-_ ]?(api[-_ ]?)?(key|token)|replace[-_]?me|change[-_]?me"
    r"|todo|fixme|placeholder|insert[-_ ]?token[-_ ]?here|x{3,})$"
)


def strip_scheme_prefix(value: str) -> str:
    """Return *value* with a leading auth scheme prefix (``Bearer `` etc.) removed.

    Returns *value* unchanged when no recognised scheme prefix is present, so a
    header with no prefix at all (e.g. ``X-Api-Key: ${API_KEY}``) is handled by
    the same code path as one with ``Bearer``/``Basic``/``Token``.
    """
    return _SCHEME_PREFIX_RE.sub("", value, count=1)


def is_header_value_env_only(value: str) -> bool:
    """Return True if *value* is (optionally scheme-prefixed) purely an env reference.

    This is the "correct form" predicate for CRED-003: a scheme prefix
    followed entirely by a single ``${VAR}``/``$VAR``/``%VAR%`` reference, with
    nothing else. Used both to suppress the finding and, in the fixer, to
    detect an already-remediated header (idempotency).
    """
    return bool(_ENV_REF_FULL_RE.match(strip_scheme_prefix(value)))


def _is_placeholder_value(value: str) -> bool:
    """Return True if *value* looks like a template/placeholder rather than a secret."""
    return bool(_PLACEHOLDER_RE.match(value.strip()))


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

        # Check authentication headers for literal (non-env-referenced) secrets.
        # Any transport — a literal token in a config file on disk is exposed
        # whether or not the transport ever sends it, and a stdio server can
        # carry a stale `headers` block. Not gated on `_is_remote_transport`.
        findings.extend(self._check_headers(server))

        return findings

    # ── CRED-003 ──────────────────────────────────────────────────────────────

    def _check_headers(self, server: ServerConfig) -> list[Finding]:
        """Detect literal secrets in authentication headers (CRED-003)."""
        findings: list[Finding] = []
        for key, value in server.headers.items():
            if key.lower() in AUTH_HEADER_NAMES:
                finding = self._check_auth_header_value(server, key, value)
                if finding is not None:
                    findings.append(finding)
                continue
            # Not a recognised auth-header key: fall back to provider-pattern
            # matching, the one place value-matching earns its keep here — a
            # leaked GitHub token under a non-standard header name is still a
            # leaked GitHub token.
            for secret_name, pattern, provider in SECRET_PATTERNS:
                if pattern.search(value):
                    findings.append(
                        Finding(
                            id="CRED-003",
                            severity=Severity.HIGH,
                            analyzer=self.name,
                            client=server.client,
                            server=server.name,
                            title=f"{provider} credential in server header",
                            description=(
                                f"{secret_name} found in header {key!r}. This is"
                                " not a recognised authentication header name,"
                                f" but its value matches a known {provider}"
                                " credential format."
                            ),
                            evidence=f"Header: {key} | Matches {secret_name} pattern",
                            remediation=(
                                "Move the value out of the header into an"
                                " environment variable, e.g."
                                f' "{key}": "${{MY_SERVER_TOKEN}}", with the'
                                " variable set in the environment."
                            ),
                            cwe="CWE-798",
                            owasp_mcp_top_10=["MCP01"],
                        )
                    )
                    break
        return findings

    def _check_auth_header_value(
        self, server: ServerConfig, key: str, value: str
    ) -> Finding | None:
        """Return a CRED-003 finding for a single recognised auth-header value.

        Returns ``None`` when the value is the documented correct form: an
        optional scheme prefix followed entirely by a single environment
        reference.
        """
        if not value.strip():
            return None

        if is_header_value_env_only(value):
            return None

        if _is_placeholder_value(value):
            return Finding(
                id="CRED-003",
                severity=Severity.INFO,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title="Placeholder value in authentication header",
                description=(
                    f"Server '{server.name}' sets the {key!r} header to what"
                    " looks like a placeholder/template value rather than a"
                    " real credential. Not flagged as a live secret, but the"
                    " header should be wired to an environment variable"
                    " before this configuration is used for anything real."
                ),
                evidence=f"Header: {key} | Placeholder value detected",
                remediation=(
                    f"Replace the placeholder in {key!r} with an environment"
                    f' reference, e.g. "{key}": "Bearer ${{MY_SERVER_TOKEN}}",'
                    " before using this configuration."
                ),
                cwe="CWE-798",
                owasp_mcp_top_10=["MCP01"],
            )

        return Finding(
            id="CRED-003",
            severity=Severity.HIGH,
            analyzer=self.name,
            client=server.client,
            server=server.name,
            title="Live credential embedded in authentication header",
            description=(
                f"Server '{server.name}' sets the {key!r} header — a"
                " recognised authentication header name — to a literal value"
                " rather than an environment reference. The header key alone"
                " is a strong signal the value is a credential; anyone who"
                " can read this configuration file has the live token."
                " Authentication is correctly configured here (AUTH-001 does"
                " not fire); the defect is how the value is stored, not"
                " whether the header is present."
            ),
            evidence=f"Header: {key}",
            remediation=(
                "Keep the header, move the value out: e.g."
                f' "{key}": "Bearer ${{MY_SERVER_TOKEN}}" (or the scheme this'
                " server expects), with MY_SERVER_TOKEN set in the"
                " environment."
            ),
            cwe="CWE-798",
            owasp_mcp_top_10=["MCP01"],
        )
