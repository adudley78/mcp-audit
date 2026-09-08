"""Fix strategy for CRED-001, CRED-002, and CRED-003 — redact plaintext secrets."""

from __future__ import annotations

import copy
import re

from mcp_audit.analyzers.credentials import (
    SECRET_PATTERNS,
    is_header_value_env_only,
    strip_scheme_prefix,
)
from mcp_audit.fixer.strategies.base import BaseFixStrategy, find_server_section
from mcp_audit.models import Finding

# Matches an already-redacted placeholder so we can skip idempotent re-runs.
_PLACEHOLDER_RE: re.Pattern[str] = re.compile(r"^\$\{[^}]+\}$")

# Parses the env key name from CRED-001 evidence:
# "env.GITHUB_TOKEN matches GitHub Token pattern"
_ENV_KEY_RE: re.Pattern[str] = re.compile(r"^env\.(\w+)\s+matches")

# Parses the header key from CRED-003 evidence, which always starts with
# "Header: <key>" regardless of which of the three CRED-003 branches fired
# (a trailing " | ..." detail may follow, e.g. "| Matches GitHub Token pattern").
_HEADER_KEY_RE: re.Pattern[str] = re.compile(r"^Header:\s*([^|]+)")

# Characters not valid in a bare env-var name, collapsed to a single "_" when
# synthesising a placeholder name from a header key (e.g. "X-Api-Key" ->
# "X_API_KEY").
_NON_ENV_NAME_CHARS_RE: re.Pattern[str] = re.compile(r"[^A-Za-z0-9]+")


def _synthesize_env_name(header_key: str) -> str:
    """Derive a placeholder env-var name from a header key.

    This mirrors CRED-002's own precedent (``${REDACTED_SECRET}`` — a
    generic, recognisable placeholder rather than a guessed "real" name) but
    keys it to the header so two different headers on the same server don't
    collide on one shared name.
    """
    name = _NON_ENV_NAME_CHARS_RE.sub("_", header_key).strip("_").upper()
    return name or "TOKEN"


class CredentialsFixStrategy(BaseFixStrategy):
    """Redact plaintext credentials found by the credentials analyzer.

    * **CRED-001** (env var) — replaces the secret value with
      ``${ENV_KEY_NAME}`` using the key name extracted from the finding
      evidence.  The env key itself is preserved so the config remains
      structurally valid.
    * **CRED-002** (command args) — searches the args list for the first
      token that matches a known secret pattern and replaces the matching
      substring with ``${REDACTED_SECRET}``.
    * **CRED-003** (authentication header) — replaces the value with a
      synthesised ``${HEADER_NAME}`` placeholder. Any scheme prefix
      (``Bearer ``, ``Basic ``, ``Token ``) already present in the value is
      preserved; only the credential tail is replaced.

    All three fixes are idempotent: if the value already matches ``${…}``
    (optionally scheme-prefixed, for CRED-003), the config is returned
    unchanged.
    """

    def can_fix(self, finding: Finding) -> bool:
        return finding.id in ("CRED-001", "CRED-002", "CRED-003")

    def apply(self, config: dict, finding: Finding) -> tuple[dict, str]:
        server_dict, root_key = find_server_section(config, finding.server)
        if server_dict is None or root_key is None:
            raise ValueError(
                f"Server {finding.server!r} not found in config; cannot apply fix."
            )

        if finding.id == "CRED-001":
            return self._fix_env(config, root_key, finding)
        if finding.id == "CRED-002":
            return self._fix_args(config, root_key, finding)
        return self._fix_header(config, root_key, finding)

    # ── CRED-001 ──────────────────────────────────────────────────────────────

    def _fix_env(
        self, config: dict, root_key: str, finding: Finding
    ) -> tuple[dict, str]:
        """Replace a plaintext env-var value with a ``${KEY}`` placeholder."""
        m = _ENV_KEY_RE.match(finding.evidence)
        if m is None:
            raise ValueError(
                f"Cannot parse env key from CRED-001 evidence: {finding.evidence!r}"
            )
        env_key = m.group(1)

        server_dict = config[root_key][finding.server]
        env = server_dict.get("env", {})

        current_value = env.get(env_key)
        if current_value is None:
            raise ValueError(
                f"Env key {env_key!r} not found in server {finding.server!r}."
            )

        # Idempotent: already a placeholder.
        if _PLACEHOLDER_RE.match(str(current_value)):
            return config, f"env.{env_key} already redacted (already fixed)"

        new_config = copy.deepcopy(config)
        new_config[root_key][finding.server]["env"][env_key] = f"${{{env_key}}}"
        return (
            new_config,
            f"Redacted env.{env_key} → ${{{env_key}}} in {finding.server!r}",
        )

    # ── CRED-002 ──────────────────────────────────────────────────────────────

    def _fix_args(
        self, config: dict, root_key: str, finding: Finding
    ) -> tuple[dict, str]:
        """Replace a secret substring inside command args with a placeholder."""
        server_dict = config[root_key][finding.server]
        args: list[str] = server_dict.get("args", [])

        new_args = list(args)
        fixed_count = 0
        for i, arg in enumerate(new_args):
            for _name, pattern, _provider in SECRET_PATTERNS:
                m = pattern.search(arg)
                if m:
                    # Idempotent: already a placeholder.
                    if _PLACEHOLDER_RE.match(arg.strip()):
                        continue
                    new_args[i] = pattern.sub("${REDACTED_SECRET}", arg)
                    fixed_count += 1
                    break  # one substitution per arg

        if fixed_count == 0:
            return (
                config,
                f"No secret patterns matched in args for "
                f"{finding.server!r} (already fixed)",
            )

        new_config = copy.deepcopy(config)
        new_config[root_key][finding.server]["args"] = new_args
        return (
            new_config,
            f"Redacted {fixed_count} secret(s) in args for {finding.server!r}",
        )

    # ── CRED-003 ──────────────────────────────────────────────────────────────

    def _fix_header(
        self, config: dict, root_key: str, finding: Finding
    ) -> tuple[dict, str]:
        """Replace a literal header value with a ``${NAME}`` placeholder.

        A scheme prefix (``Bearer ``, ``Basic ``, ``Token ``) already present
        in the value is preserved verbatim — only the tail is replaced —
        because the placeholder is a drop-in credential, not a header rewrite.
        """
        m = _HEADER_KEY_RE.match(finding.evidence)
        if m is None:
            raise ValueError(
                f"Cannot parse header key from CRED-003 evidence: {finding.evidence!r}"
            )
        header_key = m.group(1).strip()

        server_dict = config[root_key][finding.server]
        headers = server_dict.get("headers", {})

        current_value = headers.get(header_key)
        if current_value is None:
            raise ValueError(
                f"Header {header_key!r} not found in server {finding.server!r}."
            )

        # Idempotent: already the documented correct form.
        if is_header_value_env_only(str(current_value)):
            return config, f"headers.{header_key} already redacted (already fixed)"

        # Reuse the analyzer's own prefix-stripping so "what counts as a
        # scheme prefix" is defined in exactly one place: whatever
        # strip_scheme_prefix() removes from the front is the prefix to keep.
        raw_value = str(current_value)
        remainder = strip_scheme_prefix(raw_value)
        prefix = raw_value[: len(raw_value) - len(remainder)]
        env_name = _synthesize_env_name(header_key)
        new_value = f"{prefix}${{{env_name}}}"

        new_config = copy.deepcopy(config)
        new_config[root_key][finding.server]["headers"][header_key] = new_value
        return (
            new_config,
            f"Redacted headers.{header_key} → {new_value} in {finding.server!r}",
        )
