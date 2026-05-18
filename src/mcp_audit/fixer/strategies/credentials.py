"""Fix strategy for CRED-001 and CRED-002 — redact plaintext secrets."""

from __future__ import annotations

import copy
import re

from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.fixer.strategies.base import BaseFixStrategy, find_server_section
from mcp_audit.models import Finding

# Matches an already-redacted placeholder so we can skip idempotent re-runs.
_PLACEHOLDER_RE: re.Pattern[str] = re.compile(r"^\$\{[^}]+\}$")

# Parses the env key name from CRED-001 evidence:
# "env.GITHUB_TOKEN matches GitHub Token pattern"
_ENV_KEY_RE: re.Pattern[str] = re.compile(r"^env\.(\w+)\s+matches")


class CredentialsFixStrategy(BaseFixStrategy):
    """Redact plaintext credentials found by the credentials analyzer.

    * **CRED-001** (env var) — replaces the secret value with
      ``${ENV_KEY_NAME}`` using the key name extracted from the finding
      evidence.  The env key itself is preserved so the config remains
      structurally valid.
    * **CRED-002** (command args) — searches the args list for the first
      token that matches a known secret pattern and replaces the matching
      substring with ``${REDACTED_SECRET}``.

    Both fixes are idempotent: if the value already matches ``${…}``, the
    config is returned unchanged.
    """

    def can_fix(self, finding: Finding) -> bool:
        return finding.id in ("CRED-001", "CRED-002")

    def apply(self, config: dict, finding: Finding) -> tuple[dict, str]:
        server_dict, root_key = find_server_section(config, finding.server)
        if server_dict is None or root_key is None:
            raise ValueError(
                f"Server {finding.server!r} not found in config; cannot apply fix."
            )

        if finding.id == "CRED-001":
            return self._fix_env(config, root_key, finding)
        return self._fix_args(config, root_key, finding)

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
