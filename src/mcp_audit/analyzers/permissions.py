"""Claude Code permission rules that don't do what they say (PERM-001..007).

STORY-0092 (EPIC-0007).  Every rule semantic in this module comes from
Anthropic's own documentation and is quoted where the check is defined:

- code.claude.com/docs/en/permissions ("permissions doc")
- code.claude.com/docs/en/sandboxing ("sandboxing doc")
- code.claude.com/docs/en/settings-reference ("settings reference")
- code.claude.com/docs/en/mcp ("MCP doc")
- the Claude Code CHANGELOG, 2.1.299: "Changed MCP allow rules to reach only
  the server they name: ``mcp__a`` no longer allows a server named ``a__b`` or
  ``a_``; write ``mcp__<server>__*`` with the server's whole normalized name"

The module has two layers.

1. **Parsing** (public, reused by the sandbox checks of STORY-0093):
   :func:`parse_permission_rule`, :func:`load_claude_settings`,
   :func:`is_claude_code_settings_file`, :func:`settings_scope`,
   :class:`PermissionRule` and :class:`ClaudeSettings`.  They work on a
   settings dict that has already been parsed from JSON.
2. **Checks**: :func:`analyze_permission_rules` (PERM-001..006, one settings
   file at a time, called from
   :meth:`~mcp_audit.analyzers.config_hygiene.ConfigHygieneAnalyzer.analyze_config`
   beside HARNESS-001..006) and :func:`analyze_flagged_server_allows`
   (PERM-007, a post-pass in :func:`mcp_audit.scanner._run_static_pipeline`,
   because it needs every other analyzer's findings first).

Each settings file is evaluated on its own, as HARNESS-001..006 are: Claude
Code merges user, project, local and managed settings, and that merge is not
modelled (GAPS.md).  A finding says what this file's rules do, not the
effective policy.  Nothing scanned is executed.  The only filesystem access is
PERM-002 asking whether the directory a misanchored path rule points into
exists, and PERM-007 reading a plugin's ``.claude-plugin/plugin.json`` for the
plugin's name.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mcp_audit.models import Finding, ServerConfig, Severity

#: Analyzer label on every PERM-* finding.  PERM-001..006 are emitted through
#: config hygiene's per-file pass, like HARNESS-*, so the family shares it.
ANALYZER_NAME = "config_hygiene"

#: The three rule lists of a Claude Code ``permissions`` block.
RULE_LISTS: tuple[str, ...] = ("allow", "ask", "deny")

#: Rules quoted in one finding before "(+N more)".
_EVIDENCE_RULE_CAP = 20

#: Largest plugin manifest PERM-007 reads for the plugin's name.
_PLUGIN_MANIFEST_MAX_BYTES = 1024 * 1024

# ── Parsing ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PermissionRule:
    """One entry of ``permissions.allow``, ``permissions.ask`` or ``permissions.deny``.

    Permissions doc: "Permission rules follow the format ``Tool`` or
    ``Tool(specifier)``. Parentheses inside the specifier are literal".

    Attributes:
        text: The rule as written, surrounding whitespace removed.
        list_name: ``"allow"``, ``"ask"`` or ``"deny"``.
        tool: The tool-name part, before the first ``(``.
        specifier: Text between the first ``(`` and the final ``)``, or
            ``None`` for a bare tool name.
    """

    text: str
    list_name: str
    tool: str
    specifier: str | None

    @property
    def is_bare(self) -> bool:
        """True for a rule with no specifier, such as ``Bash`` or ``mcp__github``."""
        return self.specifier is None


def parse_permission_rule(text: object, list_name: str) -> PermissionRule | None:
    """Split one permission rule string into its tool name and specifier.

    Args:
        text: The raw list entry.  Anything that is not a string is ignored.
        list_name: The list it came from (``allow``, ``ask`` or ``deny``).

    Returns:
        The parsed rule, or ``None`` for a non-string, an empty string, a rule
        with an opening ``(`` but no closing ``)``, or an empty tool name.
    """
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None
    if "(" not in stripped:
        return PermissionRule(stripped, list_name, stripped, None)
    if not stripped.endswith(")"):
        return None
    open_at = stripped.index("(")
    tool = stripped[:open_at].strip()
    if not tool:
        return None
    return PermissionRule(stripped, list_name, tool, stripped[open_at + 1 : -1])


def is_claude_code_settings_file(path: Path) -> bool:
    """True for the Claude Code files that carry permissions, hooks and sandbox keys.

    ``~/.claude.json``, and ``settings.json`` / ``settings.local.json`` inside a
    ``.claude`` directory (the user's ``~/.claude/`` or a project's
    ``.claude/``).
    """
    if path.name == ".claude.json":
        return True
    if path.name in ("settings.json", "settings.local.json"):
        return path.parent.name == ".claude"
    return False


def settings_scope(path: Path) -> str:
    """Return which Claude Code settings layer *path* is.

    Returns:
        ``"global"`` for ``~/.claude.json``; ``"local"`` for any
        ``settings.local.json``; ``"user"`` for ``~/.claude/settings.json``;
        ``"project"`` otherwise (a repository's ``.claude/settings.json``).
    """
    if path.name == ".claude.json":
        return "global"
    if path.name == "settings.local.json":
        return "local"
    try:
        if path.parent.resolve() == (Path.home() / ".claude").resolve():
            return "user"
    except OSError:
        pass
    return "project"


_SCOPE_LABELS: dict[str, str] = {
    "global": "the global Claude Code config (~/.claude.json)",
    "local": "local project settings (.claude/settings.local.json)",
    "user": "user settings (~/.claude/settings.json), which apply to every project",
    "project": (
        "committed project settings (.claude/settings.json), which reach everyone"
        " who clones the repository"
    ),
}


@dataclass(frozen=True)
class ClaudeSettings:
    """The permission- and sandbox-relevant parts of one Claude Code settings file.

    Attributes:
        path: The settings file.
        scope: :func:`settings_scope` of *path*.
        permissions: The ``permissions`` object, or ``{}`` when absent or not
            an object.
        sandbox: The ``sandbox`` object, or ``{}`` when absent or not an object.
        rules: Every parseable rule across ``allow``, ``ask`` and ``deny``, in
            that order and in file order within each list.
    """

    path: Path
    scope: str
    permissions: dict
    sandbox: dict
    rules: tuple[PermissionRule, ...]

    @property
    def default_mode(self) -> str | None:
        """``permissions.defaultMode`` when it is a string, else ``None``."""
        mode = self.permissions.get("defaultMode")
        return mode if isinstance(mode, str) else None

    @property
    def sandbox_enabled(self) -> bool:
        """True only when this file sets ``sandbox.enabled`` to ``true``.

        Settings reference, ``sandbox.enabled``: "Default: ``false``".
        """
        return self.sandbox.get("enabled") is True

    @property
    def sandbox_auto_allow(self) -> bool:
        """``sandbox.autoAllowBashIfSandboxed``; only an explicit ``false`` is off.

        Settings reference, ``sandbox.autoAllowBashIfSandboxed``: "Default:
        ``true``".
        """
        return self.sandbox.get("autoAllowBashIfSandboxed") is not False

    @property
    def scope_label(self) -> str:
        """Lower-case description of this settings layer, for finding text."""
        return _SCOPE_LABELS.get(self.scope, f"the settings file {self.path.name}")

    @property
    def path_anchor(self) -> Path | None:
        """Directory a single-slash ``/path`` rule in this file anchors at.

        Permissions doc, "Where a pattern anchors": project and local settings
        anchor at ``<primary working directory>`` (taken here as the directory
        holding ``.claude/``), user settings at ``~/.claude``.  ``None`` for
        ``~/.claude.json``, whose anchoring the doc does not describe.
        """
        if self.scope == "user":
            return self.path.parent
        if self.scope in ("project", "local") and self.path.parent.name == ".claude":
            return self.path.parent.parent
        return None

    def rules_in(self, list_name: str) -> list[PermissionRule]:
        """Rules from one list, in file order."""
        return [rule for rule in self.rules if rule.list_name == list_name]


def load_claude_settings(raw: object, path: Path) -> ClaudeSettings | None:
    """Build a :class:`ClaudeSettings` from a parsed settings dict.

    Malformed parts are tolerated the way the rest of config hygiene tolerates
    them: a ``permissions`` or ``sandbox`` value that is not an object, or a
    rule list that is not a list, contributes nothing.  A rule repeated in the
    same list is kept once.

    Args:
        raw: The parsed JSON of the settings file.
        path: Where it was read from (used for scope and anchoring).

    Returns:
        The settings, or ``None`` when *raw* is not a JSON object.
    """
    if not isinstance(raw, dict):
        return None
    permissions = raw.get("permissions")
    permissions = permissions if isinstance(permissions, dict) else {}
    sandbox = raw.get("sandbox")
    sandbox = sandbox if isinstance(sandbox, dict) else {}
    rules: list[PermissionRule] = []
    seen: set[tuple[str, str]] = set()
    for list_name in RULE_LISTS:
        entries = permissions.get(list_name)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            rule = parse_permission_rule(entry, list_name)
            if rule is None or (list_name, rule.text) in seen:
                continue
            seen.add((list_name, rule.text))
            rules.append(rule)
    return ClaudeSettings(
        path=path,
        scope=settings_scope(path),
        permissions=permissions,
        sandbox=sandbox,
        rules=tuple(rules),
    )


def _strip_trailing_wildcard(specifier: str) -> tuple[str, bool]:
    """Remove a trailing ``:*``, `` *`` or ``*``; report whether one was there."""
    inner = specifier.strip()
    for suffix in (":*", " *", "*"):
        if inner.endswith(suffix):
            return inner[: -len(suffix)].strip(), True
    return inner, False


def _program(word: str) -> str:
    """Basename of a command word, lower-cased (``/usr/bin/curl`` → ``curl``)."""
    return word.rsplit("/", 1)[-1].lower()


# ── Shared finding builder ────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Hit:
    """One rule a check flagged: what it does, and what to write instead."""

    rule: PermissionRule
    why: str
    fix: str


def _capped(items: list[str], sep: str = "; ") -> str:
    """Join *items*, listing at most :data:`_EVIDENCE_RULE_CAP` of them."""
    shown = sep.join(items[:_EVIDENCE_RULE_CAP])
    if len(items) > _EVIDENCE_RULE_CAP:
        shown += f"{sep}(+{len(items) - _EVIDENCE_RULE_CAP} more)"
    return shown


def _rule_ref(rule: PermissionRule) -> str:
    return f"{rule.list_name} {rule.text!r}"


@dataclass(frozen=True)
class _Check:
    """The fixed text and taxonomy of one PERM-* check."""

    finding_id: str
    title: str
    remediation: str
    cwe: str
    owasp: tuple[str, ...]


def _build(
    check: _Check,
    severity: Severity,
    settings: ClaudeSettings,
    client: str,
    analyzer: str,
    summary: str,
    hits: list[_Hit],
    extra_evidence: str = "",
) -> Finding:
    """One finding for every rule *check* flagged at *severity* in one file."""
    rules = _capped([_rule_ref(hit.rule) for hit in hits], ", ")
    detail = _capped([f"{hit.rule.text!r}: {hit.why}" for hit in hits])
    fixes = _capped([f"{hit.rule.text!r} → {hit.fix}" for hit in hits])
    evidence = f"{settings.path}: " + _capped(
        [f"permissions.{hit.rule.list_name} contains {hit.rule.text!r}" for hit in hits]
    )
    return Finding(
        id=check.finding_id,
        severity=severity,
        analyzer=analyzer,
        client=client,
        server="(config-level)",
        title=check.title,
        description=(f"Rules in {settings.scope_label}: {rules}. {summary} {detail}."),
        evidence=evidence + extra_evidence,
        remediation=f"{check.remediation} {fixes}.",
        cwe=check.cwe,
        owasp_mcp_top_10=list(check.owasp),
        finding_path=str(settings.path),
    )


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def _by_severity(
    graded: list[tuple[Severity, _Hit]],
) -> list[tuple[Severity, list[_Hit]]]:
    """Group hits by severity, most severe first, file order within a group."""
    groups: dict[Severity, list[_Hit]] = {}
    for severity, hit in graded:
        groups.setdefault(severity, []).append(hit)
    return [(sev, groups[sev]) for sev in _SEVERITY_ORDER if sev in groups]


# ── PERM-001: rules Claude Code skips or never matches ───────────────────────

#: Each built-in tool's primary content field.  Permissions doc: "You can't
#: match a tool's primary content field this way: ``command`` for Bash and
#: PowerShell, ``file_path`` for Read, Edit, and Write, ``path`` for Grep and
#: Glob, ``notebook_path`` for NotebookEdit, and ``url`` for WebFetch. A rule
#: like ``Bash(command:rm *)`` would be bypassable by a compound command, so
#: Claude Code ignores it and emits a startup warning."
_CONTENT_FIELDS: dict[str, str] = {
    "Bash": "command",
    "PowerShell": "command",
    "Read": "file_path",
    "Edit": "file_path",
    "Write": "file_path",
    "Grep": "path",
    "Glob": "path",
    "NotebookEdit": "notebook_path",
    "WebFetch": "url",
}
#: The tool whose own rule syntax replaces a content-field rule
#: ("Use ``Bash(rm *)``, ``Read(./path)``, or ``WebFetch(domain:host)`` instead").
_CONTENT_FIELD_FIX_TOOL: dict[str, str] = {
    "Bash": "Bash",
    "PowerShell": "PowerShell",
    "Read": "Read",
    "Edit": "Edit",
    "Write": "Edit",
    "Grep": "Read",
    "Glob": "Read",
    "NotebookEdit": "Edit",
}
#: ``param:value``.  "Whitespace around the colon is ignored."  A parameter
#: name has two or more characters, so a Windows drive (``C:\``) is not one.
_PARAM_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]+)\s*:")

_SHELL_TOOLS: frozenset[str] = frozenset({"Bash", "PowerShell"})

#: Permissions doc: "If you write a path rule for ``Write``, ``NotebookEdit``,
#: ``Glob``, or legacy ``MultiEdit``, Claude Code accepts the rule but never
#: matches a read or edit against it.  Use ``Edit(docs/**)`` in place of
#: ``Write(docs/**)``, ``NotebookEdit(docs/**)``, or ``MultiEdit(docs/**)``,
#: and ``Read(docs/**)`` in place of ``Glob(docs/**)``."
_DEAD_PATH_RULE_TOOLS: dict[str, str] = {
    "Write": "Edit",
    "NotebookEdit": "Edit",
    "MultiEdit": "Edit",
    "Glob": "Read",
}

#: ``Bash(git:* push)``.  Permissions doc: "The ``:*`` form is only recognized
#: at the end of a pattern. In a pattern like ``Bash(git:* push)``, the colon
#: is treated as a literal character and won't match git commands."  Only the
#: shape where ``:*`` follows the program name is flagged, so ``scp host:* .``
#: (a literal colon the author meant) is left alone.
_MID_COLON_STAR_RE = re.compile(r"^([^\s:*]+):\*\s+(\S.*)$")

_PERM_001 = _Check(
    finding_id="PERM-001",
    title="Permission rules that Claude Code ignores or never matches",
    remediation=(
        "Rewrite each rule in a form Claude Code applies (code.claude.com/docs/en/"
        "permissions, Permission rule syntax):"
    ),
    cwe="CWE-693",
    owasp=("MCP07", "MCP02"),
)
_PERM_001_SUMMARY: dict[str, str] = {
    "deny": (
        "Claude Code ignores these deny rules or never matches them, so the"
        " calls they were written to block are not blocked by them."
    ),
    "ask": (
        "Claude Code ignores these ask rules or never matches them, so the"
        " calls they were written to confirm are not confirmed by them."
    ),
    "allow": (
        "These allow rules approve nothing, so the calls they name still go"
        " through the normal prompt."
    ),
}
_PERM_001_SEVERITY: dict[str, Severity] = {
    "deny": Severity.HIGH,
    "ask": Severity.MEDIUM,
    "allow": Severity.INFO,
}


def _is_anchored_mcp_allow_glob(tool: str) -> bool:
    """True for ``mcp__<server>__<glob>`` with a glob-free, non-empty server segment.

    Permissions doc: "Allow rules accept tool-name globs only after a literal
    ``mcp__<server>__`` prefix. The server segment must be glob-free".
    """
    if not tool.startswith("mcp__"):
        return False
    rest = tool[len("mcp__") :]
    separator = rest.find("__")
    return separator > 0 and "*" not in rest[:separator]


def _ignored_or_dead(rule: PermissionRule) -> _Hit | None:
    """PERM-001: why *rule* is skipped at load or can never match, or ``None``."""
    spec = rule.specifier
    if rule.tool.startswith("mcp__") and spec is not None:
        return _Hit(
            rule,
            "Claude Code skips any mcp__ rule that has parentheses when it loads"
            " a settings file",
            f"{rule.tool} with no parentheses (an MCP tool's parameter can be"
            " matched only by a --disallowedTools deny rule)",
        )
    field = _CONTENT_FIELDS.get(rule.tool)
    if spec is not None and field is not None:
        match = _PARAM_RE.match(spec)
        if match and match.group(1) == field:
            value = spec[match.end() :].strip()
            # Bash(command:*) / PowerShell(command:*) is also the documented
            # ``:*`` prefix form for a program named "command"; leave it alone.
            if not (rule.tool in _SHELL_TOOLS and value == "*"):
                fix_tool = _CONTENT_FIELD_FIX_TOOL.get(rule.tool)
                if fix_tool is None:  # WebFetch
                    fix = "WebFetch(domain:<host>)"
                elif fix_tool in ("Read", "Edit") and value.startswith("/"):
                    # A path rule's single leading slash is not the root (PERM-002).
                    fix = f"{fix_tool}(//{value.lstrip('/')})"
                else:
                    fix = f"{fix_tool}({value})"
                why = (
                    f"Claude Code ignores a rule on {rule.tool}'s primary content"
                    f" field ({field}) and emits a startup warning"
                )
                if rule.tool in _SHELL_TOOLS:
                    why += ", because a compound command would bypass it"
                return _Hit(rule, why, fix)
    if (
        spec is not None
        and rule.tool in _DEAD_PATH_RULE_TOOLS
        and spec.strip() not in ("", "*")
        and not _PARAM_RE.match(spec)
    ):
        alternative = _DEAD_PATH_RULE_TOOLS[rule.tool]
        return _Hit(
            rule,
            "Claude Code checks file permissions against Edit(path) and Read(path)"
            f" rules only; it accepts a {rule.tool} path rule but never matches it",
            f"{alternative}({spec.strip()}), or a bare {rule.tool} rule for every"
            f" use of {rule.tool}",
        )
    if spec is not None and rule.tool in _SHELL_TOOLS:
        mid = _MID_COLON_STAR_RE.match(spec.strip())
        if mid:
            return _Hit(
                rule,
                "':*' is recognized only at the end of a pattern; here the colon"
                " is a literal character, so the rule matches no real command",
                f"{rule.tool}({mid.group(1)} {mid.group(2).strip()} *)",
            )
    if (
        rule.list_name == "allow"
        and "*" in rule.tool
        and not _is_anchored_mcp_allow_glob(rule.tool)
    ):
        return _Hit(
            rule,
            "an unanchored allow glob is skipped and doesn't auto-approve"
            " anything; allow rules take a tool-name glob only after a literal"
            " mcp__<server>__ prefix",
            "the tool names you mean, or mcp__<server>__* for one server's tools",
        )
    return None


def _check_perm_001(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    graded = []
    for rule in settings.rules:
        hit = _ignored_or_dead(rule)
        if hit is not None:
            graded.append((_PERM_001_SEVERITY[rule.list_name], hit))
    findings = []
    for severity, hits in _by_severity(graded):
        # One list per severity: deny is HIGH, ask MEDIUM, allow INFO.
        summary = _PERM_001_SUMMARY[hits[0].rule.list_name]
        findings.append(
            _build(_PERM_001, severity, settings, client, analyzer, summary, hits)
        )
    return findings


# ── PERM-002: single-slash path rules anchored at the settings source ────────

#: First path segments that name a filesystem-root directory, not a directory
#: of a project.  Only consulted for project and local settings; a match is
#: still skipped when the project really has a top-level directory of that name.
_SYSTEM_ROOT_DIRS: frozenset[str] = frozenset(
    {
        "Users",
        "home",
        "root",
        "etc",
        "var",
        "tmp",
        "opt",
        "usr",
        "private",
        "Volumes",
        "mnt",
        "media",
        "srv",
        "proc",
        "sys",
        "Library",
        "System",
        "Applications",
    }
)
#: Second segment of a Windows path in Claude Code's POSIX form (``/c/Users``).
#: Permissions doc: "On Windows, paths are normalized to POSIX form before
#: matching. ``C:\\Users\\alice`` becomes ``/c/Users/alice``, so use
#: ``//c/**/.env``".
_WINDOWS_ROOT_DIRS: frozenset[str] = frozenset(
    {"Users", "Windows", "ProgramData", "Program Files", "Program Files (x86)"}
)
_GLOB_CHARS: frozenset[str] = frozenset("*?[]{}!")

_PERM_002 = _Check(
    finding_id="PERM-002",
    title="Path rules with one leading slash point inside the project, not at /",
    remediation=(
        'Use two slashes for an absolute path (permissions doc: "Use'
        ' //Users/alice/file for absolute paths"):'
    ),
    cwe="CWE-706",
    owasp=("MCP07", "MCP10"),
)
_PERM_002_SUMMARY = (
    "Permissions doc: \"A pattern like /Users/alice/file isn't an absolute path."
    " The single leading slash anchors at the settings source, not the"
    ' filesystem root."'
)


def _misanchored(rule: PermissionRule, settings: ClaudeSettings) -> _Hit | None:
    """PERM-002: a ``Read(/…)`` or ``Edit(/…)`` rule naming a root path, or None."""
    if rule.tool not in ("Read", "Edit") or rule.specifier is None:
        return None
    spec = rule.specifier.strip()
    if not spec.startswith("/") or spec.startswith("//"):
        return None
    segments = spec[1:].split("/")
    first = segments[0]
    if not first or any(ch in _GLOB_CHARS for ch in first):
        return None
    anchor = settings.path_anchor
    if anchor is None:
        return None
    if settings.scope != "user":
        drive = (
            len(first) == 1
            and first.isalpha()
            and len(segments) > 1
            and segments[1] in _WINDOWS_ROOT_DIRS
        )
        if first not in _SYSTEM_ROOT_DIRS and not drive:
            return None
    try:
        if (anchor / first).exists():
            return None  # the anchored path is real; the rule may mean it
    except OSError:
        return None
    if settings.scope == "user":
        where, prefix = "~/.claude", "~/.claude"
    else:
        where, prefix = "the project root", "<project>"
    return _Hit(
        rule,
        f"one leading slash anchors at {where}, so this names {prefix}{spec},"
        f" which does not exist, rather than {spec}",
        f"{rule.tool}(/{spec})",
    )


def _check_perm_002(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    graded = []
    for rule in settings.rules:
        hit = _misanchored(rule, settings)
        if hit is not None:
            severity = Severity.INFO if rule.list_name == "allow" else Severity.MEDIUM
            graded.append((severity, hit))
    findings = []
    for severity, hits in _by_severity(graded):
        consequence = (
            " So the absolute path these allow rules name is not approved."
            if severity is Severity.INFO
            else " So the absolute path these deny or ask rules name is not guarded"
            " by them."
        )
        findings.append(
            _build(
                _PERM_002,
                severity,
                settings,
                client,
                analyzer,
                _PERM_002_SUMMARY + consequence,
                hits,
            )
        )
    return findings


# ── PERM-003: a trailing * with no space also matches other programs ─────────

#: One command word ending in a word character, with no space or ``*``.
_PREFIX_WORD_RE = re.compile(r"^[^\s*]*[A-Za-z0-9_.\-]$")

_PERM_003 = _Check(
    finding_id="PERM-003",
    title="Allow rules whose trailing * also matches other programs",
    remediation="Put a space before the * so the rule names one program:",
    cwe="CWE-187",
    owasp=("MCP02", "MCP05"),
)
_PERM_003_SUMMARY = (
    'Permissions doc: "The space before a trailing * is part of the rule.'
    " Bash(ls *) requires a space after ls, so lsof doesn't match. Bash(ls*) has"
    ' no space, so it matches lsof too."'
)


def _prefix_collision(
    rule: PermissionRule, is_broad_allow_rule: Callable[[str], bool]
) -> _Hit | None:
    """PERM-003: ``Bash(ls*)``-style allow rule, or ``None``."""
    if rule.list_name != "allow" or rule.tool not in _SHELL_TOOLS:
        return None
    if rule.specifier is None:
        return None
    spec = rule.specifier.strip()
    if not spec.endswith("*") or spec.endswith((" *", ":*")):
        return None
    prefix = spec[:-1]
    if not _PREFIX_WORD_RE.match(prefix) or is_broad_allow_rule(rule.text):
        return None  # a broad program's rule is HARNESS-005's
    return _Hit(
        rule,
        f"it approves every program whose name starts with {prefix!r}, not"
        f" just {prefix}",
        f"{rule.tool}({prefix} *)",
    )


def _check_perm_003(
    settings: ClaudeSettings,
    client: str,
    analyzer: str,
    is_broad_allow_rule: Callable[[str], bool],
) -> list[Finding]:
    hits = [
        hit
        for rule in settings.rules
        if (hit := _prefix_collision(rule, is_broad_allow_rule)) is not None
    ]
    if not hits:
        return []
    return [
        _build(
            _PERM_003, Severity.LOW, settings, client, analyzer, _PERM_003_SUMMARY, hits
        )
    ]


# ── PERM-004: deny/ask on network or delete commands without the sandbox ─────

#: Programs whose arguments reach the network, and programs that delete or
#: overwrite files.  The permissions doc's own examples are ``curl``, ``rm``
#: and ``git push``.
_NETWORK_PROGRAMS: frozenset[str] = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "ssh",
        "scp",
        "sftp",
        "ftp",
        "telnet",
        "rsync",
        "http",
        "https",
        "xh",
        "aria2c",
    }
)
_DESTRUCTIVE_PROGRAMS: frozenset[str] = frozenset(
    {"rm", "rmdir", "dd", "shred", "mkfs", "unlink", "truncate"}
)
_NETWORK_SUBCOMMANDS: frozenset[tuple[str, str]] = frozenset({("git", "push")})
#: Programs that run another command given as their arguments, so an allow
#: rule for one of them approves ``sh -c '<anything>'``-style forms.
_SHELL_LAUNCHERS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "env", "xargs", "sudo"}
)

_PERM_004 = _Check(
    finding_id="PERM-004",
    title=(
        "Deny or ask rules on network or delete commands are not a boundary"
        " without the sandbox"
    ),
    remediation=(
        "Turn on the sandbox (sandbox.enabled: true, with a network allowlist) for"
        " enforcement that doesn't depend on the command text, or add a"
        " PreToolUse hook that inspects the full command:"
    ),
    cwe="CWE-184",
    owasp=("MCP05", "MCP07"),
)
_PERM_004_BASIS = (
    'Permissions doc: a Bash deny or ask rule "covers the invocation Claude'
    " usually produces and isn't a security boundary around the program\", and"
    ' "your other rules and the permission mode decide" the forms it misses.'
    " sandbox.enabled is not true in this file."
)


def _not_a_boundary(rule: PermissionRule) -> _Hit | None:
    """PERM-004: a Bash deny/ask rule on a network or delete program, or ``None``."""
    if rule.list_name not in ("deny", "ask") or rule.tool != "Bash":
        return None
    if rule.specifier is None:
        return None
    inner, _ = _strip_trailing_wildcard(rule.specifier)
    words = inner.split()
    if not words:
        return None
    program = _program(words[0])
    if len(words) > 1 and (program, words[1].lower()) in _NETWORK_SUBCOMMANDS:
        bypass = (
            f"{program} -C . {words[1]} …, {program} -c push.default=current"
            f" {words[1]} …, {program} '{words[1]}' …"
        )
    elif program in _NETWORK_PROGRAMS or program in _DESTRUCTIVE_PROGRAMS:
        bypass = f"/usr/bin/{program} … (any full path) or sh -c '{program} …'"
    else:
        return None
    return _Hit(
        rule,
        f"it doesn't stop {bypass}",
        "sandbox.enabled: true or a PreToolUse hook",
    )


def _approves_any_shell_form(rule: PermissionRule) -> bool:
    """True for a Bash allow rule that approves ``sh -c '<anything>'`` or a full path.

    Bare ``Bash``/``Bash(*)``; a rule that starts with ``*`` (the doc's
    ``Bash(* --version)`` matches ``bash -c 'echo hi' --version``); an absolute
    directory followed by a wildcard (``Bash(/usr/bin/*)``); or a shell or
    launcher followed only by options and a wildcard (``Bash(sh -c *)``,
    ``Bash(bash:*)``, ``Bash(env *)``, ``Bash(sudo -E *)``).  A launcher rule
    narrowed to a script or a command (``Bash(bash scripts/test.sh *)``,
    ``Bash(sudo systemctl status *)``) and a relative directory
    (``Bash(./scripts/*)``) do not count.
    """
    if rule.tool != "Bash":
        return False
    spec = "*" if rule.specifier is None else rule.specifier.strip()
    if not spec:
        return False
    if spec.startswith("*"):
        return True
    inner, wildcard = _strip_trailing_wildcard(spec)
    words = inner.split()
    if not words:
        return True
    if not wildcard:
        return False
    if len(words) == 1 and words[0].startswith("/") and words[0].endswith("/"):
        return True
    return _program(words[0]) in _SHELL_LAUNCHERS and all(
        word.startswith("-") for word in words[1:]
    )


def _bypass_forms_run_unprompted(settings: ClaudeSettings) -> str | None:
    """What in this file runs a rule's other forms without a prompt, if anything.

    ``defaultMode`` counts only in user settings.  Settings reference,
    ``permissions.defaultMode``: "``auto`` and ``bypassPermissions`` don't take
    effect from project or local settings, so set them in
    ``~/.claude/settings.json`` instead. Before v2.1.257, ``bypassPermissions``
    took effect from any file."  The installed version is not read, so a
    project or local file's mode is not counted (GAPS.md).
    """
    mode = settings.default_mode
    if settings.scope == "user":
        if mode == "bypassPermissions":
            return (
                "permissions.defaultMode is 'bypassPermissions', so those forms run"
                " without a prompt"
            )
        if mode == "auto":
            return (
                "permissions.defaultMode is 'auto', so the auto-mode classifier, not"
                " you, decides whether those forms run"
            )
    for rule in settings.rules_in("allow"):
        if _approves_any_shell_form(rule):
            return (
                f"allow {rule.text!r} approves those forms, so they run without a"
                " prompt"
            )
    return None


def _check_perm_004(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    if settings.sandbox_enabled:
        return []
    hits = [hit for rule in settings.rules if (hit := _not_a_boundary(rule))]
    if not hits:
        return []
    runs = _bypass_forms_run_unprompted(settings)
    if runs is not None:
        severity = Severity.MEDIUM
        summary = f"{_PERM_004_BASIS} Here {runs}."
    else:
        severity = Severity.INFO
        summary = (
            f"{_PERM_004_BASIS} Nothing in this file approves those forms, so they"
            " still prompt; the rule holds only while each of those prompts is"
            " refused."
        )
    return [_build(_PERM_004, severity, settings, client, analyzer, summary, hits)]


# ── PERM-005: WebFetch(domain:*) allow ───────────────────────────────────────

_DOMAIN_RE = re.compile(r"^\s*domain\s*:\s*(.*?)\s*$")

_PERM_005 = _Check(
    finding_id="PERM-005",
    title="WebFetch(domain:*) allow opens the sandbox to every host",
    remediation=(
        "Use a bare WebFetch allow rule to fetch without prompts and leave the"
        " sandbox allowlist as it is, or allow named hosts:"
    ),
    cwe="CWE-862",
    owasp=("MCP02", "MCP10"),
)
_PERM_005_BASIS = (
    'Permissions doc: in allow, WebFetch(domain:*) means "Claude fetches without'
    ' prompting you, and sandboxed commands can reach any host"; only the domain:'
    " form adds its host to the sandbox's allowed domains, and the sandbox"
    " honours a bare * there."
)


def _check_perm_005(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    hits = []
    for rule in settings.rules_in("allow"):
        if rule.tool != "WebFetch" or rule.specifier is None:
            continue
        match = _DOMAIN_RE.match(rule.specifier)
        if match and match.group(1) == "*":
            hits.append(
                _Hit(
                    rule,
                    "every host joins the sandbox's allowed domains",
                    "WebFetch, or WebFetch(domain:<host>) per host",
                )
            )
    if not hits:
        return []
    if settings.sandbox_enabled:
        severity = Severity.HIGH
        summary = (
            f"{_PERM_005_BASIS} This file turns the sandbox on, so its network"
            " allowlist no longer limits where shell commands can send data."
        )
    else:
        severity = Severity.LOW
        summary = (
            f"{_PERM_005_BASIS} This file doesn't turn the sandbox on; whenever a"
            " settings file does, this rule opens it to every host."
        )
    return [_build(_PERM_005, severity, settings, client, analyzer, summary, hits)]


# ── PERM-006: a bare Bash ask rule under sandbox auto-allow ──────────────────

_PERM_006 = _Check(
    finding_id="PERM-006",
    title="A bare Bash ask rule is skipped for sandboxed commands",
    remediation=(
        "Set sandbox.autoAllowBashIfSandboxed to false to be asked about every"
        " command, or ask about the commands that matter with content-scoped"
        " rules, which still prompt for sandboxed commands:"
    ),
    cwe="CWE-693",
    owasp=("MCP07", "MCP05"),
)
_PERM_006_BASIS = (
    'Sandboxing doc: "A bare Bash ask rule, or the equivalent Bash(*) form, is'
    " skipped for commands that run sandboxed; it still applies to commands that"
    ' run outside the sandbox." This file turns the sandbox on and leaves'
    " sandbox.autoAllowBashIfSandboxed at true (its default), so sandboxed"
    " commands, including ones that change files in the project, run without the"
    " prompt this rule asks for."
)


def _check_perm_006(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    if not (settings.sandbox_enabled and settings.sandbox_auto_allow):
        return []
    if settings.default_mode == "plan":
        return []  # "In plan mode, the rule isn't skipped"
    hits = [
        _Hit(
            rule,
            "skipped for every command that runs in the sandbox",
            "sandbox.autoAllowBashIfSandboxed: false, or rules such as"
            " Bash(git push *)",
        )
        for rule in settings.rules_in("ask")
        if rule.tool == "Bash" and rule.text in ("Bash", "Bash(*)")
    ]
    if not hits:
        return []
    auto = settings.sandbox.get("autoAllowBashIfSandboxed")
    state = "true" if auto is True else "unset (default true)"
    return [
        _build(
            _PERM_006,
            Severity.MEDIUM,
            settings,
            client,
            analyzer,
            _PERM_006_BASIS,
            hits,
            extra_evidence=(
                f"; sandbox.enabled = true; sandbox.autoAllowBashIfSandboxed {state}"
            ),
        )
    ]


# ── PERM-001..006 entry point ─────────────────────────────────────────────────


def _never_broad(_rule: str) -> bool:
    return False


def analyze_permission_rules(
    raw: object,
    config_path: Path,
    client: str,
    *,
    analyzer: str = ANALYZER_NAME,
    is_broad_allow_rule: Callable[[str], bool] | None = None,
) -> list[Finding]:
    """PERM-001..006 for one Claude Code settings file.

    Args:
        raw: Parsed JSON of the file.
        config_path: The file; anything that is not a Claude Code settings file
            (:func:`is_claude_code_settings_file`) yields nothing.
        client: Client name to attach to findings.
        analyzer: Analyzer label for findings.
        is_broad_allow_rule: HARNESS-005's predicate, so PERM-003 does not
            report a rule HARNESS-005 already reports.  ``None`` treats no rule
            as broad.

    Returns:
        Findings ordered by ID, most severe first within an ID.
    """
    if not is_claude_code_settings_file(config_path):
        return []
    settings = load_claude_settings(raw, config_path)
    if settings is None or not settings.rules:
        return []
    broad = is_broad_allow_rule or _never_broad
    return [
        *_check_perm_001(settings, client, analyzer),
        *_check_perm_002(settings, client, analyzer),
        *_check_perm_003(settings, client, analyzer, broad),
        *_check_perm_004(settings, client, analyzer),
        *_check_perm_005(settings, client, analyzer),
        *_check_perm_006(settings, client, analyzer),
    ]


# ── PERM-007: an allow rule pre-approving a server with HIGH+ findings ───────

#: Clients whose servers Claude Code loads.  An explicit ``--path`` config
#: (client ``custom``) counts when its file is a Claude Code file.
_CLAUDE_CODE_CLIENTS: frozenset[str] = frozenset(
    {"claude-code", "claude-code-project", "claude-code-plugin"}
)
#: Analyzers whose findings indict the server itself: poisoned metadata
#: (poisoning), a definition that changed since it was approved (rug_pull), or
#: a typosquatted, unknown or vulnerable package (supply_chain).  Not counted,
#: because they would make PERM-007 fire on ordinary configs without saying
#: the server's tools are unsafe to run unprompted: how the config file is
#: stored (config_hygiene; CFHYG-001 fires on any 0644 file), secrets in it
#: (credentials), transport, auth, launch hygiene (community rules; COMM-013
#: fires on every ``npx -y`` server, the documented install form), and
#: toxic_flow, whose single-server TOXIC-*/INTEG-* describe capability
#: combinations many legitimate servers have and already carry their own
#: severity.  Attestation findings are added after the pipeline
#: (``--verify-hashes``/``--verify-signatures``), so PERM-007 cannot see them.
_SERVER_RISK_ANALYZERS: frozenset[str] = frozenset(
    {"poisoning", "rug_pull", "supply_chain"}
)
#: SC-004 text for an unpinned launch (``supply_chain._emit_known_cve_findings``):
#: the configured version is not known to be affected, so it does not count.
_SC004_VERSION_UNKNOWN = "cannot tell offline whether the installed release"
_HIGH_PLUS: frozenset[Severity] = frozenset({Severity.HIGH, Severity.CRITICAL})
#: MCP doc: in an MCP tool name "any character outside A-Z, a-z, 0-9, _, and -
#: is replaced with _".
_SERVER_NAME_CHARS_RE = re.compile(r"[^A-Za-z0-9_-]")

_PERM_007 = _Check(
    finding_id="PERM-007",
    title="Allow rule pre-approves every tool of a server with high-severity findings",
    remediation="",
    cwe="CWE-862",
    owasp=("MCP02", "MCP07"),
)


class SettingsSource(Protocol):
    """What PERM-007 needs from a discovered config (``DiscoveredConfig`` fits)."""

    path: Path
    raw: dict
    client_name: str


def normalize_mcp_server_name(name: str) -> str:
    """The server name as it appears in Claude Code's ``mcp__<server>__<tool>`` names.

    Permissions doc: for "Names with characters such as ``.`` or spaces: those
    characters become ``_``"; MCP doc: "any character outside ``A-Z``,
    ``a-z``, ``0-9``, ``_``, and ``-`` is replaced with ``_``".
    """
    return _SERVER_NAME_CHARS_RE.sub("_", name)


def whole_server_allow_target(rule: PermissionRule) -> str | None:
    """The normalized server name an allow rule approves *every* tool of, if any.

    Claude Code 2.1.299 and the permissions doc: ``mcp__<server>`` and
    ``mcp__<server>__*`` match every tool of ``<server>``; for a name that
    "contains ``__`` or ends in ``_``", only ``mcp__<whole name>__*`` matches,
    because "Claude Code reads both [``mcp__reports__v2`` and ``mcp__reports``]
    as rules for a server named ``reports``".  So the bare form names the text
    up to the first ``__``; a bare form with a ``__`` in it is a one-tool rule.

    Returns:
        The server segment, or ``None`` for anything that is not a whole-server
        allow rule (a single tool, a tool-prefix glob such as
        ``mcp__github__get_*``, a skipped unanchored glob, or a rule with
        parentheses, which Claude Code skips).
    """
    if rule.list_name != "allow" or rule.specifier is not None:
        return None
    if not rule.tool.startswith("mcp__"):
        return None
    rest = rule.tool[len("mcp__") :]
    if rest.endswith("__*"):
        server = rest[: -len("__*")]
        return server if server and "*" not in server else None
    # "A <server> that contains __ or ends in _: write the wildcard form".
    if "*" in rest or "__" in rest or not rest or rest.endswith("_"):
        return None
    return rest


def _plugin_name(config_path: Path) -> str | None:
    """The ``name`` in the plugin manifest beside a plugin's MCP config, if readable."""
    if config_path.name == ".mcp.json":
        root = config_path.parent
    else:
        root = config_path.parent.parent
    manifest = root / ".claude-plugin" / "plugin.json"
    try:
        if manifest.stat().st_size > _PLUGIN_MANIFEST_MAX_BYTES:
            return None
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    name = data.get("name") if isinstance(data, dict) else None
    return name.strip() if isinstance(name, str) and name.strip() else None


def _is_claude_code_server_file(path: Path) -> bool:
    return path.name in (".mcp.json", ".claude.json") or path.parent.name == ".claude"


def claude_code_server_key(server: ServerConfig) -> str | None:
    """The normalized name Claude Code's ``mcp__`` rules use for *server*.

    A plugin's server takes the plugin-scoped form (MCP doc:
    ``mcp__plugin_<plugin-name>_<server-name>__<tool-name>``).

    Returns:
        The name, or ``None`` when Claude Code does not load *server* (another
        client's config) or a plugin's name cannot be read.
    """
    if server.client == "claude-code-plugin":
        plugin = _plugin_name(server.config_path)
        if plugin is None:
            return None
        return normalize_mcp_server_name(f"plugin_{plugin}_{server.name}")
    if server.client in _CLAUDE_CODE_CLIENTS or (
        server.client == "custom" and _is_claude_code_server_file(server.config_path)
    ):
        return normalize_mcp_server_name(server.name)
    return None


def _same_dir(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def _reaches(settings: ClaudeSettings, server: ServerConfig) -> bool:
    """Whether *settings*' rules apply in sessions that load *server*.

    User settings and ``~/.claude.json`` apply everywhere.  A project's
    settings apply to that project's servers, to user-scope servers
    (``~/.claude.json``, ``~/.claude/settings.json``) and to plugin servers,
    but not to another project's ``.mcp.json``.
    """
    root = settings.path_anchor
    if settings.scope in ("user", "global") or root is None:
        return True
    path = server.config_path
    if server.client == "claude-code-plugin" or path.name == ".claude.json":
        return True
    if path.name == ".mcp.json":
        project = path.parent
    elif path.parent.name == ".claude":
        project = path.parent.parent
    else:
        return True
    return _same_dir(project, root) or _same_dir(project, Path.home())


def _indicts_server(finding: Finding) -> bool:
    """A HIGH or CRITICAL finding that says the server itself is not safe."""
    if finding.severity not in _HIGH_PLUS:
        return False
    if finding.analyzer not in _SERVER_RISK_ANALYZERS:
        return False
    # SC-004 counts only when the configured version is known to be affected.
    return not (
        finding.id == "SC-004" and _SC004_VERSION_UNKNOWN in finding.description
    )


def _flagged_servers(
    servers: list[ServerConfig], findings: list[Finding]
) -> dict[str, list[tuple[ServerConfig, list[Finding]]]]:
    """Claude Code servers with HIGH or CRITICAL findings, by normalized name.

    Only findings that indict the server count (:func:`_indicts_server`).
    """
    serious = [f for f in findings if _indicts_server(f)]
    if not serious:
        return {}
    flagged: dict[str, list[tuple[ServerConfig, list[Finding]]]] = {}
    for server in servers:
        own = [
            f
            for f in serious
            if f.server == server.name
            and f.client == server.client
            and (f.finding_path is None or f.finding_path == str(server.config_path))
        ]
        if not own:
            continue
        key = claude_code_server_key(server)
        if key is not None:
            flagged.setdefault(key, []).append((server, own))
    return flagged


def _flagged_allow_finding(
    settings: ClaudeSettings,
    client: str,
    analyzer: str,
    rules: list[PermissionRule],
    key: str,
    server: ServerConfig,
    own: list[Finding],
) -> Finding:
    ids = sorted({f.id for f in own})
    shown = _capped(ids, ", ")
    critical = any(f.severity is Severity.CRITICAL for f in own)
    grade = "CRITICAL or HIGH" if critical else "HIGH"
    quoted = _capped([repr(rule.text) for rule in rules], ", ")
    return Finding(
        id=_PERM_007.finding_id,
        severity=Severity.HIGH,
        analyzer=analyzer,
        client=client,
        server=server.name,
        title=_PERM_007.title,
        description=(
            f"An allow rule in {settings.scope_label} ({quoted}) approves every tool"
            f" of the MCP server '{server.name}' without a prompt, and this scan"
            f" reports {len(own)} {grade} finding(s) on that server ({shown})."
            " Since Claude Code 2.1.299 an MCP allow rule"
            " reaches only the server it names, by the server's whole normalized"
            f" name ('{key}'), so this rule reaches exactly that server."
        ),
        evidence=(
            f"{settings.path}: permissions.allow contains {quoted}; server"
            f" '{server.name}' in {server.config_path}: {shown}"
        ),
        remediation=(
            f"Remove {quoted} until those findings are fixed, or allow only the"
            f" tools you have checked (mcp__{key}__<tool>) so the rest prompt."
        ),
        cwe=_PERM_007.cwe,
        owasp_mcp_top_10=list(_PERM_007.owasp),
        finding_path=str(settings.path),
    )


def analyze_flagged_server_allows(
    configs: Iterable[SettingsSource],
    servers: Iterable[ServerConfig],
    findings: Iterable[Finding],
    *,
    analyzer: str = ANALYZER_NAME,
) -> list[Finding]:
    """PERM-007 — whole-server MCP allow rules on servers with HIGH+ findings.

    Runs after every other analyzer (:func:`mcp_audit.scanner._run_static_pipeline`
    step 5b, and again across scopes after ``scan --project``), because "has
    HIGH or CRITICAL findings" is known only then.  A server counts when a HIGH
    or CRITICAL poisoning, rug-pull or supply-chain finding names it (same
    name, client and config file); an SC-004 counts only when the configured
    version is known to be affected.

    Args:
        configs: Discovered config files; Claude Code settings files among
            them are read for ``permissions.allow``.
        servers: Every server parsed in this scan.
        findings: Every finding so far.
        analyzer: Analyzer label for findings.

    Returns:
        One HIGH finding per (settings file, flagged server) pair.
    """
    flagged = _flagged_servers(list(servers), list(findings))
    if not flagged:
        return []
    out: list[Finding] = []
    for config in configs:
        if not is_claude_code_settings_file(config.path):
            continue
        settings = load_claude_settings(config.raw, config.path)
        if settings is None:
            continue
        matched: dict[tuple[str, str], tuple[str, ServerConfig, list, list]] = {}
        for rule in settings.rules_in("allow"):
            key = whole_server_allow_target(rule)
            if key is None:
                continue
            for server, own in flagged.get(key, []):
                if not _reaches(settings, server):
                    continue
                slot = (server.name, str(server.config_path))
                if slot not in matched:
                    matched[slot] = (key, server, own, [])
                matched[slot][3].append(rule)
        for key, server, own, rules in matched.values():
            out.append(
                _flagged_allow_finding(
                    settings, config.client_name, analyzer, rules, key, server, own
                )
            )
    return out
