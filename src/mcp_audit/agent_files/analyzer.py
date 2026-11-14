"""Analyze agent instruction and memory files for security issues.

Finding IDs
-----------
SKILL-001 (HIGH; the pattern's ``skill_severity`` for POISON-070..075)
    Injection or exfiltration instruction detected in a skill / command /
    instruction file.  Fires when any PATTERNS entry from
    :mod:`mcp_audit.analyzers.poisoning` (except POISON-040/060 obfuscation
    patterns and POISON-050 length) matches the file body.  The directive
    patterns (STORY-0099) report at their own severity: HIGH for secrecy,
    MEDIUM for tool-disabling, LOW for autonomy override, coercive framing,
    startup execution and remote instructions.

SKILL-002 (MEDIUM)
    Obfuscated or oversized block in a skill / command file.  Fires on
    zero-width Unicode (POISON-040), homoglyph substitution (POISON-060),
    or body length ≥ 2 000 chars.

SKILL-003 (MEDIUM)
    Unpinned external content instruction.  Fires when the file body
    references a raw ``http(s)://``, ``ftp(s)://``, or ``ws(s)://`` URL, or an
    inline ``data:`` URI — any of which can pull in or reference external (and
    potentially attacker-controlled) content at runtime.  ``data:`` URIs get a
    distinct description because they can embed an obfuscated payload directly.

MEM-001 (MEDIUM)
    Imperative override instruction in a memory file.  Fires on POISON-012
    (behavioral override) except a "do not tell <someone> to <verb>"
    instruction to someone other than the user (and not a purpose clause),
    or on POISON-070 (a secrecy directive aimed at the user or
    the conversation) — more conservative than SKILL-001 to control the
    false-positive rate on innocuous project CLAUDE.md files (STORY-0099).

MEM-002 (MEDIUM)
    Injection pattern in a memory file.  Fires on the restricted subset
    confirmed for memory: POISON-010 (XML markers), POISON-011 (LLM format
    markers), POISON-040 (zero-width Unicode), POISON-060 (homoglyphs).
    Exfiltration, cross-tool, and length patterns are intentionally excluded
    — the false-positive rate on innocent memory files is too high.

Sidecars (STORY-0095)
    Every other prose file in a skill's directory (``.md``, ``.txt`` …) gets
    SKILL-001, the SKILL-002 obfuscation check and POISON-041/042, but not the
    SKILL-002 length check or SKILL-003; see
    :func:`mcp_audit.agent_files.skill_package.sidecar_findings`.

MEM-003 (MEDIUM; LOW for a Markdown file under ``~/.claude/``)
    A project instruction file's Claude Code ``@path`` import resolves
    outside the scanned folder (an "external import", which Claude Code asks
    once per project to approve), or to a file matched by ``.gitignore`` (so
    normally never committed or reviewed).  Read from the import edges
    discovery records (:mod:`mcp_audit.agent_files.imports`); the external
    target itself is never read.  LOW for the shape Claude Code's own memory
    docs suggest for personal instructions (``@~/.claude/....md``).  STORY-0098.

MEM-004 (HIGH)
    A heartbeat file (OpenClaw ``HEARTBEAT.md``, run on a timer) tells the
    agent to answer with the suppression reply (``HEARTBEAT_OK``,
    ``NO_REPLY``, ``notify: false``) unconditionally, while hiding a step,
    or straight after running something: the Agent Commander shape, a
    recurring step whose result the owner never sees.  See
    :mod:`mcp_audit.agent_files.heartbeat`.  STORY-0098.

MEM-005 (MEDIUM)
    An always-loaded instruction file (CLAUDE.md tiers, rules, AGENTS.md,
    OpenClaw workspace and heartbeat files) holds a conditional sleeper
    trigger (a later cue from the user, a privilege, hostname or date test,
    an unobserved time) in an if/when clause, a consequence that opens with
    an action verb, and a payload cue in it.  Runs with MEM-003/004 (default scan).  See
    :mod:`mcp_audit.agent_files.sleeper`.  STORY-0099.

MEM-007 (MEDIUM)
    An instruction file (``AGENTS.md``, ``CLAUDE.md``, ``GEMINI.md``,
    ``.cursorrules``) sits at the top of ``~/Downloads`` or ``~/Desktop``.  An
    agent started in that folder follows it, and the folders are where files
    arrive from outside.  Forever Security (Gal Weizman, Omer Samet), 2026-10-26.
    STORY-0155.

MEM-008 (HIGH outside a git repository, MEDIUM inside one)
    An instruction file tells the agent to edit a machine-wide agent config
    (``~/.codex/config.toml``, ``~/.claude/settings.json``, ``~/.cursor/mcp.json``,
    ``~/.gemini/settings.json``), to set a model base URL to a host that is not
    the vendor's, or to run an agent with approvals off.  See
    :mod:`mcp_audit.agent_files.instruction_shapes`.  STORY-0155.

MEM-006 (HIGH in a project file, MEDIUM in the user's own)
    An always-applied instruction file (the MEM-005 files plus Cursor rules
    and Copilot instruction files) tells the agent, in one sentence, to send
    environment variables, ``.env``, SSH or cloud credential files, or "all
    the secrets / tokens / keys" to a URL, IP address, email address or a
    named server / endpoint / webhook.  Runs with MEM-003/004/005.  See
    :mod:`mcp_audit.agent_files.exfil`.

Imported and referenced files (``AgentFile.imported_from`` set) are scanned
with the importing file's rule set; secrets matching ``SECRET_PATTERNS`` are
redacted from their findings' text.

SKILL-004 (INFO)
    Skill bundles executable scripts.  Fires once per discovered
    ``SKILL.md`` when its own directory contains a ``scripts/`` subdirectory
    with at least one file.  Purely an inventory finding — it lists bundled
    script *filenames* only, never file contents, and never runs or reads
    the scripts themselves.  A skill's bundled scripts run with the same
    trust as the skill's instructions; this exists so a reviewer knows they
    are there.

POISON-041/042/043/044 — documented exception
    (POISON-041 HIGH, POISON-042 LOW, POISON-043/044 MEDIUM.)
    Concealment channels (Unicode TAG-character runs decoding to hidden
    text; HTML comments invisible when this file renders as Markdown;
    zero-width characters read as bits and variation-selector runs read as
    bytes, STORY-0099).
    Fires on both skill/command/instruction and memory surfaces via
    :func:`mcp_audit.analyzers.poisoning.scan_concealed_channels` and
    :func:`mcp_audit.analyzers.poisoning.build_concealment_finding` — the
    SAME shared builder the config surface (``PoisoningAnalyzer``) calls, so
    the two never drift (STORY-0068).  Unlike every other finding this
    module emits, these two carry ``analyzer="poisoning"``, not
    ``"agent_files"`` — a deliberate exception, because the finding IDs and
    their meaning are identical regardless of surface (an "outer" SKILL-/
    MEM- rebrand would imply severity or scope differs by surface, which it
    does not; the precedent is ``discovery.py``'s shared symlink-finding
    builders, which keep ``analyzer="discovery"`` regardless of whether
    ``discovery.py`` or ``agent_files/discovery.py`` calls them).
    POISON-042/043/044 fire only for the TAG, zero-width binary and
    variation-selector channels — a bare HTML comment is common and
    legitimate in Markdown and must stay silent unless its content actually
    matches an existing pattern.

Subagent definitions (STORY-0094)
---------------------------------
A ``.claude/agents/**/*.md`` body is the subagent's system prompt, so it gets
the skill/command rules above (the memory subset would miss exfiltration
instructions such as reading ``~/.ssh``), without the SKILL-002 length check.
Its frontmatter findings, AGENT-001..004 plus HOOK-001/002 on its hooks, come
from :meth:`ConfigHygieneAnalyzer.analyze_agent_definition`, shared with the
scan pipeline; see :mod:`mcp_audit.agent_files.subagents`.

Pattern import policy
---------------------
Detection patterns are **imported** from :mod:`mcp_audit.analyzers.poisoning`
— the ``PATTERNS`` list is NOT forked or duplicated here.  Any change to the
master pattern list in ``poisoning.py`` automatically applies here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_audit._paths import find_git_root
from mcp_audit.agent_files.exfil import find_exfil_directives
from mcp_audit.agent_files.framing import (
    STATE_ITEM_PATTERN_IDS,
    FileFraming,
    Framing,
)
from mcp_audit.agent_files.heartbeat import find_suppression
from mcp_audit.agent_files.instruction_shapes import find_instruction_hits
from mcp_audit.agent_files.models import MEMORY_SURFACES, AgentFile, AgentFileSurface
from mcp_audit.agent_files.sleeper import find_sleepers
from mcp_audit.analyzers.credentials import redact_secret_patterns
from mcp_audit.analyzers.poisoning import (
    PATTERNS,
    ConcealmentMatch,
    DetectionPattern,
    build_concealment_finding,
    concealment_finding_id,
    iter_pattern_matches,
    matched_pattern,
    memory_override_match,
    normalize_for_detection,
    redacted_snippet,
    scan_concealed_channels,
)
from mcp_audit.analyzers.supply_chain import redact_command_text
from mcp_audit.models import Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Callable

# ── Pattern sub-sets ──────────────────────────────────────────────────────────

# IDs of obfuscation patterns that become SKILL-002 (not SKILL-001).
_OBFUSCATION_IDS: frozenset[str] = frozenset({"POISON-040", "POISON-060"})

# IDs of patterns used for MEM-002 (restricted memory injection set).
_MEM_INJECTION_IDS: frozenset[str] = frozenset(
    {"POISON-010", "POISON-011", "POISON-040", "POISON-060"}
)

# ID of the excessive-length pattern — applied to skills but not memory.
_LENGTH_PATTERN_ID: str = "POISON-050"

# MEM-001 uses the behavioral override pattern (read by
# memory_override_match) and the secrecy directive (STORY-0099).
_MEM_OVERRIDE_ID: str = "POISON-012"
_MEM_SECRECY_ID: str = "POISON-070"

# Minimum body length (chars) that triggers SKILL-002 oversized finding.
_SKILL_OVERSIZED_THRESHOLD: int = 2_000

# URL pattern for SKILL-003 (raw external URL in instruction text).  Covers
# http(s), ftp(s), and ws(s) — the WebSocket schemes are a live bidirectional
# channel and therefore higher risk than a one-shot HTTP fetch.
_EXTERNAL_URL_RE: re.Pattern[str] = re.compile(
    r"(?:https?|ftps?|wss?)://[^\s\)\]>\"']{4,}", re.IGNORECASE
)

# Inline data: URI (data:text/..., data:application/...).  These can embed an
# obfuscated payload that is decoded and executed at runtime, so they get their
# own SKILL-003 description distinct from the remote-URL case.
_DATA_URI_RE: re.Pattern[str] = re.compile(
    r"data:[a-z][a-z0-9.+-]*/[a-z0-9.+-]+[;,]", re.IGNORECASE
)

# Matches of one pattern judged by the describes-vs-directs gate per file
# (the first directed one is reported); the rest are not looked at.
_MAX_GATED_MATCHES: int = 256

# Longest excerpt of the matched line shown in evidence.
_LINE_EXCERPT_CHARS: int = 160

# ── Helpers ───────────────────────────────────────────────────────────────────


def _body_start(af: AgentFile) -> int:
    """Offset in ``raw_content`` where ``body`` begins (0 when unknown)."""
    raw, body = af.raw_content, af.body
    if body and len(body) < len(raw) and raw.endswith(body):
        return len(raw) - len(body)
    return 0


def _concealment_text(af: AgentFile) -> tuple[str, int]:
    """The text the concealment channels read, and its first line's index.

    The body, plus the blank lines frontmatter splitting strips from its
    start: padding placed straight after the frontmatter is still padding
    (POISON-045, STORY-0141).
    """
    start = _body_start(af)
    if start == 0:
        return af.body, 0
    raw = af.raw_content
    back = start
    while back > 0 and raw[back - 1] in "\n\r \t":
        back -= 1
    # Skip the rest of the line the walk stopped on (the closing "---").
    nl = raw.find("\n", back)
    back = start if nl == -1 or nl >= start else nl + 1
    return raw[back:], raw.count("\n", 0, back)


def _line_excerpt(line: str, start: int, end: int) -> str:
    """Up to :data:`_LINE_EXCERPT_CHARS` of *line* around ``[start, end)``.

    Redacted with :func:`~mcp_audit.analyzers.supply_chain.redact_command_text`
    (URL userinfo, ``SECRET_PATTERNS``, inline schemes and credential
    headers) before it is cut, over a window reaching 300 characters past
    each side of the match, so a secret straddling the cut is never
    half-printed.
    """
    line = line.rstrip("\r")
    limit = _LINE_EXCERPT_CHARS
    if len(line.strip()) <= limit:
        red = redact_command_text(line.strip())
        return red if len(red) <= limit else red[:limit] + "…"
    lo = max(0, start - 300)
    window = line[lo : end + 300]
    red = redact_command_text(window)
    anchor = red.find(line[start:end]) if end > start else -1
    if anchor < 0:
        anchor = min(start - lo, len(red))
    # Start at the line's beginning when the match fits there.
    fits = lo == 0 and anchor + (end - start) <= limit - 20
    cut = 0 if fits else max(0, anchor - limit // 3)
    piece = red[cut : cut + limit].strip()
    head = "…" if cut > 0 or lo > 0 else ""
    tail = "…" if cut + limit < len(red) or end + 300 < len(line) else ""
    return f"{head}{piece}{tail}"


def _line_evidence(
    lines: list[str], index: int, offset: int, pattern: DetectionPattern | None
) -> tuple[int, str]:
    """``(1-based line number, excerpt)`` for 0-based body line *index*.

    *offset* is the number of file lines before the body.  The excerpt is
    centred on *pattern*'s match in the original line when it matches there
    (it may only have matched after Unicode normalization).
    """
    line = lines[index] if 0 <= index < len(lines) else ""
    m = pattern.pattern.search(line) if pattern is not None else None
    start, end = (m.start(), m.end()) if m else (0, 0)
    return index + 1 + offset, _line_excerpt(line, start, end)


def _with_concealment_line(
    finding: Finding, cmatch: ConcealmentMatch, scan_text: str, first_line: int
) -> Finding:
    """Prefix a concealment finding's evidence with the line it starts on."""
    start = cmatch.channel.start
    if start is None:
        return finding
    line = scan_text.count("\n", 0, start) + 1 + first_line
    return finding.model_copy(
        update={"evidence": f"Line {line}: {finding.evidence}", "line": line}
    )


def _is_skill_surface(af: AgentFile) -> bool:
    """Return True for skill/command/instruction surfaces (not memory)."""
    return af.surface in (
        AgentFileSurface.CLAUDE_COMMAND,
        AgentFileSurface.CLAUDE_SKILL,
        AgentFileSurface.CURSOR_RULE,
        AgentFileSurface.COPILOT_INSTRUCTION,
        AgentFileSurface.COPILOT_SCOPED,
        AgentFileSurface.COPILOT_PROMPT,
    )


def _check_skill_scripts(af: AgentFile) -> Finding | None:
    """SKILL-004 (INFO): inventory a skill's bundled ``scripts/`` directory.

    Fires once per skill (one Finding per ``SKILL.md``) when the skill's own
    directory contains a ``scripts/`` subdirectory with at least one file.
    Lists filenames only — never file contents — this is an inventory
    finding, not a content-based detection, and never opens the scripts.
    """
    scripts_dir = af.path.parent / "scripts"
    if not scripts_dir.is_dir() or scripts_dir.is_symlink():
        return None
    try:
        filenames = sorted(
            p.name for p in scripts_dir.iterdir() if p.is_file() and not p.is_symlink()
        )
    except OSError:
        return None
    if not filenames:
        return None
    return _skill_finding(
        af,
        "SKILL-004",
        Severity.INFO,
        "Skill bundles executable scripts",
        (
            f"The skill '{af.path.parent.name}' bundles a 'scripts/'"
            f" directory containing {len(filenames)} file(s). Bundled"
            " scripts run with the same trust as the skill's own"
            " instructions — review their contents before relying on"
            " this skill."
        ),
        f"scripts/: {', '.join(filenames)}",
        "Review each bundled script's contents before trusting this skill.",
        owasp_mcp_top_10=["MCP03"],
    )


def _is_memory_surface(af: AgentFile) -> bool:
    """Return True for memory/context surfaces (always-loaded instructions)."""
    return af.surface in MEMORY_SURFACES


def redact_secrets(text: str) -> str:
    """Replace anything matching ``SECRET_PATTERNS`` (as ``advisory.feed.redact``)."""
    return redact_secret_patterns(text)


def _redacted(finding: Finding) -> Finding:
    return finding.model_copy(
        update={
            "title": redact_secrets(finding.title),
            "server": redact_secrets(finding.server),
            "description": redact_secrets(finding.description),
            "evidence": redact_secrets(finding.evidence),
            "remediation": redact_secrets(finding.remediation),
        }
    )


# ── MEM-003: imports from outside the project or from ignored files ───────────


def _is_personal_claude_md(target: Path, home: Path) -> bool:
    """A Markdown file under ``~/.claude/`` (the docs' personal-import shape)."""
    try:
        target.relative_to(home / ".claude")
    except ValueError:
        return False
    return target.suffix.lower() == ".md"


def _mem003_findings(af: AgentFile, home: Path) -> list[Finding]:
    findings: list[Finding] = []
    for edge in af.edges:
        if edge.kind != "import" or edge.status not in ("outside", "ignored"):
            continue
        where = f"'@{edge.raw}' (line {edge.line})"
        if edge.status == "outside":
            personal = _is_personal_claude_md(edge.target, home)
            severity = Severity.LOW if personal else Severity.MEDIUM
            title = "Instruction file imports a file from outside the project"
            description = (
                f"'{af.path.name}' imports {where}, which resolves to"
                f" '{edge.target}', outside the scanned folder. Claude Code loads"
                " an imported file into the agent's context with the file that"
                " imports it (imports nest up to four hops). For a project file it"
                " asks once per project to approve external imports; an AGENTS.md"
                " it reads directly loads them with no prompt once approved. The"
                " imported text is not in the repository, so a review of the"
                " repository never sees it, and it differs on every machine."
                " mcp-audit did not read it."
            )
            if personal:
                description += (
                    " This is the shape Claude Code's memory docs suggest for"
                    " personal instructions shared across worktrees"
                    " (@~/.claude/my-project-instructions.md); if you added it,"
                    " nothing needs to change."
                )
            evidence = f"@{edge.raw} (line {edge.line}) -> {edge.target}"
            remediation = (
                "Move the instructions into the repository where they are reviewed,"
                " or remove the import. Decline Claude Code's external-imports"
                " prompt in projects you don't trust."
            )
        else:
            severity = Severity.MEDIUM
            title = "Instruction file imports a .gitignore'd file"
            description = (
                f"'{af.path.name}' imports {where}, and '{edge.target}' is matched"
                f" by .gitignore ({edge.detail}), so it is normally never"
                " committed. Its text reaches every agent session without ever"
                " appearing in review or git diff, and anything that can write the"
                " file (a tool, a script, the agent itself) changes the agent's"
                " instructions with no trace in the repository. mcp-audit reads"
                " .gitignore files only; it cannot see a file that was force-added."
            )
            evidence = (
                f"@{edge.raw} (line {edge.line}) -> {edge.target}"
                f" | .gitignore: {edge.detail}"
            )
            remediation = "Commit and review the imported file, or remove the import."
        if af.imported_from is not None:
            description += (
                f" '{af.path.name}' is itself imported from '{af.imported_from}'."
            )
        findings.append(
            _redacted(
                _skill_finding(
                    af,
                    "MEM-003",
                    severity,
                    title,
                    description,
                    evidence,
                    remediation,
                    owasp_mcp_top_10=["MCP10"],
                    cwe="CWE-829",
                )
            )
        )
    return findings


# ── MEM-004: heartbeat output suppression ─────────────────────────────────────

_MEM004_REASON = {
    "forced": "answer with the suppression reply no matter what happened",
    "hidden": (
        "answer with the suppression reply while also being told to keep a step"
        " from the owner"
    ),
    "after-action": (
        "run something and then answer with the suppression reply, with no"
        " 'nothing to report' condition"
    ),
}


def _mem005_findings(af: AgentFile) -> list[Finding]:
    """MEM-005: conditional sleeper triggers in an always-loaded file (STORY-0099)."""
    if af.surface not in MEMORY_SURFACES:
        return []
    findings: list[Finding] = []
    for hit in find_sleepers(af.body):
        findings.append(
            _redacted(
                _skill_finding(
                    af,
                    "MEM-005",
                    Severity.MEDIUM,
                    "Instruction file holds a conditional sleeper trigger",
                    (
                        f"Line {hit.line} of '{af.path.name}' makes an action wait"
                        " for a trigger (a later cue from the user, a privilege,"
                        " hostname or production-host test, a calendar date, or a"
                        " time when nobody is watching), and the action sends,"
                        " runs or deletes something sensitive (a URL, credentials,"
                        " backups, a remote endpoint, or done silently). The file"
                        " is loaded into every"
                        " session, so the rule sits dormant until the condition"
                        " holds. Conditional triggers were 18.4% of the hidden"
                        " features of confirmed-malicious skills (USENIX Security"
                        " 2026, arXiv 2602.06547)."
                    ),
                    f"Line {hit.line}: {redacted_snippet(hit.sentence, 160)!r}",
                    (
                        "Remove the rule unless you wrote it and know what the"
                        " condition guards; then check whether the condition has"
                        " already been met."
                    ),
                    owasp_mcp_top_10=["MCP03", "MCP06"],
                    cwe="CWE-511",
                )
            )
        )
    return findings


#: Always-applied instruction files MEM-006 reads: the memory surfaces plus
#: Cursor rules and Copilot instruction files, which a repository can plant
#: the same way (JFrog's testmetest repositories planted ``.cursor/rules``).
_MEM006_SURFACES: frozenset[AgentFileSurface] = MEMORY_SURFACES | frozenset(
    {
        AgentFileSurface.CURSOR_RULE,
        AgentFileSurface.COPILOT_INSTRUCTION,
        AgentFileSurface.COPILOT_SCOPED,
    }
)


def _mem006_findings(af: AgentFile) -> list[Finding]:
    """MEM-006: an instruction file tells the agent to send secrets somewhere."""
    if af.surface not in _MEM006_SURFACES:
        return []
    repository = af.scope == "project"
    severity = Severity.HIGH if repository else Severity.MEDIUM
    whose = (
        "a repository file, so anyone who could change the repository wrote it"
        if repository
        else "one of your own instruction files"
    )
    findings: list[Finding] = []
    for hit in find_exfil_directives(af.body):
        findings.append(
            _redacted(
                _skill_finding(
                    af,
                    "MEM-006",
                    severity,
                    "Instruction file tells the agent to send secrets out",
                    (
                        f"Line {hit.line} of '{af.path.name}' tells the agent to send"
                        " environment variables, a .env file, SSH or cloud credentials,"
                        " or all of some kind of secret to a URL, address or named"
                        " server. The agent reads this file as standing orders in"
                        f" every session; this is {whose}. With auto-approval on, the"
                        " send runs without a prompt. Planting instruction files in"
                        " repositories was part of campaigns reported in October 2026"
                        " (JFrog Security Research; SafeDep)."
                    ),
                    f"Line {hit.line}: {redacted_snippet(hit.sentence, 160)!r}",
                    (
                        "Do not run an agent in this folder until the line is removed,"
                        " and never with auto-approval. If an agent already ran here,"
                        " rotate the credentials it could read."
                    ),
                    owasp_mcp_top_10=["MCP03", "MCP01"],
                    cwe="CWE-200",
                )
            )
        )
    return findings


def _in_git_repository(path: Path) -> bool:
    """True when *path* sits inside a git working tree other than ``$HOME`` itself.

    A dotfiles repository at ``$HOME`` would otherwise make every file under it
    look reviewed.  Reads the filesystem for a ``.git`` entry only; never runs
    git.
    """
    try:
        root = find_git_root(path.parent)
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        return False
    return root is not None and root != home


def _mem007_findings(af: AgentFile) -> list[Finding]:
    """MEM-007: an instruction file in Downloads or Desktop (STORY-0155)."""
    if not af.dropped:
        return []
    folder = af.path.parent.name
    return [
        _redacted(
            _skill_finding(
                af,
                "MEM-007",
                Severity.MEDIUM,
                f"Agent instruction file in {folder}",
                (
                    f"'{af.path.name}' sits at the top of your {folder} folder."
                    " An agent (Codex, Claude Code, Gemini CLI, Cursor) started in"
                    " this folder reads it as standing instructions, and"
                    f" {folder} is where files arrive from a browser, a chat or a"
                    " mail attachment. Forever Security (Gal Weizman, Omer Samet,"
                    " disclosed 2026-10-26) found an AGENTS.md planted in a"
                    " customer's Downloads that told Codex to add an MCP server"
                    " to its config and then run with approvals and sandbox off."
                    " mcp-audit looked only at this one folder level."
                ),
                f"~/{folder}/{af.path.name}",
                (
                    "Open the file. If you did not put it there, delete it, and"
                    " do not start a coding agent in this folder. Start agents in"
                    " a project folder instead."
                ),
                owasp_mcp_top_10=["MCP03", "MCP06"],
                cwe="CWE-426",
            )
        )
    ]


_MEM008_KIND = {
    "config-edit": "edit a machine-wide agent config",
    "permissions": "run an agent with approvals off",
    "base-url": "send model traffic to another host",
}


def _mem008_findings(af: AgentFile) -> list[Finding]:
    """MEM-008: an instruction file reaches past its folder (STORY-0155)."""
    if af.surface not in _MEM006_SURFACES:
        return []
    hits = find_instruction_hits(af.body)
    if not hits:
        return []
    in_repo = _in_git_repository(af.path)
    severity = Severity.MEDIUM if in_repo else Severity.HIGH
    where = (
        "inside a git repository, where a change would show in a diff"
        if in_repo
        else "outside any git repository, so nothing reviews it"
    )
    kinds = sorted({h.kind for h in hits}, key=lambda k: list(_MEM008_KIND).index(k))
    what = "; ".join(_MEM008_KIND[k] for k in kinds)
    first = hits[0]
    detail = f"line {first.line}" + (
        f" (and {len(hits) - 1} more)" if len(hits) > 1 else ""
    )
    return [
        _redacted(
            _skill_finding(
                af,
                "MEM-008",
                severity,
                "Instruction file changes machine-wide agent settings or approvals",
                (
                    f"'{af.path.name}' tells the agent to {what} ({detail}). Each"
                    " reaches past the folder the agent runs in: a machine-wide"
                    " config change stays after the session, a changed base URL"
                    " sends prompts, code and the API key elsewhere, and approvals"
                    " off lets every later step run unasked. This file is"
                    f" {where}. Forever Security (Gal Weizman, Omer Samet,"
                    " disclosed 2026-10-26) reported an AGENTS.md in Downloads that"
                    " added an MCP server to ~/.codex/config.toml and ran codex"
                    " with approvals and sandbox off. Setup guides can say the"
                    " first of these on purpose; read the line."
                ),
                f"Line {first.line}: {redacted_snippet(first.source, 160)!r}",
                (
                    "Do not follow the instruction. If you did not write it,"
                    " remove it. If an agent already ran here, check the config"
                    " file it names for entries you did not add."
                ),
                owasp_mcp_top_10=["MCP03", "MCP02"],
                cwe="CWE-269",
            )
        )
    ]


def _mem004_findings(af: AgentFile) -> list[Finding]:
    if af.surface != AgentFileSurface.HEARTBEAT:
        return []
    findings: list[Finding] = []
    for hit in find_suppression(af.body):
        findings.append(
            _redacted(
                _skill_finding(
                    af,
                    "MEM-004",
                    Severity.HIGH,
                    "Heartbeat file hides what the agent does",
                    (
                        f"'{af.path.name}' is a heartbeat checklist: OpenClaw reads"
                        " it on a timer (every 30 minutes by default) and drops a"
                        " reply that starts or ends with HEARTBEAT_OK when at most"
                        " 300 characters remain; NO_REPLY and notify: false"
                        " likewise deliver nothing. Line"
                        f" {hit.line} tells the agent to {_MEM004_REASON[hit.reason]}."
                        " That is the Agent Commander shape (Embrace The Red,"
                        " 2026): a recurring step that runs while its result never"
                        " reaches the owner. The documented use is conditional"
                        " ('if nothing needs attention, reply HEARTBEAT_OK')."
                        " Newer OpenClaw releases no longer read HEARTBEAT.md at"
                        " runtime; openclaw doctor --fix imports its tasks into"
                        " automation jobs."
                    ),
                    f"Line {hit.line}: {hit.sentence!r}",
                    (
                        "Remove the step and the suppression instruction unless you"
                        " wrote them, and check what the agent ran on earlier"
                        " heartbeats. Reply HEARTBEAT_OK only when nothing needs"
                        " attention."
                    ),
                    owasp_mcp_top_10=["MCP06", "MCP08"],
                    cwe="CWE-223",
                )
            )
        )
    return findings


def analyze_instruction_reach(
    files: list[AgentFile], home: Path | None = None
) -> list[Finding]:
    """MEM-003 to MEM-008 only: the checks the default scan runs.

    Args:
        files: Agent files with their import edges filled in by discovery.
        home: The user's home directory (defaults to :meth:`Path.home`).

    Returns:
        MEM-003 findings for each external or ``.gitignore``'d import of a
        project file, MEM-004 findings for heartbeat files, MEM-005
        findings for sleeper triggers in always-loaded instruction files, and
        MEM-006 findings for directives that send secrets out.
    """
    home = home if home is not None else Path.home()
    findings: list[Finding] = []
    seen_bodies: set[str] = set()
    for af in files:
        if af.scope == "project":
            findings.extend(_mem003_findings(af, home))
        findings.extend(_mem004_findings(af))
        # One file reached twice (CLAUDE.md -> AGENTS.md symlink, or imported
        # by two files) is checked once for MEM-005.
        key = _real_path_key(af.path)
        if key in seen_bodies:
            continue
        seen_bodies.add(key)
        findings.extend(_mem005_findings(af))
        findings.extend(_mem006_findings(af))
        findings.extend(_mem007_findings(af))
        findings.extend(_mem008_findings(af))
    return findings


def _real_path_key(path: Path) -> str:
    """Return *path* resolved through symlinks, or as written if that fails."""
    try:
        return str(path.resolve())
    except (OSError, RuntimeError):
        return str(path)


def _skill_finding(
    af: AgentFile,
    finding_id: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    owasp_mcp_top_10: list[str],
    cwe: str | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="agent_files",
        client=af.client,
        server=af.display_name,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        finding_path=str(af.path),
        owasp_mcp_top_10=owasp_mcp_top_10,
        cwe=cwe,
    )


# ── Skill/instruction analyzers ───────────────────────────────────────────────


def _skill001_finding(
    af: AgentFile,
    pat: DetectionPattern,
    first: re.Match[str],
    norm_text: str,
    framing: FileFraming,
    lines: list[str],
    offset: int,
    gate_off: bool = False,
) -> Finding:
    """SKILL-001 for *pat*: the first directed occurrence, else INFO.

    Every occurrence (up to :data:`_MAX_GATED_MATCHES`) is put through the
    describes-vs-directs gate (:mod:`mcp_audit.agent_files.framing`); the
    finding names the first one that directs the agent at the pattern's
    severity.  When none does, it names the first occurrence at INFO and
    says why it reads as described.  Evidence carries the line number and
    the matched line (STORY-0141).

    The gate fails closed: with *gate_off* (the file has a concealment
    channel) or when the pattern matches more than
    :data:`_MAX_GATED_MATCHES` times with none of the judged ones directed,
    the first occurrence is reported at the pattern's own severity.
    """
    matches = iter_pattern_matches(pat, af.body, norm_text, _MAX_GATED_MATCHES + 1) or [
        first
    ]
    chosen = matches[0]
    state_items = pat.id in STATE_ITEM_PATTERN_IDS
    framed = framing.classify(chosen.start(), chosen.end(), state_items=state_items)
    if gate_off or len(matches) > _MAX_GATED_MATCHES:
        framed = Framing(directed=True)
    else:
        for m in matches:
            f = framing.classify(m.start(), m.end(), state_items=state_items)
            if f.directed:
                chosen, framed = m, f
                break
    line_no, excerpt = _line_evidence(
        lines, framing.line_of(chosen.start()), offset, pat
    )
    raw_line = lines[framing.line_of(chosen.start())] if lines else ""
    raw_m = pat.pattern.search(raw_line)
    matched = redacted_snippet(raw_m.group(0) if raw_m else chosen.group(0), 120)
    evidence = f"Line {line_no}: {excerpt!r} (matched {matched!r})"
    description = (
        f"The file '{af.path.name}' contains an instruction"
        f" matching the pattern '{pat.name}': {pat.description}."
        " This pattern is associated with prompt injection or"
        " data exfiltration attacks."
    )
    title = f"Injection/exfiltration instruction in skill file ({pat.name})"
    severity = pat.skill_severity or Severity.HIGH
    if not framed.directed:
        severity = Severity.INFO
        title += " - described, not directed"
        description = (
            f"The file '{af.path.name}' contains text matching the pattern"
            f" '{pat.name}' ({pat.description}), but every occurrence reads as"
            f" described, not directed: line {line_no} sits {framed.reason}."
            " Security checklists and attack write-ups name the same files and"
            " phrases an attack uses. Listed at INFO so a reviewer can confirm;"
            " the same text addressed to the agent ('you must ...', 'before"
            " formatting, run ...', or a sentence opening with an order) would"
            " be reported at the pattern's own severity."
        )
        evidence += f" - described, not directed ({framed.reason})"
    return _skill_finding(
        af,
        "SKILL-001",
        severity,
        title,
        description,
        evidence,
        (
            "Review the file for malicious instructions. Remove any"
            " content you did not intentionally add."
        ),
        owasp_mcp_top_10=["MCP03", "MCP01"],
        cwe=pat.cwe,
    )


def _concealment_findings(
    af: AgentFile, surface_noun: str, emit: Callable[[str, str, Finding], None]
) -> None:
    """POISON-041..045 for *af*, each with the line its channel starts on.

    The shared builder (see the module docstring's "documented exception")
    reads the body plus any blank lines frontmatter splitting stripped from
    its start (:func:`_concealment_text`).
    """
    scan_text, first_line = _concealment_text(af)
    for cmatch in scan_concealed_channels(scan_text):
        pat_key = cmatch.matched_pattern.id if cmatch.matched_pattern else "none"
        fid = concealment_finding_id(cmatch)
        emit(
            fid,
            f"concealment:{cmatch.channel.kind}:{pat_key}",
            _with_concealment_line(
                build_concealment_finding(
                    cmatch,
                    client=af.client,
                    server=af.display_name,
                    surface_noun=surface_noun,
                    markdown_surface=True,
                    finding_path=str(af.path),
                ),
                cmatch,
                scan_text,
                first_line,
            ),
        )


def _analyze_skill(af: AgentFile, check_length: bool = True) -> list[Finding]:
    """Analyze one skill / command / instruction file.

    Returns SKILL-001, SKILL-002, and/or SKILL-003 findings.
    Deduplicates by (finding_id, poison_pattern_id) so the same pattern
    cannot produce two findings on the same file.

    Args:
        af: The file to analyze.
        check_length: Apply the SKILL-002 oversized-file check. ``False`` for
            subagent definitions: the body is the subagent's whole system
            prompt, where length is expected rather than a signal.
    """
    findings: list[Finding] = []
    text = af.body
    # Normalize once for matching (homoglyph/compat folding); evidence always
    # shows the original bytes via the raw-match fallback below.
    norm_text = normalize_for_detection(text)
    seen: set[tuple[str, str]] = set()
    lines = text.split("\n")
    offset = af.raw_content.count("\n", 0, _body_start(af))
    framing: FileFraming | None = None
    gate_off = False

    def _emit(fid: str, pat_id: str, f: Finding) -> None:
        key = (fid, pat_id)
        if key not in seen:
            seen.add(key)
            findings.append(f)

    for pat in PATTERNS:
        # Length pattern: only fire when the full body is long enough — use
        # the len() check instead of running the DOTALL regex for speed.
        if pat.id == _LENGTH_PATTERN_ID:
            if check_length and len(text) >= _SKILL_OVERSIZED_THRESHOLD:
                _emit(
                    "SKILL-002",
                    pat.id,
                    _skill_finding(
                        af,
                        "SKILL-002",
                        Severity.MEDIUM,
                        "Oversized skill/command file",
                        (
                            f"The file '{af.path.name}' contains"
                            f" {len(text):,} characters, which exceeds the"
                            f" {_SKILL_OVERSIZED_THRESHOLD:,}-character"
                            " threshold. Oversized instruction files can be"
                            " used to inject hidden content into the agent"
                            " context window."
                        ),
                        f"File length: {len(text):,} chars",
                        "Review the full file content for hidden instructions."
                        " Keep skill files concise.",
                        owasp_mcp_top_10=["MCP03"],
                        cwe="CWE-116",
                    ),
                )
            continue

        match = matched_pattern(pat, text, norm_text)
        if not match:
            continue

        # Evidence shows the attacker's ORIGINAL text: prefer the raw match;
        # fall back to a body snippet when the pattern only matched after
        # Unicode normalization.
        raw_match = pat.pattern.search(text)
        evidence_snippet = redacted_snippet(
            raw_match.group(0) if raw_match else text.strip(), 120
        )

        if pat.id in _OBFUSCATION_IDS:
            # POISON-040/060 match the original text, so offsets are raw.
            line_no, excerpt = _line_evidence(
                lines, text.count("\n", 0, match.start()), offset, pat
            )
            _emit(
                "SKILL-002",
                pat.id,
                _skill_finding(
                    af,
                    "SKILL-002",
                    Severity.MEDIUM,
                    f"Obfuscated content in skill file ({pat.name})",
                    (
                        f"The file '{af.path.name}' contains obfuscated"
                        f" content: {pat.description}. Stealth Unicode"
                        " techniques hide malicious instructions from human"
                        " reviewers while remaining readable to language models."
                    ),
                    f"Line {line_no}: {excerpt!r} (matched {evidence_snippet!r})",
                    "Investigate and remove obfuscating Unicode characters.",
                    owasp_mcp_top_10=["MCP03"],
                    cwe=pat.cwe or "CWE-116",
                ),
            )
        else:
            # Injection / exfiltration pattern → SKILL-001 (HIGH, or the
            # directive pattern's own skill_severity, STORY-0099), unless
            # every occurrence describes rather than directs (STORY-0141).
            if framing is None:
                framing = FileFraming(norm_text)
                # A file that hides or disguises text never gets the benefit
                # of the doubt: a concealment channel, or zero-width /
                # homoglyph obfuscation (POISON-040/060), turns the gate off.
                gate_off = bool(
                    scan_concealed_channels(_concealment_text(af)[0])
                ) or any(
                    matched_pattern(p, text, norm_text)
                    for p in PATTERNS
                    if p.id in _OBFUSCATION_IDS
                )
            _emit(
                "SKILL-001",
                pat.id,
                _skill001_finding(
                    af, pat, match, norm_text, framing, lines, offset, gate_off
                ),
            )

    # SKILL-003: unpinned external URL
    url_match = _EXTERNAL_URL_RE.search(text)
    if url_match:
        url_snippet = redacted_snippet(url_match.group(0), 100)
        key = ("SKILL-003", "url")
        if key not in seen:
            seen.add(key)
            findings.append(
                _skill_finding(
                    af,
                    "SKILL-003",
                    Severity.MEDIUM,
                    "Skill file references external URL",
                    (
                        f"The file '{af.path.name}' references an external URL"
                        f" ({url_snippet!r}). Instruction files that fetch or"
                        " link to unpinned external content can be used to"
                        " inject malicious instructions via a compromised or"
                        " attacker-controlled external resource."
                    ),
                    f"URL: {url_snippet!r}",
                    (
                        "Pin all referenced external resources to a specific,"
                        " verified commit or content hash. Prefer self-contained"
                        " instruction files with no outbound references."
                    ),
                    owasp_mcp_top_10=["MCP03", "MCP04"],
                    cwe="CWE-829",
                )
            )

    # SKILL-003: inline data: URI (distinct description — payload carrier)
    data_match = _DATA_URI_RE.search(text)
    if data_match:
        data_snippet = redacted_snippet(data_match.group(0), 100)
        key = ("SKILL-003", "data")
        if key not in seen:
            seen.add(key)
            findings.append(
                _skill_finding(
                    af,
                    "SKILL-003",
                    Severity.MEDIUM,
                    "Skill file contains inline data: URI",
                    (
                        f"The file '{af.path.name}' contains an inline data URI"
                        f" ({data_snippet!r}). Inline data URIs in a skill"
                        " instruction may embed an obfuscated payload that is"
                        " decoded and executed at runtime, bypassing review of"
                        " externally-hosted content."
                    ),
                    f"Data URI: {data_snippet!r}",
                    (
                        "Remove inline data: URIs from instruction files. If"
                        " external content is required, reference a pinned,"
                        " verified resource instead of embedding encoded data."
                    ),
                    owasp_mcp_top_10=["MCP03", "MCP04"],
                    cwe="CWE-829",
                )
            )

    # POISON-041..045: concealment channels (TAG-character runs, HTML
    # comments, zero-width and variation-selector runs, blank-line padding).
    # Shared builder with the config surface — see the module docstring's
    # "documented exception" note (analyzer="poisoning" here, not
    # "agent_files").
    _concealment_findings(af, f"the file '{af.path.name}'", _emit)

    return findings


# ── Memory analyzers ──────────────────────────────────────────────────────────


def _mem001_match(
    text: str, norm_text: str, patterns_by_id: dict[str, DetectionPattern]
) -> tuple[DetectionPattern, str, int] | None:
    """Return the pattern, evidence and match offset MEM-001 reports, or ``None``.

    POISON-012 counts as :func:`memory_override_match` reads it (a "do not
    tell <someone> to <verb>" instruction is not an override); a secrecy
    directive counts when POISON-070 matches.  Evidence is the original text
    when it matches, else a snippet; the offset is into *norm_text*.
    """
    override_pat = patterns_by_id.get(_MEM_OVERRIDE_ID)
    if override_pat is not None:
        m = memory_override_match(norm_text)
        if m is not None:
            raw_m = memory_override_match(text)
            snippet = raw_m.group(0) if raw_m else text.strip()
            return override_pat, redacted_snippet(snippet, 120), m.start()
    secrecy_pat = patterns_by_id.get(_MEM_SECRECY_ID)
    sm = (
        matched_pattern(secrecy_pat, text, norm_text)
        if secrecy_pat is not None
        else None
    )
    if secrecy_pat is not None and sm is not None:
        raw_m = secrecy_pat.pattern.search(text)
        snippet = raw_m.group(0) if raw_m else text.strip()
        return secrecy_pat, redacted_snippet(snippet, 120), sm.start()
    return None


def _analyze_memory(af: AgentFile) -> list[Finding]:
    """Analyze one memory/context file (CLAUDE.md tiers).

    Uses the restricted pattern subset confirmed for memory to control FP rate.
    Returns MEM-001 and/or MEM-002 findings.
    """
    findings: list[Finding] = []
    text = af.body
    # Normalize once for matching; evidence shows original bytes (raw fallback).
    norm_text = normalize_for_detection(text)
    seen: set[tuple[str, str]] = set()
    lines = text.split("\n")
    offset = af.raw_content.count("\n", 0, _body_start(af))

    # Patterns indexed by ID for O(1) lookup.
    patterns_by_id: dict[str, DetectionPattern] = {p.id: p for p in PATTERNS}

    def _emit(fid: str, pat_id: str, f: Finding) -> None:
        key = (fid, pat_id)
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # MEM-001: behavioral override (POISON-012, except "do not tell
    # <someone> to <verb>") or a secrecy directive aimed at the user
    # (POISON-070).  STORY-0099: that shape fired on ordinary prose
    # ("Do not tell a reviewer to pre-filter", trailofbits/skills AGENTS.md).
    hit = _mem001_match(text, norm_text, patterns_by_id)
    if hit is not None:
        override_pat, evidence_snippet, at = hit
        line_no, excerpt = _line_evidence(
            lines, norm_text.count("\n", 0, at), offset, override_pat
        )
        _emit(
            "MEM-001",
            _MEM_OVERRIDE_ID,
            _skill_finding(
                af,
                "MEM-001",
                Severity.MEDIUM,
                "Imperative override instruction in memory file",
                (
                    f"The memory file '{af.path.name}' contains an"
                    " instruction that attempts to override agent behavior"
                    f" ({override_pat.description}). Memory files are"
                    " injected into every session — a malicious override"
                    " instruction persists across all future interactions."
                ),
                f"Line {line_no}: {excerpt!r} (matched {evidence_snippet!r})",
                (
                    "Review the memory file for instructions you did not"
                    " intentionally add. Remove any behavioral overrides."
                    " Restrict write access: chmod 600 CLAUDE.md (or"
                    " equivalent)."
                ),
                owasp_mcp_top_10=["MCP03"],
                cwe="CWE-74",
            ),
        )

    # MEM-002: restricted injection subset (POISON-010/011/040/060)
    for pat_id in sorted(_MEM_INJECTION_IDS):
        pat = patterns_by_id.get(pat_id)
        if pat is None:
            continue
        m = matched_pattern(pat, text, norm_text)
        if not m:
            continue
        raw_m = pat.pattern.search(text)
        evidence_snippet = redacted_snippet(
            raw_m.group(0) if raw_m else text.strip(), 120
        )
        searched = text if pat_id in _OBFUSCATION_IDS else norm_text
        line_no, excerpt = _line_evidence(
            lines, searched.count("\n", 0, m.start()), offset, pat
        )
        _emit(
            "MEM-002",
            pat_id,
            _skill_finding(
                af,
                "MEM-002",
                Severity.MEDIUM,
                f"Injection pattern in memory file ({pat.name})",
                (
                    f"The memory file '{af.path.name}' contains an injection"
                    f" pattern: {pat.description}. Because memory files are"
                    " loaded into every agent session, a single injected pattern"
                    " provides persistent control over the agent's behavior."
                ),
                f"Line {line_no}: {excerpt!r} (matched {evidence_snippet!r})",
                (
                    "Inspect the memory file for content you did not add."
                    " Remove the offending pattern. Restrict write access to"
                    " the file."
                ),
                owasp_mcp_top_10=["MCP03"],
                cwe=pat.cwe or "CWE-74",
            ),
        )

    # POISON-041..045: concealment channels — same shared builder as
    # _analyze_skill (see the module docstring's "documented exception"
    # note). Applied to memory files too: a concealment channel is
    # anomalous on its own merit, independent of the restricted
    # _MEM_INJECTION_IDS subset used above for direct pattern matches.
    _concealment_findings(af, f"the memory file '{af.path.name}'", _emit)

    return findings


def _sidecar_findings(af: AgentFile) -> list[Finding]:
    """The rules above, on a skill's other prose files (STORY-0095).

    Lives in :mod:`mcp_audit.agent_files.skill_package`, imported here lazily
    because that module imports :func:`_analyze_skill` from this one.
    """
    from mcp_audit.agent_files.skill_package import sidecar_findings  # noqa: PLC0415

    return sidecar_findings(af)


# ── Public API ────────────────────────────────────────────────────────────────


def _analyze_agent_definition(af: AgentFile) -> list[Finding]:
    """AGENT-001..004 and HOOK-001/002 for one subagent definition file.

    Delegates to the one implementation the scan pipeline also uses
    (:meth:`ConfigHygieneAnalyzer.analyze_agent_definition`).
    """
    from mcp_audit.analyzers.config_hygiene import (  # noqa: PLC0415
        ConfigHygieneAnalyzer,
    )

    return ConfigHygieneAnalyzer().analyze_agent_definition(
        af.definition if af.definition is not None else af.frontmatter,
        af.path,
        af.client,
        af.scope,
    )


def analyze_agent_files(
    files: list[AgentFile], include_definitions: bool = True
) -> list[Finding]:
    """Analyze a list of agent files for security issues.

    Dispatches each file to the appropriate analyzer based on its surface type.
    A subagent definition's body (its system prompt) gets the same
    instruction-file rules as a command or skill (SKILL-001/002/003,
    POISON-041/042) except the length check; its frontmatter gets
    AGENT-001..004 and HOOK-001/002 when *include_definitions* is set.

    Args:
        files: Agent files returned by :func:`~mcp_audit.agent_files.discovery
            .discover_agent_files`.
        include_definitions: Produce the subagent frontmatter findings.
            ``scan --include-agent-files`` passes ``False`` because the scan's
            own discovery already produced them for the same files.

    Returns:
        List of :class:`~mcp_audit.models.Finding` objects.  Empty when no
        issues are detected.
    """
    findings: list[Finding] = []
    for af in files:
        file_findings: list[Finding] = []
        if af.surface == AgentFileSurface.CLAUDE_AGENT:
            file_findings.extend(_analyze_skill(af, check_length=False))
            if include_definitions:
                file_findings.extend(_analyze_agent_definition(af))
        elif _is_skill_surface(af):
            file_findings.extend(_analyze_skill(af))
            if af.surface == AgentFileSurface.CLAUDE_SKILL:
                script_finding = _check_skill_scripts(af)
                if script_finding is not None:
                    file_findings.append(script_finding)
                file_findings.extend(_sidecar_findings(af))
        elif _is_memory_surface(af):
            file_findings.extend(_analyze_memory(af))
        if af.imported_from is not None:
            via = (
                f" mcp-audit reached this file from '{af.imported_from.name}'"
                f" ({af.imported_from})."
            )
            file_findings = [
                _redacted(f.model_copy(update={"description": f.description + via}))
                for f in file_findings
            ]
        findings.extend(file_findings)
    findings.extend(analyze_instruction_reach(files))
    return findings
