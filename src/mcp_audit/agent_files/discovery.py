"""Discover agent instruction and memory files across supported AI coding clients.

Confirmed file surfaces (2026-06-14; skills added 2026-09-08):

**Claude Code — custom commands (skills)**
  - ``~/.claude/commands/*.md``  (user-global)
  - ``.claude/commands/*.md``    (project-level, found by project-tree walk)

**Claude Code — skills**
  - ``~/.claude/skills/**/SKILL.md``  (user-global)
  - ``.claude/skills/**/SKILL.md``    (project-level)
  Nesting is permitted by the skill spec — matched recursively, at any depth
  up to the same walk cap as the rest of this module. A symlinked skill
  directory or a symlinked ``SKILL.md`` is never silently dropped — see
  "Symlink handling" below.

**Claude Code — memory / context**
  - ``~/.claude/CLAUDE.md``      (user-global)
  - ``.claude/CLAUDE.md``        (project-level)
  - ``CLAUDE.md``                (project root)

**Claude Code — subagent definitions** (added 2026-10-25, STORY-0094)
  - ``~/.claude/agents/**/*.md``  (user-global)
  - ``.claude/agents/**/*.md``    (project-level)
  Scanned recursively, as Claude Code does. Only files that open with YAML
  frontmatter are definitions. The frontmatter is a config surface (see
  :mod:`mcp_audit.agent_files.subagents`); the body is the subagent's system
  prompt and gets the same instruction-file rules as commands and skills.

**Claude Code — more memory and rules** (added 2026-10-25, STORY-0098)
  - ``CLAUDE.local.md``          (project root; "loads alongside CLAUDE.md
    and is treated the same way")
  - ``~/.claude/rules/**/*.md``, ``.claude/rules/**/*.md`` (rules; "All
    ``.md`` files are discovered recursively")
  Every Claude Code memory file, and the ``AGENTS.md`` files below, have
  their ``@path`` imports followed (see :mod:`mcp_audit.agent_files.imports`).

**AGENTS.md** (added 2026-10-25, STORY-0098)
  - ``AGENTS.md`` in any directory (agents.md: Codex, Cursor, Copilot,
    Gemini CLI and others; Claude Code 2.1.277+ when there is no CLAUDE.md)
  - ``.claude/AGENTS.md`` (Claude Code)
  - ``AGENTS.override.md`` in any directory, ``~/.codex/AGENTS.md`` and
    ``~/.codex/AGENTS.override.md`` (Codex)

**OpenClaw workspace** (added 2026-10-25, STORY-0098)
  - ``~/.openclaw/workspace/{AGENTS,SOUL,USER,MEMORY,HEARTBEAT}.md``
  - ``SOUL.md``, ``USER.md``, ``MEMORY.md``, ``HEARTBEAT.md`` in any
    project directory (a workspace kept in a repository)

**Cursor — rules / instruction files**
  - ``~/.cursor/rules/*.mdc``    (user-global)
  - ``.cursor/rules/*.mdc``      (project-level)

**GitHub Copilot — instruction files**
  - ``.github/copilot-instructions.md``           (workspace)
  - ``.github/instructions/*.instructions.md``    (scoped)
  - ``.github/prompts/*.prompt.md``               (prompt templates)

Unconfirmed surfaces (Windsurf, Augment, Kiro, user-global Copilot) are
tracked in GAPS.md and intentionally omitted from this module.

Symlink handling
-----------------
Every matched file and every intermediate directory segment in
:data:`AGENT_INSTRUCTION_PATTERNS` is checked for symlink-ness. A match that
is a symlink is *not* dropped — it is still read normally (the OS follows the
link transparently) so scan coverage is unaffected — but it additionally
gets a TRUST-002 (project-scoped) or TRUST-004 (user-global) finding via
``mcp_audit.discovery.build_project_symlink_finding`` /
``build_info_symlink_finding``, collected into the optional ``skip_findings``
parameter threaded through :func:`discover_agent_files`. An intermediate
directory segment that is itself a symlink is still never descended into
(loop/blow-up protection, unchanged) — but the refusal now emits a TRUST-005
(LOW) finding naming the directory instead of silently returning no results.
See ``humans/decisions/2026-09-08-trust-002-symlink-sites.md`` (marcus repo).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from mcp_audit.agent_files.imports import (
    READ_CAP_BYTES,
    ReadBudget,
    follow_references,
    read_text_capped,
)
from mcp_audit.agent_files.models import AgentFile, AgentFileSurface
from mcp_audit.agent_files.subagents import parse_agent_frontmatter, read_agent_text
from mcp_audit.discovery import (
    AGENT_DEFINITION_CLIENT,
    build_info_symlink_finding,
    build_project_symlink_finding,
    build_untraversed_symlink_dir_finding,
)
from mcp_audit.models import Finding

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

# Directory names skipped during project-tree walking (mirrors discovery.py).
_WALK_SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".tox",
        "venv",
        ".venv",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)

_WALK_MAX_DEPTH: int = 8

#: Agent files read per discovery call, and their total bytes.  Reaching
#: either is reported through ``errors``; files past it are not read.
DISCOVERY_MAX_FILES: int = 5000
DISCOVERY_MAX_BYTES: int = 128 * 1024 * 1024


@dataclass(frozen=True)
class AgentInstructionPathPattern:
    """One relative-glob pattern describing where an agent-instruction file lives.

    ``relative_glob`` is a ``/``-separated glob pattern resolved relative to a
    base directory (``$HOME`` for ``scope="user"``, or a project-tree
    directory for ``scope="project"`` — see :func:`_resolve_relative_pattern`).
    The final path segment may contain glob wildcards (``*.md``); every
    segment before it is treated as a literal directory name that must exist
    and must not be a symlink, mirroring the guards this module has always
    applied. A ``"**"`` segment (skills only) matches zero or more directory
    levels recursively — see :func:`_resolve_relative_pattern`.
    """

    relative_glob: str
    surface: AgentFileSurface
    client: str
    scope: str  # "user" | "project"
    #: Claude Code expands ``@path`` imports in files at this location.
    follows_imports: bool = False


# The single source of truth for every agent-instruction-file location this
# module discovers. Both ``_discover_user_global`` and ``_discover_project_tree``
# below are driven by this list rather than keeping a second, hand-written copy
# of the same paths — a second copy that drifts from the module docstring above
# is worse than the inline version it replaced (R39).
#
# Consumed outside this module by anything that needs to ask "does this
# directory reach a known agent-instruction path?" without re-deriving the
# path set — see GAPS.md ("FILE_WRITE integrity axis") for why that question
# was investigated and what blocked building on it in R39.
AGENT_INSTRUCTION_PATTERNS: tuple[AgentInstructionPathPattern, ...] = (
    # ── User-global ──────────────────────────────────────────────────────────
    AgentInstructionPathPattern(
        ".claude/commands/*.md", AgentFileSurface.CLAUDE_COMMAND, "claude-code", "user"
    ),
    AgentInstructionPathPattern(
        ".claude/skills/**/SKILL.md",
        AgentFileSurface.CLAUDE_SKILL,
        "claude-code",
        "user",
    ),
    AgentInstructionPathPattern(
        ".claude/CLAUDE.md",
        AgentFileSurface.CLAUDE_MEMORY,
        "claude-code",
        "user",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        ".cursor/rules/*.mdc", AgentFileSurface.CURSOR_RULE, "cursor", "user"
    ),
    AgentInstructionPathPattern(
        ".claude/agents/**/*.md",
        AgentFileSurface.CLAUDE_AGENT,
        AGENT_DEFINITION_CLIENT,
        "user",
    ),
    # STORY-0098: more files the agent reads as instructions.
    AgentInstructionPathPattern(
        ".claude/rules/**/*.md",
        AgentFileSurface.CLAUDE_RULE,
        "claude-code",
        "user",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        ".codex/AGENTS.md", AgentFileSurface.AGENTS_MD, "codex", "user"
    ),
    AgentInstructionPathPattern(
        ".codex/AGENTS.override.md", AgentFileSurface.AGENTS_MD, "codex", "user"
    ),
    AgentInstructionPathPattern(
        ".openclaw/workspace/AGENTS.md",
        AgentFileSurface.OPENCLAW_WORKSPACE,
        "openclaw",
        "user",
    ),
    AgentInstructionPathPattern(
        ".openclaw/workspace/SOUL.md",
        AgentFileSurface.OPENCLAW_WORKSPACE,
        "openclaw",
        "user",
    ),
    AgentInstructionPathPattern(
        ".openclaw/workspace/USER.md",
        AgentFileSurface.OPENCLAW_WORKSPACE,
        "openclaw",
        "user",
    ),
    AgentInstructionPathPattern(
        ".openclaw/workspace/MEMORY.md",
        AgentFileSurface.OPENCLAW_WORKSPACE,
        "openclaw",
        "user",
    ),
    AgentInstructionPathPattern(
        ".openclaw/workspace/HEARTBEAT.md",
        AgentFileSurface.HEARTBEAT,
        "openclaw",
        "user",
    ),
    # ── Project-level (checked at every directory during the tree walk) ────────
    AgentInstructionPathPattern(
        ".claude/commands/*.md",
        AgentFileSurface.CLAUDE_COMMAND,
        "claude-code",
        "project",
    ),
    AgentInstructionPathPattern(
        ".claude/skills/**/SKILL.md",
        AgentFileSurface.CLAUDE_SKILL,
        "claude-code",
        "project",
    ),
    AgentInstructionPathPattern(
        ".claude/CLAUDE.md",
        AgentFileSurface.CLAUDE_MEMORY,
        "claude-code",
        "project",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        "CLAUDE.md",
        AgentFileSurface.CLAUDE_MEMORY,
        "claude-code",
        "project",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        ".cursor/rules/*.mdc", AgentFileSurface.CURSOR_RULE, "cursor", "project"
    ),
    AgentInstructionPathPattern(
        ".github/copilot-instructions.md",
        AgentFileSurface.COPILOT_INSTRUCTION,
        "copilot",
        "project",
    ),
    AgentInstructionPathPattern(
        ".github/instructions/*.instructions.md",
        AgentFileSurface.COPILOT_SCOPED,
        "copilot",
        "project",
    ),
    AgentInstructionPathPattern(
        ".github/prompts/*.prompt.md",
        AgentFileSurface.COPILOT_PROMPT,
        "copilot",
        "project",
    ),
    AgentInstructionPathPattern(
        ".claude/agents/**/*.md",
        AgentFileSurface.CLAUDE_AGENT,
        AGENT_DEFINITION_CLIENT,
        "project",
    ),
    # STORY-0098: more files the agent reads as instructions.
    AgentInstructionPathPattern(
        "CLAUDE.local.md",
        AgentFileSurface.CLAUDE_MEMORY,
        "claude-code",
        "project",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        ".claude/rules/**/*.md",
        AgentFileSurface.CLAUDE_RULE,
        "claude-code",
        "project",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        "AGENTS.md",
        AgentFileSurface.AGENTS_MD,
        "agents-md",
        "project",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        ".claude/AGENTS.md",
        AgentFileSurface.AGENTS_MD,
        "claude-code",
        "project",
        follows_imports=True,
    ),
    AgentInstructionPathPattern(
        "AGENTS.override.md", AgentFileSurface.AGENTS_MD, "codex", "project"
    ),
    AgentInstructionPathPattern(
        "SOUL.md", AgentFileSurface.OPENCLAW_WORKSPACE, "openclaw", "project"
    ),
    AgentInstructionPathPattern(
        "USER.md", AgentFileSurface.OPENCLAW_WORKSPACE, "openclaw", "project"
    ),
    AgentInstructionPathPattern(
        "MEMORY.md", AgentFileSurface.OPENCLAW_WORKSPACE, "openclaw", "project"
    ),
    AgentInstructionPathPattern(
        "HEARTBEAT.md", AgentFileSurface.HEARTBEAT, "openclaw", "project"
    ),
)


def _is_symlink(path: Path) -> bool:
    """``Path.is_symlink`` that treats an unreadable path as not a link."""
    try:
        return path.is_symlink()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    """``Path.is_dir`` that treats an unreadable path as not a directory."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    """``Path.is_file`` that treats an unreadable path as not a file."""
    try:
        return path.is_file()
    except OSError:
        return False


def _glob(directory: Path, pattern: str) -> list[Path]:
    """Sorted ``Path.glob`` that returns nothing for an unreadable directory."""
    try:
        return sorted(directory.glob(pattern))
    except OSError:
        return []


def _record_symlinked_match(
    matched: Path,
    root: Path | None,
    skip_findings: list[Finding] | None,
) -> None:
    """Append the appropriate finding for a matched file that is a symlink.

    *root* is ``None`` for a user-global pattern (info-shaped — TRUST-004,
    always INFO; this is the dotfile-manager shape) and the project-tree
    root for a project-scoped pattern (boundary-shaped — TRUST-002).
    """
    if skip_findings is None:
        return
    if root is not None:
        skip_findings.append(
            build_project_symlink_finding(matched, "agent-files", root)
        )
    else:
        skip_findings.append(build_info_symlink_finding(matched, "agent-files"))


def _resolve_relative_pattern(
    base: Path,
    relative_glob: str,
    root: Path | None,
    skip_findings: list[Finding] | None = None,
) -> list[Path]:
    """Resolve one ``/``-separated relative glob pattern under ``base``.

    Every path segment before the final one is a literal directory name
    (never a glob) and must exist and be a real directory — except a
    ``"**"`` segment (skills only), which matches zero or more directory
    levels recursively up to :data:`_WALK_MAX_DEPTH`. Only the final segment
    is glob-matched (it may be a literal filename, e.g. ``"CLAUDE.md"``,
    which ``Path.glob`` matches exactly).

    A matched file that is itself a symlink is *included* in the returned
    list (still read normally — the OS follows the link transparently) but
    also reported via *skip_findings* (see :func:`_record_symlinked_match`).
    An intermediate directory segment that is itself a symlink is never
    descended into; when *skip_findings* is given, this appends a TRUST-005
    finding naming it instead of returning silently.

    Returns:
        Matched paths that are regular files (following symlinks). Empty
        list if any intermediate directory is missing or is a symlink.
    """
    segments = relative_glob.split("/")

    if "**" in segments:
        star_idx = segments.index("**")
        pre_segments = segments[:star_idx]
        post_segments = segments[star_idx + 1 :]
        final_pattern = post_segments[0] if post_segments else "*"

        current = base
        for segment in pre_segments:
            current = current / segment
            if _is_symlink(current):
                if skip_findings is not None:
                    skip_findings.append(
                        build_untraversed_symlink_dir_finding(current, "agent-files")
                    )
                return []
            if not _is_dir(current):
                return []

        matches: list[Path] = []

        def _walk_recursive(d: Path, depth: int) -> None:
            if depth > _WALK_MAX_DEPTH:
                return
            for p in _glob(d, final_pattern):
                if not _is_file(p):
                    continue
                matches.append(p)
                if _is_symlink(p):
                    _record_symlinked_match(p, root, skip_findings)
            try:
                children = sorted(d.iterdir())
            except OSError:
                return
            for child in children:
                if _is_symlink(child):
                    if _is_dir(child) and skip_findings is not None:
                        skip_findings.append(
                            build_untraversed_symlink_dir_finding(child, "agent-files")
                        )
                    continue
                if not _is_dir(child):
                    continue
                if child.name in _WALK_SKIP_DIRS:
                    continue
                _walk_recursive(child, depth + 1)

        _walk_recursive(current, 0)
        return sorted(matches)

    current = base
    for segment in segments[:-1]:
        current = current / segment
        if _is_symlink(current):
            if skip_findings is not None:
                skip_findings.append(
                    build_untraversed_symlink_dir_finding(current, "agent-files")
                )
            return []
        if not _is_dir(current):
            return []
    final_pattern = segments[-1]
    matches = []
    for p in _glob(current, final_pattern):
        if not _is_file(p):
            continue
        matches.append(p)
        if _is_symlink(p):
            _record_symlinked_match(p, root, skip_findings)
    return matches


# ── YAML frontmatter parsing ──────────────────────────────────────────────────


def _split_frontmatter(content: str) -> tuple[dict, str]:
    """Split YAML frontmatter from Markdown body.

    Returns:
        ``(frontmatter_dict, body_text)`` where ``frontmatter_dict`` is empty
        when no frontmatter is present.  Never raises — YAML parse errors
        return an empty dict with the original content as the body.
    """
    if not content.startswith("---"):
        return {}, content

    # Find the closing ``---`` delimiter.
    rest = content[3:]
    end = rest.find("\n---")
    if end == -1:
        return {}, content

    yaml_block = rest[:end]
    body = rest[end + 4 :].lstrip("\n")

    try:
        fm = yaml.safe_load(yaml_block)
        return (fm if isinstance(fm, dict) else {}), body
    except yaml.YAMLError:
        return {}, content


def _read_agent_file(
    path: Path,
    surface: AgentFileSurface,
    client: str,
    scope: str,
    budget: ReadBudget | None = None,
    errors: list[str] | None = None,
) -> AgentFile | None:
    """Read and parse a single agent file.  Returns ``None`` on any I/O error.

    A subagent definition is read with Claude Code's 1 MiB cap (a larger file
    returns ``None``, as Claude Code skips it) and parsed by
    :func:`~mcp_audit.agent_files.subagents.parse_agent_frontmatter`; one
    without frontmatter is not a definition and returns ``None``.  Every
    other file is read up to :data:`~mcp_audit.agent_files.imports.READ_CAP_BYTES`
    (4 MiB, the size above which Claude Code skips a memory file); a longer
    file is scanned on its first part and marked ``truncated``.  With a
    *budget*, a file past it is not read; both cases are noted in *errors*.
    """
    definition: dict | None = None
    truncated = False
    if budget is not None:
        try:
            size = path.stat().st_size
        except OSError as exc:
            logger.debug("agent_files: cannot stat %s: %s", path, exc)
            return None
        if not budget.take(min(size, READ_CAP_BYTES)):
            if errors is not None and not budget.noted:
                budget.noted = True
                errors.append(
                    f"agent files: stopped after {budget.max_files} files /"
                    f" {budget.max_bytes} bytes; later files were not read"
                )
            return None
    try:
        if surface == AgentFileSurface.CLAUDE_AGENT:
            text = read_agent_text(path)
            if text is None:
                logger.debug("agent_files: %s is over the 1 MiB cap", path)
                return None
            raw = text
        else:
            raw, truncated = read_text_capped(path)
    except OSError as exc:
        logger.debug("agent_files: cannot read %s: %s", path, exc)
        if errors is not None:
            errors.append(f"agent files: cannot read {path}: {exc}")
        return None
    if truncated and errors is not None:
        errors.append(
            f"agent files: {path} is over {READ_CAP_BYTES} bytes; only the first"
            " part was scanned"
        )

    if surface == AgentFileSurface.CLAUDE_AGENT:
        parsed = parse_agent_frontmatter(raw)
        if not parsed.present:
            return None
        fm, body, definition = parsed.data, parsed.body, parsed.to_record()
    else:
        fm, body = _split_frontmatter(raw)
    return AgentFile(
        path=path,
        surface=surface,
        client=client,
        scope=scope,
        raw_content=raw,
        body=body,
        frontmatter=fm,
        definition=definition,
        truncated=truncated,
    )


# ── User-global discovery ─────────────────────────────────────────────────────


def _read_from_pattern(
    match: Path,
    pattern: AgentInstructionPathPattern,
    scope: str,
    budget: ReadBudget | None,
    errors: list[str] | None,
) -> AgentFile | None:
    af = _read_agent_file(
        match, pattern.surface, pattern.client, scope, budget=budget, errors=errors
    )
    if af is not None:
        af.follows_imports = pattern.follows_imports
    return af


def _discover_user_global(
    skip_findings: list[Finding] | None = None,
    *,
    budget: ReadBudget | None = None,
    errors: list[str] | None = None,
) -> list[AgentFile]:
    """Discover agent files at user-global (non-project) paths.

    Driven by the ``scope="user"`` entries in :data:`AGENT_INSTRUCTION_PATTERNS`
    rather than a hand-written copy of the same paths. Symlinked matches are
    info-shaped (``root=None``) — see module docstring.
    """
    home = Path.home()
    results: list[AgentFile] = []

    for pattern in AGENT_INSTRUCTION_PATTERNS:
        if pattern.scope != "user":
            continue
        for match in _resolve_relative_pattern(
            home, pattern.relative_glob, root=None, skip_findings=skip_findings
        ):
            af = _read_from_pattern(match, pattern, "user", budget, errors)
            if af is not None:
                results.append(af)

    return results


# ── Project-tree discovery ────────────────────────────────────────────────────


def _discover_project_tree(
    root: Path,
    skip_findings: list[Finding] | None = None,
    *,
    budget: ReadBudget | None = None,
    errors: list[str] | None = None,
) -> list[AgentFile]:
    """Walk a project root directory and collect agent instruction files.

    Mirrors the depth-limited, skip-list walk used by
    :func:`mcp_audit.discovery.discover_project_configs`. Symlinked matches
    are boundary-shaped (compared against *root*) — see module docstring.

    Args:
        root: Resolved absolute path to the repository root.
        skip_findings: Optional list to append TRUST-002/TRUST-005 findings
            to; threaded through to :func:`_resolve_relative_pattern`.
        budget: Optional shared read budget.
        errors: Optional list that receives read problems and budget stops.

    Returns:
        List of :class:`AgentFile` objects with ``scope="project"``.
    """
    results: list[AgentFile] = []

    def _visit(dirpath: Path) -> None:
        # Every project-scope pattern is checked at this directory. Driven by
        # the ``scope="project"`` entries in AGENT_INSTRUCTION_PATTERNS rather
        # than a hand-written copy of the same paths.
        for pattern in AGENT_INSTRUCTION_PATTERNS:
            if pattern.scope != "project":
                continue
            for match in _resolve_relative_pattern(
                dirpath, pattern.relative_glob, root=root, skip_findings=skip_findings
            ):
                af = _read_from_pattern(match, pattern, "project", budget, errors)
                if af is not None:
                    results.append(af)

    _walk_project_dirs(root, _visit, skip_findings)
    return results


def _walk_project_dirs(
    root: Path,
    visit: Callable[[Path], None],
    skip_findings: list[Finding] | None,
) -> None:
    """Call *visit* on *root* and every directory below it, per the walk rules.

    Depth-capped at :data:`_WALK_MAX_DEPTH`, skips :data:`_WALK_SKIP_DIRS`, and
    never descends into a symlinked directory (TRUST-005 into *skip_findings*).
    A directory or entry that raises ``OSError`` (``PermissionError`` from
    pathlib on Python 3.12) is skipped; the rest of the walk continues.
    """

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH:
            return
        try:
            visit(dirpath)
            children = sorted(dirpath.iterdir())
        except OSError as exc:
            logger.debug("agent_files: skipping %s: %s", dirpath, exc)
            return

        for child in children:
            try:
                if child.is_symlink():
                    if child.is_dir() and skip_findings is not None:
                        skip_findings.append(
                            build_untraversed_symlink_dir_finding(child, "agent-files")
                        )
                    continue
                if not child.is_dir() or child.name in _WALK_SKIP_DIRS:
                    continue
            except OSError as exc:
                logger.debug("agent_files: skipping %s: %s", child, exc)
                continue
            _walk(child, depth + 1)

    _walk(root, 0)


# ── Subagent definition paths (STORY-0094) ────────────────────────────────────


def agent_definition_paths(
    base: Path,
    scope: str,
    root: Path | None = None,
    skip_findings: list[Finding] | None = None,
) -> list[Path]:
    """Return subagent definition candidates directly under *base*.

    Resolves the :data:`AGENT_INSTRUCTION_PATTERNS` entries whose surface is
    :attr:`AgentFileSurface.CLAUDE_AGENT` and whose scope is *scope* — so the
    pattern table stays the single source of truth for where subagents live.
    No tree walk: *base* is ``$HOME`` (``scope="user"``) or one directory.

    Args:
        base: Directory the relative patterns resolve against.
        scope: ``"user"`` or ``"project"``.
        root: Boundary for TRUST-002 on a symlinked match (``None`` for user
            scope, which reports TRUST-004).
        skip_findings: Optional list to receive TRUST-002/004/005 findings.

    Returns:
        Sorted candidate ``.md`` paths (frontmatter not yet checked).
    """
    paths: list[Path] = []
    for pattern in AGENT_INSTRUCTION_PATTERNS:
        if pattern.surface != AgentFileSurface.CLAUDE_AGENT or pattern.scope != scope:
            continue
        paths.extend(
            _resolve_relative_pattern(
                base, pattern.relative_glob, root=root, skip_findings=skip_findings
            )
        )
    return sorted(set(paths))


def project_agent_definition_paths(
    root: Path, skip_findings: list[Finding] | None = None
) -> list[Path]:
    """Return subagent definition candidates anywhere under *root*.

    Same walk as the project-tree agent-file discovery (depth cap, skip list,
    symlink rules), restricted to the subagent patterns and without reading
    the files.
    """
    resolved = root.resolve()
    found: list[Path] = []

    def _visit(dirpath: Path) -> None:
        found.extend(
            agent_definition_paths(dirpath, "project", resolved, skip_findings)
        )

    _walk_project_dirs(resolved, _visit, skip_findings)
    return sorted(set(found))


# ── Public API ────────────────────────────────────────────────────────────────


def _dedupe_findings(raw: list[Finding], out: list[Finding] | None) -> None:
    if out is None:
        return
    seen: set[tuple[str, str | None]] = set()
    for finding in raw:
        key = (finding.id, finding.finding_path)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)


def _resolved_key(path: Path) -> str:
    try:
        return str(path.resolve())
    except (OSError, RuntimeError):
        return str(path)


def discover_agent_files(
    project_root: Path | None = None,
    include_user_global: bool = True,
    skip_findings: list[Finding] | None = None,
    *,
    follow_imports: bool = True,
    include_references: bool = True,
    errors: list[str] | None = None,
) -> list[AgentFile]:
    """Discover agent instruction and memory files.

    Args:
        project_root: When supplied, walk this directory tree for project-level
            files (``.claude/commands/``, ``.claude/skills/``, ``.cursor/rules/``,
            ``.github/`` subtrees, ``CLAUDE.md`` tiers, ``AGENTS.md``,
            OpenClaw workspace files).  When ``None``, only user-global paths
            are searched.
        include_user_global: When ``False``, skip user-global paths (useful
            when the caller only wants project-scoped results).
        skip_findings: Optional list to append TRUST-002/TRUST-004/TRUST-005
            symlink findings to.  Deduplicated by ``(id, finding_path)``
            internally before being appended — the user-global and
            project-tree walks (and, within the project-tree walk, multiple
            patterns sharing a symlinked ancestor directory) can otherwise
            each report the same symlinked path once.  When ``None``, no
            findings are collected (symlinked candidates are still scanned;
            only the reporting is skipped).
        follow_imports: Follow ``@path`` imports and prose references out of
            memory-surface files (STORY-0098); reached files are returned
            with ``imported_from`` set and each file's ``edges`` filled in.
        include_references: With *follow_imports*, also follow "read X"
            prose references (not only ``@path`` imports).
        errors: Optional list that receives read problems and budget stops
            (never silent).

    Returns:
        Deduplicated list of :class:`AgentFile` objects sorted by path.
        A file that appears at both the user-global and project-tree path
        (an unlikely but possible symlink scenario) is included only once.
    """
    results: list[AgentFile] = []
    seen: set[str] = set()
    budget = ReadBudget(max_files=DISCOVERY_MAX_FILES, max_bytes=DISCOVERY_MAX_BYTES)

    def _add(af: AgentFile) -> None:
        key = _resolved_key(af.path)
        if key not in seen:
            seen.add(key)
            results.append(af)

    raw_skip: list[Finding] = []
    resolved: Path | None = None

    if include_user_global:
        for af in _discover_user_global(
            skip_findings=raw_skip, budget=budget, errors=errors
        ):
            _add(af)

    if project_root is not None:
        resolved = project_root.resolve()
        for af in _discover_project_tree(
            resolved, skip_findings=raw_skip, budget=budget, errors=errors
        ):
            _add(af)

    if follow_imports:
        for af in follow_references(
            list(results),
            project_root=resolved,
            include_references=include_references,
            skip_findings=raw_skip,
            notes=errors,
        ):
            _add(af)

    _dedupe_findings(raw_skip, skip_findings)
    return sorted(results, key=lambda af: str(af.path))


def discover_root_agent_files(
    root: Path,
    skip_findings: list[Finding] | None = None,
    errors: list[str] | None = None,
) -> list[AgentFile]:
    """Instruction files at the top of *root* only, with their imports.

    The default ``scan``/``check`` pass (STORY-0098): no tree walk, only the
    project patterns whose files Claude Code expands ``@path`` imports in, and
    ``HEARTBEAT.md``.  A symlinked candidate is reported through
    *skip_findings* (TRUST-002) and not read as the repository's own.
    Imports are followed; prose references are not (they never produce a
    finding on this path).

    Args:
        root: The working directory (resolved).
        skip_findings: Receives TRUST-002/TRUST-005 for links on the way.
        errors: Receives read problems and budget stops.

    Returns:
        The root files followed by the files their imports reached.
    """
    root = root.resolve()
    budget = ReadBudget(max_files=DISCOVERY_MAX_FILES, max_bytes=DISCOVERY_MAX_BYTES)
    files: list[AgentFile] = []
    seen: set[str] = set()
    for pattern in AGENT_INSTRUCTION_PATTERNS:
        if pattern.scope != "project":
            continue
        if not (
            pattern.follows_imports or pattern.surface == AgentFileSurface.HEARTBEAT
        ):
            continue
        for match in _resolve_relative_pattern(
            root, pattern.relative_glob, root=root, skip_findings=skip_findings
        ):
            if _is_symlink(match):
                continue
            key = _resolved_key(match)
            if key in seen:
                continue
            seen.add(key)
            af = _read_from_pattern(match, pattern, "project", budget, errors)
            if af is not None:
                files.append(af)
    files.extend(
        follow_references(
            list(files),
            project_root=root,
            include_references=False,
            skip_findings=skip_findings,
            notes=errors,
        )
    )
    return files


def discover_user_heartbeat_files(
    skip_findings: list[Finding] | None = None,
    errors: list[str] | None = None,
) -> list[AgentFile]:
    """The user's own heartbeat files (``~/.openclaw/workspace/HEARTBEAT.md``).

    Read in every default scan for MEM-004; a symlinked file is read through
    the link and reported as TRUST-004 (the dotfile-manager shape), like every
    other user-global agent file.
    """
    files: list[AgentFile] = []
    for pattern in AGENT_INSTRUCTION_PATTERNS:
        if pattern.scope != "user" or pattern.surface != AgentFileSurface.HEARTBEAT:
            continue
        for match in _resolve_relative_pattern(
            Path.home(), pattern.relative_glob, root=None, skip_findings=skip_findings
        ):
            af = _read_from_pattern(match, pattern, "user", None, errors)
            if af is not None:
                files.append(af)
    return files
