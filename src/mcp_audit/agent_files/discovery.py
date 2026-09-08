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
from dataclasses import dataclass
from pathlib import Path

import yaml

from mcp_audit.agent_files.models import AgentFile, AgentFileSurface
from mcp_audit.discovery import (
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
        ".claude/CLAUDE.md", AgentFileSurface.CLAUDE_MEMORY, "claude-code", "user"
    ),
    AgentInstructionPathPattern(
        ".cursor/rules/*.mdc", AgentFileSurface.CURSOR_RULE, "cursor", "user"
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
        ".claude/CLAUDE.md", AgentFileSurface.CLAUDE_MEMORY, "claude-code", "project"
    ),
    AgentInstructionPathPattern(
        "CLAUDE.md", AgentFileSurface.CLAUDE_MEMORY, "claude-code", "project"
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
)


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
            if current.is_symlink():
                if skip_findings is not None:
                    skip_findings.append(
                        build_untraversed_symlink_dir_finding(current, "agent-files")
                    )
                return []
            if not current.is_dir():
                return []

        matches: list[Path] = []

        def _walk_recursive(d: Path, depth: int) -> None:
            if depth > _WALK_MAX_DEPTH:
                return
            for p in sorted(d.glob(final_pattern)):
                if not p.is_file():
                    continue
                matches.append(p)
                if p.is_symlink():
                    _record_symlinked_match(p, root, skip_findings)
            try:
                children = sorted(d.iterdir())
            except (PermissionError, OSError):
                return
            for child in children:
                if child.is_symlink():
                    if child.is_dir() and skip_findings is not None:
                        skip_findings.append(
                            build_untraversed_symlink_dir_finding(child, "agent-files")
                        )
                    continue
                if not child.is_dir():
                    continue
                if child.name in _WALK_SKIP_DIRS:
                    continue
                _walk_recursive(child, depth + 1)

        _walk_recursive(current, 0)
        return sorted(matches)

    current = base
    for segment in segments[:-1]:
        current = current / segment
        if current.is_symlink():
            if skip_findings is not None:
                skip_findings.append(
                    build_untraversed_symlink_dir_finding(current, "agent-files")
                )
            return []
        if not current.is_dir():
            return []
    final_pattern = segments[-1]
    matches = []
    for p in sorted(current.glob(final_pattern)):
        if not p.is_file():
            continue
        matches.append(p)
        if p.is_symlink():
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
) -> AgentFile | None:
    """Read and parse a single agent file.  Returns ``None`` on any I/O error."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("agent_files: cannot read %s: %s", path, exc)
        return None

    fm, body = _split_frontmatter(raw)
    return AgentFile(
        path=path,
        surface=surface,
        client=client,
        scope=scope,
        raw_content=raw,
        body=body,
        frontmatter=fm,
    )


# ── User-global discovery ─────────────────────────────────────────────────────


def _discover_user_global(
    skip_findings: list[Finding] | None = None,
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
            af = _read_agent_file(match, pattern.surface, pattern.client, "user")
            if af is not None:
                results.append(af)

    return results


# ── Project-tree discovery ────────────────────────────────────────────────────


def _discover_project_tree(
    root: Path, skip_findings: list[Finding] | None = None
) -> list[AgentFile]:
    """Walk a project root directory and collect agent instruction files.

    Mirrors the depth-limited, skip-list walk used by
    :func:`mcp_audit.discovery.discover_project_configs`. Symlinked matches
    are boundary-shaped (compared against *root*) — see module docstring.

    Args:
        root: Resolved absolute path to the repository root.
        skip_findings: Optional list to append TRUST-002/TRUST-005 findings
            to; threaded through to :func:`_resolve_relative_pattern`.

    Returns:
        List of :class:`AgentFile` objects with ``scope="project"``.
    """
    results: list[AgentFile] = []

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH:
            return

        # Every project-scope pattern is checked at this directory. Driven by
        # the ``scope="project"`` entries in AGENT_INSTRUCTION_PATTERNS rather
        # than a hand-written copy of the same paths.
        for pattern in AGENT_INSTRUCTION_PATTERNS:
            if pattern.scope != "project":
                continue
            for match in _resolve_relative_pattern(
                dirpath, pattern.relative_glob, root=root, skip_findings=skip_findings
            ):
                af = _read_agent_file(match, pattern.surface, pattern.client, "project")
                if af is not None:
                    results.append(af)

        # Recurse
        try:
            children = sorted(dirpath.iterdir())
        except PermissionError:
            return

        for child in children:
            if child.is_symlink():
                if child.is_dir() and skip_findings is not None:
                    skip_findings.append(
                        build_untraversed_symlink_dir_finding(child, "agent-files")
                    )
                continue
            if not child.is_dir():
                continue
            if child.name in _WALK_SKIP_DIRS:
                continue
            _walk(child, depth + 1)

    _walk(root, 0)
    return results


# ── Public API ────────────────────────────────────────────────────────────────


def discover_agent_files(
    project_root: Path | None = None,
    include_user_global: bool = True,
    skip_findings: list[Finding] | None = None,
) -> list[AgentFile]:
    """Discover agent instruction and memory files.

    Args:
        project_root: When supplied, walk this directory tree for project-level
            files (``.claude/commands/``, ``.claude/skills/``, ``.cursor/rules/``,
            ``.github/`` subtrees, ``CLAUDE.md`` tiers).  When ``None``, only
            user-global paths are searched.
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

    Returns:
        Deduplicated list of :class:`AgentFile` objects sorted by path.
        A file that appears at both the user-global and project-tree path
        (an unlikely but possible symlink scenario) is included only once.
    """
    results: list[AgentFile] = []
    seen: set[str] = set()

    def _add(af: AgentFile) -> None:
        key = str(af.path.resolve())
        if key not in seen:
            seen.add(key)
            results.append(af)

    raw_skip: list[Finding] = []

    if include_user_global:
        for af in _discover_user_global(skip_findings=raw_skip):
            _add(af)

    if project_root is not None:
        resolved = project_root.resolve()
        for af in _discover_project_tree(resolved, skip_findings=raw_skip):
            _add(af)

    if skip_findings is not None:
        seen_findings: set[tuple[str, str | None]] = set()
        for finding in raw_skip:
            key = (finding.id, finding.finding_path)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            skip_findings.append(finding)

    return sorted(results, key=lambda af: str(af.path))
