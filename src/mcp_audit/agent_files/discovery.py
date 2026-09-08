"""Discover agent instruction and memory files across supported AI coding clients.

Confirmed file surfaces (2026-06-14):

**Claude Code — custom commands (skills)**
  - ``~/.claude/commands/*.md``  (user-global)
  - ``.claude/commands/*.md``    (project-level, found by project-tree walk)

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

Unconfirmed surfaces (Windsurf, Augment, Kiro, ``.claude/skills/``) are tracked
in GAPS.md and intentionally omitted from this module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from mcp_audit.agent_files.models import AgentFile, AgentFileSurface

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
    applied.
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


def _resolve_relative_pattern(base: Path, relative_glob: str) -> list[Path]:
    """Resolve one ``/``-separated relative glob pattern under ``base``.

    Every path segment before the final one is a literal directory name
    (never a glob) and must exist, be a real directory, and not be a
    symlink — the same guard this module has always applied per-directory,
    generalised so it works for any pattern in :data:`AGENT_INSTRUCTION_PATTERNS`
    regardless of how many directory levels it has. Only the final segment is
    glob-matched (it may be a literal filename, e.g. ``"CLAUDE.md"``, which
    ``Path.glob`` matches exactly).

    Returns:
        Matched paths that are regular files and not symlinks, sorted.
        Empty list if any intermediate directory is missing or is a symlink.
    """
    segments = relative_glob.split("/")
    current = base
    for segment in segments[:-1]:
        current = current / segment
        if not current.is_dir() or current.is_symlink():
            return []
    final_pattern = segments[-1]
    return [
        p
        for p in sorted(current.glob(final_pattern))
        if p.is_file() and not p.is_symlink()
    ]


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


def _discover_user_global() -> list[AgentFile]:
    """Discover agent files at user-global (non-project) paths.

    Driven by the ``scope="user"`` entries in :data:`AGENT_INSTRUCTION_PATTERNS`
    rather than a hand-written copy of the same three paths.
    """
    home = Path.home()
    results: list[AgentFile] = []

    for pattern in AGENT_INSTRUCTION_PATTERNS:
        if pattern.scope != "user":
            continue
        for match in _resolve_relative_pattern(home, pattern.relative_glob):
            af = _read_agent_file(match, pattern.surface, pattern.client, "user")
            if af is not None:
                results.append(af)

    return results


# ── Project-tree discovery ────────────────────────────────────────────────────


def _discover_project_tree(root: Path) -> list[AgentFile]:
    """Walk a project root directory and collect agent instruction files.

    Mirrors the depth-limited, skip-list walk used by
    :func:`mcp_audit.discovery.discover_project_configs`.

    Args:
        root: Resolved absolute path to the repository root.

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
            for match in _resolve_relative_pattern(dirpath, pattern.relative_glob):
                af = _read_agent_file(match, pattern.surface, pattern.client, "project")
                if af is not None:
                    results.append(af)

        # Recurse
        try:
            children = sorted(dirpath.iterdir())
        except PermissionError:
            return

        for child in children:
            if child.is_symlink() or not child.is_dir():
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
) -> list[AgentFile]:
    """Discover agent instruction and memory files.

    Args:
        project_root: When supplied, walk this directory tree for project-level
            files (``.claude/commands/``, ``.cursor/rules/``, ``.github/``
            subtrees, ``CLAUDE.md`` tiers).  When ``None``, only user-global
            paths are searched.
        include_user_global: When ``False``, skip user-global paths (useful
            when the caller only wants project-scoped results).

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

    if include_user_global:
        for af in _discover_user_global():
            _add(af)

    if project_root is not None:
        resolved = project_root.resolve()
        for af in _discover_project_tree(resolved):
            _add(af)

    return sorted(results, key=lambda af: str(af.path))
