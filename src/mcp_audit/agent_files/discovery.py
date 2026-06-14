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
    """Discover agent files at user-global (non-project) paths."""
    home = Path.home()
    results: list[AgentFile] = []

    # ── Claude Code custom commands ───────────────────────────────────────────
    commands_dir = home / ".claude" / "commands"
    if commands_dir.is_dir() and not commands_dir.is_symlink():
        for md in sorted(commands_dir.glob("*.md")):
            if md.is_file() and not md.is_symlink():
                af = _read_agent_file(
                    md, AgentFileSurface.CLAUDE_COMMAND, "claude-code", "user"
                )
                if af is not None:
                    results.append(af)

    # ── Claude Code user-global memory ───────────────────────────────────────
    user_memory = home / ".claude" / "CLAUDE.md"
    if user_memory.is_file() and not user_memory.is_symlink():
        af = _read_agent_file(
            user_memory, AgentFileSurface.CLAUDE_MEMORY, "claude-code", "user"
        )
        if af is not None:
            results.append(af)

    # ── Cursor user-global rules ──────────────────────────────────────────────
    cursor_rules_dir = home / ".cursor" / "rules"
    if cursor_rules_dir.is_dir() and not cursor_rules_dir.is_symlink():
        for mdc in sorted(cursor_rules_dir.glob("*.mdc")):
            if mdc.is_file() and not mdc.is_symlink():
                af = _read_agent_file(
                    mdc, AgentFileSurface.CURSOR_RULE, "cursor", "user"
                )
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

        # ── Claude Code commands (project-level) ─────────────────────────────
        claude_cmds = dirpath / ".claude" / "commands"
        if claude_cmds.is_dir() and not claude_cmds.is_symlink():
            for md in sorted(claude_cmds.glob("*.md")):
                if md.is_file() and not md.is_symlink():
                    af = _read_agent_file(
                        md, AgentFileSurface.CLAUDE_COMMAND, "claude-code", "project"
                    )
                    if af is not None:
                        results.append(af)

        # ── Claude Code project memory ────────────────────────────────────────
        for rel_path in (".claude/CLAUDE.md", "CLAUDE.md"):
            candidate = dirpath / rel_path
            if candidate.is_file() and not candidate.is_symlink():
                af = _read_agent_file(
                    candidate,
                    AgentFileSurface.CLAUDE_MEMORY,
                    "claude-code",
                    "project",
                )
                if af is not None:
                    results.append(af)

        # ── Cursor project rules ──────────────────────────────────────────────
        cursor_rules = dirpath / ".cursor" / "rules"
        if cursor_rules.is_dir() and not cursor_rules.is_symlink():
            for mdc in sorted(cursor_rules.glob("*.mdc")):
                if mdc.is_file() and not mdc.is_symlink():
                    af = _read_agent_file(
                        mdc, AgentFileSurface.CURSOR_RULE, "cursor", "project"
                    )
                    if af is not None:
                        results.append(af)

        # ── GitHub Copilot instruction files ─────────────────────────────────
        gh = dirpath / ".github"
        if gh.is_dir() and not gh.is_symlink():
            # Workspace-level instruction file
            ci = gh / "copilot-instructions.md"
            if ci.is_file() and not ci.is_symlink():
                af = _read_agent_file(
                    ci,
                    AgentFileSurface.COPILOT_INSTRUCTION,
                    "copilot",
                    "project",
                )
                if af is not None:
                    results.append(af)

            # Scoped instruction files (.github/instructions/*.instructions.md)
            instr_dir = gh / "instructions"
            if instr_dir.is_dir() and not instr_dir.is_symlink():
                for md in sorted(instr_dir.glob("*.instructions.md")):
                    if md.is_file() and not md.is_symlink():
                        af = _read_agent_file(
                            md,
                            AgentFileSurface.COPILOT_SCOPED,
                            "copilot",
                            "project",
                        )
                        if af is not None:
                            results.append(af)

            # Prompt template files (.github/prompts/*.prompt.md)
            prompts_dir = gh / "prompts"
            if prompts_dir.is_dir() and not prompts_dir.is_symlink():
                for md in sorted(prompts_dir.glob("*.prompt.md")):
                    if md.is_file() and not md.is_symlink():
                        af = _read_agent_file(
                            md,
                            AgentFileSurface.COPILOT_PROMPT,
                            "copilot",
                            "project",
                        )
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
