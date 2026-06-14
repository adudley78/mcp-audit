"""Data models for the agent-file scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class AgentFileSurface(StrEnum):
    """Identifies which agent instruction surface a discovered file belongs to."""

    # Claude Code custom slash commands (~/.claude/commands/, .claude/commands/)
    CLAUDE_COMMAND = "claude-command"
    # Claude Code memory / project-context files (CLAUDE.md tiers)
    CLAUDE_MEMORY = "claude-memory"
    # Cursor AI rules (.cursor/rules/*.mdc, ~/.cursor/rules/*.mdc)
    CURSOR_RULE = "cursor-rule"
    # GitHub Copilot workspace instruction file (.github/copilot-instructions.md)
    COPILOT_INSTRUCTION = "copilot-instruction"
    # GitHub Copilot scoped instruction files (.github/instructions/*.instructions.md)
    COPILOT_SCOPED = "copilot-scoped"
    # GitHub Copilot prompt templates (.github/prompts/*.prompt.md)
    COPILOT_PROMPT = "copilot-prompt"


@dataclass
class AgentFile:
    """A discovered agent instruction / memory file with parsed content.

    Attributes:
        path: Absolute resolved path to the file.
        surface: Which instruction surface this file belongs to.
        client: Client name (e.g. ``"claude-code"``, ``"cursor"``).
        scope: ``"user"`` for user-global paths, ``"project"`` for project-tree paths.
        raw_content: Full file content as read from disk.
        body: Instruction text with YAML frontmatter stripped (for ``.mdc`` /
            ``.instructions.md`` / ``.prompt.md`` files).  Equal to
            ``raw_content`` for plain Markdown files without frontmatter.
        frontmatter: Parsed YAML frontmatter dict (empty for files without it).
    """

    path: Path
    surface: AgentFileSurface
    client: str
    scope: str  # "user" | "project"
    raw_content: str
    body: str
    frontmatter: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        """Short human-readable identifier (filename or relative path)."""
        return self.path.name
