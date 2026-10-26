"""Data models for the agent-file scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class AgentFileSurface(StrEnum):
    """Identifies which agent instruction surface a discovered file belongs to."""

    # Claude Code custom slash commands (~/.claude/commands/, .claude/commands/)
    CLAUDE_COMMAND = "claude-command"
    # Claude Code skills (~/.claude/skills/**/SKILL.md, .claude/skills/**/SKILL.md)
    CLAUDE_SKILL = "claude-code-skills"
    # Claude Code memory / project-context files (CLAUDE.md tiers)
    CLAUDE_MEMORY = "claude-memory"
    # Claude Code subagent definitions (~/.claude/agents/**/*.md,
    # .claude/agents/**/*.md); frontmatter is a config surface (STORY-0094)
    CLAUDE_AGENT = "claude-code-agents"
    # Cursor AI rules (.cursor/rules/*.mdc, ~/.cursor/rules/*.mdc)
    CURSOR_RULE = "cursor-rule"
    # GitHub Copilot workspace instruction file (.github/copilot-instructions.md)
    COPILOT_INSTRUCTION = "copilot-instruction"
    # GitHub Copilot scoped instruction files (.github/instructions/*.instructions.md)
    COPILOT_SCOPED = "copilot-scoped"
    # GitHub Copilot prompt templates (.github/prompts/*.prompt.md)
    COPILOT_PROMPT = "copilot-prompt"
    # Claude Code rules (~/.claude/rules/**/*.md, .claude/rules/**/*.md),
    # loaded like CLAUDE.md (STORY-0098)
    CLAUDE_RULE = "claude-rule"
    # AGENTS.md / AGENTS.override.md: Codex, Cursor, Copilot, Claude Code and
    # the other agents.md readers (STORY-0098)
    AGENTS_MD = "agents-md"
    # OpenClaw workspace files loaded every session: AGENTS.md, SOUL.md,
    # USER.md, MEMORY.md (STORY-0098)
    OPENCLAW_WORKSPACE = "openclaw-workspace"
    # OpenClaw HEARTBEAT.md: the checklist a timer runs (STORY-0098)
    HEARTBEAT = "heartbeat"


#: Surfaces analysed with the memory rule set (MEM-001/002, POISON-041/042):
#: always-loaded context files, as opposed to skills, commands and rules that
#: are invoked for a task.
MEMORY_SURFACES: frozenset[AgentFileSurface] = frozenset(
    {
        AgentFileSurface.CLAUDE_MEMORY,
        AgentFileSurface.CLAUDE_RULE,
        AgentFileSurface.AGENTS_MD,
        AgentFileSurface.OPENCLAW_WORKSPACE,
        AgentFileSurface.HEARTBEAT,
    }
)


@dataclass(frozen=True)
class ImportEdge:
    """One ``@path`` import (or prose reference) found in an instruction file.

    Attributes:
        raw: The import text as written, without the leading ``@``.
        line: 1-based line number in the importing file.
        target: The path it resolves to (lexically normalised, not resolved
            through symlinks).
        kind: ``"import"`` (Claude Code ``@path``, loaded with the file) or
            ``"reference"`` (a "read X before starting" sentence the agent
            follows at its own discretion).
        status: ``"followed"`` (inside the scan root, read and scanned),
            ``"outside"`` (resolves outside the scan root; not read),
            ``"ignored"`` (inside the root but matched by ``.gitignore``;
            read and scanned), ``"symlink"`` (a symlink on the way; not read),
            ``"skipped"`` (over a size or count budget; not read).
        detail: For ``"ignored"``, the ``.gitignore`` file and pattern that
            matched; otherwise empty.
    """

    raw: str
    line: int
    target: Path
    kind: str
    status: str
    detail: str = ""


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
        definition: For a subagent definition only, the full record from
            :meth:`~mcp_audit.agent_files.subagents.AgentFrontmatter.to_record`
            (every reading, repeated and unreadable security keys).
    """

    path: Path
    surface: AgentFileSurface
    client: str
    scope: str  # "user" | "project"
    raw_content: str
    body: str
    frontmatter: dict = field(default_factory=dict)
    definition: dict | None = None
    #: True when the harness expands Claude Code ``@path`` imports in this
    #: file (CLAUDE.md tiers, CLAUDE.local.md, rules, AGENTS.md as Claude Code
    #: reads it, and every file they import).
    follows_imports: bool = False
    #: The file that imported or referenced this one, when it was reached
    #: that way rather than discovered at a known location.
    imported_from: Path | None = None
    #: Import/reference edges out of this file (filled in by discovery).
    edges: list[ImportEdge] = field(default_factory=list)
    #: True when the file was larger than the read cap and only its first
    #: part was read.
    truncated: bool = False

    @property
    def display_name(self) -> str:
        """Short human-readable identifier (filename or relative path)."""
        return self.path.name
