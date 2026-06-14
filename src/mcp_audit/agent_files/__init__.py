"""Agent-file security scanner: skills, instruction files, memory, and hooks.

This package extends mcp-audit beyond MCP config files to cover the other
instruction surfaces an AI agent reads:

- **Skills / command files** — Claude Code custom slash commands
  (``~/.claude/commands/``, ``.claude/commands/``), Cursor rules
  (``.cursor/rules/*.mdc``), and GitHub Copilot instruction files
  (``.github/copilot-instructions.md``, ``.github/instructions/``,
  ``.github/prompts/``).
- **Memory / context files** — Claude Code CLAUDE.md tiers
  (``~/.claude/CLAUDE.md``, ``.claude/CLAUDE.md``, project-root ``CLAUDE.md``).
- Hook-command content analysis is handled in
  :mod:`mcp_audit.analyzers.config_hygiene` (HOOK-001, HOOK-002), not here.

All discovery and analysis is **fully offline** — no network calls.
"""
