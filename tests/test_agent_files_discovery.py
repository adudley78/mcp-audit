"""Tests for agent-file discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.agent_files.discovery import discover_agent_files
from mcp_audit.agent_files.models import AgentFileSurface

# ---------------------------------------------------------------------------
# _split_frontmatter
# ---------------------------------------------------------------------------


def test_split_frontmatter_plain_markdown() -> None:
    """Plain Markdown without frontmatter returns empty dict and original body."""
    from mcp_audit.agent_files.discovery import _split_frontmatter

    content = "# Hello\n\nThis is a test."
    fm, body = _split_frontmatter(content)
    assert fm == {}
    assert body == content


def test_split_frontmatter_with_yaml() -> None:
    """Frontmatter is parsed and stripped from body."""
    from mcp_audit.agent_files.discovery import _split_frontmatter

    content = (
        "---\napplyTo: '**/*.py'\ndescription: Python conventions\n---\n# Body\nHello."
    )
    fm, body = _split_frontmatter(content)
    assert fm == {"applyTo": "**/*.py", "description": "Python conventions"}
    assert "# Body" in body
    assert "---" not in body


def test_split_frontmatter_invalid_yaml_returns_full_body() -> None:
    """Invalid YAML frontmatter returns empty dict and original content as body."""
    from mcp_audit.agent_files.discovery import _split_frontmatter

    content = "---\n: invalid: yaml: content\n---\n# Body"
    fm, body = _split_frontmatter(content)
    # Invalid YAML returns empty dict and original content
    assert fm == {}


def test_split_frontmatter_missing_closing_delimiter() -> None:
    """Frontmatter with no closing --- returns empty dict and original content."""
    from mcp_audit.agent_files.discovery import _split_frontmatter

    content = "---\nkey: value\n# No closing delimiter"
    fm, body = _split_frontmatter(content)
    assert fm == {}
    assert body == content


# ---------------------------------------------------------------------------
# User-global discovery
# ---------------------------------------------------------------------------


def test_discover_user_global_finds_nothing_when_dirs_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When no user-global agent-file dirs exist, discover returns empty list."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    files = discover_agent_files(include_user_global=True)
    assert files == []


def test_discover_user_global_finds_claude_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claude Code user commands in ~/.claude/commands/*.md are discovered."""
    home = tmp_path
    cmd_dir = home / ".claude" / "commands"
    cmd_dir.mkdir(parents=True)
    (cmd_dir / "deploy.md").write_text("Deploy to staging", encoding="utf-8")
    (cmd_dir / "test.md").write_text("Run tests", encoding="utf-8")

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    files = discover_agent_files(include_user_global=True)

    surfaces = {f.surface for f in files}
    assert AgentFileSurface.CLAUDE_COMMAND in surfaces
    assert sum(1 for f in files if f.surface == AgentFileSurface.CLAUDE_COMMAND) == 2
    assert all(f.client == "claude-code" for f in files)
    assert all(f.scope == "user" for f in files)


def test_discover_user_global_finds_claude_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """User-global CLAUDE.md at ~/.claude/CLAUDE.md is discovered."""
    home = tmp_path
    claude_dir = home / ".claude"
    claude_dir.mkdir()
    (claude_dir / "CLAUDE.md").write_text(
        "# Project context\n\nStack: Python.", encoding="utf-8"
    )

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    files = discover_agent_files(include_user_global=True)

    assert len(files) == 1
    af = files[0]
    assert af.surface == AgentFileSurface.CLAUDE_MEMORY
    assert af.client == "claude-code"
    assert af.scope == "user"


def test_discover_user_global_finds_cursor_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cursor user-global rules in ~/.cursor/rules/*.mdc are discovered."""
    home = tmp_path
    rules_dir = home / ".cursor" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "conventions.mdc").write_text(
        "# Always use TypeScript", encoding="utf-8"
    )

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    files = discover_agent_files(include_user_global=True)

    assert len(files) == 1
    af = files[0]
    assert af.surface == AgentFileSurface.CURSOR_RULE
    assert af.client == "cursor"
    assert af.scope == "user"


# ---------------------------------------------------------------------------
# Project-tree discovery
# ---------------------------------------------------------------------------


def test_discover_project_finds_claude_commands(tmp_path: Path) -> None:
    """Project-level .claude/commands/*.md are discovered."""
    cmd_dir = tmp_path / ".claude" / "commands"
    cmd_dir.mkdir(parents=True)
    (cmd_dir / "lint.md").write_text("Run linter", encoding="utf-8")

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert len(files) == 1
    assert files[0].surface == AgentFileSurface.CLAUDE_COMMAND
    assert files[0].scope == "project"


def test_discover_project_finds_claude_memory_root(tmp_path: Path) -> None:
    """Project-root CLAUDE.md is discovered as claude-memory."""
    (tmp_path / "CLAUDE.md").write_text("# My project", encoding="utf-8")

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert len(files) == 1
    assert files[0].surface == AgentFileSurface.CLAUDE_MEMORY
    assert files[0].scope == "project"


def test_discover_project_finds_cursor_rules(tmp_path: Path) -> None:
    """Project-level .cursor/rules/*.mdc are discovered."""
    rules_dir = tmp_path / ".cursor" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "style.mdc").write_text(
        "---\napplyTo: '**/*.ts'\n---\nUse TS.", encoding="utf-8"
    )

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert len(files) == 1
    af = files[0]
    assert af.surface == AgentFileSurface.CURSOR_RULE
    assert af.client == "cursor"
    # Frontmatter should be stripped
    assert "---" not in af.body


def test_discover_project_finds_copilot_instruction(tmp_path: Path) -> None:
    """.github/copilot-instructions.md is discovered as COPILOT_INSTRUCTION."""
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "copilot-instructions.md").write_text("Use Python 3.12+", encoding="utf-8")

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert len(files) == 1
    assert files[0].surface == AgentFileSurface.COPILOT_INSTRUCTION
    assert files[0].client == "copilot"


def test_discover_project_finds_copilot_scoped(tmp_path: Path) -> None:
    """.github/instructions/*.instructions.md are discovered as COPILOT_SCOPED."""
    instr_dir = tmp_path / ".github" / "instructions"
    instr_dir.mkdir(parents=True)
    (instr_dir / "backend.instructions.md").write_text("Use FastAPI.", encoding="utf-8")

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert len(files) == 1
    assert files[0].surface == AgentFileSurface.COPILOT_SCOPED


def test_discover_project_finds_copilot_prompts(tmp_path: Path) -> None:
    """.github/prompts/*.prompt.md are discovered as COPILOT_PROMPT."""
    prompts_dir = tmp_path / ".github" / "prompts"
    prompts_dir.mkdir(parents=True)
    (prompts_dir / "fix-bug.prompt.md").write_text(
        "Fix the bug in $SELECTION.", encoding="utf-8"
    )

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert len(files) == 1
    assert files[0].surface == AgentFileSurface.COPILOT_PROMPT


def test_discover_deduplicates_same_path(tmp_path: Path) -> None:
    """The same resolved path is never returned twice."""
    (tmp_path / "CLAUDE.md").write_text("# Project", encoding="utf-8")

    # Call twice with same project root — simulate double invocation.
    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    paths = [str(f.path.resolve()) for f in files]
    assert len(paths) == len(set(paths)), "Duplicate paths in results"


def test_discover_skips_node_modules(tmp_path: Path) -> None:
    """node_modules subtrees are skipped during project-tree walk."""
    nm = tmp_path / "node_modules" / ".claude" / "commands"
    nm.mkdir(parents=True)
    (nm / "evil.md").write_text("Malicious command", encoding="utf-8")

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert files == []


def test_discover_reads_content_and_frontmatter(tmp_path: Path) -> None:
    """Frontmatter is separated from body; raw_content has the full file."""
    mdc = tmp_path / ".cursor" / "rules"
    mdc.mkdir(parents=True)
    content = "---\napplyTo: '**/*.py'\n---\n# Rule body\nUse black."
    (mdc / "style.mdc").write_text(content, encoding="utf-8")

    files = discover_agent_files(
        project_root=tmp_path,
        include_user_global=False,
    )
    assert len(files) == 1
    af = files[0]
    assert af.raw_content == content
    assert af.frontmatter == {"applyTo": "**/*.py"}
    assert "# Rule body" in af.body
    assert "---" not in af.body
