"""Discover MCP configuration files across supported clients."""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ClientSpec:
    """Specification for a supported MCP client."""

    name: str
    root_key: str  # JSON key containing server definitions
    config_paths: list[Path]  # Paths to check, in priority order


def _home() -> Path:
    return Path.home()


def _get_client_specs() -> list[ClientSpec]:
    """Return client specifications for the current platform."""
    system = platform.system()
    home = _home()

    clients: list[ClientSpec] = []

    # Claude Desktop
    if system == "Darwin":
        claude_desktop_path = (
            home
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    elif system == "Windows":
        appdata = _home() / "AppData" / "Roaming"
        claude_desktop_path = appdata / "Claude" / "claude_desktop_config.json"
    else:  # Linux
        claude_desktop_path = home / ".config" / "Claude" / "claude_desktop_config.json"

    clients.append(
        ClientSpec(
            name="claude-desktop",
            root_key="mcpServers",
            config_paths=[claude_desktop_path],
        )
    )

    # Cursor
    clients.append(
        ClientSpec(
            name="cursor",
            root_key="mcpServers",
            config_paths=[home / ".cursor" / "mcp.json"],
        )
    )

    # VS Code — workspace-level configs discovered separately
    # Note: VS Code uses "servers" not "mcpServers"
    clients.append(
        ClientSpec(
            name="vscode",
            root_key="servers",
            config_paths=[],  # Workspace configs found via --path or CWD scanning
        )
    )

    # Windsurf
    clients.append(
        ClientSpec(
            name="windsurf",
            root_key="mcpServers",
            config_paths=[home / ".codeium" / "windsurf" / "mcp_config.json"],
        )
    )

    # Claude Code (user-level)
    clients.append(
        ClientSpec(
            name="claude-code",
            root_key="mcpServers",
            config_paths=[home / ".claude.json"],
        )
    )

    # GitHub Copilot CLI
    clients.append(
        ClientSpec(
            name="copilot-cli",
            root_key="mcpServers",
            config_paths=[home / ".copilot" / "mcp-config.json"],
        )
    )

    # Augment Code — settings.json may contain non-MCP keys alongside mcpServers
    clients.append(
        ClientSpec(
            name="augment",
            root_key="mcpServers",
            config_paths=[home / ".augment" / "settings.json"],
        )
    )

    return clients


@dataclass
class DiscoveredConfig:
    """A discovered MCP configuration file."""

    client_name: str
    root_key: str
    path: Path
    raw: dict = field(default_factory=dict)
    # True when found via discover_project_configs() (--project flag).
    # Never set by the normal user-level discovery path.
    is_project_scoped: bool = False


def discover_configs(
    extra_paths: list[Path] | None = None,
    skip_auto_discovery: bool = False,
) -> list[DiscoveredConfig]:
    """Find all MCP configuration files on this machine.

    Args:
        extra_paths: Additional paths to check (e.g., from --path flag).
        skip_auto_discovery: When ``True``, skip known-client and CWD discovery
            and return only configs built from *extra_paths*.  Used when the
            caller has already provided an explicit config path — combining
            that with auto-discovery would inflate ``clients_scanned`` with
            zero-server system configs.

    Returns:
        List of discovered configuration files.
    """
    discovered: list[DiscoveredConfig] = []

    if not skip_auto_discovery:
        # Check known client locations
        for spec in _get_client_specs():
            for config_path in spec.config_paths:
                if (
                    config_path.exists()
                    and config_path.is_file()
                    and not config_path.is_symlink()
                ):
                    discovered.append(
                        DiscoveredConfig(
                            client_name=spec.name,
                            root_key=spec.root_key,
                            path=config_path,
                        )
                    )

        # Check for VS Code / Claude Code project-level configs in CWD
        cwd = Path.cwd()
        vscode_mcp = cwd / ".vscode" / "mcp.json"
        if vscode_mcp.exists() and not vscode_mcp.is_symlink():
            discovered.append(
                DiscoveredConfig(
                    client_name="vscode",
                    root_key="servers",
                    path=vscode_mcp,
                )
            )

        claude_code_project = cwd / ".mcp.json"
        if claude_code_project.exists() and not claude_code_project.is_symlink():
            discovered.append(
                DiscoveredConfig(
                    client_name="claude-code-project",
                    root_key="mcpServers",
                    path=claude_code_project,
                )
            )

    # Check extra paths
    if extra_paths:
        for p in extra_paths:
            expanded = Path(p).expanduser()
            if expanded.is_symlink():
                continue
            resolved = expanded.resolve()
            if resolved.is_file() and resolved.exists():
                discovered.append(
                    DiscoveredConfig(
                        client_name="custom",
                        root_key="mcpServers",  # Assume default; parser will try both
                        path=resolved,
                    )
                )
            elif resolved.is_dir():
                # Scan all JSON files in the directory.  The parser handles
                # root-key detection (mcpServers vs servers) and silently
                # returns [] for files that contain neither key.
                for candidate in sorted(resolved.glob("*.json")):
                    if candidate.is_file() and not candidate.is_symlink():
                        discovered.append(
                            DiscoveredConfig(
                                client_name="custom",
                                root_key="mcpServers",
                                path=candidate,
                            )
                        )

    return discovered


# ── Project-level config discovery (for --project flag) ───────────────────────

# Project-scoped config files, each as (relative-path, client-name, root-key).
# These are files that live *inside* a repository and are typically committed to
# version control, causing the named MCP server to auto-spawn for every developer
# who trusts the folder in a supporting AI editor.
#
# Research basis: Adversa TrustFall (May 2026), corroborated by CVE-2026-30615.
# OWASP MCP09: Shadow MCP Servers.
#
# Confirmed-active clients and paths (verified against official docs, 2026-06-11):
#   Claude Code  — .mcp.json                   (Anthropic official docs)
#   Claude Code  — .claude/settings.json        (project settings, mcpServers key)
#   Claude Code  — .claude/settings.local.json  (local override, same schema)
#   Cursor       — .cursor/mcp.json             (Cursor official docs)
#   Cursor       — .cursor/settings.json        (workspace settings; inclusion
#                                                tentative — see GAPS.md)
#   VS Code      — .vscode/mcp.json             (VS Code official docs; "servers" key)
#
# Windsurf: global-only config (~/.codeium/windsurf/mcp_config.json); no
#   project-level MCP file — omitted intentionally.
# Zed: uses "context_servers" key in settings.json; different schema — omitted.
# Continue.dev: YAML-based (.continue/config.yaml) — out of scope for JSON parser.
_PROJECT_CONFIG_SPECS: list[tuple[str, str, str]] = [
    (".mcp.json", "claude-code", "mcpServers"),
    (".claude/settings.json", "claude-code", "mcpServers"),
    (".claude/settings.local.json", "claude-code", "mcpServers"),
    (".cursor/mcp.json", "cursor", "mcpServers"),
    (".cursor/settings.json", "cursor", "mcpServers"),
    (".vscode/mcp.json", "vscode", "servers"),
]

# Directory names to skip while walking the project tree.
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

# Maximum directory depth to descend from the project root (inclusive).
# Depth 0 = root itself, depth 8 = 8 levels below root.
_WALK_MAX_DEPTH: int = 8


def discover_project_configs(root: Path) -> list[DiscoveredConfig]:
    """Walk a repository tree and find all project-level MCP config files.

    This function is the discovery back-end for ``mcp-audit scan --project``.
    It is entirely separate from :func:`discover_configs` and does **not**
    alter the default scan behaviour.

    Walk rules:
    - Skips directories named in :data:`_WALK_SKIP_DIRS`.
    - Caps recursion at depth :data:`_WALK_MAX_DEPTH` below *root*.
    - Does **not** follow symlinked directories or files.

    Args:
        root: Resolved absolute path of the repository root to walk.

    Returns:
        List of :class:`DiscoveredConfig` objects with
        ``is_project_scoped=True``.  The list is empty when no project-level
        MCP config files are found under *root*.
    """
    discovered: list[DiscoveredConfig] = []

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH:
            return

        # Check each known project-config pattern relative to this directory.
        for rel_path, client_name, root_key in _PROJECT_CONFIG_SPECS:
            candidate = dirpath / rel_path
            if candidate.is_symlink():
                continue
            if candidate.is_file():
                discovered.append(
                    DiscoveredConfig(
                        client_name=client_name,
                        root_key=root_key,
                        path=candidate,
                        is_project_scoped=True,
                    )
                )

        # Recurse into non-symlink subdirectories not in the skip list.
        try:
            children = sorted(dirpath.iterdir())
        except PermissionError:
            return

        for child in children:
            if child.is_symlink():
                continue
            if not child.is_dir():
                continue
            if child.name in _WALK_SKIP_DIRS:
                continue
            _walk(child, depth + 1)

    _walk(root, 0)
    return discovered
