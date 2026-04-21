"""Discover MCP configuration files across supported clients."""

from __future__ import annotations

import platform
from dataclasses import dataclass
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
        appdata = Path.home() / "AppData" / "Roaming"
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
