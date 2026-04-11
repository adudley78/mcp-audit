"""Parse MCP configuration files into structured ServerConfig objects."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import ServerConfig, TransportType


def _detect_transport(server_data: dict) -> TransportType:
    """Detect the transport type from a server config entry."""
    if "command" in server_data:
        return TransportType.STDIO
    if "url" in server_data:
        url = server_data["url"]
        if "/sse" in url or url.endswith("/sse"):
            return TransportType.SSE
        return TransportType.STREAMABLE_HTTP
    return TransportType.UNKNOWN


def parse_config(config: DiscoveredConfig) -> list[ServerConfig]:
    """Parse a discovered config file into a list of ServerConfig objects.

    Handles the VS Code 'servers' vs 'mcpServers' key difference.

    Args:
        config: A discovered configuration file.

    Returns:
        List of parsed server configurations.

    Raises:
        ValueError: If the config file cannot be parsed.
    """
    try:
        raw_text = config.path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"Cannot read {config.path}: {e}") from e

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {config.path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {config.path}, got {type(data).__name__}")

    # Try the expected root key first, then the alternative
    servers_dict = data.get(config.root_key)
    if servers_dict is None:
        # Try the other key as fallback
        alt_key = "servers" if config.root_key == "mcpServers" else "mcpServers"
        servers_dict = data.get(alt_key)

    if servers_dict is None or not isinstance(servers_dict, dict):
        return []

    servers: list[ServerConfig] = []
    for name, server_data in servers_dict.items():
        if not isinstance(server_data, dict):
            continue

        transport = _detect_transport(server_data)

        servers.append(ServerConfig(
            name=name,
            client=config.client_name,
            config_path=config.path,
            transport=transport,
            command=server_data.get("command"),
            args=server_data.get("args", []),
            env=server_data.get("env", {}),
            url=server_data.get("url"),
            raw=server_data,
        ))

    return servers
