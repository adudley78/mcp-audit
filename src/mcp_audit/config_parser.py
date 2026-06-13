"""Parse MCP configuration files into structured ServerConfig objects."""

from __future__ import annotations

import json

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

    As a side effect, stores the top-level parsed JSON dict in
    ``config.raw`` so downstream pipeline steps (e.g. config-level
    analyzer checks) can access the raw file contents without a second
    disk read.

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
        raise ValueError(
            f"Expected JSON object in {config.path}, got {type(data).__name__}"
        )

    # Persist the raw dict so callers can access it without a second disk read.
    config.raw = data

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

        raw_headers = server_data.get("headers", {})
        servers.append(
            ServerConfig(
                name=name,
                client=config.client_name,
                config_path=config.path,
                transport=transport,
                command=server_data.get("command"),
                args=server_data.get("args", []),
                env=server_data.get("env", {}),
                url=server_data.get("url"),
                # Normalise headers to dict[str, str]; skip non-dict values
                # (malformed config entries) without crashing.
                headers={k: str(v) for k, v in raw_headers.items()}
                if isinstance(raw_headers, dict)
                else {},
                raw=server_data,
                capabilities=server_data.get("capabilities"),
                # Thread origin from discovery — True only for --project scans.
                is_project_scoped=config.is_project_scoped,
            )
        )

    return servers
