"""Load diff inputs (directory, JSON scan file, or git SHA) into ServerConfig lists."""

from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
from pathlib import Path

from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import DiscoveredConfig, discover_configs
from mcp_audit.models import ScanResult, ServerConfig

# Relative paths within a git checkout that may contain MCP configs.
# Order matters — more specific paths first.
_KNOWN_GIT_RELATIVE_PATHS: list[tuple[str, str]] = [
    # (relative_path, root_key)
    (".vscode/mcp.json", "servers"),
    (".cursor/mcp.json", "mcpServers"),
    (".mcp.json", "mcpServers"),
    ("claude_desktop_config.json", "mcpServers"),
    (".claude.json", "mcpServers"),
    ("mcp.json", "mcpServers"),
]


def _load_from_directory(path: Path) -> list[ServerConfig]:
    """Load all ServerConfigs discovered under *path*."""
    discovered = discover_configs(extra_paths=[path], skip_auto_discovery=True)
    servers: list[ServerConfig] = []
    for cfg in discovered:
        with contextlib.suppress(ValueError):
            servers.extend(parse_config(cfg))
    return servers


def _load_from_json_file(path: Path) -> list[ServerConfig]:
    """Load ServerConfigs from a JSON file.

    Accepts either a ``mcp-audit scan --output-file`` ScanResult JSON or a
    raw MCP config JSON (``mcpServers`` / ``servers`` root keys).
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read JSON from {path}: {exc}") from exc

    if not isinstance(raw, dict):
        return []

    # ScanResult format: "servers" key is a list of dicts with a "name" field.
    servers_field = raw.get("servers")
    has_server_list = (
        isinstance(servers_field, list)
        and bool(servers_field)
        and isinstance(servers_field[0], dict)
    )
    if has_server_list:
        with contextlib.suppress(Exception):  # noqa: BLE001
            result = ScanResult.model_validate(raw)
            return result.servers

    # Raw MCP config — try both root keys.
    for root_key in ("mcpServers", "servers"):
        discovered = DiscoveredConfig(
            client_name="diff-input",
            root_key=root_key,
            path=path,
        )
        try:
            servers = parse_config(discovered)
            if servers:
                return servers
        except ValueError:
            pass
    return []


def _load_from_git_sha(sha: str) -> list[ServerConfig]:
    """Load ServerConfigs from a git SHA by checking known config locations.

    Uses ``git show <sha>:<path>`` to read each known MCP config path.
    Files not present at the given SHA are silently skipped.

    Args:
        sha: A git ref — SHA, branch name, tag, HEAD~N, etc.

    Returns:
        List of parsed server configurations found at *sha*.

    Raises:
        ValueError: If the git ref cannot be resolved at all (git exits with an
            error for every path and the ref itself is invalid).
    """
    servers: list[ServerConfig] = []

    # Quick sanity check: does the ref exist?
    # nosec S603 S607 — git is a well-known system binary; sha is a git ref string
    probe = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--verify", sha],  # noqa: S607
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        raise ValueError(
            f"Git ref {sha!r} could not be resolved: {probe.stderr.strip()}"
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        for rel_path, root_key in _KNOWN_GIT_RELATIVE_PATHS:
            try:
                # nosec S603 S607 — git is well-known; sha validated by rev-parse above
                result = subprocess.run(  # noqa: S603
                    ["git", "show", f"{sha}:{rel_path}"],  # noqa: S607
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                # File didn't exist at this SHA — normal case, not an error.
                continue

            safe_name = rel_path.replace("/", "_")
            tmp_path = Path(tmpdir) / safe_name
            tmp_path.write_text(result.stdout, encoding="utf-8")

            discovered = DiscoveredConfig(
                client_name=f"git:{sha}",
                root_key=root_key,
                path=tmp_path,
            )
            with contextlib.suppress(ValueError):
                servers.extend(parse_config(discovered))

    return servers


def load_input(input_str: str) -> list[ServerConfig]:
    """Load a diff input into a list of ServerConfig objects.

    Routing logic:

    1. If the string resolves to an existing directory — load all MCP configs
       found under it (same discovery as ``mcp-audit scan --path``).
    2. If the string resolves to an existing file — treat as a JSON file
       (ScanResult or raw MCP config).
    3. Otherwise — treat as a git ref and resolve via ``git show``.

    Args:
        input_str: Raw CLI argument (directory path, file path, or git ref).

    Returns:
        List of parsed server configurations.

    Raises:
        ValueError: If the input cannot be resolved to any configs.
    """
    path = Path(input_str)
    resolved = path.resolve()

    if resolved.is_dir():
        return _load_from_directory(resolved)

    if resolved.is_file():
        return _load_from_json_file(resolved)

    # Git ref fallback — also handles partial paths that don't exist locally.
    return _load_from_git_sha(input_str)
