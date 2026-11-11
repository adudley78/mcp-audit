"""Load diff inputs (directory, JSON scan file, or git SHA) into ServerConfig lists."""

from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
from pathlib import Path

from mcp_audit.config_parser import config_dialect, parse_config
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
    # Codex and Gemini CLI project files (STORY-0110).  The parser reads each
    # in its own dialect (``DiscoveredConfig.dialect``), since the temporary
    # copy's name no longer says which file it was.
    (".codex/config.toml", "mcp_servers"),
    (".gemini/settings.json", "mcpServers"),
    # OpenCode (STORY-0142): JSONC, top-level ``mcp``.
    ("opencode.json", "mcp"),
    ("opencode.jsonc", "mcp"),
]

#: Parser dialect for the known paths above whose format is not plain JSON.
_GIT_PATH_DIALECT: dict[str, str] = {
    ".codex/config.toml": "codex",
    ".gemini/settings.json": "gemini",
    "opencode.json": "opencode",
    "opencode.jsonc": "opencode",
}


#: Seconds any one git call may take. A hung git (a lock, a network
#: filesystem) must fail the diff, not hang a CI job for six hours.
GIT_TIMEOUT_SECONDS = 30

#: Same cap the config parser applies to a file on disk.
_MAX_GIT_BLOB_BYTES = 4 * 1024 * 1024

# A repository's own .git/config can name an fsmonitor program that git
# runs on index access. Switched off on every call.
_GIT_SAFE_CONFIG = ("-c", "core.fsmonitor=false")


def _check_git_ref(ref: str) -> None:
    """Reject a ref git would read as an option (``--output=...``)."""
    if not ref or ref.startswith("-") or any(c in ref for c in "\x00\n\r"):
        raise ValueError(f"Not a usable git ref: {ref!r}")


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    """Run a read-only git query: list form, bounded, captured, no pager."""
    try:
        return subprocess.run(  # noqa: S603  # nosec B603 — list form, shell=False
            ["git", *_GIT_SAFE_CONFIG, "--no-pager", *args],  # noqa: S607
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise ValueError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError(
            f"git {args[0]} timed out after {GIT_TIMEOUT_SECONDS}s"
        ) from exc


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
    raw MCP config JSON (``mcpServers`` / ``servers`` root keys).  A ``.toml``
    file is read as Codex's ``config.toml`` and ``.gemini/settings.json`` as
    Gemini CLI's settings (STORY-0110).
    """
    probe = DiscoveredConfig(client_name="diff-input", root_key="mcpServers", path=path)
    if config_dialect(probe) is not None:
        return parse_config(probe)
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

    Uses ``git cat-file blob <sha>:<path>`` to read each known MCP config path.
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
    _check_git_ref(sha)

    # Quick sanity check: does the ref exist?
    probe = _git("rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}")
    if probe.returncode != 0:
        raise ValueError(f"Git ref {sha!r} could not be resolved to a commit.")

    with tempfile.TemporaryDirectory() as tmpdir:
        for rel_path, root_key in _KNOWN_GIT_RELATIVE_PATHS:
            # ``cat-file blob`` prints the stored bytes. ``git show`` would
            # run a textconv driver from the repository's own .git/config,
            # which a downloaded repository controls (TRUST-006).
            result = _git("cat-file", "blob", f"{sha}:{rel_path}")
            if result.returncode != 0:
                # File didn't exist at this SHA — normal case, not an error.
                continue
            if len(result.stdout) > _MAX_GIT_BLOB_BYTES:
                continue
            text = result.stdout.decode("utf-8", errors="replace")

            safe_name = rel_path.replace("/", "_")
            tmp_path = Path(tmpdir) / safe_name
            tmp_path.write_text(text, encoding="utf-8")

            discovered = DiscoveredConfig(
                client_name=f"git:{sha}",
                root_key=root_key,
                path=tmp_path,
                dialect=_GIT_PATH_DIALECT.get(rel_path),
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
    3. Otherwise — treat as a git ref and read it with ``git cat-file``.

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
