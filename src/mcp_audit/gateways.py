"""Servers behind an MCP gateway (STORY-0111).

A gateway (an aggregator or proxy) is one MCP server entry in a client's
config that starts and fronts many other servers, its *upstreams*.  A scan
that reads only the client config sees one server; the upstreams, and the
capabilities they give the agent, live in the gateway's own config file.
This module knows where three gateways keep that file and how to read it, so
the upstream servers can join discovery and every analyzer (toxic flow
included) like any other server, under the client ``<gateway>-upstream``.

Read-only and offline: files are read as text and parsed as JSON or TOML.
Nothing in them is run, expanded or fetched (``${cmd: ...}`` placeholders,
1MCP Handlebars templates and ``${VAR}`` references stay literal).

Locations and formats, each confirmed from the gateway's own source or docs
(see PROVENANCE.md, "Gateway upstream configs"):

- **mcptoon** (``mcptoon/config.py``, 0.8.32): user config
  ``~/.mcptoon/config.json`` and ``config.toml``, or the same names under
  ``$MCPTOON_HOME`` or ``$XDG_CONFIG_HOME/mcptoon``; project config
  ``./.mcptoon.json`` and ``./.mcptoon.toml`` in the directory ``mcptoon``
  runs from.  Root key ``servers``; ``command`` is an argv list (or one
  string) that ``args`` is appended to; ``transport`` is ``stdio`` or
  ``http``.  An entry named ``mcptoon``, or one whose argv runs
  ``mcptoon ... serve``, is dropped by mcptoon itself and is skipped here.
- **1MCP** (docs.1mcp.app, MCP Servers reference): ``~/.config/1mcp/mcp.json``
  on macOS and Linux, ``%APPDATA%\\1mcp\\mcp.json`` on Windows, or ``mcp.json``
  in ``$ONE_MCP_CONFIG_DIR`` / the file ``$ONE_MCP_CONFIG``.  Root key
  ``mcpServers`` plus ``mcpTemplates`` (a template wins over a static server of
  the same name); ``serverDefaults.env`` is merged under each server's
  ``env``; ``env`` may be an object or a ``["KEY=value", "NAME"]`` list.
- **MCPHub.nvim / mcp-hub** (mcphub.nvim ``doc/configuration.md``,
  ``doc/mcp/servers_json.md``): ``~/.config/mcphub/servers.json`` (the
  plugin's default ``config``), and ``.mcphub/servers.json`` in a project
  (workspace detection is on by default).  Root key ``servers`` (VS Code
  format, wins when both are present) or ``mcpServers``.
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

#: Largest gateway config file that is read.  A larger file is reported in
#: ``result.errors`` (not read).  Real files are a few KiB.
GATEWAY_CONFIG_MAX_BYTES = 4 * 1024 * 1024

#: Most upstream servers analysed from one gateway config file; the rest are
#: named in a parse warning (``result.errors``), never dropped silently.
GATEWAY_MAX_SERVERS = 1000

MCPTOON_CLIENT = "mcptoon-upstream"
ONEMCP_CLIENT = "1mcp-upstream"
MCPHUB_CLIENT = "mcphub-upstream"

#: Client names given to servers read from a gateway's config.  Like
#: ``claude-code-plugin``, these servers are never written to
#: ``mcp-lock.json``; user-level ones are left out of the rug-pull state key.
GATEWAY_UPSTREAM_CLIENTS: frozenset[str] = frozenset(
    {MCPTOON_CLIENT, ONEMCP_CLIENT, MCPHUB_CLIENT}
)

#: Human name of the gateway behind each client, for finding text.
GATEWAY_DISPLAY_NAMES: dict[str, str] = {
    MCPTOON_CLIENT: "mcptoon",
    ONEMCP_CLIENT: "1MCP",
    MCPHUB_CLIENT: "MCPHub",
}

#: Project-level gateway configs, relative to a working directory or a
#: directory of a ``scan --project`` walk: ``(relative path, client)``.
#: mcptoon reads ``.mcptoon.toml`` then ``.mcptoon.json`` from the directory it
#: runs in; MCPHub.nvim's workspace detection looks for ``.mcphub/servers.json``.
#: 1MCP documents no project-level server file (``.1mcprc`` holds context, not
#: servers).
PROJECT_GATEWAY_FILES: tuple[tuple[str, str], ...] = (
    (".mcptoon.json", MCPTOON_CLIENT),
    (".mcptoon.toml", MCPTOON_CLIENT),
    (".mcphub/servers.json", MCPHUB_CLIENT),
)


@dataclass(frozen=True)
class GatewayServers:
    """The upstream servers read from one gateway config file.

    Attributes:
        servers: ``{name: entry}`` with each entry normalised to the shape the
            config parser reads (``command`` a string, ``args``/``env``/
            ``headers`` of strings) and the gateway's own other keys kept.
        transports: Declared transport per server name, when the file says
            (``stdio``, ``sse`` or ``streamable-http``).
        raw: The parsed top-level document (JSON-safe), for config-level checks.
        warnings: Notes about content that was not analysed.
    """

    servers: dict[str, dict]
    transports: dict[str, str]
    raw: dict
    warnings: list[str]


def _gateway_home() -> Path:
    """Home directory for user-level gateway configs (patched by tests)."""
    return Path.home()


def _gateway_environ() -> Mapping[str, str]:
    """The environment the gateway paths are read from (patched by tests)."""
    return os.environ


def _env_path(name: str) -> Path | None:
    """``$name`` as an absolute path, or ``None`` when unset, empty or relative.

    A relative value is resolved by the gateway against its own working
    directory, which a scan cannot know, so it is not guessed at.
    """
    value = _gateway_environ().get(name, "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else None


def user_gateway_config_paths() -> list[tuple[str, Path]]:
    """User-level gateway config candidates, as ``(client, path)`` pairs.

    Every location the gateway could read is listed (an override directory
    from the environment the scan runs in, and the default), deduplicated;
    the caller keeps the ones that exist.  Never touches the filesystem.
    """
    home = _gateway_home()
    out: list[tuple[str, Path]] = []

    # mcptoon: MCPTOON_HOME, then $XDG_CONFIG_HOME/mcptoon, then ~/.mcptoon.
    mcptoon_roots: list[Path] = []
    explicit = _env_path("MCPTOON_HOME")
    if explicit is not None:
        mcptoon_roots.append(explicit)
    xdg = _env_path("XDG_CONFIG_HOME")
    if xdg is not None:
        mcptoon_roots.append(xdg / "mcptoon")
    mcptoon_roots.append(home / ".mcptoon")
    for root in mcptoon_roots:
        out.append((MCPTOON_CLIENT, root / "config.toml"))
        out.append((MCPTOON_CLIENT, root / "config.json"))

    # 1MCP: ONE_MCP_CONFIG (a file), ONE_MCP_CONFIG_DIR, then the default dir.
    onemcp_file = _env_path("ONE_MCP_CONFIG")
    if onemcp_file is not None:
        out.append((ONEMCP_CLIENT, onemcp_file))
    onemcp_dir = _env_path("ONE_MCP_CONFIG_DIR")
    if onemcp_dir is not None:
        out.append((ONEMCP_CLIENT, onemcp_dir / "mcp.json"))
    if platform.system() == "Windows":
        appdata = _env_path("APPDATA") or home / "AppData" / "Roaming"
        out.append((ONEMCP_CLIENT, appdata / "1mcp" / "mcp.json"))
    else:
        out.append((ONEMCP_CLIENT, home / ".config" / "1mcp" / "mcp.json"))

    # MCPHub.nvim: the plugin's default `config` path (~ expanded by Neovim).
    out.append((MCPHUB_CLIENT, home / ".config" / "mcphub" / "servers.json"))

    seen: set[Path] = set()
    unique: list[tuple[str, Path]] = []
    for client, path in out:
        if path in seen:
            continue
        seen.add(path)
        unique.append((client, path))
    return unique


def gateway_spawn_text(server: object) -> str:
    """TRUST-001's "how it starts" sentence for a gateway project server.

    *server* is a :class:`~mcp_audit.models.ServerConfig` (typed loosely so
    this module stays free of model imports).
    """
    name = getattr(server, "name", "")
    client = getattr(server, "client", "")
    path = getattr(server, "config_path", None)
    file_name = path.name if isinstance(path, Path) else str(path)
    if client == MCPHUB_CLIENT:
        how = (
            " MCPHub.nvim reads this file when Neovim opens the project"
            " (workspace detection is on by default) and its hub can start the"
            " servers listed in it"
        )
    else:
        how = (
            " mcptoon reads this file from the directory it runs in, so when"
            " `mcptoon serve` (or another mcptoon command that starts servers)"
            " runs in this repository, for example launched by an agent that"
            " uses the repository as its working directory, it can start this"
            " server behind the gateway"
        )
    return (
        f"Server '{name}' is defined in '{file_name}', a project-level"
        f" {GATEWAY_DISPLAY_NAMES.get(client, client)} gateway config that is"
        " likely committed to version control." + how + ", with the developer's"
        " full OS privileges. The agent sees only the gateway, not this server."
    )


# ── Reading ──────────────────────────────────────────────────────────────────


def _read_text(path: Path) -> str:
    """Read a gateway config, size-capped, BOM stripped.

    Raises:
        ValueError: The file cannot be read, is not UTF-8, or is larger than
            :data:`GATEWAY_CONFIG_MAX_BYTES`.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(GATEWAY_CONFIG_MAX_BYTES + 1)
    except OSError as e:
        raise ValueError(f"Cannot read {path}: {e}") from e
    if len(data) > GATEWAY_CONFIG_MAX_BYTES:
        raise ValueError(
            f"{path} is over mcp-audit's {GATEWAY_CONFIG_MAX_BYTES}-byte limit for"
            " a gateway config; it was not read. Review its servers by hand."
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{path} is not UTF-8 text: {e}") from e
    return text.removeprefix("﻿")


def _load_document(path: Path) -> dict:
    """Parse *path* as TOML (``.toml``) or JSON into a dict.

    Raises:
        ValueError: Unreadable, malformed, too deeply nested, or not an object.
    """
    text = _read_text(path)
    try:
        if path.suffix.lower() == ".toml":
            data: object = tomllib.loads(text)
        else:
            data = json.loads(text)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid gateway config {path}: {e}") from e
    except RecursionError as e:
        raise ValueError(
            f"Invalid gateway config {path}: nested too deeply to read"
        ) from e
    if not isinstance(data, dict):
        raise ValueError(
            f"Expected an object in gateway config {path}, got {type(data).__name__}"
        )
    return _json_safe(data)  # type: ignore[return-value]


def _json_safe(value: object) -> object:
    """Parsed TOML/JSON as JSON-serialisable values (TOML dates become text).

    ``raw`` is hashed with ``json.dumps`` (rug-pull) and written to JSON
    output.  Iterative, so a deeply nested document cannot overflow the stack.
    """
    root: list[object] = [None]
    stack: list[tuple[object, object, object]] = [(value, root, 0)]
    while stack:
        node, parent, key = stack.pop()
        if isinstance(node, dict):
            new: object = {}
            for k, v in node.items():
                stack.append((v, new, str(k)))
        elif isinstance(node, list):
            new = [None] * len(node)
            for i, v in enumerate(node):
                stack.append((v, new, i))
        elif isinstance(node, datetime.date | datetime.time):
            new = node.isoformat()
        else:
            new = node
        parent[key] = new  # type: ignore[index]
    return root[0]


def _text(value: object) -> str | None:
    """A scalar as text; ``None`` for a missing or structured value."""
    if value is None or isinstance(value, dict | list):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _text_list(value: object) -> list[str]:
    """The scalar items of a list as text (structured items dropped)."""
    if not isinstance(value, list):
        return []
    return [t for t in (_text(item) for item in value) if t is not None]


def _text_map(value: object) -> dict[str, str]:
    """An object's scalar values as text (structured values dropped)."""
    if not isinstance(value, dict):
        return {}
    return {str(k): t for k, v in value.items() if (t := _text(v)) is not None}


def _env_map(value: object) -> dict[str, str]:
    """An ``env`` given as an object, or as 1MCP's ``["KEY=value", "NAME"]`` list.

    A bare ``NAME`` (inherited from the gateway's environment) becomes the
    reference ``${NAME}``, so it reads as a name, not a literal value.
    """
    if isinstance(value, list):
        out: dict[str, str] = {}
        for item in _text_list(value):
            key, eq, val = item.partition("=")
            key = key.strip()
            if key:
                out[key] = val if eq else "${" + key + "}"
        return out
    return _text_map(value)


_TRANSPORT_ALIASES: dict[str, str] = {
    "stdio": "stdio",
    "sse": "sse",
    "http": "streamable-http",
    "streamablehttp": "streamable-http",
    "streamable-http": "streamable-http",
}


def _normalise_entry(entry: dict, command_value: object, args_value: object) -> dict:
    """Build the parser-shaped entry: gateway keys kept, launch fields as text."""
    out = dict(entry)
    command: str | None
    if isinstance(command_value, list):
        argv = _text_list(command_value)
        command = argv[0] if argv else None
        lead = argv[1:]
    else:
        command = _text(command_value)
        lead = []
    args = (
        _text_list(args_value)
        if isinstance(args_value, list)
        else ([t] if (t := _text(args_value)) else [])
    )
    for key in ("command", "args", "env", "headers", "url"):
        out.pop(key, None)
    if command is not None:
        out["command"] = command
    out["args"] = lead + args
    out["env"] = _env_map(entry.get("env"))
    headers = _text_map(entry.get("headers"))
    if headers:
        out["headers"] = headers
    url = _text(entry.get("url"))
    if url is not None:
        out["url"] = url
    return out


def _is_mcptoon_self_entry(name: str, entry: dict) -> bool:
    """mcptoon's own rule (``config._is_self_entry``): the gateway's entry.

    The reserved name ``mcptoon``, or an argv with a ``mcptoon`` token and a
    ``serve`` token (path, case and ``.exe``/``.cmd``/``.bat``/``.py`` ignored).
    mcptoon drops these on read, so they never start.
    """
    if name.strip().lower() == "mcptoon":
        return True
    command = entry.get("command")
    if isinstance(command, str):
        parts = command.split()
    elif isinstance(command, list):
        parts = _text_list(command)
    else:
        return False
    args = entry.get("args")
    if isinstance(args, list):
        parts += _text_list(args)
    elif isinstance(args, str):
        parts += args.split()

    def base(token: str) -> str:
        b = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
        for ext in (".exe", ".cmd", ".bat", ".py"):
            if b.endswith(ext):
                b = b[: -len(ext)]
        return b

    tokens = {base(t) for t in parts}
    return "mcptoon" in tokens and "serve" in tokens


def _mcptoon_servers(doc: dict) -> tuple[dict[str, dict], dict[str, str]]:
    section = doc.get("servers")
    if not isinstance(section, dict):
        return {}, {}
    servers: dict[str, dict] = {}
    transports: dict[str, str] = {}
    for name, entry in section.items():
        if not isinstance(entry, dict) or _is_mcptoon_self_entry(name, entry):
            continue
        declared = str(entry.get("transport", "stdio")).lower()
        if declared == "http":
            # mcptoon's http transport talks to a URL; command is not used.
            norm = _normalise_entry(entry, None, None)
        else:
            norm = _normalise_entry(entry, entry.get("command"), entry.get("args"))
        servers[name] = norm
        if declared in _TRANSPORT_ALIASES:
            transports[name] = _TRANSPORT_ALIASES[declared]
    return servers, transports


def _onemcp_servers(doc: dict) -> tuple[dict[str, dict], dict[str, str]]:
    defaults = doc.get("serverDefaults")
    defaults = defaults if isinstance(defaults, dict) else {}
    default_env = _env_map(defaults.get("env"))
    default_headers = _text_map(defaults.get("headers"))
    merged: dict[str, object] = {}
    for key in ("mcpServers", "mcpTemplates"):
        section = doc.get(key)
        if isinstance(section, dict):
            merged.update(section)  # a template wins over a same-name server
    servers: dict[str, dict] = {}
    transports: dict[str, str] = {}
    for name, entry in merged.items():
        if not isinstance(entry, dict):
            continue
        norm = _normalise_entry(entry, entry.get("command"), entry.get("args"))
        declared = str(entry.get("type", "")).lower()
        if default_env:
            norm["env"] = {**default_env, **norm["env"]}
        if default_headers and "url" in norm and "headers" not in norm:
            norm["headers"] = dict(default_headers)
        servers[name] = norm
        if declared in _TRANSPORT_ALIASES:
            transports[name] = _TRANSPORT_ALIASES[declared]
    return servers, transports


def _mcphub_servers(doc: dict) -> tuple[dict[str, dict], dict[str, str]]:
    section = doc.get("servers")
    if not isinstance(section, dict):
        section = doc.get("mcpServers")
    if not isinstance(section, dict):
        return {}, {}
    servers: dict[str, dict] = {}
    transports: dict[str, str] = {}
    for name, entry in section.items():
        if not isinstance(entry, dict):
            continue
        servers[name] = _normalise_entry(entry, entry.get("command"), entry.get("args"))
        declared = str(entry.get("type", "")).lower()
        if declared in _TRANSPORT_ALIASES:
            transports[name] = _TRANSPORT_ALIASES[declared]
    return servers, transports


_READERS = {
    MCPTOON_CLIENT: _mcptoon_servers,
    ONEMCP_CLIENT: _onemcp_servers,
    MCPHUB_CLIENT: _mcphub_servers,
}


def read_gateway_servers(path: Path, client: str) -> GatewayServers:
    """Read the upstream servers from one gateway config file.

    Args:
        path: The gateway config file.
        client: One of :data:`GATEWAY_UPSTREAM_CLIENTS`; picks the format.

    Returns:
        The servers, at most :data:`GATEWAY_MAX_SERVERS` of them (the rest are
        named in ``warnings``).

    Raises:
        ValueError: The file cannot be read or parsed (the caller records the
            message in ``result.errors``).
    """
    doc = _load_document(path)
    servers, transports = _READERS[client](doc)
    warnings: list[str] = []
    if len(servers) > GATEWAY_MAX_SERVERS:
        skipped = len(servers) - GATEWAY_MAX_SERVERS
        servers = dict(list(servers.items())[:GATEWAY_MAX_SERVERS])
        warnings.append(
            f"Gateway config {path}: {skipped} server(s) past the first"
            f" {GATEWAY_MAX_SERVERS} were not analysed. Review them by hand."
        )
    return GatewayServers(
        servers=servers, transports=transports, raw=doc, warnings=warnings
    )
