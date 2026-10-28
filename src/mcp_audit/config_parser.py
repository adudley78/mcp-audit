"""Parse MCP configuration files into structured ServerConfig objects."""

from __future__ import annotations

import datetime
import json
import os
import tomllib
from pathlib import Path

from mcp_audit.discovery import (
    AGENT_DEFINITION_CLIENT,
    CODEX_ROOT_KEY,
    DiscoveredConfig,
)
from mcp_audit.models import ServerConfig, TransportType

#: ``DiscoveredConfig.dialect`` values (STORY-0110).
CODEX_DIALECT = "codex"
GEMINI_DIALECT = "gemini"

#: Largest Codex ``config.toml`` or Gemini CLI ``settings.json`` that is read.
#: A larger file is reported in ``result.errors`` (not read), never skipped
#: silently.  Real files are a few KiB.
SETTINGS_MAX_BYTES = 4 * 1024 * 1024


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

    Handles the VS Code 'servers' vs 'mcpServers' key difference, Codex's
    TOML ``config.toml`` and Gemini CLI's ``settings.json`` (see
    :func:`config_dialect`).

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
    if config.client_name == AGENT_DEFINITION_CLIENT:
        return _parse_agent_definition(config)
    dialect = config_dialect(config)
    if dialect == CODEX_DIALECT:
        return _parse_codex_config(config)
    if dialect == GEMINI_DIALECT:
        return _parse_gemini_settings(config)

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

    return _servers_from_dict(servers_dict, config)


def _parse_agent_definition(config: DiscoveredConfig) -> list[ServerConfig]:
    """Parse a Claude Code subagent definition (STORY-0094).

    ``config.raw`` becomes the definition record
    (:meth:`~mcp_audit.agent_files.subagents.AgentFrontmatter.to_record`: every
    reading of the frontmatter plus repeated and unreadable security keys), so
    the config-level checks at pipeline step 0 see all of it. The servers are
    one per inline ``mcpServers`` item across all readings (a repeated name is
    kept as ``name#2``…), coerced to the string types a JSON config would
    carry. Notes about frontmatter that could not be read go to
    ``config.parse_warnings`` rather than being raised, so whatever did parse
    is still checked.

    Raises:
        ValueError: If the file cannot be read.
    """
    from mcp_audit.agent_files.subagents import (  # noqa: PLC0415
        agent_mcp_servers,
        normalize_server_entry,
        read_agent_definition,
        redact_secrets,
    )

    try:
        parsed = read_agent_definition(config.path)
    except OSError as e:
        raise ValueError(f"Cannot read {config.path}: {e}") from e
    config.raw = parsed.to_record()
    config.parse_warnings = [
        redact_secrets(
            problem
            if problem.startswith("Subagent definition ")
            else f"Subagent definition {config.path}: {problem}. Claude Code's own"
            " parser may still load it; review it by hand."
        )
        for problem in parsed.problems
    ]
    servers_dict = {
        display: normalize_server_entry(spec)
        for display, _declared, spec in agent_mcp_servers(parsed)
    }
    return _servers_from_dict(servers_dict, config)


def _servers_from_dict(
    servers_dict: dict, config: DiscoveredConfig
) -> list[ServerConfig]:
    """Build :class:`ServerConfig` objects from a ``{name: entry}`` mapping."""
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


# ── Codex and Gemini CLI (STORY-0110) ─────────────────────────────────────────


def config_dialect(config: DiscoveredConfig) -> str | None:
    """Return how *config* is read: ``"codex"``, ``"gemini"`` or ``None`` (JSON).

    Discovery sets ``config.dialect`` for the files it finds.  For an explicit
    ``--path`` (client ``custom``) or a ``diff`` input, the path decides: any
    ``.toml`` file is read as Codex's ``config.toml``, and a ``settings.json``
    whose directory is ``.gemini`` as Gemini CLI's settings.
    """
    if config.dialect is not None:
        return config.dialect
    if config.path.suffix.lower() == ".toml":
        return CODEX_DIALECT
    if config.path.name == "settings.json" and config.path.parent.name == ".gemini":
        return GEMINI_DIALECT
    return None


def _read_settings_text(path: Path) -> str:
    """Read a Codex or Gemini CLI settings file, size-capped, BOM stripped.

    Raises:
        ValueError: The file cannot be read, is not UTF-8, or is larger than
            :data:`SETTINGS_MAX_BYTES` (the caller records the message in
            ``result.errors``).
    """
    try:
        size = os.stat(path).st_size
    except OSError as e:
        raise ValueError(f"Cannot read {path}: {e}") from e
    if size > SETTINGS_MAX_BYTES:
        raise ValueError(
            f"{path} is {size} bytes, over mcp-audit's {SETTINGS_MAX_BYTES}-byte"
            " limit for a settings file; it was not read. Review it by hand."
        )
    try:
        with path.open("rb") as handle:
            data = handle.read(SETTINGS_MAX_BYTES + 1)
    except OSError as e:
        raise ValueError(f"Cannot read {path}: {e}") from e
    if len(data) > SETTINGS_MAX_BYTES:
        raise ValueError(
            f"{path} is over mcp-audit's {SETTINGS_MAX_BYTES}-byte limit for a"
            " settings file; it was not read. Review it by hand."
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{path} is not UTF-8 text: {e}") from e
    return text.removeprefix("\ufeff")


def _json_safe(value: object) -> object:
    """Convert parsed TOML into JSON-serialisable values.

    TOML has date and time values JSON does not; ``raw`` is hashed with
    ``json.dumps`` (rug-pull) and written to JSON output, so they become ISO
    8601 strings.  Keys become strings.
    """
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, datetime.date | datetime.time):
        return value.isoformat()
    return value


def _as_text(value: object) -> str | None:
    """A scalar config value as text; ``None`` for a missing or structured value."""
    if value is None or isinstance(value, dict | list):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime.date | datetime.time):
        return value.isoformat()
    return str(value)


def _text_list(value: object) -> list[str]:
    """The scalar items of a list, as text (structured items are dropped)."""
    if not isinstance(value, list):
        return []
    return [text for text in (_as_text(item) for item in value) if text is not None]


def _text_dict(value: object) -> dict[str, str]:
    """The scalar values of a table, as text, keyed by the table's keys."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for key, item in value.items():
        text = _as_text(item)
        if text is not None:
            out[str(key)] = text
    return out


def _parse_codex_config(config: DiscoveredConfig) -> list[ServerConfig]:
    """Parse Codex's ``config.toml``: one server per ``[mcp_servers.<name>]`` table.

    Keys follow Codex's own ``RawMcpServerConfig`` (``codex-rs/config/src/
    mcp_types.rs``): ``command`` makes a stdio server (``args``, ``env``,
    ``cwd``; ``env_vars`` lists variable *names* to pass through), otherwise
    ``url`` makes a streamable-HTTP server.  Headers are gathered from
    ``http_headers`` (literal values), ``env_http_headers`` (header -> variable
    name, recorded as ``${NAME}``), ``bearer_token_env_var`` (recorded as
    ``Authorization: Bearer ${NAME}``) and the retired literal ``bearer_token``
    (which Codex now refuses, but which is still a secret in the file).  Every
    field is kept as written: an entry Codex would refuse (both ``command``
    and ``url``) or has switched off (``enabled = false``) is still analysed,
    because one edit makes it live.

    Raises:
        ValueError: The file cannot be read or is not valid TOML.
    """
    text = _read_settings_text(config.path)
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as e:
        raise ValueError(f"Invalid TOML in {config.path}: {e}") from e
    config.raw = _json_safe(data)  # type: ignore[assignment]
    tables = data.get(CODEX_ROOT_KEY)
    if not isinstance(tables, dict):
        return []
    servers: list[ServerConfig] = []
    for name, entry in tables.items():
        if not isinstance(entry, dict):
            continue
        command = _as_text(entry.get("command"))
        url = _as_text(entry.get("url"))
        headers = _text_dict(entry.get("http_headers"))
        for header, variable in _text_dict(entry.get("env_http_headers")).items():
            headers.setdefault(header, f"${{{variable}}}")
        token_variable = _as_text(entry.get("bearer_token_env_var"))
        literal_token = _as_text(entry.get("bearer_token"))
        if literal_token:
            headers["Authorization"] = f"Bearer {literal_token}"
        elif token_variable:
            headers.setdefault("Authorization", f"Bearer ${{{token_variable}}}")
        env = _text_dict(entry.get("env"))
        # ``env_vars``: names of variables Codex passes through from its own
        # environment (strings, or tables with ``name``).  Recorded as
        # references so lock and rug-pull see which variables reach the server.
        env_vars = entry.get("env_vars")
        for item in env_vars if isinstance(env_vars, list) else []:
            var = item.get("name") if isinstance(item, dict) else item
            if isinstance(var, str) and var:
                env.setdefault(var, f"${{{var}}}")
        if command:
            transport = TransportType.STDIO
        elif url:
            # Codex's only remote transport is streamable HTTP (no SSE).
            transport = TransportType.STREAMABLE_HTTP
        else:
            transport = TransportType.UNKNOWN
        servers.append(
            _server(
                str(name),
                config,
                transport=transport,
                command=command,
                args=_text_list(entry.get("args")),
                env=env,
                url=url,
                headers=headers,
                raw=_json_safe(entry),  # type: ignore[arg-type]
            )
        )
    return servers


def _strip_json_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments outside strings, as Gemini CLI does.

    Gemini CLI reads ``settings.json`` with ``JSON.parse(stripJsonComments(
    content))`` (``packages/cli/src/config/settings.ts``): comments are
    allowed, trailing commas are not.  Linear, string-aware scan.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escape = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            # An unterminated block comment runs to the end, as in
            # strip-json-comments; whitespace keeps JSON error positions sane.
            i = n if end == -1 else end + 2
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_gemini_settings(config: DiscoveredConfig) -> list[ServerConfig]:
    """Parse Gemini CLI's ``settings.json`` (``mcpServers``).

    Comments are allowed and trailing commas are not, as in Gemini CLI.  The
    transport follows Gemini CLI's own order (``packages/core/src/tools/
    mcp-client.ts``): ``httpUrl`` (streamable HTTP) wins, then ``url`` with
    ``type`` ``"http"`` or ``"sse"``, then ``url`` alone, then ``command``
    (stdio).  The command of an entry that also has a URL never runs, but it
    is still analysed (the stricter reading: one edit makes it live).

    Raises:
        ValueError: The file cannot be read or is not valid JSON.
    """
    text = _read_settings_text(config.path)
    try:
        data = json.loads(_strip_json_comments(text))
    except (json.JSONDecodeError, RecursionError) as e:
        raise ValueError(f"Invalid JSON in {config.path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(
            f"Expected JSON object in {config.path}, got {type(data).__name__}"
        )
    config.raw = data
    entries = data.get("mcpServers")
    if not isinstance(entries, dict):
        return []
    servers: list[ServerConfig] = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        command = _as_text(entry.get("command"))
        http_url = _as_text(entry.get("httpUrl"))
        url = _as_text(entry.get("url"))
        declared = entry.get("type")
        if http_url:
            transport, effective_url = TransportType.STREAMABLE_HTTP, http_url
        elif url:
            effective_url = url
            if declared == "sse":
                transport = TransportType.SSE
            elif declared == "http":
                transport = TransportType.STREAMABLE_HTTP
            else:
                transport = _detect_transport({"url": url})
        else:
            effective_url = None
            transport = TransportType.STDIO if command else TransportType.UNKNOWN
        servers.append(
            _server(
                str(name),
                config,
                transport=transport,
                command=command,
                args=_text_list(entry.get("args")),
                env=_text_dict(entry.get("env")),
                url=effective_url,
                headers=_text_dict(entry.get("headers")),
                raw=entry,
            )
        )
    return servers


def _server(
    name: str,
    config: DiscoveredConfig,
    *,
    transport: TransportType,
    command: str | None,
    args: list[str],
    env: dict[str, str],
    url: str | None,
    headers: dict[str, str],
    raw: dict,
) -> ServerConfig:
    """Build one :class:`ServerConfig` from already-normalised fields."""
    capabilities = raw.get("capabilities")
    return ServerConfig(
        name=name,
        client=config.client_name,
        config_path=config.path,
        transport=transport,
        command=command,
        args=args,
        env=env,
        url=url,
        headers=headers,
        raw=raw,
        capabilities=capabilities if isinstance(capabilities, dict) else None,
        is_project_scoped=config.is_project_scoped,
    )
