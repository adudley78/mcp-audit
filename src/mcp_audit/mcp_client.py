"""MCP client for live server enumeration via protocol handshake.

Connects to running MCP servers, performs the MCP initialization handshake, and
enumerates tools, resources, and prompts — the actual attack surface seen by AI
agents at runtime.  This reveals poisoned tool descriptions that look clean in
static config files.

The ``mcp`` package is an optional dependency.  If it is not installed,
:func:`connect_and_enumerate` returns a :class:`~mcp_audit.models.ServerEnumeration`
with the ``error`` field set and a helpful installation message.

Usage::

    enumeration = await connect_and_enumerate(server, timeout=10.0)
    if enumeration.error:
        print(f"Could not connect: {enumeration.error}")
    else:
        for tool in enumeration.tools:
            print(tool.name, tool.description)

Auth tokens::

    # For SSE/HTTP servers that require Bearer auth:
    enumeration = await connect_and_enumerate(
        server, timeout=10.0, auth_token="my-secret-token"
    )
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import sys
import tempfile
from typing import Any

from mcp_audit.models import (
    PromptInfo,
    ResourceInfo,
    ServerConfig,
    ServerEnumeration,
    ToolInfo,
    TransportType,
)

# Only these host environment variables are forwarded to MCP server
# subprocesses.  Everything else (AWS keys, tokens, etc.) is withheld
# to prevent leakage to potentially untrusted servers.
SAFE_ENV_VARS: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "TERM",
        "SHELL",
        "USER",
        "TMPDIR",
        "NODE_PATH",
        "NODE_OPTIONS",
    }
)

# Shown to the user when the optional mcp package is absent.
MCP_NOT_INSTALLED = (
    "MCP SDK not installed. Run: pip install 'mcp-audit-scanner[mcp]' "
    "or pip install mcp"
)
# Standalone binary: pip-installing into the frozen artifact is not possible.
# See the four *.spec files — `mcp` is excluded the same way `sigstore` is.
MCP_NOT_INSTALLED_FROZEN = (
    "MCP SDK is not bundled in the standalone binary. "
    "Live --connect requires a pip install of mcp-audit-scanner with the mcp extra."
)


def _mcp_missing_message() -> str:
    """Return the install hint appropriate for pip vs the frozen binary."""
    if getattr(sys, "frozen", False):
        return MCP_NOT_INSTALLED_FROZEN
    return MCP_NOT_INSTALLED


async def connect_and_enumerate(
    server: ServerConfig,
    timeout: float = 10.0,
    auth_token: str | None = None,
) -> ServerEnumeration:
    """Connect to a running MCP server and enumerate its exposed interface.

    Always returns a :class:`~mcp_audit.models.ServerEnumeration` — never raises.
    When connection or enumeration fails, the returned object has ``error`` set
    and empty tool/resource/prompt lists.

    Args:
        server: The server configuration describing how to reach the server.
        timeout: Per-server timeout in seconds (default 10).  Servers that do
            not complete the handshake within this window are skipped with an
            error finding.
        auth_token: Bearer token to pass as ``Authorization: Bearer <token>``
            on SSE/HTTP connections.  Silently ignored for stdio servers (which
            do not use HTTP auth).  Never stored or logged.

    Returns:
        :class:`~mcp_audit.models.ServerEnumeration` with discovered interface
        or an ``error`` string on failure.
    """
    try:
        return await asyncio.wait_for(
            _enumerate(server, auth_token=auth_token), timeout=timeout
        )
    except TimeoutError:
        return ServerEnumeration(error=f"Connection timed out after {timeout:.0f}s")
    except Exception as exc:  # noqa: BLE001
        return ServerEnumeration(error=f"Enumeration failed: {exc}")


def build_runtime_server_config(
    server: ServerConfig,
    enumeration: ServerEnumeration,
) -> ServerConfig | None:
    """Build a synthetic :class:`~mcp_audit.models.ServerConfig` from live data.

    Embeds enumerated tool descriptions into the ``raw`` field so that the
    :class:`~mcp_audit.analyzers.poisoning.PoisoningAnalyzer` can inspect what
    the AI agent actually sees — without any modifications to the analyzer itself.

    Returns ``None`` when the enumeration is empty (nothing to analyze).

    Args:
        server: The original static server configuration.
        enumeration: Live data returned by :func:`connect_and_enumerate`.

    Returns:
        A synthetic :class:`~mcp_audit.models.ServerConfig` whose ``raw`` field
        contains the tool/resource/prompt data, or ``None`` if all lists are empty.
    """
    if not enumeration.tools and not enumeration.resources and not enumeration.prompts:
        return None

    raw: dict = {
        "tools": [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.input_schema,
            }
            for t in enumeration.tools
        ],
        "resources": [
            {
                "uri": r.uri,
                "name": r.name or "",
                "description": r.description or "",
            }
            for r in enumeration.resources
        ],
        "prompts": [
            {
                "name": p.name,
                "description": p.description or "",
            }
            for p in enumeration.prompts
        ],
    }

    return ServerConfig(
        name=f"{server.name}:runtime",
        client=server.client,
        config_path=server.config_path,
        transport=server.transport,
        command=server.command,
        args=server.args,
        env=server.env,
        url=server.url,
        raw=raw,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


async def _enumerate(
    server: ServerConfig,
    auth_token: str | None = None,
) -> ServerEnumeration:
    """Dispatch to the appropriate transport and collect enumeration data."""
    try:
        from mcp import ClientSession  # type: ignore[import-untyped]
        from mcp.client.sse import sse_client  # type: ignore[import-untyped]
        from mcp.client.stdio import (  # type: ignore[import-untyped]
            StdioServerParameters,
            stdio_client,
        )
    except ImportError:
        return ServerEnumeration(error=_mcp_missing_message())

    if server.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP):
        return await _enumerate_sse(
            server, ClientSession, sse_client, auth_token=auth_token
        )
    if server.transport == TransportType.STDIO:
        return await _enumerate_stdio(
            server, ClientSession, stdio_client, StdioServerParameters
        )
    return ServerEnumeration(
        error=f"Transport {server.transport!r} does not support live enumeration"
    )


async def _enumerate_stdio(
    server: ServerConfig,
    client_session_cls: Any,
    stdio_client_fn: Any,
    params_cls: Any,
) -> ServerEnumeration:
    """Connect to a stdio MCP server and enumerate its interface.

    Server stderr is captured into a temporary file so it does not leak into
    the mcp-audit terminal output.  The captured text is returned in
    :attr:`~mcp_audit.models.ServerEnumeration.server_stderr` for optional
    display (e.g. via ``--verbose``).

    ``auth_token`` is silently ignored for stdio servers — they do not use
    HTTP auth.
    """
    if not server.command:
        return ServerEnumeration(error="Stdio server has no command configured")

    # Build a minimal env from the allowlist, then overlay server-specific vars.
    # This prevents leaking the user's full environment to untrusted servers.
    env = {k: v for k, v in os.environ.items() if k in SAFE_ENV_VARS}
    env.update(server.env)
    params = params_cls(command=server.command, args=server.args, env=env)

    # Capture stderr to a real temporary file so:
    # (a) it never leaks to the user's terminal, and
    # (b) we can surface it in --verbose mode.
    # We use a TemporaryFile (real fd) because asyncio's subprocess machinery
    # requires an object with a valid fileno().
    raw_stderr: bytes = b""
    failure: Exception | None = None
    result: ServerEnumeration | None = None
    with tempfile.TemporaryFile(mode="w+b") as stderr_buf:
        try:
            result = await _run_stdio_session(
                server,
                env,
                params,
                params_cls,
                client_session_cls,
                stdio_client_fn,
                stderr_buf,
            )
        except Exception as exc:  # noqa: BLE001
            # A server that dies during the handshake surfaces here, wrapped
            # in anyio's TaskGroup ExceptionGroup (Q-014).  Keep it, so the
            # captured stderr below can say why.
            failure = exc
        finally:
            # Read whatever the subprocess wrote to stderr (may be empty),
            # also when the handshake failed: that is when it matters most.
            raw_stderr = _read_stderr_tail(stderr_buf)

    captured_stderr = (
        redact_server_text(
            raw_stderr.decode("utf-8", errors="replace").strip(),
            server.env.values(),
            server.args,
        )
        if raw_stderr
        else None
    )

    if failure is not None or result is None:
        reason = (
            redact_server_text(
                describe_exception(failure), server.env.values(), server.args
            )
            if failure is not None
            else "no result"
        )
        error = f"Enumeration failed: {reason}"
        last = _last_line(captured_stderr)
        if last:
            error += f" (server stderr: {last})"
        return ServerEnumeration(error=error, server_stderr=captured_stderr or None)

    return ServerEnumeration(
        tools=result.tools,
        resources=result.resources,
        prompts=result.prompts,
        error=result.error,
        server_stderr=captured_stderr or None,
        tools_error=result.tools_error,
    )


async def _run_stdio_session(
    server: ServerConfig,
    env: dict[str, str],
    params: Any,
    params_cls: Any,
    client_session_cls: Any,
    stdio_client_fn: Any,
    stderr_buf: Any,
) -> ServerEnumeration:
    """Open the stdio session (with the SDK-version fallbacks) and collect."""
    try:
        async with (
            stdio_client_fn(params, errlog=stderr_buf) as (read, write),
            client_session_cls(read, write) as session,
        ):
            return await _collect(session)
    except TypeError:
        # SDK version does not support the errlog parameter — fall back to
        # capturing via StdioServerParameters.stderr when available, otherwise
        # accept that stderr may briefly appear in the terminal.
        try:
            import subprocess  # noqa: PLC0415

            params_with_pipe = params_cls(
                command=server.command,
                args=server.args,
                env=env,
                stderr=subprocess.PIPE,
            )
            async with (
                stdio_client_fn(params_with_pipe) as (read, write),
                client_session_cls(read, write) as session,
            ):
                return await _collect(session)
        except Exception:  # noqa: BLE001
            # Last resort: call without any stderr override.
            async with (
                stdio_client_fn(params) as (read, write),
                client_session_cls(read, write) as session,
            ):
                return await _collect(session)


# Most server stderr kept for an error message or --verbose (the tail: the
# reason a server exits is usually its last words).
_MAX_STDERR_BYTES = 64 * 1024
# Longest stderr line quoted inside a connect error message.
_MAX_STDERR_LINE = 300
_REDACTED = "[REDACTED]"
# An env value shorter than this is not redacted by value: "1", "true" or
# "dev" would blank out ordinary words.  Real secrets are longer.
_MIN_REDACTED_ENV_VALUE = 8


def _read_stderr_tail(stderr_buf: Any) -> bytes:
    """Return at most the last ``_MAX_STDERR_BYTES`` written to *stderr_buf*."""
    try:
        size = stderr_buf.seek(0, os.SEEK_END)
        stderr_buf.seek(max(0, size - _MAX_STDERR_BYTES))
        data = stderr_buf.read()
    except (OSError, ValueError):
        return b""
    return data if isinstance(data, bytes) else b""


def describe_exception(exc: BaseException) -> str:
    """Return a readable message for *exc*, unwrapping exception groups.

    The MCP SDK runs the stdio transport in an anyio TaskGroup, so a server
    that exits during the handshake reaches us as "unhandled errors in a
    TaskGroup (1 sub-exception)" (Q-014).  The first leaf exception is the
    one that says what happened.

    Args:
        exc: The exception raised while connecting.

    Returns:
        ``"<Type>: <message>"`` for the first non-group exception, or just
        the type name when it has no message.
    """
    leaf: BaseException = exc
    for _ in range(32):  # groups nest; never loop on a pathological chain
        if isinstance(leaf, BaseExceptionGroup) and leaf.exceptions:
            leaf = leaf.exceptions[0]
        else:
            break
    message = str(leaf).strip()
    return f"{type(leaf).__name__}: {message}" if message else type(leaf).__name__


def redact_server_text(
    text: str, env_values: Any = (), args: list[str] | None = None
) -> str:
    """Redact secrets from text a server process produced (stderr, errors).

    Server output is shown to the user and written into scan results, and a
    server that fails to start often prints the value it rejected.  Passes,
    each linear: the server's own secrets first, by value (every ``env``
    value and every value of a secret-named flag in its ``args``,
    ``supply_chain.secret_arg_values``, at least ``_MIN_REDACTED_ENV_VALUE``
    characters long), so a pattern match cannot leave part of one behind;
    then every ``SECRET_PATTERNS`` match; then the userinfo of every
    ``scheme://user:pass@host`` on each line.

    Args:
        text: The text to clean.
        env_values: The values of the server's configured ``env``.
        args: The server's launch arguments.

    Returns:
        The text with secrets replaced by ``[REDACTED]``.
    """
    # Imported lazily: the analyzers are not otherwise needed by the client.
    from mcp_audit.analyzers.credentials import SECRET_PATTERNS  # noqa: PLC0415
    from mcp_audit.analyzers.supply_chain import (  # noqa: PLC0415
        _redact_userinfo,
        secret_arg_values,
    )

    candidates = [v for v in env_values if isinstance(v, str)]
    candidates.extend(secret_arg_values(list(args or [])))
    values = sorted(
        {v for v in candidates if len(v) >= _MIN_REDACTED_ENV_VALUE},
        key=len,
        reverse=True,
    )
    cleaned = text
    for value in values:
        cleaned = cleaned.replace(value, _REDACTED)
    for _label, pattern, _provider in SECRET_PATTERNS:
        cleaned = pattern.sub(_REDACTED, cleaned)
    return "\n".join(_redact_userinfo(line) for line in cleaned.split("\n"))


def _last_line(text: str | None) -> str:
    """Return the last non-empty line of *text*, truncated for an error message."""
    if not text:
        return ""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line:
            if len(line) > _MAX_STDERR_LINE:
                return line[:_MAX_STDERR_LINE] + "..."
            return line
    return ""


async def _enumerate_sse(
    server: ServerConfig,
    client_session_cls: Any,
    sse_client_fn: Any,
    auth_token: str | None = None,
) -> ServerEnumeration:
    """Connect to an SSE/HTTP MCP server and enumerate its interface.

    When *auth_token* is provided, it is sent as ``Authorization: Bearer <token>``
    on every HTTP request.  The token is never stored or logged.

    A 401 or 403 response is translated into a clear, actionable error message
    rather than a raw exception traceback.
    """
    if not server.url:
        return ServerEnumeration(error="SSE server has no URL configured")

    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        async with (
            sse_client_fn(url=server.url, headers=headers or None) as (read, write),
            client_session_cls(read, write) as session,
        ):
            return await _collect(session)
    except Exception as exc:  # noqa: BLE001
        return _classify_sse_error(exc, server.url)


def _classify_sse_error(exc: Exception, url: str) -> ServerEnumeration:
    """Convert an SSE connection exception into a user-friendly error enumeration.

    Detects HTTP 401/403 responses and returns an actionable message instead
    of a raw traceback.  All other exceptions are surfaced as-is.

    Args:
        exc: The exception raised during SSE connection or enumeration.
        url: The server URL (used in the error message).

    Returns:
        :class:`~mcp_audit.models.ServerEnumeration` with ``error`` set.
    """
    exc_str = str(exc)
    exc_type = type(exc).__name__

    # Try to extract an HTTP status code from the exception.
    # httpx.HTTPStatusError carries it at exc.response.status_code.
    status_code: int | None = None
    with contextlib.suppress(AttributeError):
        status_code = exc.response.status_code  # type: ignore[union-attr]

    # Fall back to scanning the string representation for common patterns.
    if status_code is None:
        for code in (401, 403):
            if str(code) in exc_str:
                status_code = code
                break

    if status_code == 401:
        return ServerEnumeration(
            error=(
                f"Connection to {url} failed: 401 Unauthorized — "
                "use --connect-token to provide credentials"
            )
        )
    if status_code == 403:
        return ServerEnumeration(
            error=(
                f"Connection to {url} failed: 403 Forbidden — "
                "the provided token may lack the required permissions"
            )
        )

    return ServerEnumeration(error=f"SSE connection failed ({exc_type}): {exc_str}")


#: Upper bound on ``tools/list`` pages read from one server. A server that
#: keeps returning a cursor past this is reported via ``tools_error`` rather
#: than looped on forever.
_MAX_TOOL_PAGES = 100


def _str_or_none(value: Any) -> str | None:
    """Return *value* when it is a string, else ``None``."""
    return value if isinstance(value, str) else None


def _dict_or_none(value: Any) -> dict | None:
    """Return a copy of *value* when it is a dict, else ``None``."""
    return dict(value) if isinstance(value, dict) else None


def _wire(obj: Any) -> dict:
    """Return *obj* as the server sent it, in MCP wire format.

    The SDK's pydantic models dump to the protocol's own camelCase keys with
    ``by_alias=True``; ``exclude_unset=True`` keeps only the fields the server
    actually sent, so an SDK upgrade that adds a default never changes what a
    digest is computed over. Returns ``{}`` for anything that is not a
    pydantic model (very old SDKs, test doubles).
    """
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            data = dump(by_alias=True, exclude_unset=True, mode="json")
        except Exception:  # noqa: BLE001
            data = None
        if isinstance(data, dict):
            return data
    return {}


def _tool_info(tool: Any) -> ToolInfo:
    """Build a :class:`ToolInfo` from one SDK tool object.

    Reads the wire-format dump first. ``mcp`` 2.x renamed the Python
    attribute to ``input_schema`` (alias ``inputSchema``), so the old
    ``getattr(t, "inputSchema")`` silently returned nothing on 2.x and live
    input schemas never reached the poisoning analyzer.
    """
    wire = _wire(tool)
    if wire:
        schema = wire.get("inputSchema")
        return ToolInfo(
            name=str(wire.get("name", getattr(tool, "name", ""))),
            title=_str_or_none(wire.get("title")),
            description=_str_or_none(wire.get("description")),
            input_schema=dict(schema) if isinstance(schema, dict) else {},
            output_schema=_dict_or_none(wire.get("outputSchema")),
            annotations=_dict_or_none(wire.get("annotations")),
        )
    schema = getattr(tool, "inputSchema", None)
    if not isinstance(schema, dict):
        schema = getattr(tool, "input_schema", None)
    output_schema = getattr(tool, "outputSchema", None)
    if not isinstance(output_schema, dict):
        output_schema = getattr(tool, "output_schema", None)
    return ToolInfo(
        name=tool.name,
        title=_str_or_none(getattr(tool, "title", None)),
        description=_str_or_none(getattr(tool, "description", None)),
        input_schema=dict(schema) if isinstance(schema, dict) else {},
        output_schema=_dict_or_none(output_schema),
        annotations=_dict_or_none(getattr(tool, "annotations", None)),
    )


def _next_cursor(resp: Any) -> str | None:
    """Return the pagination cursor of a list result, or ``None`` on the last page."""
    for attr in ("next_cursor", "nextCursor"):
        value = getattr(resp, attr, None)
        if isinstance(value, str) and value:
            return value
    return None


async def _list_tools_page(session: Any, cursor: str) -> Any | None:
    """Request the ``tools/list`` page after *cursor*.

    ``mcp`` 2.x takes ``params=PaginatedRequestParams(cursor=...)``; later
    1.x releases take ``cursor=``; the earliest 1.x releases cannot paginate
    at all, in which case this returns ``None``.
    """
    try:
        accepted = inspect.signature(session.list_tools).parameters
    except (TypeError, ValueError):
        accepted = {}
    if "params" in accepted:
        from mcp import types as mcp_types  # noqa: PLC0415

        return await session.list_tools(
            params=mcp_types.PaginatedRequestParams(cursor=cursor)
        )
    if "cursor" in accepted:
        return await session.list_tools(cursor=cursor)
    return None


async def _list_all_tools(session: Any) -> tuple[list[Any], str | None]:
    """Read every ``tools/list`` page.

    Returns:
        ``(tools, problem)``. *problem* is ``None`` when the last page was
        reached, otherwise a sentence saying why the list may be incomplete.
    """
    resp = await session.list_tools()
    tools = list(resp.tools)
    cursor = _next_cursor(resp)
    pages = 1
    while cursor is not None:
        if pages >= _MAX_TOOL_PAGES:
            return tools, (
                f"tools/list returned more than {_MAX_TOOL_PAGES} pages; "
                "stopped reading"
            )
        resp = await _list_tools_page(session, cursor)
        if resp is None:
            return tools, (
                "the server paginates tools/list and this version of the mcp "
                "package cannot request later pages; upgrade it"
            )
        tools.extend(resp.tools)
        cursor = _next_cursor(resp)
        pages += 1
    return tools, None


def _declares_tools(init_result: Any) -> bool | None:
    """Whether the server's ``initialize`` result declares the tools capability.

    ``None`` when the result does not say (very old SDKs, test doubles).
    """
    caps = getattr(init_result, "capabilities", None)
    if caps is None or not hasattr(caps, "tools"):
        return None
    return caps.tools is not None


async def _collect(session: Any) -> ServerEnumeration:
    """Initialize a session and call list_tools / list_resources / list_prompts.

    Each list call is attempted independently — partial results are returned
    when a server supports only a subset of the MCP capabilities. Every
    ``tools/list`` page is read. When the server declares tools but the list
    could not be read in full, ``tools_error`` says why, so a caller never
    mistakes a failed read for "this server has no tools".

    Args:
        session: An initialized :class:`mcp.ClientSession`.

    Returns:
        :class:`~mcp_audit.models.ServerEnumeration` with whatever the server
        reported.
    """
    init_result = await session.initialize()

    tools: list[ToolInfo] = []
    resources: list[ResourceInfo] = []
    prompts: list[PromptInfo] = []
    tools_error: str | None = None

    try:
        raw_tools, tools_error = await _list_all_tools(session)
        tools = [_tool_info(t) for t in raw_tools]
    except Exception as exc:  # noqa: BLE001
        # A server that does not declare tools legitimately has none.
        if _declares_tools(init_result) is not False:
            tools_error = f"tools/list failed: {exc}"

    try:
        resp = await session.list_resources()
        for r in resp.resources:
            resources.append(
                ResourceInfo(
                    uri=str(r.uri),
                    name=getattr(r, "name", None),
                    description=getattr(r, "description", None),
                )
            )
    except Exception:  # noqa: BLE001, S110
        pass  # Server may not implement resources capability.

    try:
        resp = await session.list_prompts()
        for p in resp.prompts:
            prompts.append(
                PromptInfo(
                    name=p.name,
                    description=getattr(p, "description", None),
                )
            )
    except Exception:  # noqa: BLE001, S110
        pass  # Server may not implement prompts capability.

    return ServerEnumeration(
        tools=tools,
        resources=resources,
        prompts=prompts,
        tools_error=tools_error,
    )
