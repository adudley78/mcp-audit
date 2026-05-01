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
import os
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
    "MCP SDK not installed. Run: pip install 'mcp-audit[mcp]'  or  pip install mcp"
)


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
        return ServerEnumeration(error=MCP_NOT_INSTALLED)

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
    captured_stderr: str | None = None
    with tempfile.TemporaryFile(mode="w+b") as stderr_buf:
        try:
            async with (
                stdio_client_fn(params, errlog=stderr_buf) as (read, write),
                client_session_cls(read, write) as session,
            ):
                result = await _collect(session)
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
                    result = await _collect(session)
            except Exception:  # noqa: BLE001
                # Last resort: call without any stderr override.
                async with (
                    stdio_client_fn(params) as (read, write),
                    client_session_cls(read, write) as session,
                ):
                    result = await _collect(session)

        # Read whatever the subprocess wrote to stderr (may be empty).
        try:
            stderr_buf.seek(0)
            raw_bytes = stderr_buf.read()
            if raw_bytes:
                captured_stderr = raw_bytes.decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001, S110
            pass

    return ServerEnumeration(
        tools=result.tools,
        resources=result.resources,
        prompts=result.prompts,
        error=result.error,
        server_stderr=captured_stderr or None,
    )


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


async def _collect(session: Any) -> ServerEnumeration:
    """Initialize a session and call list_tools / list_resources / list_prompts.

    Each list call is attempted independently — partial results are returned
    when a server supports only a subset of the MCP capabilities.

    Args:
        session: An initialized :class:`mcp.ClientSession`.

    Returns:
        :class:`~mcp_audit.models.ServerEnumeration` with whatever the server
        reported.
    """
    await session.initialize()

    tools: list[ToolInfo] = []
    resources: list[ResourceInfo] = []
    prompts: list[PromptInfo] = []

    try:
        resp = await session.list_tools()
        for t in resp.tools:
            tools.append(
                ToolInfo(
                    name=t.name,
                    description=getattr(t, "description", None),
                    input_schema=dict(getattr(t, "inputSchema", {})),
                )
            )
    except Exception:  # noqa: BLE001, S110
        pass  # Server may not implement tools capability.

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

    return ServerEnumeration(tools=tools, resources=resources, prompts=prompts)
