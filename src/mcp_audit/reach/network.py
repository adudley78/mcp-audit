"""Which of an agent's MCP servers can reach the network (question 3).

Uses the same capability tagging the toxic-flow analyzer uses
(:func:`mcp_audit.analyzers.toxic_flow.tag_server` with the shared registry),
so ``reach`` and TOXIC-* never disagree about what a server can do.  A server
reaches the network when it is tagged ``NETWORK_OUT`` or ``COMMS_OUT`` or is
remote (an ``http``/``sse`` transport or a URL).  A stdio server with no tag at
all is *unclassified*: nothing says it cannot reach the network, so the
network question is COULDN'T CHECK for it, never "none".
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp_audit.analyzers import secret_reach
from mcp_audit.analyzers.supply_chain import resolve_launch_entry
from mcp_audit.analyzers.toxic_flow import Capability, tag_server
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.reach.context import Env
from mcp_audit.reach.surface import launch_tail, path_candidates, server_env_declared

_NETWORK_CAPS = frozenset(
    {
        Capability.NETWORK_OUT,
        Capability.COMMS_OUT,
        Capability.SHELL_EXEC,
        Capability.BROWSER,
    }
)
_SHOWN_CAPS = frozenset(c.value for c in _NETWORK_CAPS)


@dataclass(frozen=True)
class ServerView:
    """One server, as ``reach`` shows it.

    Attributes:
        name: Server name from the config.
        caps: Capability tags (``tag_server``), sorted values.
        remote: ``True`` for an http/sse transport or a URL.
        host: Host of a remote server's URL (no userinfo, path or query).
        ref: ``<config file>#<name>`` pointer, home masked.
    """

    name: str
    caps: tuple[str, ...]
    remote: bool
    host: str | None
    ref: str
    #: The registry resolved the server to an entry with declared capabilities.
    declared: bool = False
    #: A local (non-remote) server that can read files or run a shell.  MCP
    #: servers ignore ``Read`` deny rules, so an ``mcp__<server>`` allow rule
    #: hands such a server's reach to the agent whatever the deny rules say.
    local_reader: bool = False
    #: ``local_reader`` and its path arguments all exclude the home directory
    #: and every well-known credential store (never true for a shell server).
    bounded: bool = False

    @property
    def reaches_network(self) -> bool:
        """Tagged network-out, comms-out, shell, browser, or remote."""
        return self.remote or bool(_NETWORK_CAPS & {Capability(c) for c in self.caps})

    def describe(self) -> str:
        """``name (NETWORK_OUT, remote host)`` for reasons and facts."""
        bits = [c.upper() for c in self.caps if c in _SHOWN_CAPS]
        if self.remote:
            bits.append(f"remote {self.host}" if self.host else "remote")
        return f"{self.name} ({', '.join(bits)})" if bits else self.name


@dataclass
class NetworkView:
    """An agent's servers split by what is known about their reach."""

    reaching: list[ServerView] = field(default_factory=list)
    unclassified: list[ServerView] = field(default_factory=list)
    quiet: list[ServerView] = field(default_factory=list)
    #: MCP config files that exist but could not be read, as ``"<path> <why>"``:
    #: what is in them is unknown, so the network answer cannot be "none".
    unread: list[str] = field(default_factory=list)


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _real(text: str) -> str:
    """*text* with symlinks resolved (``strict=False``); raises on failure."""
    return str(Path(text).resolve(strict=False))


def path_excludes_home(
    raw: str,
    *,
    home: str,
    stores: list[str],
    cwd: str,
    pm: Any = os.path,  # noqa: ANN401 — posixpath or ntpath
    real: Callable[[str], str] = _real,
) -> bool:
    """True when the path argument *raw* stays out of *home* and every store.

    Symlinks are resolved with *real* (a failure counts as not excluded), a
    bare root (``/``, ``C:\\``) is never excluded, and every comparison is
    normcased, so Windows case and separator differences cannot hide home.
    A drive-less rooted path (``/``) belongs to the drive of *cwd*.
    """
    text = raw
    if text.startswith(("$", "%")) or text in ("~", "~/", "~\\"):
        return False
    if text[:2] in ("~/", "~\\"):
        text = pm.join(home, text[2:])
    elif pm.splitdrive(text)[0] == "" and text[:1] in ("/", "\\"):
        text = pm.splitdrive(cwd)[0] + text  # the cwd's drive on Windows
    elif not pm.isabs(text):
        text = pm.join(cwd, text)

    def norm(value: str) -> str:
        return pm.normcase(pm.normpath(value))

    def covers(outer: str, inner: str) -> bool:
        return inner == outer or inner.startswith(outer.rstrip(pm.sep) + pm.sep)

    try:
        protected = {norm(home), norm(real(home))}
        for store in stores:
            protected |= {norm(store), norm(real(store))}
        candidates = {norm(text), norm(real(pm.normpath(text)))}
    except (OSError, RuntimeError, ValueError):
        return False
    for cand in candidates:
        if pm.splitdrive(cand)[1].strip("/\\") == "":
            return False  # a bare root or drive root contains everything on it
        if any(covers(cand, other) for other in protected):
            return False
    return True


def _bounded(server: ServerConfig, caps: frozenset[Capability], env: Env) -> bool:
    """Do the server's path arguments all stay out of home and the stores?"""
    if Capability.SHELL_EXEC in caps:
        return False
    tail = launch_tail(server.command, list(server.args))
    if tail is None:
        return False
    paths = path_candidates(tail)
    if not paths:
        return False
    stores = [
        str(p) for _s, p in secret_reach.existing_home_stores(env.home, env.config_dir)
    ]
    return all(
        path_excludes_home(raw, home=str(env.home), stores=stores, cwd=str(env.cwd))
        for raw in paths
    )


def _known_cap(value: str) -> bool:
    try:
        Capability(value)
    except ValueError:
        return False
    return True


def _launch_entry(server: ServerConfig, registry: object | None):  # noqa: ANN202
    """The registry entry for the package *server* actually launches, or None.

    Resolved through ``supply_chain.resolve_launch_entry`` so that neither the
    server's NAME nor a stray argument (``node evil.js <known-package>``) can
    claim a registry identity: only the package the launch command installs
    counts.
    """
    if registry is None:
        return None
    # Only the one launch shape and a benign server env can claim a registry
    # identity; anything else is not provably the registry's package.
    if launch_tail(server.command, list(server.args)) is None:
        return None
    if not server_env_declared(getattr(server, "env", None)):
        return None
    try:
        entry = resolve_launch_entry(server, registry)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 — an unreadable registry declares nothing
        return None
    if entry is None or entry.capabilities is None:
        return None
    return entry


def _declared(server: ServerConfig, registry: object | None) -> bool:
    """True when the launched package has registry-declared capabilities."""
    return _launch_entry(server, registry) is not None


def view_of(server: ServerConfig, registry: object | None, env: Env) -> ServerView:
    """Build the :class:`ServerView` of *server*."""
    try:
        entry = _launch_entry(server, registry)
        if entry is not None:
            caps = frozenset(
                Capability(c) for c in (entry.capabilities or ()) if _known_cap(c)
            )
        else:
            caps = tag_server(server, registry=None)
    except Exception:  # noqa: BLE001 — an unclassifiable server is unclassified
        caps = frozenset()
    remote = server.transport in (
        TransportType.SSE,
        TransportType.STREAMABLE_HTTP,
    ) or bool(server.url)
    local_reader = not remote and bool(
        {Capability.FILE_READ, Capability.SHELL_EXEC} & caps
    )
    try:
        bounded = local_reader and _bounded(server, caps, env)
    except Exception:  # noqa: BLE001 — unbounded is the safe answer
        bounded = False
    return ServerView(
        name=server.name,
        caps=tuple(sorted(c.value for c in caps)),
        remote=remote,
        host=_host(server.url) if remote else None,
        ref=f"{env.mask(server.config_path)}#{server.name}",
        declared=_declared(server, registry),
        local_reader=local_reader,
        bounded=bounded,
    )


def classify(
    servers: list[ServerConfig], registry: object | None, env: Env
) -> NetworkView:
    """Split *servers* into network-reaching, unclassified and quiet."""
    out = NetworkView()
    for server in servers:
        view = view_of(server, registry, env)
        if view.reaches_network:
            out.reaching.append(view)
        elif not view.declared:
            out.unclassified.append(view)
        else:
            out.quiet.append(view)
    return out
