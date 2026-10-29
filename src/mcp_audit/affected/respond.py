"""The "Respond" half of ``affected`` (STORY-0126).

For each AFFECTED server: what it could read (so what to rotate), who else
shares those names, which well-known credential files exist on this machine,
and whether tool text was saved for it.  And, on request, the Claude Code
managed-policy entries that would stop it loading.

Everything is names and paths.  No environment, header or argument *value* is
read into the output, no credential file is opened (it is only ``stat()``-ed,
the way REACH-001..003 do), and saved tool text is counted, never shown.
mcp-audit writes only the one file ``--policy-out`` names, and refuses a path
inside Claude Code's managed-settings directory: deploying is the admin's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from mcp_audit.analyzers.managed_policy import PolicyEntry, entry_matches
from mcp_audit.analyzers.supply_chain import redact_args
from mcp_audit.models import ServerConfig

#: Flags whose *value* is probably a credential; only the flag name is kept.
_SECRET_FLAG = re.compile(
    r"^--?[A-Za-z0-9_.-]*(token|key|secret|password|passwd|auth|credential)"
    r"[A-Za-z0-9_.-]*",
    re.IGNORECASE,
)

#: Beyond REACH's fixed list: files that hold MCP env and header values.
_EXTRA_STORES: tuple[tuple[str, str], ...] = (
    (".claude.json", "Claude Code config; holds MCP env and header values"),
    (".codex/config.toml", "Codex config; holds MCP env and header values"),
)


@dataclass
class Respond:
    """What to do about one AFFECTED server."""

    subject: str
    config_path: str | None
    env_names: list[str] = field(default_factory=list)
    header_names: list[str] = field(default_factory=list)
    flag_names: list[str] = field(default_factory=list)
    #: ``{other server: names it shares with this one}`` in the same config file.
    shared: dict[str, list[str]] = field(default_factory=dict)
    #: ``(path as ~/..., what it holds)`` for credential files that exist.
    stores: list[tuple[str, str]] = field(default_factory=list)
    #: Saved tool definitions for this server, and the file they are in.
    tool_text: tuple[int, str] | None = None

    def names(self) -> list[str]:
        """Everything the server could read, by name."""
        return sorted({*self.env_names, *self.header_names, *self.flag_names})


def _flag_names(args: list[str]) -> list[str]:
    out: set[str] = set()
    for arg in args:
        text = str(arg)
        if text.startswith("-") and _SECRET_FLAG.match(text):
            out.add(text.split("=", 1)[0])
    return sorted(out)


def _tilde(path: Path, home: Path) -> str:
    try:
        return "~/" + path.relative_to(home).as_posix()
    except ValueError:
        return path.name


def credential_files(home: Path, cwd: Path, errors: list[str]) -> list[tuple[str, str]]:
    """Well-known credential files that exist (``stat()`` only; never opened)."""
    from mcp_audit.analyzers import secret_reach as sr  # noqa: PLC0415
    from mcp_audit.plugins import mods  # noqa: PLC0415

    config_dir = mods.claude_config_dir(home)
    found: list[tuple[str, str]] = []
    for store in sr.HOME_STORES:
        if not sr._store_applies(store):  # noqa: SLF001
            continue
        path = sr._home_store_rel(store, home, config_dir)  # noqa: SLF001
        if sr._stat_store(path) is not None:  # noqa: SLF001
            found.append((_tilde(path, home), store.label))
    for rel, label in _EXTRA_STORES:
        path = home / rel
        if sr._stat_store(path) is not None:  # noqa: SLF001
            found.append((_tilde(path, home), label))
    if cwd.resolve() != home.resolve():
        found.extend(
            (path.name + " (working directory)", "environment file")
            for path in sr._env_files(cwd, errors)  # noqa: SLF001
        )
    return found


def _tool_text(server: ServerConfig) -> tuple[int, str] | None:
    from mcp_audit.lock import tool_text  # noqa: PLC0415
    from mcp_audit.lock.discovery import find_lock_for  # noqa: PLC0415

    lock = find_lock_for(server.config_path)
    if lock is None:
        return None
    path = tool_text.tool_text_path(lock)
    doc, _problem = tool_text.load(path)
    if doc is None:
        return None
    record = doc["servers"].get(f"{server.client}/{server.name}")
    tools = record.get("tools") if isinstance(record, dict) else None
    if not isinstance(tools, dict) or not tools:
        return None
    return len(tools), path.name


def build(
    server: ServerConfig,
    all_servers: list[ServerConfig],
    stores: list[tuple[str, str]],
) -> Respond:
    """The Respond block for *server* among *all_servers*."""
    out = Respond(
        subject=f"{server.client}/{server.name}",
        config_path=str(server.config_path),
        env_names=sorted(server.env),
        header_names=sorted(server.headers),
        flag_names=_flag_names(server.args),
        stores=stores,
        tool_text=_tool_text(server),
    )
    mine = set(out.names())
    for other in all_servers:
        if other is server or other.config_path != server.config_path:
            continue
        common = sorted(mine & {*other.env, *other.headers, *_flag_names(other.args)})
        if common:
            out.shared[f"{other.client}/{other.name}"] = common
    return out


# ── Managed-policy entries ────────────────────────────────────────────────────


def _candidates(server: ServerConfig) -> list[PolicyEntry]:
    src = Path("policy-out")
    out: list[PolicyEntry] = []
    if server.url:
        parts = urlsplit(server.url)
        host = parts.hostname or ""
        # Userinfo makes matching uncertain, so that falls back to the name;
        # a query string (where tokens live) is simply left off.
        if parts.scheme and host and parts.username is None and parts.password is None:
            netloc = host + (f":{parts.port}" if parts.port else "")
            out.append(
                PolicyEntry("serverUrl", f"{parts.scheme}://{netloc}{parts.path}", src)
            )
    if server.command:
        command = [server.command, *server.args]
        # A secret-looking flag may carry its value anywhere in the argument
        # list, and the policy file is deployed: use the command only when no
        # such flag is present at all.
        if (
            redact_args(list(command)) == command
            and not _flag_names(server.args)
            and not any("${" in part for part in command)
        ):
            out.append(PolicyEntry("serverCommand", tuple(command), src))
    out.append(PolicyEntry("serverName", server.name, src))
    return out


def policy_entry(server: ServerConfig) -> tuple[dict, str | None]:
    """The ``deniedMcpServers`` entry for *server*, and a note when it is weak.

    The first of URL, command, name that carries no secret *and* that the
    managed-policy evaluator (``entry_matches``) says matches this server.
    A name entry is the fallback: it works in a denylist but a renamed server
    escapes it, which the note says.
    """
    for entry in _candidates(server):
        if entry_matches(entry, server) is not True:
            continue
        value = list(entry.value) if isinstance(entry.value, tuple) else entry.value
        note = None
        if entry.kind == "serverName":
            note = (
                f"{server.name!r}: matched by name only (a server renamed in a "
                "user's config is not caught)"
            )
        return {entry.kind: value}, note
    raise AssertionError("the name entry always matches")  # pragma: no cover


def policy_document(servers: list[ServerConfig]) -> tuple[dict, list[str]]:
    """``{"deniedMcpServers": [...]}`` for *servers*, de-duplicated, and notes."""
    import json  # noqa: PLC0415

    seen: dict[str, dict] = {}
    notes: list[str] = []
    for server in servers:
        entry, note = policy_entry(server)
        seen.setdefault(json.dumps(entry, sort_keys=True), entry)
        if note and note not in notes:
            notes.append(note)
    return {"deniedMcpServers": list(seen.values())}, notes


def inside_managed_dir(path: Path) -> bool:
    """Is *path* inside Claude Code's managed-settings directory?"""
    from mcp_audit.plugins import mods  # noqa: PLC0415

    try:
        target = path.resolve()
        root = mods.managed_settings_dir().resolve()
    except (OSError, RuntimeError):
        return False
    return target == root or root in target.parents
