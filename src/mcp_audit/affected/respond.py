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

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.analyzers.managed_policy import PolicyEntry, entry_matches
from mcp_audit.analyzers.supply_chain import redact_args
from mcp_audit.models import ServerConfig

#: Flags whose *value* is probably a credential; only the flag name is kept.
_SECRET_FLAG = re.compile(
    r"^--?[A-Za-z0-9_.-]*(token|key|secret|password|passwd|auth|credential|header|"
    r"cookie|bearer|login|user)[A-Za-z0-9_.-]*",
    re.IGNORECASE,
)
_SHORT_SECRET_FLAGS = frozenset({"-H", "-u", "-b", "-e", "-p"})
_LONG_NAME = re.compile(r"^--[A-Za-z0-9][A-Za-z0-9_-]*")

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


def _flag_name(arg: str) -> str | None:
    """The flag's own name when *arg* looks like a credential flag, else ``None``.

    The value is never kept, however it is attached (``--k=v``, ``--k:v``,
    ``-Hv``).
    """
    if not arg.startswith("-") or arg == "-":
        return None
    if arg.startswith("--"):
        match = _LONG_NAME.match(arg)
        name = match.group(0) if match else None
        return name if name and _SECRET_FLAG.match(name) else None
    return arg[:2] if arg[:2] in _SHORT_SECRET_FLAGS else None


def _flag_names(args: list[str]) -> list[str]:
    return sorted({n for a in args if (n := _flag_name(str(a))) is not None})


def _tilde(path: Path, home: Path) -> str:
    try:
        return "~/" + path.relative_to(home).as_posix()
    except ValueError:
        return path.name


def credential_files(
    home: Path, cwd: Path | None, errors: list[str]
) -> list[tuple[str, str]]:
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
    codex_home = Path(os.environ.get("CODEX_HOME") or home / ".codex")
    extras = (
        (home / ".claude.json", _EXTRA_STORES[0][1]),
        (config_dir / ".claude.json", _EXTRA_STORES[0][1]),
        (codex_home / "config.toml", _EXTRA_STORES[1][1]),
    )
    shown = {p for p, _ in found}
    for path, label in extras:
        if sr._stat_store(path) is not None and _tilde(path, home) not in shown:  # noqa: SLF001
            found.append((_tilde(path, home), label))
            shown.add(_tilde(path, home))
    if cwd is not None and cwd.resolve() != home.resolve():
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

#: Arguments a launcher takes that cannot carry a secret.
_SAFE_ARGS = frozenset(
    {"-y", "--yes", "-q", "--quiet", "run", "dlx", "--transport", "stdio", "sse",
     "http", "streamable-http"}
)  # fmt: skip
_SPEC = re.compile(
    r"^(?P<name>@?[A-Za-z0-9][A-Za-z0-9._/-]*?)(?:(?:==|@)[0-9A-Za-z.+!-]+)?$"
)


def _safe_command(server: ServerConfig) -> tuple[str, ...] | None:
    """The launch as a ``serverCommand`` value, only if it cannot hold a secret.

    The policy file is deployed to other machines, so the command is written
    only when every argument is the package itself (name, optionally with a
    version) or a launcher/transport word from a short list.  A URL, a path, a
    positional value or any other flag could be a secret and stops it.
    """
    from mcp_audit.analyzers.supply_chain import launch_package  # noqa: PLC0415

    found = launch_package(server)
    if found is None or not server.command:
        return None
    package = found[1].lower().replace("_", "-")
    spec_seen = False
    for arg in server.args:
        text = str(arg)
        if text in _SAFE_ARGS:
            continue
        match = _SPEC.match(text)
        if (
            match
            and not spec_seen
            and "://" not in text
            and match.group("name").lower().replace("_", "-") == package
        ):
            spec_seen = True
            continue
        return None
    command = (server.command, *server.args)
    if not spec_seen or redact_args(list(command)) != list(command):
        return None
    return command


def policy_entry(server: ServerConfig) -> tuple[dict | None, str | None]:
    """The ``deniedMcpServers`` entry for *server*, or why there is none.

    Only an exact ``serverCommand`` that the managed-policy evaluator
    (``entry_matches``) says matches this server.  A name entry is never
    written: it would deny every server of that name on every machine the
    file reaches, patched ones included.
    """
    command = _safe_command(server)
    if command is not None:
        entry = PolicyEntry("serverCommand", command, Path("policy-out"))
        if entry_matches(entry, server) is True:
            return {"serverCommand": list(command)}, None
    return None, (
        f"{server.name!r}: no entry written. Its launch carries arguments that "
        "might be secrets, so no exact command entry is safe to deploy; add an "
        "entry for it by hand"
    )


def policy_document(servers: list[ServerConfig]) -> tuple[dict, list[str]]:
    """``{"deniedMcpServers": [...]}`` for *servers*, de-duplicated, and notes."""
    import json  # noqa: PLC0415

    seen: dict[str, dict] = {}
    notes: list[str] = []
    for server in servers:
        entry, note = policy_entry(server)
        if entry is not None:
            seen.setdefault(json.dumps(entry, sort_keys=True), entry)
        if note and note not in notes:
            notes.append(note)
    return {"deniedMcpServers": list(seen.values())}, notes


def inside_managed_dir(path: Path) -> bool:
    """Is *path* inside Claude Code's managed-settings directory?"""
    from mcp_audit.plugins import mods  # noqa: PLC0415

    try:
        target = Path(str(path.resolve()).casefold())
        root = Path(str(mods.managed_settings_dir().resolve()).casefold())
    except (OSError, RuntimeError):
        return False
    return target == root or root in target.parents
