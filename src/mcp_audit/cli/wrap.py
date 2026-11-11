"""``mcp-audit wrap`` / ``unwrap``: put MCP servers behind ``mcp-audit run``.

EPIC-0009 Story 1.2. ``wrap`` rewrites each local (stdio) server entry in the
discovered MCP config files so the client launches ``mcp-audit run ... --
<original command>`` instead of the server (see
:mod:`mcp_audit.runtime.wrapping` for the exact shape). ``unwrap`` restores
each entry and checks it against the digest recorded at wrap time.

Both are dry runs by default: they print the diff and, for ``wrap``, what
the launch gate would decide for each server today. ``--apply`` writes, with
the same backup-then-atomic-write path as ``mcp-audit fix``.

First batch of clients (JSON configs): Claude Code, Cursor, Claude Desktop,
VS Code, plus Windsurf, Copilot CLI and Augment, which share the format, and
any JSON config named with ``--path``. Codex (TOML), Gemini CLI, OpenCode,
gateway files, plugin and subagent definitions are not rewritten.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from mcp_audit.cli import app
from mcp_audit.discovery import DiscoveredConfig, discover_configs
from mcp_audit.fixer.fixer import write_config_change
from mcp_audit.runtime.gate import check_launch
from mcp_audit.runtime.wrapping import (
    MODES,
    WRAPPABLE_CLIENTS,
    inner_launch,
    unwrap_entry,
    wrap_entry,
)

console = Console()


@dataclass
class _Plan:
    config: DiscoveredConfig
    original_text: str
    data: dict
    servers_key: str
    changed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _default_exe() -> str:
    """Absolute path of the mcp-audit executable clients should launch.

    Absolute because GUI clients (Claude Desktop, Cursor) don't inherit the
    shell's PATH.
    """
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    found = shutil.which("mcp-audit")
    if found:
        return str(Path(found).resolve())
    raise typer.BadParameter(
        "can't find the mcp-audit executable on PATH; pass --exe /path/to/mcp-audit"
    )


def _configs(
    paths: list[Path] | None, clients: list[str] | None
) -> list[DiscoveredConfig]:
    if paths:
        for p in paths:
            if not p.exists():
                console.print(f"[red]Error:[/red] config not found: {escape(str(p))}")
                raise typer.Exit(2)
        found = discover_configs(
            extra_paths=[p.resolve() for p in paths], skip_auto_discovery=True
        )
    else:
        found = discover_configs(
            include_plugins=False, include_agents=False, include_gateways=False
        )
    out: list[DiscoveredConfig] = []
    seen: set[Path] = set()
    for config in found:
        if clients and config.client_name not in clients:
            continue
        key = config.path.resolve()
        if key in seen:
            continue
        seen.add(key)
        out.append(config)
    return out


def _load(config: DiscoveredConfig) -> _Plan | str:
    """Read *config* for rewriting, or return why it can't be."""
    if config.client_name not in WRAPPABLE_CLIENTS:
        return f"{config.client_name} configs aren't rewritten yet"
    if config.path.suffix.lower() == ".toml" or config.path.name.startswith("opencode"):
        return "not a JSON MCP config"
    try:
        text = config.path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"can't read it: {exc.strerror or exc}"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "not plain JSON (comments or trailing commas?); edit it by hand"
    if not isinstance(data, dict):
        return "not a JSON object"
    for key in (config.root_key, "mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            return _Plan(config, text, data, key)
    return "no MCP servers in it"


def _gate_note(config_path: Path, name: str, argv: list[str]) -> str:
    result = check_launch(argv, config_path=config_path, server_name=name)
    if result.ok:
        return "gate: approved in mcp-lock.json"
    return f"gate: {result.finding_id} ({result.summary})"


def _report(plan: _Plan, diff: str, *, apply: bool, backup: Path | None) -> None:
    path = escape(str(plan.config.path))
    console.print(f"\n[bold]{path}[/bold] ({plan.config.client_name})")
    for note in plan.notes:
        console.print(f"  {note}")
    if not plan.changed:
        return
    if apply:
        shown = escape(str(backup)) if backup else "-"
        console.print(f"  [green]written[/green]; backup: {shown}")
    else:
        console.print(diff, markup=False, highlight=False, end="")


@app.command("wrap")
def wrap(
    path: list[Path] = typer.Option(  # noqa: B008
        None,
        "--path",
        help="MCP config file to rewrite (repeatable). Default: every discovered one.",
    ),
    client: list[str] = typer.Option(  # noqa: B008
        None, "--client", help="Only these clients (e.g. claude-code, cursor)."
    ),
    server: list[str] = typer.Option(  # noqa: B008
        None, "--server", help="Only these server names (repeatable)."
    ),
    mode: str = typer.Option(
        "monitor", "--mode", help="Mode for the wrapped servers: monitor or enforce."
    ),
    exe: str = typer.Option(
        None,
        "--exe",
        help="mcp-audit executable clients should launch (absolute path).",
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Write the changes (default: dry run showing the diff)."
    ),
) -> None:
    """Launch local MCP servers through `mcp-audit run` (EPIC-0009).

    Dry run by default: shows the diff and what the launch gate would decide
    for each server today. `--apply` writes, keeping a backup.
    """
    if mode not in MODES:
        console.print(f"[red]Error:[/red] --mode must be one of {', '.join(MODES)}")
        raise typer.Exit(2)
    executable = exe or _default_exe()
    if not Path(executable).is_absolute():
        console.print("[red]Error:[/red] --exe must be an absolute path")
        raise typer.Exit(2)
    wanted = set(server or [])
    total = 0
    refused = 0
    for config in _configs(path, client):
        plan = _load(config)
        if isinstance(plan, str):
            console.print(f"\n{escape(str(config.path))}: skipped, {plan}")
            continue
        servers = plan.data[plan.servers_key]
        abs_config = str(config.path.resolve())
        for name in list(servers):
            entry = servers[name]
            if wanted and name not in wanted:
                continue
            if not isinstance(entry, dict):
                continue
            if not isinstance(entry.get("command"), str):
                plan.notes.append(f"{escape(name)}: skipped, remote server")
                continue
            if inner_launch(entry.get("command"), entry.get("args")) is not None:
                plan.notes.append(f"{escape(name)}: already wrapped")
                continue
            try:
                new_entry = wrap_entry(
                    entry,
                    exe=executable,
                    config_path=abs_config,
                    server=name,
                    mode=mode,
                )
            except ValueError as exc:
                plan.notes.append(f"{escape(name)}: skipped, {exc}")
                continue
            servers[name] = new_entry
            plan.changed.append(name)
            argv = [entry["command"], *entry.get("args", [])]
            note = _gate_note(config.path.resolve(), name, argv)
            if mode == "enforce" and not note.startswith("gate: approved"):
                refused += 1
                note += " [yellow]— enforce mode would refuse to start it[/yellow]"
            plan.notes.append(f"{escape(name)}: wrapped ({mode}); {note}")
        if not plan.changed:
            _report(plan, "", apply=apply, backup=None)
            continue
        result = write_config_change(
            config.path, plan.original_text, plan.data, apply=apply
        )
        total += len(plan.changed)
        _report(plan, result.diff, apply=apply, backup=result.backup_path)
    verb = "Wrapped" if apply else "Would wrap"
    console.print(f"\n{verb} {total} server(s).")
    if refused:
        console.print(
            f"[yellow]{refused} of them aren't approved in mcp-lock.json; in enforce "
            "mode they won't start until you run `mcp-audit lock`.[/yellow]"
        )
    if total and not apply:
        console.print("Run again with --apply to write. Restart the client afterwards.")


@app.command("unwrap")
def unwrap(
    path: list[Path] = typer.Option(  # noqa: B008
        None,
        "--path",
        help="MCP config file to restore (repeatable). Default: every discovered one.",
    ),
    client: list[str] = typer.Option(  # noqa: B008
        None, "--client", help="Only these clients."
    ),
    server: list[str] = typer.Option(  # noqa: B008
        None, "--server", help="Only these server names (repeatable)."
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Write the changes (default: dry run showing the diff)."
    ),
) -> None:
    """Restore servers wrapped by `mcp-audit wrap` to their original entries."""
    wanted = set(server or [])
    total = 0
    unverified = 0
    for config in _configs(path, client):
        plan = _load(config)
        if isinstance(plan, str):
            continue
        servers = plan.data[plan.servers_key]
        for name in list(servers):
            entry = servers[name]
            if (wanted and name not in wanted) or not isinstance(entry, dict):
                continue
            restored = unwrap_entry(entry)
            if restored is None:
                continue
            original, verified = restored
            servers[name] = original
            plan.changed.append(name)
            if verified:
                plan.notes.append(
                    f"{escape(name)}: restored (matches the original exactly)"
                )
            else:
                unverified += 1
                plan.notes.append(
                    f"{escape(name)}: restored [yellow](the entry changed after it was "
                    "wrapped, so it can't be checked against the original)[/yellow]"
                )
        if not plan.changed:
            continue
        result = write_config_change(
            config.path, plan.original_text, plan.data, apply=apply
        )
        total += len(plan.changed)
        _report(plan, result.diff, apply=apply, backup=result.backup_path)
    verb = "Restored" if apply else "Would restore"
    console.print(f"\n{verb} {total} server(s).")
    if total and not apply:
        console.print("Run again with --apply to write. Restart the client afterwards.")
