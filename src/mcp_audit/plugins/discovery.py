"""Discover installed Claude Code plugins and what they ship (STORY-0080).

File formats, from Claude Code's documentation and public bug reports:

* ``installed_plugins.json``: ``{"version": 2, "plugins": {"<name>@<marketplace>":
  [{"scope", "projectPath", "installPath", "version", ...}, ...]}}`` — one array
  entry per install (anthropics/claude-code issues #45997, #17032).  Records
  written by Claude Code 2.1.311 also carry ``installedAt``, ``lastUpdated`` and
  ``gitCommitSha`` (observed, undocumented; STORY-0096).
* ``known_marketplaces.json``: per marketplace, ``source``, ``installLocation``,
  ``lastUpdated``, ``autoUpdate`` (docs: plugins/loading).
* ``<marketplace root>/.claude-plugin/marketplace.json``: ``plugins`` entries with
  ``name``, ``source`` (relative path string or an object with ``source``,
  ``repo``/``url``, ``ref``, ``sha``) and optional ``version``
  (docs: plugins/marketplace-reference).

Every read is defensive: a missing or malformed file yields nothing, never an
exception, because these are another tool's internal state files.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from mcp_audit.agent_files.discovery import _read_agent_file
from mcp_audit.agent_files.models import AgentFile, AgentFileSurface
from mcp_audit.plugins.models import InstalledPlugin, normalize_object_id

logger = logging.getLogger(__name__)


def plugins_root(home: Path | None = None) -> Path:
    """Return Claude Code's plugins root.

    ``CLAUDE_CODE_PLUGIN_CACHE_DIR`` overrides the default ``~/.claude/plugins``.
    """
    override = os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    return (home or Path.home()) / ".claude" / "plugins"


_MAX_JSON_BYTES = 2 * 1024 * 1024


def _load_json(path: Path) -> Any:
    """Read a plugin record/manifest; ``None`` when unreadable, huge or too nested."""
    try:
        if path.stat().st_size > _MAX_JSON_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def _expand(value: object) -> Path | None:
    if isinstance(value, str) and value.strip():
        return Path(value.strip()).expanduser()
    return None


def _marketplace_manifests(root: Path) -> dict[str, dict]:
    """Map marketplace name → parsed ``marketplace.json``."""
    known = _load_json(root / "known_marketplaces.json")
    known = known if isinstance(known, dict) else {}
    clones = root / "marketplaces"
    names = set(known)
    if clones.is_dir():
        names |= {p.name for p in clones.iterdir() if p.is_dir()}

    manifests: dict[str, dict] = {}
    for name in sorted(names):
        info = known.get(name)
        location = (
            _expand(info.get("installLocation")) if isinstance(info, dict) else None
        )
        for base in (location, clones / name):
            if base is None:
                continue
            manifest = _load_json(base / ".claude-plugin" / "marketplace.json")
            if isinstance(manifest, dict):
                manifests[name] = manifest
                break
    return manifests


def _entry_for(manifest: dict | None, name: str) -> dict | None:
    if not isinstance(manifest, dict):
        return None
    for entry in manifest.get("plugins") or []:
        if isinstance(entry, dict) and entry.get("name") == name:
            return entry
    return None


def _manifest_version(install_path: Path | None) -> str | None:
    if install_path is None:
        return None
    data = _load_json(install_path / ".claude-plugin" / "plugin.json")
    if isinstance(data, dict) and isinstance(data.get("version"), str):
        return data["version"]
    return None


def discover_installed_plugins(root: Path | None = None) -> list[InstalledPlugin]:
    """Return every install record in ``installed_plugins.json``.

    Args:
        root: Plugins root; defaults to :func:`plugins_root`.

    Returns:
        One :class:`InstalledPlugin` per install record, sorted by plugin id.
        Empty when Claude Code has no plugins installed or the file is unreadable.
    """
    root = root or plugins_root()
    record_path = root / "installed_plugins.json"
    data = _load_json(record_path)
    if not isinstance(data, dict) or not isinstance(data.get("plugins"), dict):
        return []
    manifests = _marketplace_manifests(root)

    found: list[InstalledPlugin] = []
    for plugin_id, records in sorted(data["plugins"].items()):
        if not isinstance(plugin_id, str):
            continue
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            continue
        name, _, marketplace = plugin_id.partition("@")
        entry = _entry_for(manifests.get(marketplace), name)
        for record in records:
            if not isinstance(record, dict):
                continue
            install_path = _expand(record.get("installPath"))
            version = record.get("version")
            entry_version = entry.get("version") if entry else None
            found.append(
                InstalledPlugin(
                    plugin_id=plugin_id,
                    name=name,
                    marketplace=marketplace,
                    scope=str(record.get("scope") or "unknown"),
                    project_path=record.get("projectPath")
                    if isinstance(record.get("projectPath"), str)
                    else None,
                    install_path=install_path,
                    version=version if isinstance(version, str) else None,
                    source=entry.get("source") if entry else None,
                    entry_version=entry_version
                    if isinstance(entry_version, str)
                    else None,
                    manifest_version=_manifest_version(install_path),
                    record_path=record_path,
                    git_commit_sha=normalize_object_id(record.get("gitCommitSha")),
                )
            )
    return found


def _install_dirs(plugins: list[InstalledPlugin]) -> list[Path]:
    seen: list[Path] = []
    for plugin in plugins:
        path = plugin.install_path
        if path is not None and path.is_dir() and path not in seen:
            seen.append(path)
    return seen


def plugin_agent_files(plugins: list[InstalledPlugin]) -> list[AgentFile]:
    """Return the skills and commands installed plugins ship, as agent files.

    Plugin layout (docs: plugins/components): ``skills/<name>/SKILL.md`` and
    ``commands/*.md`` at the plugin root.  Scope is recorded as ``"plugin"``.
    """
    files: list[AgentFile] = []
    for root in _install_dirs(plugins):
        for path in sorted(root.glob("skills/**/SKILL.md")):
            agent_file = _read_agent_file(
                path, AgentFileSurface.CLAUDE_SKILL, "claude-code", "plugin"
            )
            if agent_file is not None:
                files.append(agent_file)
        for path in sorted(root.glob("commands/*.md")):
            agent_file = _read_agent_file(
                path, AgentFileSurface.CLAUDE_COMMAND, "claude-code", "plugin"
            )
            if agent_file is not None:
                files.append(agent_file)
    return files


def plugin_mcp_config_paths(plugins: list[InstalledPlugin]) -> list[Path]:
    """Return plugin files that declare MCP servers under ``mcpServers``.

    A plugin declares servers inline in ``.claude-plugin/plugin.json`` or in a
    ``.mcp.json`` at its root (docs: plugins/loading).  A ``plugin.json`` whose
    ``mcpServers`` is a path string rather than an object is skipped.
    """
    paths: list[Path] = []
    for root in _install_dirs(plugins):
        mcp_json = root / ".mcp.json"
        if mcp_json.is_file():
            paths.append(mcp_json)
        manifest = root / ".claude-plugin" / "plugin.json"
        data = _load_json(manifest)
        if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
            paths.append(manifest)
    return paths
