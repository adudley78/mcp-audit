"""Data model for an installed Claude Code plugin."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Plugin source types that fetch a git checkout and can pin a commit with `sha`
# (code.claude.com/docs/en/plugins/marketplace-reference#plugin-sources).
GIT_SOURCE_TYPES: frozenset[str] = frozenset({"github", "url", "git-subdir"})

_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_OBJECT_ID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


@dataclass(frozen=True)
class InstalledPlugin:
    """One install record from ``installed_plugins.json``, joined with its source.

    Attributes:
        plugin_id: ``<name>@<marketplace>``, the key Claude Code records.
        name: Marketplace entry name.
        marketplace: Marketplace name ("" when the id carries none).
        scope: Install scope as recorded (``user``, ``project``, ``local``, ...).
        project_path: Project the install belongs to, when recorded.
        install_path: Directory the plugin loads from, when recorded.
        version: Version Claude Code recorded for this install.
        source: The marketplace entry's ``source`` (string or object), or
            ``None`` when the marketplace manifest could not be read.
        entry_version: ``version`` set on the marketplace entry, if any.
        manifest_version: ``version`` in the installed ``plugin.json``, if any.
        record_path: The ``installed_plugins.json`` this came from.
        git_commit_sha: ``gitCommitSha`` from the install record, lower-cased,
            when it is a full object id.  Undocumented; observed on Claude Code
            2.1.311 as the resolved commit of a git-sourced plugin (the pin) and
            as the marketplace's commit for a relative-path plugin (STORY-0096).
    """

    plugin_id: str
    name: str
    marketplace: str
    scope: str
    project_path: str | None
    install_path: Path | None
    version: str | None
    source: dict | str | None
    entry_version: str | None
    manifest_version: str | None
    record_path: Path
    git_commit_sha: str | None = None

    @property
    def source_type(self) -> str | None:
        """``github`` / ``url`` / ``git-subdir`` / ``npm`` / ..., or ``relative``."""
        if isinstance(self.source, dict):
            value = self.source.get("source")
            return value if isinstance(value, str) else None
        if isinstance(self.source, str):
            return "relative"
        return None

    @property
    def pinned_sha(self) -> str | None:
        """The 40-hex commit the marketplace entry pins, or ``None``."""
        if not isinstance(self.source, dict):
            return None
        sha = self.source.get("sha")
        if isinstance(sha, str) and _FULL_SHA_RE.match(sha.strip().lower()):
            return sha.strip().lower()
        return None


def normalize_object_id(value: object) -> str | None:
    """Return *value* lower-cased when it is a full 40- or 64-hex object id."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if _OBJECT_ID_RE.match(candidate) else None
