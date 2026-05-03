"""Allowlist model and loader for ``mcp-audit shadow``.

An allowlist declares which MCP servers are *sanctioned* — i.e. explicitly
approved by the operator.  Servers **not** in the allowlist are treated as
``shadow`` regardless of their registry membership (the registry is a trust
signal, not an allowlist — that distinction is central to the shadow pitch).

File format
-----------
::

    # .mcp-audit-allowlist.yml
    sanctioned_servers:
      - "@modelcontextprotocol/server-filesystem"          # package-name match
      - name: "internal-postgres"                          # server-name match
        command: "/opt/internal/mcp/postgres-server"       # + optional command match

    sanctioned_capabilities: []  # informational only — does not affect classification

Resolution order when ``--allowlist`` is not given:
  1. ``.mcp-audit-allowlist.yml`` / ``.mcp-audit-allowlist.yaml`` in CWD.
  2. Same filenames in the git repo root (if found).
  3. ``<user-config-dir>/mcp-audit/allowlist.yml`` (resolved via ``platformdirs``).
  4. No allowlist — all servers are classified as ``shadow``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import yaml
from platformdirs import user_config_dir
from pydantic import BaseModel, Field

from mcp_audit.models import ServerConfig

# ── Schema ────────────────────────────────────────────────────────────────────

_USER_ALLOWLIST_PATH = Path(user_config_dir("mcp-audit")) / "allowlist.yml"

ALLOWLIST_FILENAMES = [
    ".mcp-audit-allowlist.yml",
    ".mcp-audit-allowlist.yaml",
    "mcp-audit-allowlist.yml",
]


class AllowlistServerEntry(BaseModel):
    """A structured allowlist entry matching by name and/or command path."""

    name: str | None = None
    command: str | None = None


# An allowlist entry is either a bare string (package / server name) or a
# structured dict with ``name`` and/or ``command`` fields.
AllowlistItem = Annotated[
    str | AllowlistServerEntry,
    Field(union_mode="left_to_right"),
]


class ShadowAllowlist(BaseModel):
    """Parsed and validated shadow allowlist file."""

    sanctioned_servers: list[AllowlistItem] = Field(default_factory=list)
    sanctioned_capabilities: list[str] = Field(default_factory=list)


# ── Loading ───────────────────────────────────────────────────────────────────


def _find_git_root(start: Path) -> Path | None:
    """Walk parent directories until a ``.git`` entry is found."""
    current = start.resolve()
    while True:
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _load_from_path(path: Path) -> ShadowAllowlist:
    """Parse and validate an allowlist YAML file.

    Args:
        path: Path to the allowlist file.

    Returns:
        A validated :class:`ShadowAllowlist`.

    Raises:
        ValueError: If the file cannot be read or the YAML is invalid.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Cannot read allowlist file {path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in allowlist file {path}: {exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ValueError(
            f"Allowlist file {path} must be a YAML mapping, got {type(data).__name__}"
        )

    from pydantic import ValidationError  # noqa: PLC0415

    try:
        return ShadowAllowlist.model_validate(data)
    except ValidationError as exc:
        errors = exc.errors()
        summary = "; ".join(
            f"{' → '.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in errors[:3]
        )
        if len(errors) > 3:
            summary += f" (and {len(errors) - 3} more error(s))"
        raise ValueError(
            f"Allowlist file {path} failed schema validation: {summary}"
        ) from exc


def load_allowlist(path: Path | None = None) -> ShadowAllowlist | None:
    """Load a shadow allowlist, returning ``None`` when no file is found.

    Resolution order (unless *path* is given):
    1. Explicit ``--allowlist PATH`` flag.
    2. CWD — checks :data:`ALLOWLIST_FILENAMES` in order.
    3. Git repo root (if different from CWD).
    4. ``<user-config-dir>/mcp-audit/allowlist.yml``.
    5. Return ``None`` (all servers are shadow).

    Args:
        path: Explicit allowlist path override.

    Returns:
        Parsed :class:`ShadowAllowlist` or ``None``.

    Raises:
        ValueError: If an explicit *path* is given but the file is missing,
            malformed, or fails schema validation.
    """
    if path is not None:
        path = path.resolve()
        if not path.exists():
            raise ValueError(f"Allowlist file not found: {path}")
        return _load_from_path(path)

    cwd = Path.cwd()
    for filename in ALLOWLIST_FILENAMES:
        candidate = cwd / filename
        if candidate.exists():
            return _load_from_path(candidate)

    git_root = _find_git_root(cwd)
    if git_root is not None and git_root != cwd:
        for filename in ALLOWLIST_FILENAMES:
            candidate = git_root / filename
            if candidate.exists():
                return _load_from_path(candidate)

    if _USER_ALLOWLIST_PATH.exists():
        return _load_from_path(_USER_ALLOWLIST_PATH)

    return None


# ── Unmatched-entry validation ─────────────────────────────────────────────────


def find_unmatched_allowlist_entries(
    allowlist: ShadowAllowlist,
    servers: list[ServerConfig],
) -> list[str]:
    """Return allowlist entries that did not match any discovered server.

    Warns the operator about likely typos in the allowlist so a misconfigured
    entry doesn't silently leave an intended-sanctioned server as shadow.

    Args:
        allowlist: The loaded allowlist.
        servers: All discovered servers in the current sweep.

    Returns:
        Human-readable descriptions of unmatched entries (for display).
    """
    from mcp_audit.analyzers.supply_chain import extract_npm_package  # noqa: PLC0415

    unmatched: list[str] = []

    for item in allowlist.sanctioned_servers:
        matched = False
        for server in servers:
            pkg = (
                extract_npm_package(server.args)
                if server.command in {"npx", "bunx", "pnpx"}
                else None
            )
            if isinstance(item, str):
                if (
                    item.lower() == server.name.lower()
                    or (server.command and item.lower() == server.command.lower())
                    or (pkg and item.lower() == pkg.lower())
                ):
                    matched = True
                    break
            else:
                name_ok = item.name is None or (
                    item.name.lower() == server.name.lower()
                )
                cmd_ok = item.command is None or (
                    server.command and item.command.lower() == server.command.lower()
                )
                has_field = item.name is not None or item.command is not None
                if name_ok and cmd_ok and has_field:
                    matched = True
                    break
        if not matched:
            label = item if isinstance(item, str) else f"{item!r}"
            unmatched.append(str(label))

    return unmatched
