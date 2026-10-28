"""Discover MCP configuration files across supported clients."""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.analyzers.git_exec import GitSurface, is_bare_repository
from mcp_audit.gateways import PROJECT_GATEWAY_FILES, user_gateway_config_paths
from mcp_audit.models import Finding, Severity

#: ``mcp-lock.json``'s own filename. Imported here as a literal rather than
#: from ``lock.model`` so ``discovery`` keeps no dependency on the ``lock``
#: package (``lock`` depends on discovery, not the reverse); pinned by
#: ``tests/test_lock_autoverify.py``.
_LOCK_FILENAME = "mcp-lock.json"

#: Client name for MCP servers declared inline in a Claude Code subagent
#: definition (``.claude/agents/**/*.md``, ``~/.claude/agents/**/*.md``;
#: STORY-0094). Like ``claude-code-plugin``, these servers join default
#: auto-discovery but are never written to or verified against
#: ``mcp-lock.json`` and are left out of the rug-pull state key.
AGENT_DEFINITION_CLIENT = "claude-code-agent"


@dataclass
class ClientSpec:
    """Specification for a supported MCP client."""

    name: str
    root_key: str  # JSON key containing server definitions
    config_paths: list[Path]  # Paths to check, in priority order


def _home() -> Path:
    return Path.home()


def is_lock_file(path: Path) -> bool:
    """Return ``True`` when *path* is an ``mcp-lock.json``, not an MCP config.

    A lock file's top-level ``servers`` key looks exactly like a VS Code MCP
    config root, so the explicit-directory ``*.json`` glob used to ingest a
    project's own lock and invent a phantom server named after the lock's
    ``<client>/<name>`` entry key (R60-01's compounding half). Two
    independent signals, either of which is sufficient:

    - the conventional filename, so a lock is skipped without being read;
    - a top-level ``lock_version`` key, so a *renamed* lock — or any other
      producer's lock-shaped file, e.g. an issue-#88 tree generator's
      output — is skipped too.

    Args:
        path: A candidate JSON file.

    Returns:
        ``True`` if the file should never be parsed as an MCP config.
    """
    if path.name == _LOCK_FILENAME:
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return False
    return isinstance(data, dict) and "lock_version" in data


def _get_client_specs() -> list[ClientSpec]:
    """Return client specifications for the current platform."""
    system = platform.system()
    home = _home()

    clients: list[ClientSpec] = []

    # Claude Desktop
    if system == "Darwin":
        claude_desktop_path = (
            home
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    elif system == "Windows":
        appdata = _home() / "AppData" / "Roaming"
        claude_desktop_path = appdata / "Claude" / "claude_desktop_config.json"
    else:  # Linux
        claude_desktop_path = home / ".config" / "Claude" / "claude_desktop_config.json"

    clients.append(
        ClientSpec(
            name="claude-desktop",
            root_key="mcpServers",
            config_paths=[claude_desktop_path],
        )
    )

    # Cursor
    clients.append(
        ClientSpec(
            name="cursor",
            root_key="mcpServers",
            config_paths=[home / ".cursor" / "mcp.json"],
        )
    )

    # VS Code — workspace-level configs discovered separately
    # Note: VS Code uses "servers" not "mcpServers"
    clients.append(
        ClientSpec(
            name="vscode",
            root_key="servers",
            config_paths=[],  # Workspace configs found via --path or CWD scanning
        )
    )

    # Windsurf
    clients.append(
        ClientSpec(
            name="windsurf",
            root_key="mcpServers",
            config_paths=[home / ".codeium" / "windsurf" / "mcp_config.json"],
        )
    )

    # Claude Code (user-level)
    clients.append(
        ClientSpec(
            name="claude-code",
            root_key="mcpServers",
            # ~/.claude/settings.json holds user-level hooks and permissions but no
            # MCP servers; it is discovered so config-level checks (HOOK-*,
            # CFHYG-005/006, HARNESS-*) see it.  Added in STORY-0079.
            config_paths=[home / ".claude.json", home / ".claude" / "settings.json"],
        )
    )

    # GitHub Copilot CLI
    clients.append(
        ClientSpec(
            name="copilot-cli",
            root_key="mcpServers",
            config_paths=[home / ".copilot" / "mcp-config.json"],
        )
    )

    # Augment Code — settings.json may contain non-MCP keys alongside mcpServers
    clients.append(
        ClientSpec(
            name="augment",
            root_key="mcpServers",
            config_paths=[home / ".augment" / "settings.json"],
        )
    )

    # Amazon Q Developer — project-level only; see _PROJECT_CONFIG_SPECS below.
    # No user-global config path is documented, so no entry is added here.

    # Codex — ``[mcp_servers.<name>]`` tables in ``$CODEX_HOME/config.toml``
    # (default ``~/.codex``), read as TOML by the parser (STORY-0110).
    clients.append(
        ClientSpec(
            name=CODEX_CLIENT,
            root_key=CODEX_ROOT_KEY,
            config_paths=[codex_user_config_path()],
        )
    )

    # Gemini CLI — ``mcpServers`` in ``~/.gemini/settings.json`` (JSON with
    # comments; STORY-0110).
    clients.append(
        ClientSpec(
            name=GEMINI_CLIENT,
            root_key="mcpServers",
            config_paths=[gemini_user_config_path()],
        )
    )

    return clients


#: Client names for Codex and Gemini CLI (STORY-0110).  A server found in the
#: working directory's ``.codex/config.toml`` / ``.gemini/settings.json`` by a
#: default scan is labelled ``<client>-project`` (as ``claude-code-project``),
#: so it never shares a rug-pull key with a user-level server of the same
#: name; ``scan --project`` and ``lock`` use the plain name, as for the other
#: project config files.
CODEX_CLIENT = "codex"
GEMINI_CLIENT = "gemini-cli"
CODEX_ROOT_KEY = "mcp_servers"

#: Parser dialect for each Codex / Gemini CLI client label.
_HARNESS_DIALECT: dict[str, str] = {
    CODEX_CLIENT: "codex",
    f"{CODEX_CLIENT}-project": "codex",
    GEMINI_CLIENT: "gemini",
    f"{GEMINI_CLIENT}-project": "gemini",
}


def codex_user_config_path() -> Path:
    """Codex's user config: ``$CODEX_HOME/config.toml``, else ``~/.codex/config.toml``.

    Codex reads ``CODEX_HOME`` when it is set and non-empty
    (``codex-rs/utils/home-dir``); the value is resolved like any user path.
    """
    override = os.environ.get("CODEX_HOME", "").strip()
    if override:
        try:
            return Path(override).expanduser().resolve() / "config.toml"
        except (OSError, RuntimeError):
            return Path(override).expanduser() / "config.toml"
    return _home() / ".codex" / "config.toml"


def gemini_user_config_path() -> Path:
    """Gemini CLI's user settings file, ``~/.gemini/settings.json``."""
    return _home() / ".gemini" / "settings.json"


@dataclass
class DiscoveredConfig:
    """A discovered MCP configuration file."""

    client_name: str
    root_key: str
    path: Path
    raw: dict = field(default_factory=dict)
    # True when found via discover_project_configs() (--project flag).
    # Never set by the normal user-level discovery path.
    is_project_scoped: bool = False
    # True when `path` is itself a symlink (TRUST-002/TRUST-004). The file is
    # still parsed normally — Path.read_text() follows a symlink transparently,
    # so scan coverage is unaffected. This field exists purely to make what
    # used to be a silent `continue` visible as a finding.
    is_symlink: bool = False
    # Set only when `is_symlink` is True. `None` means "info-shaped" (TRUST-004
    # — a user-global or explicitly-requested path; dotfile managers routinely
    # manage exactly these paths this way, so severity stays INFO regardless
    # of where the target resolves). A concrete Path means "boundary-shaped"
    # (TRUST-002 — a project- or cwd-scoped path; severity depends on whether
    # the resolved target falls inside or outside this root).
    symlink_root: Path | None = None
    # Notes from parse_config() about content it could read only in part (a
    # subagent definition whose frontmatter has a security-relevant key strict
    # YAML rejects). Callers that report errors append these to
    # ScanResult.errors, so partly-read content is never dropped silently.
    parse_warnings: list[str] = field(default_factory=list)
    # How parse_config() reads the file when the path alone does not say:
    # ``"codex"`` (TOML, ``[mcp_servers.<name>]`` tables) or ``"gemini"``
    # (``settings.json`` with comments, ``httpUrl``/``type`` transports).
    # ``None`` lets the parser infer it from the path (a ``.toml`` suffix, or
    # ``.gemini/settings.json``) and otherwise read plain JSON (STORY-0110).
    dialect: str | None = None


def _agent_definitions_home() -> Path:
    """Home directory whose ``.claude/agents/`` holds user-level subagents.

    Separate from :func:`_home` only so tests can point user-level subagent
    discovery at an empty directory without moving every other client path.
    """
    return _home()


def agent_definition_scope(path: Path) -> str:
    """Return ``"user"`` for a file under ``~/.claude/agents/``, else ``"project"``.

    Used by config-level checks that receive only a path. The unresolved path
    is compared first, so a dotfile-managed (symlinked) user agent stays
    user-scoped.
    """
    user_dir = _agent_definitions_home() / ".claude" / "agents"
    candidates = [path]
    try:
        candidates.append(path.resolve())
        user_dirs = [user_dir, user_dir.resolve()]
    except OSError:
        user_dirs = [user_dir]
    for candidate in candidates:
        for base in user_dirs:
            if candidate.is_relative_to(base):
                return "user"
    return "project"


def _agent_definition_configs(
    paths: list[Path],
    *,
    is_project_scoped: bool,
    errors: list[str] | None = None,
    findings: list[Finding] | None = None,
) -> list[DiscoveredConfig]:
    """Wrap subagent definition files as configs, within the per-scan budgets.

    Keeps files that open with frontmatter and are at most 1 MiB (Claude Code
    skips larger ones), up to the per-scan file and byte budgets; every skip
    other than "no frontmatter" goes to *errors*, and the files past the
    budget are pre-screened for security keys into *findings* (see
    :func:`~mcp_audit.agent_files.subagents.select_agent_definitions`).
    A symlinked definition is reported by the agent-file resolver itself
    (TRUST-002/TRUST-004 into ``skip_findings``), so ``is_symlink`` stays
    ``False`` here and the finding is not emitted twice.
    """
    from mcp_audit.agent_files.subagents import (  # noqa: PLC0415
        select_agent_definitions,
    )

    return [
        DiscoveredConfig(
            client_name=AGENT_DEFINITION_CLIENT,
            root_key="mcpServers",
            path=path,
            is_project_scoped=is_project_scoped,
        )
        for path in select_agent_definitions(paths, errors, findings)
    ]


def _resolved_or_self(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def _safe_is_symlink(path: Path) -> bool:
    """``Path.is_symlink`` that treats an unreadable path as not a link."""
    try:
        return path.is_symlink()
    except OSError:
        return False


def _safe_is_file(path: Path) -> bool:
    """``Path.is_file`` that treats an unreadable path as not a file."""
    try:
        return path.is_file()
    except OSError:
        return False


def _safe_is_dir(path: Path) -> bool:
    """``Path.is_dir`` that treats an unreadable path as not a directory."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _reached_through_symlink(base: Path, rel_path: str) -> bool:
    """True when a directory between *base* and ``base / rel_path`` is a symlink.

    Only the intermediate components are checked (``.claude`` in
    ``.claude/settings.json``); the final component is the caller's own
    ``is_symlink`` test.  A symlinked parent (``.claude -> /elsewhere``) puts
    the file outside the reviewed tree just as a symlinked file does
    (STORY-0090 for auto-run files, STORY-0108 for project MCP configs and
    settings), so the candidate is reported as TRUST-002, not as the
    repository's own file.  An unreadable component counts as not a link.
    """
    current = base
    for part in Path(rel_path).parts[:-1]:
        current = current / part
        if _safe_is_symlink(current):
            return True
    return False


# ── Symlink findings (TRUST-002 / TRUST-004 / TRUST-005) ──────────────────────
#
# See humans/decisions/2026-09-08-trust-002-symlink-sites.md (marcus repo) for
# the full design rationale. Two harms, deliberately kept as separate axes:
#
#   Evasion (read-side): the scanner skipped a symlinked candidate, so a real
#   config went unexamined and the user got a report covering less than they
#   think. Present regardless of where the link points — fixed by never
#   `continue`-ing past a symlinked candidate; the OS follows the link
#   transparently for the actual read, so coverage is restored "for free."
#
#   Escape (write-side): the symlink's resolved target falls outside the
#   boundary being scanned, so the visible, reviewed (and, for a git-tracked
#   project file, committed) path is a decoy for content that actually lives
#   somewhere else on the host. This is what makes a project-scoped symlink
#   (TRUST-002) severity-worthy in a way a user-global one (TRUST-004) is
#   not: dotfile managers (GNU Stow, chezmoi, yadm, dotbot) manage
#   ~/.claude.json, ~/.cursor/mcp.json, and equivalent paths by symlinking
#   them into a dotfiles repo — that is correct, common, and not an attack.
_SYMLINK_CWE = "CWE-61"
_SYMLINK_OWASP = ["MCP09", "MCP05"]


def _resolve_symlink_target(path: Path) -> tuple[str, bool]:
    """Resolve *path* (a known symlink) for reporting only.

    Never opens or parses the target beyond what the normal read path
    already does via OS-level symlink following.

    Returns:
        ``(resolved_str, broken)`` — ``resolved_str`` is the best-effort
        absolute resolved path (``Path.resolve()`` never raises for a
        nonexistent target); ``broken`` is ``True`` when the target does not
        exist (``path.exists()`` follows the link).
    """
    resolved = path.resolve()
    return str(resolved), not path.exists()


def build_project_symlink_finding(path: Path, client_name: str, root: Path) -> Finding:
    """TRUST-002: a project- or cwd-scoped config candidate path is a symlink.

    Severity: INFO for a broken/dangling link (there is no live target to
    escape to, and treating a stale link as an attack teaches people to
    ignore the finding); HIGH when the resolved target falls outside *root*
    (the reviewed/committed path is a decoy for content that lives elsewhere
    — the GhostApproval shape: ``.mcp.json -> ~/.ssh/authorized_keys``, and
    git preserves the symlink for whoever clones the repo); MEDIUM when the
    target resolves inside *root* (worth a second look, but not a boundary
    violation).
    """
    resolved_str, broken = _resolve_symlink_target(path)
    if broken:
        severity = Severity.INFO
        note = "The link is broken — there is no live target to inspect."
    else:
        try:
            Path(resolved_str).relative_to(root.resolve())
        except ValueError:
            severity = Severity.HIGH
            note = (
                "The resolved target falls OUTSIDE the scanned root — the"
                " reviewed (and, if committed, version-controlled) path is a"
                " decoy for content that actually lives elsewhere on this host."
            )
        else:
            severity = Severity.MEDIUM
            note = "The resolved target stays inside the scanned root."
    return Finding(
        id="TRUST-002",
        severity=severity,
        analyzer="discovery",
        client=client_name,
        server=path.name,
        title="Project-scoped config path is a symlink",
        description=(
            f"'{path}' is a symlink, not a real file. {note} Because git"
            " preserves symlinks, this can ship inside a repository and"
            " silently redirect a reviewer's approval to different content on"
            " whichever host later clones, opens, and trusts it."
        ),
        evidence=f"Visible path: {path} | Resolved target: {resolved_str}",
        remediation=(
            "Replace the symlink with a real, reviewable file at this path."
            " If a symlink is required, verify the resolved target's exact"
            " content directly — do not rely on this path's own git history"
            " to reflect it."
        ),
        finding_path=str(path),
        owasp_mcp_top_10=list(_SYMLINK_OWASP),
        cwe=_SYMLINK_CWE,
    )


def build_info_symlink_finding(path: Path, client_name: str) -> Finding:
    """TRUST-004: a user-global or explicitly-requested config path is a symlink.

    Always INFO. Dotfile managers (GNU Stow, chezmoi, yadm, dotbot) routinely
    manage exactly these paths this way — this must never read as an
    accusation, or a rule that fires on every correctly-configured machine
    gets switched off wholesale. Coverage is unaffected: the caller still
    reads *path* normally (OS-level symlink following returns the real
    target's bytes) — this finding only makes that fact visible.
    """
    resolved_str, broken = _resolve_symlink_target(path)
    detail = (
        "the link is broken (no target exists)"
        if broken
        else f"resolved target: {resolved_str}"
    )
    return Finding(
        id="TRUST-004",
        severity=Severity.INFO,
        analyzer="discovery",
        client=client_name,
        server=path.name,
        title="Config path is a symlink",
        description=(
            f"'{path}' is a symlink ({detail}). This is commonly how dotfile"
            " managers (GNU Stow, chezmoi, yadm, dotbot) keep client configs"
            " under version control — no action is required if this was set"
            " up intentionally. mcp-audit scanned the file's real content"
            " through the link."
        ),
        evidence=f"Visible path: {path} | Resolved target: {resolved_str}",
        remediation=(
            "No action required if this symlink is intentional (e.g. a"
            " dotfile manager). Otherwise, verify what it points to."
        ),
        finding_path=str(path),
        owasp_mcp_top_10=["MCP09"],
        cwe=_SYMLINK_CWE,
    )


def build_untraversed_symlink_dir_finding(path: Path, client_name: str) -> Finding:
    """TRUST-005: a symlinked directory was not traversed during discovery.

    mcp-audit never follows a symlinked directory while walking a tree — loop
    and blow-up protection that predates this finding and does not change.
    That refusal used to be entirely silent; this finding makes it visible so
    a config or agent-instruction file nested only inside a symlinked
    directory does not disappear from a scan with no explanation. Always LOW:
    this is a coverage note, not an accusation — the directory itself may be
    completely benign (a monorepo tooling symlink, a package-manager link).
    """
    return Finding(
        id="TRUST-005",
        severity=Severity.LOW,
        analyzer="discovery",
        client=client_name,
        server=path.name,
        title="Symlinked directory was not scanned",
        description=(
            f"'{path}' is a symlinked directory. mcp-audit does not follow"
            " symlinked directories while walking a tree (this prevents"
            " symlink loops and runaway recursion), so nothing under this"
            " path was examined by this scan."
        ),
        evidence=f"Directory: {path}",
        remediation=(
            "If this directory can contain MCP configs or agent-instruction"
            " files, scan it directly (e.g. --path) or replace the symlink"
            " with a real directory."
        ),
        finding_path=str(path),
        owasp_mcp_top_10=["MCP09"],
        cwe=_SYMLINK_CWE,
    )


def discover_configs(
    extra_paths: list[Path] | None = None,
    skip_auto_discovery: bool = False,
    include_plugins: bool = True,
    include_agents: bool = True,
    skip_findings: list[Finding] | None = None,
    errors: list[str] | None = None,
    include_gateways: bool = True,
) -> list[DiscoveredConfig]:
    """Find all MCP configuration files on this machine.

    Args:
        extra_paths: Additional paths to check (e.g., from --path flag).
        skip_auto_discovery: When ``True``, skip known-client and CWD discovery
            and return only configs built from *extra_paths*.  Used when the
            caller has already provided an explicit config path — combining
            that with auto-discovery would inflate ``clients_scanned`` with
            zero-server system configs.
        include_plugins: Also return the MCP server declarations shipped by
            installed Claude Code plugins (``.mcp.json`` or inline
            ``mcpServers`` in ``plugin.json``), as client ``claude-code-plugin``
            (STORY-0080).  On by default as part of auto-discovery, so it is
            ignored when *skip_auto_discovery* is ``True``: an explicit config
            path never pulls in plugin servers.  Pass ``False`` to opt out.
        include_agents: Also return Claude Code subagent definitions
            (``~/.claude/agents/**/*.md`` and ``<cwd>/.claude/agents/**/*.md``
            files that open with frontmatter) as client
            ``claude-code-agent`` (STORY-0094).  Their inline ``mcpServers``
            become servers; their frontmatter feeds AGENT-001..004 and
            HOOK-001/002 at pipeline step 0.  Same rules as *include_plugins*:
            on by default, ignored with *skip_auto_discovery*; ``lock`` passes
            ``False``.
        skip_findings: Optional list to receive TRUST-002/004/005 findings for
            symlinked subagent files and untraversed symlinked directories
            under the agents directories (the other candidates here are fixed
            paths and report symlinks through ``is_symlink`` instead).
        errors: Optional list to receive subagent-discovery filesystem errors
            and budget notes (a scan's ``result.errors``).
        include_gateways: Also return the config files of MCP gateways
            (mcptoon, 1MCP, MCPHub; :mod:`mcp_audit.gateways`), whose upstream
            servers become servers of client ``<gateway>-upstream``
            (STORY-0111): the user-level files, and the working directory's
            project files (``.mcptoon.json``, ``.mcptoon.toml``,
            ``.mcphub/servers.json``, marked ``is_project_scoped``).  Same rules
            as *include_plugins*: on by default, ignored with
            *skip_auto_discovery*; ``lock`` passes ``False``.

    Returns:
        List of discovered configuration files.  A candidate that is itself a
        symlink is included (``is_symlink=True``) rather than skipped — the
        caller still reads it normally (the OS follows the link transparently)
        and is expected to emit a TRUST-002/TRUST-004 finding for it via
        :func:`build_project_symlink_finding` / :func:`build_info_symlink_finding`.
    """
    discovered: list[DiscoveredConfig] = []

    if not skip_auto_discovery:
        # Check known client locations. User-global — info-shaped (TRUST-004)
        # if a symlink: this is exactly the path shape dotfile managers own.
        for spec in _get_client_specs():
            for config_path in spec.config_paths:
                # An unreadable directory (PermissionError on ~/.codex) is
                # "not there", never a crash of the whole scan (STORY-0110).
                if _safe_is_symlink(config_path):
                    discovered.append(
                        DiscoveredConfig(
                            client_name=spec.name,
                            root_key=spec.root_key,
                            path=config_path,
                            is_symlink=True,
                            dialect=_HARNESS_DIALECT.get(spec.name),
                        )
                    )
                elif _safe_is_file(config_path):
                    discovered.append(
                        DiscoveredConfig(
                            client_name=spec.name,
                            root_key=spec.root_key,
                            path=config_path,
                            dialect=_HARNESS_DIALECT.get(spec.name),
                        )
                    )

        # Gateway configs (STORY-0111): the servers behind an MCP gateway.
        # User-global — info-shaped (TRUST-004) if a symlink, like the client
        # configs above.
        if include_gateways:
            for gw_client, gw_path in user_gateway_config_paths():
                if _safe_is_symlink(gw_path):
                    discovered.append(
                        DiscoveredConfig(
                            client_name=gw_client,
                            root_key="servers",
                            path=gw_path,
                            is_symlink=True,
                        )
                    )
                elif _safe_is_file(gw_path):
                    discovered.append(
                        DiscoveredConfig(
                            client_name=gw_client, root_key="servers", path=gw_path
                        )
                    )

        # Check for VS Code / Claude Code project-level configs in CWD.
        # Boundary-shaped (TRUST-002): these live inside whatever directory the
        # user is scanning from, the same GhostApproval risk as the --project
        # walk below — not the $HOME dotfile-manager shape.
        cwd = Path.cwd()
        # A path already discovered above is not added twice: with cwd ==
        # $HOME, .claude/settings.json *is* the user-level file (STORY-0082),
        # and a symlinked ~/.claude must not turn it into a project file with
        # a false TRUST-002 (STORY-0108).
        already = {_resolved_or_self(d.path) for d in discovered}
        at_home = _is_user_level_harness_dir(cwd)

        def _add_cwd_candidate(
            rel: str,
            client_name: str,
            root_key: str,
            dialect: str | None = None,
            project_scoped: bool = False,
        ) -> None:
            candidate = cwd / rel
            # A symlinked file or a symlinked parent (``.claude -> /elsewhere``)
            # is TRUST-002, never the checkout's own file (STORY-0108).
            linked = _safe_is_symlink(candidate) or (
                _reached_through_symlink(cwd, rel) and _safe_is_file(candidate)
            )
            if not linked and not _safe_is_file(candidate):
                return
            if _resolved_or_self(candidate) in already:
                # Same file as a user-level config already discovered: analyse
                # it once, as the user's.  A repository link into it (not a
                # scan from $HOME) is still reported, without a second parse.
                if linked and not at_home and skip_findings is not None:
                    skip_findings.append(
                        build_project_symlink_finding(candidate, client_name, cwd)
                    )
                return
            discovered.append(
                DiscoveredConfig(
                    client_name=client_name,
                    root_key=root_key,
                    path=candidate,
                    is_project_scoped=project_scoped,
                    is_symlink=linked,
                    symlink_root=cwd if linked else None,
                    dialect=dialect,
                )
            )

        # VS Code project config.  Boundary-shaped (TRUST-002): it lives inside
        # whatever directory the user is scanning from, the same GhostApproval
        # risk as the --project walk below, not the $HOME dotfile-manager shape.
        _add_cwd_candidate(".vscode/mcp.json", "vscode", "servers")

        # Claude Code's project files: the server list (.mcp.json) and the
        # settings that govern approval (.claude/settings.json, committed, and
        # .claude/settings.local.json, personal).  The settings files carry no
        # servers as a rule, but config hygiene reads them for HOOK-001/002 and
        # HARNESS-001..004 — so a scan run from a repo checkout (the GitHub
        # Action's default) sees a commit that switches approval off
        # (STORY-0082).
        for rel in (
            ".mcp.json",
            ".claude/settings.json",
            ".claude/settings.local.json",
        ):
            _add_cwd_candidate(rel, "claude-code-project", "mcpServers")

        # Codex and Gemini CLI project files at the working directory's root
        # (STORY-0110): their MCP servers, as <client>-project, so a repository
        # server never shares a rug-pull key with a same-named user server.
        for rel, client_name, root_key, dialect in _HARNESS_CWD_SPECS:
            _add_cwd_candidate(rel, client_name, root_key, dialect)

        # A gateway's project config in the working directory (STORY-0111):
        # mcptoon reads ./.mcptoon.json and ./.mcptoon.toml from the directory
        # it runs in, MCPHub.nvim's workspace detection reads
        # .mcphub/servers.json.  Marked project-scoped so the servers stay in
        # this directory's rug-pull state key and lock auto-verification lists
        # them as not covered, like a repository's skills-directory plugin.
        if include_gateways:
            for rel, gw_client in PROJECT_GATEWAY_FILES:
                _add_cwd_candidate(rel, gw_client, "servers", project_scoped=True)

    # Check extra paths. Explicit — info-shaped (TRUST-004): the user named
    # this path themselves, and today's silent `continue` here is a plain bug
    # (a request for this exact path getting silence, not just an unscanned
    # default). Resolve and scan it like any other; there is no natural
    # "root" boundary to compare an arbitrary --path against.
    if extra_paths:
        for p in extra_paths:
            expanded = Path(p).expanduser()
            if expanded.is_symlink():
                discovered.append(
                    DiscoveredConfig(
                        client_name="custom",
                        root_key="mcpServers",
                        path=expanded,
                        is_symlink=True,
                    )
                )
                continue
            resolved = expanded.resolve()
            if resolved.is_file() and resolved.exists():
                if is_lock_file(resolved):
                    continue
                discovered.append(
                    DiscoveredConfig(
                        client_name="custom",
                        root_key="mcpServers",  # Assume default; parser will try both
                        path=resolved,
                    )
                )
            elif resolved.is_dir():
                # Scan all JSON files in the directory.  The parser handles
                # root-key detection (mcpServers vs servers) and silently
                # returns [] for files that contain neither key.
                for candidate in sorted(resolved.glob("*.json")):
                    if is_lock_file(candidate):
                        continue
                    if candidate.is_symlink():
                        discovered.append(
                            DiscoveredConfig(
                                client_name="custom",
                                root_key="mcpServers",
                                path=candidate,
                                is_symlink=True,
                            )
                        )
                        continue
                    if candidate.is_file():
                        discovered.append(
                            DiscoveredConfig(
                                client_name="custom",
                                root_key="mcpServers",
                                path=candidate,
                            )
                        )

    if include_plugins and not skip_auto_discovery:
        from mcp_audit.plugins.discovery import (  # noqa: PLC0415
            discover_installed_plugins,
            plugin_mcp_config_paths,
        )

        for plugin_config in plugin_mcp_config_paths(discover_installed_plugins()):
            discovered.append(
                DiscoveredConfig(
                    client_name="claude-code-plugin",
                    root_key="mcpServers",
                    path=plugin_config,
                )
            )
        discovered.extend(_skills_dir_plugin_configs(discovered))

    if include_agents and not skip_auto_discovery:
        discovered.extend(_discover_agent_definition_configs(skip_findings, errors))

    return discovered


#: Codex and Gemini CLI project files a default scan reads at the working
#: directory's root: (relative path, client, root key, parser dialect).
_HARNESS_CWD_SPECS: tuple[tuple[str, str, str, str], ...] = (
    (".codex/config.toml", "codex-project", "mcp_servers", "codex"),
    (".gemini/settings.json", "gemini-cli-project", "mcpServers", "gemini"),
)


def _discover_agent_definition_configs(
    skip_findings: list[Finding] | None,
    errors: list[str] | None = None,
) -> list[DiscoveredConfig]:
    """User-level and cwd subagent definitions for :func:`discover_configs`.

    The cwd check mirrors the cwd ``.mcp.json`` / ``.claude/settings.json``
    checks above: only ``<cwd>/.claude/agents/`` is read, not the directories
    between the cwd and the repository root (``scan --project`` walks the
    tree). When the cwd is the home directory, its agents are user-level.
    A filesystem error is recorded in *errors* and never stops the scan.
    """
    from mcp_audit.agent_files.discovery import (  # noqa: PLC0415
        agent_definition_paths,
    )

    raw_skip: list[Finding] = []
    home = _agent_definitions_home()

    def _paths(base: Path, scope: str, root: Path | None) -> list[Path]:
        try:
            return agent_definition_paths(base, scope, root, raw_skip)
        except OSError as exc:
            if errors is not None:
                errors.append(
                    f"Could not read subagent definitions under {base}: {exc}"
                )
            return []

    user_paths = _paths(home, "user", None)
    try:
        cwd = Path.cwd()
    except OSError:
        cwd = None
    seen = {_resolved_or_self(p) for p in user_paths}
    cwd_paths = (
        [p for p in _paths(cwd, "project", cwd) if _resolved_or_self(p) not in seen]
        if cwd is not None
        else []
    )
    if skip_findings is not None:
        keys: set[tuple[str, str | None]] = set()
        for finding in raw_skip:
            key = (finding.id, finding.finding_path)
            if key not in keys:
                keys.add(key)
                skip_findings.append(finding)
    return _agent_definition_configs(
        user_paths + cwd_paths,
        is_project_scoped=False,
        errors=errors,
        findings=skip_findings,
    )


def discover_project_agent_configs(
    root: Path,
    skip_findings: list[Finding] | None = None,
    errors: list[str] | None = None,
) -> list[DiscoveredConfig]:
    """Walk *root* for subagent definitions (``.claude/agents/**/*.md``).

    The ``scan --project`` counterpart of :func:`discover_project_configs`,
    kept separate so ``mcp-audit lock`` (which records
    :func:`discover_project_configs` output) never sees inline subagent
    servers. Uses the agent-file walk (same depth cap, skip list and symlink
    rules), restricted to the subagent entries of ``AGENT_INSTRUCTION_PATTERNS``.

    Args:
        root: Resolved absolute path of the repository root to walk.
        skip_findings: Optional list to receive TRUST-002/TRUST-005 findings,
            and the AGENT findings for definitions past the per-scan budget.
        errors: Optional list to receive filesystem errors and budget notes;
            a filesystem error never stops the scan.

    Returns:
        Project-scoped :class:`DiscoveredConfig` objects with client
        ``claude-code-agent``.
    """
    from mcp_audit.agent_files.discovery import (  # noqa: PLC0415
        project_agent_definition_paths,
    )

    try:
        paths = project_agent_definition_paths(root, skip_findings)
    except OSError as exc:
        if errors is not None:
            errors.append(f"Could not read subagent definitions under {root}: {exc}")
        return []
    return _agent_definition_configs(
        paths, is_project_scoped=True, errors=errors, findings=skip_findings
    )


def _skills_dir_plugin_configs(
    already: list[DiscoveredConfig],
) -> list[DiscoveredConfig]:
    """MCP servers of skills-directory plugins (STORY-0095).

    A folder directly under ``~/.claude/skills/`` or ``<cwd>/.claude/skills/``
    that holds ``.claude-plugin/plugin.json`` is loaded by Claude Code as the
    plugin ``<name>@skills-dir`` (docs: plugins/loading), so its ``.mcp.json``
    and inline ``mcpServers`` join discovery as client ``claude-code-plugin``,
    with that client's lock exclusions.  The working directory's are marked
    project-scoped, so they stay in the rug-pull state key.  Never raises;
    filesystem errors surface in the skill pass of the same scan.
    """
    from mcp_audit.agent_files import skill_package  # noqa: PLC0415

    seen: set[str] = set()
    for config in already:
        try:
            seen.add(str(config.path.resolve()))
        except (OSError, RuntimeError):
            seen.add(str(config.path))
    out: list[DiscoveredConfig] = []
    try:
        packages = skill_package.default_skill_packages()
        configs = skill_package.skills_dir_plugin_mcp_configs(packages)
    except Exception:  # noqa: BLE001 — discovery must not crash on a skills dir
        return out
    for config in configs:
        try:
            key = str(config.path.resolve())
        except (OSError, RuntimeError):
            key = str(config.path)
        if key not in seen:
            seen.add(key)
            out.append(config)
    return out


# ── Project-level config discovery (for --project flag) ───────────────────────

# Project-scoped config files, each as (relative-path, client-name, root-key).
# These are files that live *inside* a repository and are typically committed to
# version control, causing the named MCP server to auto-spawn for every developer
# who trusts the folder in a supporting AI editor.
#
# Research basis: Adversa TrustFall (May 2026), corroborated by CVE-2026-30615.
# OWASP MCP09: Shadow MCP Servers.
#
# Confirmed-active clients and paths (verified against official docs, 2026-06-11):
#   Claude Code  — .mcp.json                   (Anthropic official docs)
#   Claude Code  — .claude/settings.json        (project settings, mcpServers key)
#   Claude Code  — .claude/settings.local.json  (local override, same schema)
#   Cursor       — .cursor/mcp.json             (Cursor official docs)
#   Cursor       — .cursor/settings.json        (workspace settings; inclusion
#                                                tentative — see GAPS.md)
#   VS Code      — .vscode/mcp.json             (VS Code official docs; "servers" key)
#   Amazon Q Developer — .amazonq/mcp.json      (AWS official docs; "mcpServers" key,
#                                                same schema as Claude Code/Cursor)
#
# Windsurf: global-only config (~/.codeium/windsurf/mcp_config.json); no
#   project-level MCP file — omitted intentionally.
# Zed: uses "context_servers" key in settings.json; different schema — omitted.
# Continue.dev: YAML-based (.continue/config.yaml) — out of scope for JSON parser.
#
# Added in STORY-0110, from each vendor's source and docs (2026-10-28):
#   Codex       — .codex/config.toml in every directory from the project root
#                 down to the working directory, loaded when the project is
#                 trusted ("loaded but disabled when untrusted",
#                 codex-rs/config/src/loader/mod.rs); `mcp_servers` is not on
#                 Codex's project-config deny list.  TOML.
#   Gemini CLI  — .gemini/settings.json in the project root ("Project settings
#                 file", docs/reference/configuration.md); ignored in an
#                 untrusted folder.  JSON with comments.
# Each harness skips its project file when it is the user's own file (the
# working directory is $HOME, or .codex is $CODEX_HOME); so does the walk.
_PROJECT_CONFIG_SPECS: list[tuple[str, str, str]] = [
    (".mcp.json", "claude-code", "mcpServers"),
    (".claude/settings.json", "claude-code", "mcpServers"),
    (".claude/settings.local.json", "claude-code", "mcpServers"),
    (".cursor/mcp.json", "cursor", "mcpServers"),
    (".cursor/settings.json", "cursor", "mcpServers"),
    (".vscode/mcp.json", "vscode", "servers"),
    (".amazonq/mcp.json", "amazon-q", "mcpServers"),
    (".codex/config.toml", "codex", "mcp_servers"),
    (".gemini/settings.json", "gemini-cli", "mcpServers"),
]

# Non-MCP IDE auto-execution surfaces (TRUST-003). These files have no
# mcpServers/servers root key, so they are walked separately from
# _PROJECT_CONFIG_SPECS and handed to the config-hygiene analyzer at
# pipeline step 0 as DiscoveredAutoexecFile objects — never through
# parse_config() and never turned into a ServerConfig.
#
# Research basis: two live 2026 worms (Keyv npm worm; Shai-Hulud "V.A.P.E"
# via the official MCP Registry) planted a `.claude/settings.json`
# SessionStart hook (already covered by CFHYG-005/HOOK-001/002) AND a
# `.vscode/tasks.json` task with `"runOn": "folderOpen"` — the second file
# was previously invisible to mcp-audit.
#
# TRUST-008 (STORY-0090) adds other harnesses' repo-planted auto-run files,
# each confirmed from the vendor's own docs (see docs/agent-execution-surface.md):
#   Gemini CLI   — .gemini/settings.json (`hooks`, `tools.enableHooks`) and
#                  .gemini/.env (loaded into the CLI's environment unless the
#                  folder is marked untrusted; headless mode trusted every
#                  workspace before 0.39.1).
#                  Miasma (2026-06) planted a SessionStart hook here.
#   Codex        — .codex/config.toml (`notify`, `approval_policy`,
#                  `sandbox_mode`, inline `[hooks]`) and .codex/hooks.json;
#                  loaded when the project is trusted.
#   Claude Code  — .claude/scheduled_tasks.json and the .claude/workflows/
#                  directory, which Anthropic's sandboxing doc lists as
#                  "files Claude Code runs on its own".
_PROJECT_AUTOEXEC_SPECS: list[tuple[str, str]] = [
    (".vscode/tasks.json", "vscode-tasks"),
    (".vscode/settings.json", "vscode-settings"),
    (".gemini/settings.json", "gemini-settings"),
    (".gemini/.env", "gemini-env"),
    (".codex/config.toml", "codex-config"),
    (".codex/hooks.json", "codex-hooks"),
    (".claude/scheduled_tasks.json", "claude-scheduled-tasks"),
    (".claude/workflows", "claude-workflows"),
]

#: Autoexec kinds whose candidate path is a directory, not a file.
_AUTOEXEC_DIR_KINDS: frozenset[str] = frozenset({"claude-workflows"})

#: Client label attached to findings for each autoexec kind.
_AUTOEXEC_KIND_CLIENT: dict[str, str] = {
    "vscode-tasks": "vscode",
    "vscode-settings": "vscode",
    "gemini-settings": "gemini-cli",
    "gemini-env": "gemini-cli",
    "codex-config": "codex",
    "codex-hooks": "codex",
    "claude-scheduled-tasks": "claude-code",
    "claude-workflows": "claude-code",
}

#: TRUST-008's kinds: auto-run files of harnesses other than VS Code.  The
#: ``--project`` walk skips them directly under ``$HOME`` (user config).  Every
#: autoexec kind, TRUST-003's VS Code files included, is also read at the root
#: of the working directory by a default scan (:func:`discover_cwd_autoexec_files`),
#: so ``scan``/``check`` run from a checkout (the GitHub Action's default) see
#: them.
SIBLING_HARNESS_AUTOEXEC_KINDS: frozenset[str] = frozenset(
    {
        "gemini-settings",
        "gemini-env",
        "codex-config",
        "codex-hooks",
        "claude-scheduled-tasks",
        "claude-workflows",
    }
)


# Directory names to skip while walking the project tree.  ``.git`` stays
# skipped: discover_project_git_surfaces() records each .git entry it passes
# and git_exec reads only its config files and hooks listing (STORY-0089).
_WALK_SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".tox",
        "venv",
        ".venv",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)

# Maximum directory depth to descend from the project root (inclusive).
# Depth 0 = root itself, depth 8 = 8 levels below root.
_WALK_MAX_DEPTH: int = 8


def discover_project_configs(
    root: Path,
    skip_findings: list[Finding] | None = None,
    include_gateways: bool = False,
) -> list[DiscoveredConfig]:
    """Walk a repository tree and find all project-level MCP config files.

    This function is the discovery back-end for ``mcp-audit scan --project``.
    It is entirely separate from :func:`discover_configs` and does **not**
    alter the default scan behaviour.

    Walk rules:
    - Skips directories named in :data:`_WALK_SKIP_DIRS`.
    - Caps recursion at depth :data:`_WALK_MAX_DEPTH` below *root*.
    - Does **not** follow symlinked directories (loop/blow-up protection —
      unchanged); when *skip_findings* is given, each one not traversed
      appends a TRUST-005 (LOW) finding naming it, so the refusal is
      visible instead of silent.
    - A config candidate that is itself a symlink is *included*
      (``is_symlink=True``, ``symlink_root=root``) rather than skipped — the
      caller still parses it normally and is expected to emit a TRUST-002
      finding via :func:`build_project_symlink_finding`.  So is a file reached
      through a symlinked parent directory (``.claude -> /elsewhere`` makes
      ``.claude/settings.json`` a TRUST-002 candidate, STORY-0108), the rule
      :func:`_autoexec_candidate` applies to auto-run files.

    Args:
        root: Resolved absolute path of the repository root to walk.
        skip_findings: Optional list to append TRUST-005 findings to for
            symlinked directories that were not traversed.  When ``None``,
            those directories are still skipped, just silently (as before).
        include_gateways: Also return MCP gateway project configs
            (:data:`mcp_audit.gateways.PROJECT_GATEWAY_FILES`, STORY-0111),
            with the same symlink rules.  ``scan --project`` passes ``True``;
            ``mcp-audit lock`` does not, so locks never record gateway
            upstreams.

    Returns:
        List of :class:`DiscoveredConfig` objects with
        ``is_project_scoped=True``.  The list is empty when no project-level
        MCP config files are found under *root*.
    """
    discovered: list[DiscoveredConfig] = []

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH:
            return

        # Check each known project-config pattern relative to this directory.
        specs = list(_PROJECT_CONFIG_SPECS)
        if include_gateways:
            specs += [(rel, client, "servers") for rel, client in PROJECT_GATEWAY_FILES]
        for rel_path, client_name, root_key in specs:
            candidate = dirpath / rel_path
            # A symlinked file, or a file reached through a symlinked parent
            # directory (``.claude -> /elsewhere``, STORY-0108), is a TRUST-002
            # candidate, not the repository's own file.
            if _safe_is_symlink(candidate) or (
                _reached_through_symlink(dirpath, rel_path) and _safe_is_file(candidate)
            ):
                if is_lock_file(candidate):
                    continue
                discovered.append(
                    DiscoveredConfig(
                        client_name=client_name,
                        root_key=root_key,
                        path=candidate,
                        is_project_scoped=True,
                        is_symlink=True,
                        symlink_root=root,
                    )
                )
                continue
            if _safe_is_file(candidate) and not is_lock_file(candidate):
                discovered.append(
                    DiscoveredConfig(
                        client_name=client_name,
                        root_key=root_key,
                        path=candidate,
                        is_project_scoped=True,
                    )
                )

        # Recurse into non-symlink subdirectories not in the skip list.
        try:
            children = sorted(dirpath.iterdir())
        except OSError:
            return

        for child in children:
            if _safe_is_symlink(child):
                if _safe_is_dir(child) and skip_findings is not None:
                    skip_findings.append(
                        build_untraversed_symlink_dir_finding(child, "project")
                    )
                continue
            if not _safe_is_dir(child):
                continue
            if child.name in _WALK_SKIP_DIRS:
                continue
            _walk(child, depth + 1)

    _walk(root, 0)
    return [c for c in discovered if not _is_user_harness_config(c)]


def _is_user_harness_config(config: DiscoveredConfig) -> bool:
    """True when a project-walk candidate is the user's own Codex/Gemini file.

    Walking ``$HOME`` (``scan --project ~``) reaches ``~/.codex/config.toml``
    and ``~/.gemini/settings.json``, which are user-level config, not a
    repository's.  Codex skips a ``.codex`` directory that is ``$CODEX_HOME``
    and Gemini CLI skips workspace settings that are the user settings, so
    the walk does the same instead of reporting the user's own servers as
    TRUST-001.  The comparison is by the directory the walk was in (the
    parent of ``.codex`` / ``.gemini``) and the names below it, not by
    following links: a dotfile-managed ``~/.gemini`` is still the user's, and
    a repository whose ``.gemini`` links into the home directory is still the
    repository's (TRUST-002).  With ``CODEX_HOME`` set elsewhere, ``~/.codex``
    is an ordinary project layer to Codex, and to the walk.
    """
    user_paths = {
        "codex": codex_user_config_path(),
        "gemini-cli": gemini_user_config_path(),
    }
    user_path = user_paths.get(config.client_name)
    if user_path is None:
        return False
    return (
        config.path.name == user_path.name
        and config.path.parent.name == user_path.parent.name
        and _resolved_or_self(config.path.parent.parent)
        == _resolved_or_self(user_path.parent.parent)
    )


@dataclass
class DiscoveredAutoexecFile:
    """A discovered non-MCP IDE auto-execution surface (TRUST-003 input).

    Deliberately **not** a :class:`DiscoveredConfig` — these files carry no
    ``mcpServers``/``servers`` root key and are never parsed into
    :class:`~mcp_audit.models.ServerConfig` objects.  They are read and
    analyzed directly by
    :meth:`~mcp_audit.analyzers.config_hygiene.ConfigHygieneAnalyzer.analyze_autoexec_file`.
    """

    kind: str  # one of the labels in _PROJECT_AUTOEXEC_SPECS
    path: Path
    is_project_scoped: bool = True
    # See DiscoveredConfig.is_symlink / symlink_root — same TRUST-002 shape.
    # Always project-scoped here, so symlink_root is always set when
    # is_symlink is True (there is no info-shaped case at this call site).
    is_symlink: bool = False
    symlink_root: Path | None = None

    @property
    def client(self) -> str:
        """Client label for findings about this file (``"vscode"`` by default)."""
        return _AUTOEXEC_KIND_CLIENT.get(self.kind, "vscode")


def _is_user_level_harness_dir(dirpath: Path) -> bool:
    """True when *dirpath* is the home directory itself.

    ``~/.gemini/``, ``~/.codex/`` and ``~/.claude/`` are each harness's
    user-level config directory, not a repository's, so a TRUST-008 kind found
    directly under ``$HOME`` (a scan run from the home directory) is the
    user's own setting and is skipped.
    """
    try:
        return dirpath.resolve() == _home().resolve()
    except (OSError, RuntimeError):
        return False


def _autoexec_candidate(
    dirpath: Path, rel_path: str, kind: str, root: Path, *, at_home: bool
) -> DiscoveredAutoexecFile | None:
    """Return the autoexec candidate *rel_path* under *dirpath*, if present.

    *at_home* is :func:`_is_user_level_harness_dir` for *dirpath*, computed
    once per directory by the caller.
    """
    if at_home and kind in SIBLING_HARNESS_AUTOEXEC_KINDS:
        return None
    candidate = dirpath / rel_path
    # A symlinked *parent* (``.gemini -> /elsewhere/.gemini``) puts the file
    # outside the reviewed tree just as a symlinked file does, so any link on
    # the way down makes this a TRUST-002 candidate, not the repo's own file.
    via_link = _reached_through_symlink(dirpath, rel_path)
    if candidate.is_symlink() or (via_link and candidate.exists()):
        return DiscoveredAutoexecFile(
            kind=kind, path=candidate, is_symlink=True, symlink_root=root
        )
    if candidate.is_file() or (kind in _AUTOEXEC_DIR_KINDS and candidate.is_dir()):
        return DiscoveredAutoexecFile(kind=kind, path=candidate)
    return None


def discover_cwd_autoexec_files(
    cwd: Path | None = None,
) -> list[DiscoveredAutoexecFile]:
    """Find auto-run files (TRUST-003, TRUST-008) at the working directory's root.

    The default-scan counterpart of :func:`discover_project_autoexec_files`:
    no tree walk, only *cwd* itself, for every kind in
    :data:`_PROJECT_AUTOEXEC_SPECS`, mirroring how a default scan already
    reads ``.claude/settings.json`` at the cwd root (STORY-0082).  Nothing is
    found when *cwd* is the home directory: ``~/.gemini``, ``~/.codex`` and
    ``~/.claude`` are user-level config there, and a scan run from ``$HOME``
    is not a scan of a repository.

    Args:
        cwd: Directory to check.  Defaults to :func:`Path.cwd`.

    Returns:
        Discovered files, symlinked candidates included with
        ``is_symlink=True`` and ``symlink_root=cwd`` (TRUST-002 shape).
    """
    root = cwd if cwd is not None else Path.cwd()
    if _is_user_level_harness_dir(root):
        return []
    found: list[DiscoveredAutoexecFile] = []
    for rel_path, kind in _PROJECT_AUTOEXEC_SPECS:
        candidate = _autoexec_candidate(root, rel_path, kind, root, at_home=False)
        if candidate is not None:
            found.append(candidate)
    return found


def discover_project_autoexec_files(
    root: Path, skip_findings: list[Finding] | None = None
) -> list[DiscoveredAutoexecFile]:
    """Walk a repository tree and find non-MCP IDE auto-execution files.

    Mirrors :func:`discover_project_configs`'s walk rules (skip-dir list,
    depth cap, no symlinked directories) but targets ``.vscode/tasks.json``
    and ``.vscode/settings.json`` — files with no MCP root key that can still
    auto-run a command when a developer opens the folder (TRUST-003) — and
    the other harnesses' auto-run files in :data:`SIBLING_HARNESS_AUTOEXEC_KINDS`
    (TRUST-008; ``.claude/workflows`` is a directory candidate).  A TRUST-008
    kind directly under the home directory is the user's own config and is
    skipped.

    A candidate that is itself a symlink is *included*
    (``is_symlink=True``, ``symlink_root=root``) rather than skipped — the
    caller is expected to emit a TRUST-002 finding via
    :func:`build_project_symlink_finding` instead of passing it to
    :meth:`ConfigHygieneAnalyzer.analyze_autoexec_file`.

    Args:
        root: Resolved absolute path of the repository root to walk.
        skip_findings: Optional list to append TRUST-005 findings to for
            symlinked directories that were not traversed.

    Returns:
        List of :class:`DiscoveredAutoexecFile` objects.  Empty when none
        are found under *root*.
    """
    discovered: list[DiscoveredAutoexecFile] = []

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH:
            return

        at_home = _is_user_level_harness_dir(dirpath)
        for rel_path, kind in _PROJECT_AUTOEXEC_SPECS:
            candidate = _autoexec_candidate(
                dirpath, rel_path, kind, root, at_home=at_home
            )
            if candidate is not None:
                discovered.append(candidate)

        try:
            children = sorted(dirpath.iterdir())
        except PermissionError:
            return

        for child in children:
            if child.is_symlink():
                if child.is_dir() and skip_findings is not None:
                    skip_findings.append(
                        build_untraversed_symlink_dir_finding(child, "project")
                    )
                continue
            if not child.is_dir():
                continue
            if child.name in _WALK_SKIP_DIRS:
                continue
            _walk(child, depth + 1)

    _walk(root, 0)
    return discovered


def discover_project_git_surfaces(
    root: Path, skip_findings: list[Finding] | None = None
) -> list[GitSurface]:
    """Walk a repository tree for git surfaces that can make git run code.

    The read-only exception to the ``.git`` entry in :data:`_WALK_SKIP_DIRS`
    (STORY-0089, TRUST-006/TRUST-007): the walk still never descends into a
    ``.git`` directory or a bare repository (so ``objects/`` is never read), but
    it records each ``.git`` entry (directory or ``gitdir:`` file) it passes and
    each directory not named ``.git`` that git itself would treat as a
    repository.  :func:`mcp_audit.analyzers.git_exec.scan_git_surfaces` then
    reads only their config files and lists their hooks.

    Mirrors :func:`discover_project_configs`'s walk rules (skip-dir list, depth
    cap, no symlinked directories, TRUST-005 for each one not traversed).

    Args:
        root: Resolved absolute path of the repository root to walk.
        skip_findings: Optional list to append TRUST-005 findings to for
            symlinked directories that were not traversed.

    Returns:
        :class:`~mcp_audit.analyzers.git_exec.GitSurface` objects; a bare
        repository at *root* itself is returned with ``nested=False`` and its
        contents are not walked.
    """
    if not os.path.lexists(root / ".git") and is_bare_repository(root):
        return [GitSurface(kind="bare-repo", path=root, nested=False)]
    surfaces: list[GitSurface] = []

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH:
            return
        dot_git = dirpath / ".git"
        if os.path.lexists(dot_git):
            surfaces.append(GitSurface(kind="dot-git", path=dot_git))
        try:
            children = sorted(dirpath.iterdir())
        except OSError:
            return
        for child in children:
            if child.is_symlink():
                if child.is_dir() and skip_findings is not None:
                    skip_findings.append(
                        build_untraversed_symlink_dir_finding(child, "project")
                    )
                continue
            if not child.is_dir() or child.name in _WALK_SKIP_DIRS:
                continue
            if depth + 1 > _WALK_MAX_DEPTH:
                continue
            if is_bare_repository(child):
                surfaces.append(GitSurface(kind="bare-repo", path=child))
                continue
            _walk(child, depth + 1)

    _walk(root, 0)
    return surfaces
