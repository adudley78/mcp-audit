"""Discover MCP configuration files across supported clients."""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.models import Finding, Severity


@dataclass
class ClientSpec:
    """Specification for a supported MCP client."""

    name: str
    root_key: str  # JSON key containing server definitions
    config_paths: list[Path]  # Paths to check, in priority order


def _home() -> Path:
    return Path.home()


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
            config_paths=[home / ".claude.json"],
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

    return clients


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
) -> list[DiscoveredConfig]:
    """Find all MCP configuration files on this machine.

    Args:
        extra_paths: Additional paths to check (e.g., from --path flag).
        skip_auto_discovery: When ``True``, skip known-client and CWD discovery
            and return only configs built from *extra_paths*.  Used when the
            caller has already provided an explicit config path — combining
            that with auto-discovery would inflate ``clients_scanned`` with
            zero-server system configs.

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
                if config_path.is_symlink():
                    discovered.append(
                        DiscoveredConfig(
                            client_name=spec.name,
                            root_key=spec.root_key,
                            path=config_path,
                            is_symlink=True,
                        )
                    )
                elif config_path.exists() and config_path.is_file():
                    discovered.append(
                        DiscoveredConfig(
                            client_name=spec.name,
                            root_key=spec.root_key,
                            path=config_path,
                        )
                    )

        # Check for VS Code / Claude Code project-level configs in CWD.
        # Boundary-shaped (TRUST-002): these live inside whatever directory the
        # user is scanning from, the same GhostApproval risk as the --project
        # walk below — not the $HOME dotfile-manager shape.
        cwd = Path.cwd()
        vscode_mcp = cwd / ".vscode" / "mcp.json"
        if vscode_mcp.is_symlink():
            discovered.append(
                DiscoveredConfig(
                    client_name="vscode",
                    root_key="servers",
                    path=vscode_mcp,
                    is_symlink=True,
                    symlink_root=cwd,
                )
            )
        elif vscode_mcp.exists():
            discovered.append(
                DiscoveredConfig(
                    client_name="vscode",
                    root_key="servers",
                    path=vscode_mcp,
                )
            )

        claude_code_project = cwd / ".mcp.json"
        if claude_code_project.is_symlink():
            discovered.append(
                DiscoveredConfig(
                    client_name="claude-code-project",
                    root_key="mcpServers",
                    path=claude_code_project,
                    is_symlink=True,
                    symlink_root=cwd,
                )
            )
        elif claude_code_project.exists():
            discovered.append(
                DiscoveredConfig(
                    client_name="claude-code-project",
                    root_key="mcpServers",
                    path=claude_code_project,
                )
            )

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

    return discovered


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
_PROJECT_CONFIG_SPECS: list[tuple[str, str, str]] = [
    (".mcp.json", "claude-code", "mcpServers"),
    (".claude/settings.json", "claude-code", "mcpServers"),
    (".claude/settings.local.json", "claude-code", "mcpServers"),
    (".cursor/mcp.json", "cursor", "mcpServers"),
    (".cursor/settings.json", "cursor", "mcpServers"),
    (".vscode/mcp.json", "vscode", "servers"),
    (".amazonq/mcp.json", "amazon-q", "mcpServers"),
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
_PROJECT_AUTOEXEC_SPECS: list[tuple[str, str]] = [
    (".vscode/tasks.json", "vscode-tasks"),
    (".vscode/settings.json", "vscode-settings"),
]


# Directory names to skip while walking the project tree.
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
    root: Path, skip_findings: list[Finding] | None = None
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
      finding via :func:`build_project_symlink_finding`.

    Args:
        root: Resolved absolute path of the repository root to walk.
        skip_findings: Optional list to append TRUST-005 findings to for
            symlinked directories that were not traversed.  When ``None``,
            those directories are still skipped, just silently (as before).

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
        for rel_path, client_name, root_key in _PROJECT_CONFIG_SPECS:
            candidate = dirpath / rel_path
            if candidate.is_symlink():
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
            if candidate.is_file():
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


def discover_project_autoexec_files(
    root: Path, skip_findings: list[Finding] | None = None
) -> list[DiscoveredAutoexecFile]:
    """Walk a repository tree and find non-MCP IDE auto-execution files.

    Mirrors :func:`discover_project_configs`'s walk rules (skip-dir list,
    depth cap, no symlinked directories) but targets ``.vscode/tasks.json``
    and ``.vscode/settings.json`` — files with no MCP root key that can still
    auto-run a command when a developer opens the folder (TRUST-003).

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

        for rel_path, kind in _PROJECT_AUTOEXEC_SPECS:
            candidate = dirpath / rel_path
            if candidate.is_symlink():
                discovered.append(
                    DiscoveredAutoexecFile(
                        kind=kind,
                        path=candidate,
                        is_symlink=True,
                        symlink_root=root,
                    )
                )
                continue
            if candidate.is_file():
                discovered.append(DiscoveredAutoexecFile(kind=kind, path=candidate))

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
