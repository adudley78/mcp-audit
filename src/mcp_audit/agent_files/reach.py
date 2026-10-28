"""Instruction-file reach in the default scan and ``scan --project`` (STORY-0098).

MEM-003 and MEM-004 join the scan people already run, with no new flags:

- **Default ``scan`` / ``check``** (no explicit path; the GitHub Action's
  run): the instruction files at the top of the working directory that
  Claude Code expands ``@path`` imports in (``CLAUDE.md``,
  ``.claude/CLAUDE.md``, ``CLAUDE.local.md``, ``AGENTS.md``,
  ``.claude/AGENTS.md``, ``.claude/rules/**/*.md``) and their imports, plus
  ``HEARTBEAT.md`` there and the user's ``~/.openclaw/workspace/HEARTBEAT.md``.
  Skipped for the working directory when it is ``$HOME`` (your own
  configuration, not a repository's).
- **``scan --project <dir>``**: the same, for every directory of the walk.

The content rules (MEM-001/002, POISON-041/042) on these files stay where
agent-file scanning already runs (``scan --include-agent-files``,
``mcp-audit agent-files scan``).  On these two paths only a symlink that
leaves the scanned folder is reported (TRUST-002 HIGH); links inside it and
symlinked directories are left to the agent-file scan, which reports them
all.  Nothing here raises: problems go to the caller's ``errors`` list.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from mcp_audit.agent_files.analyzer import analyze_instruction_reach
from mcp_audit.agent_files.discovery import (
    discover_agent_files,
    discover_root_agent_files,
    discover_user_heartbeat_files,
)
from mcp_audit.agent_files.models import AgentFile
from mcp_audit.models import Finding, Severity


def finding_key(finding: Finding) -> tuple[str, str, str, str]:
    """Identity used to report a finding once across the scan paths.

    The path is resolved so ``Path.cwd() / rel`` and ``project_dir / rel``
    agree on the same file.
    """
    path = finding.finding_path or ""
    if path:
        with contextlib.suppress(OSError, RuntimeError):
            path = str(Path(path).resolve())
    return (finding.id, path, finding.title, finding.evidence)


def _boundary_links(skip: list[Finding]) -> list[Finding]:
    """Keep only symlinks that leave the scanned folder (TRUST-002 HIGH)."""
    seen: set[tuple[str, str | None]] = set()
    out: list[Finding] = []
    for f in skip:
        if f.id != "TRUST-002" or f.severity != Severity.HIGH:
            continue
        key = (f.id, f.finding_path)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _islink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return True


def _is_home(path: Path, home: Path) -> bool:
    try:
        return path.resolve() == home.resolve()
    except OSError:
        return False


def _user_heartbeat_files(errors: list[str]) -> list[AgentFile]:
    """The user's heartbeat files (indirection so tests can isolate ``$HOME``)."""
    return discover_user_heartbeat_files(None, errors)


def default_scan_findings(cwd: Path, errors: list[str]) -> list[Finding]:
    """MEM-003/MEM-004 (and boundary TRUST-002) for a default scan.

    Args:
        cwd: The working directory.
        errors: Receives read problems, budget stops and any failure; this
            function never raises.

    Returns:
        Findings for the working directory's top-level instruction files and
        the user's heartbeat file.
    """
    findings: list[Finding] = []
    home = Path.home()
    skip: list[Finding] = []
    try:
        files: list[AgentFile] = []
        if not _is_home(cwd, home):
            files.extend(discover_root_agent_files(cwd, skip, errors))
        files.extend(_user_heartbeat_files(errors))
        findings.extend(analyze_instruction_reach(files, home))
    except Exception as exc:  # noqa: BLE001 — a new default-scan pass must not crash scan
        errors.append(f"agent-file imports: {type(exc).__name__}: {exc}")
    findings.extend(_boundary_links(skip))
    return findings


def project_scan_findings(project_root: Path, errors: list[str]) -> list[Finding]:
    """MEM-003/MEM-004 (and boundary TRUST-002) for ``scan --project``.

    Walks *project_root* like the agent-file scan (depth 8, skip list, no
    symlinked directories), follows ``@path`` imports, and checks
    ``HEARTBEAT.md`` files.  Never raises; problems go to *errors*.
    """
    findings: list[Finding] = []
    skip: list[Finding] = []
    try:
        files = discover_agent_files(
            project_root=project_root,
            include_user_global=False,
            skip_findings=skip,
            include_references=False,
            errors=errors,
        )
        # A symlinked file is reported (TRUST-002), never judged as the
        # repository's own.
        own = [f for f in files if not _islink(f.path)]
        findings.extend(analyze_instruction_reach(own))
    except Exception as exc:  # noqa: BLE001 — a new scan pass must not crash scan
        errors.append(f"agent-file imports: {type(exc).__name__}: {exc}")
    findings.extend(_boundary_links(skip))
    return findings
