"""Find GitHub Actions workflow files (STORY-0091).

GitHub reads workflows from ``.github/workflows/`` at the root of a
repository, one directory level only (``*.yml`` and ``*.yaml``).  A default
scan reads that directory under the working directory, which is where the
mcp-audit GitHub Action runs.  ``scan --project`` reads it under the project
root and also under any nested directory that is itself a repository root
(holds a ``.git`` entry), so a folder of checkouts is covered without
flagging copies of workflows vendored or kept as test data inside one repo.

Walk rules match :func:`mcp_audit.discovery.discover_project_configs`:
the same skip-directory list and depth cap, and symlinked directories are
not followed (that walker already reports them as TRUST-005).  A symlinked
workflow file is read only when its target resolves inside the scanned root.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.discovery import _WALK_MAX_DEPTH, _WALK_SKIP_DIRS

logger = logging.getLogger(__name__)

_WORKFLOWS_REL = Path(".github") / "workflows"
_SUFFIXES: frozenset[str] = frozenset({".yml", ".yaml"})
# A workflow file larger than this is skipped, not parsed.
MAX_WORKFLOW_BYTES: int = 1024 * 1024
# Upper bound on files read in one discovery call (a hostile tree cannot make
# the scan read without limit).
MAX_WORKFLOW_FILES: int = 2000


@dataclass(frozen=True)
class WorkflowFile:
    """One workflow file and the repository root it belongs to."""

    path: Path
    repo_root: Path

    @property
    def rel_path(self) -> str:
        """Path relative to the repository root, POSIX separators."""
        try:
            return self.path.relative_to(self.repo_root).as_posix()
        except ValueError:
            return self.path.name


def _workflow_files_in(repo_root: Path, scan_root: Path) -> list[WorkflowFile]:
    """Return the workflow files directly under ``<repo_root>/.github/workflows``."""
    wf_dir = repo_root / _WORKFLOWS_REL
    if wf_dir.is_symlink() or not wf_dir.is_dir():
        return []
    found: list[WorkflowFile] = []
    try:
        entries = sorted(wf_dir.iterdir())
    except OSError:
        return []
    for entry in entries:
        if entry.suffix.lower() not in _SUFFIXES:
            continue
        try:
            if entry.is_symlink():
                target = entry.resolve()
                target.relative_to(scan_root)
                if not target.is_file():
                    continue
            elif not entry.is_file():
                continue
            if entry.stat().st_size > MAX_WORKFLOW_BYTES:
                logger.debug("ci_workflows: skipping oversized workflow %s", entry)
                continue
        except (OSError, ValueError, RuntimeError):
            # ValueError: symlink target outside the scanned root.
            # RuntimeError: symlink loop on older Pythons.
            continue
        found.append(WorkflowFile(path=entry, repo_root=repo_root))
    return found


def discover_workflow_files(root: Path, *, walk: bool = False) -> list[WorkflowFile]:
    """Find GitHub Actions workflow files under *root*.

    Args:
        root: Directory to start from.  Resolved before use, so paths in
            findings are absolute and stable across the default scan and
            ``--project`` (which lets the caller de-duplicate them).
        walk: Also descend into *root* (``scan --project``) and read the
            workflows of every nested directory that holds a ``.git`` entry.

    Returns:
        :class:`WorkflowFile` objects in walk order.  Empty when there are
        none or *root* is not a directory.
    """
    try:
        root = root.resolve()
    except OSError:
        return []
    if not root.is_dir():
        return []

    found: list[WorkflowFile] = list(_workflow_files_in(root, root))
    if not walk:
        return found[:MAX_WORKFLOW_FILES]

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH or len(found) >= MAX_WORKFLOW_FILES:
            return
        if depth > 0 and (dirpath / ".git").exists():
            found.extend(_workflow_files_in(dirpath, root))
        try:
            children = sorted(dirpath.iterdir())
        except OSError:
            return
        for child in children:
            if child.is_symlink() or child.name in _WALK_SKIP_DIRS:
                continue
            try:
                is_dir = child.is_dir()
            except OSError:
                continue
            if is_dir:
                _walk(child, depth + 1)

    _walk(root, 0)
    return found[:MAX_WORKFLOW_FILES]
