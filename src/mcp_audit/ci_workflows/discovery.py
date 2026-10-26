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
not followed (that walker already reports them as TRUST-005).  Neither
``.github`` nor ``.github/workflows`` may be a symlink, and every file read
must resolve inside the scanned root, so a link cannot make a file from
elsewhere look like the repository's own workflow.

Every filesystem probe catches ``OSError``: an unreadable directory skips
that directory, it never stops the scan.  Work is bounded per file
(:data:`MAX_WORKFLOW_BYTES`) and per call (:data:`MAX_TOTAL_BYTES`,
:data:`MAX_WORKFLOW_FILES`); anything skipped for size is reported through
the optional *skipped* list so the scan can say so.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.discovery import _WALK_MAX_DEPTH, _WALK_SKIP_DIRS

logger = logging.getLogger(__name__)

_WORKFLOWS_REL = Path(".github") / "workflows"
_SUFFIXES: frozenset[str] = frozenset({".yml", ".yaml"})
# A workflow file larger than this is skipped, not parsed.  PyYAML's safe
# loader can take ~10 s per MB on adversarial input; real workflows are a few
# KB.
MAX_WORKFLOW_BYTES: int = 256 * 1024
# Total bytes of workflow files accepted by one discovery call.
MAX_TOTAL_BYTES: int = 4 * 1024 * 1024
# Upper bound on files accepted by one discovery call.
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


class _Budget:
    """Byte and file-count budget shared by one discovery call."""

    def __init__(self, skipped: list[str] | None) -> None:
        self.bytes = 0
        self.files = 0
        self.skipped = skipped
        self._exhausted_noted = False

    def note(self, message: str) -> None:
        logger.debug("ci_workflows: %s", message)
        if self.skipped is not None:
            self.skipped.append(message)

    @property
    def exhausted(self) -> bool:
        return self.files >= MAX_WORKFLOW_FILES or self.bytes >= MAX_TOTAL_BYTES

    def admit(self, path: Path, size: int) -> bool:
        """Account for one file; False (and a note) when it does not fit."""
        if size > MAX_WORKFLOW_BYTES:
            self.note(
                f"ci_workflows: skipped {path}: {size} bytes is over the"
                f" {MAX_WORKFLOW_BYTES // 1024} KiB workflow file limit"
            )
            return False
        if self.files + 1 > MAX_WORKFLOW_FILES or self.bytes + size > MAX_TOTAL_BYTES:
            if not self._exhausted_noted:
                self._exhausted_noted = True
                self.note(
                    f"ci_workflows: stopped reading workflows at {path}: the"
                    f" {MAX_TOTAL_BYTES // (1024 * 1024)} MiB /"
                    f" {MAX_WORKFLOW_FILES}-file budget for one scan is used up"
                )
            return False
        self.files += 1
        self.bytes += size
        return True


def _workflow_files_in(
    repo_root: Path, scan_root: Path, budget: _Budget
) -> list[WorkflowFile]:
    """Return the workflow files directly under ``<repo_root>/.github/workflows``.

    The directory is used only when neither ``.github`` nor ``workflows`` is
    a symlink (its resolved path is exactly ``<repo_root>/.github/workflows``)
    and it lies inside *scan_root*.  Each file must also resolve inside
    *scan_root*.
    """
    wf_dir = repo_root / _WORKFLOWS_REL
    try:
        if not wf_dir.is_dir():
            return []
        resolved_dir = wf_dir.resolve()
        if resolved_dir != repo_root.resolve() / _WORKFLOWS_REL:
            logger.debug("ci_workflows: %s is reached through a symlink", wf_dir)
            return []
        resolved_dir.relative_to(scan_root)
        entries = sorted(wf_dir.iterdir())
    except (OSError, ValueError, RuntimeError):
        # OSError: unreadable; ValueError: outside the scanned root;
        # RuntimeError: symlink loop on older Pythons.
        return []
    found: list[WorkflowFile] = []
    for entry in entries:
        if entry.suffix.lower() not in _SUFFIXES:
            continue
        try:
            target = entry.resolve()
            target.relative_to(scan_root)
            if not target.is_file():
                continue
            size = target.stat().st_size
        except (OSError, ValueError, RuntimeError):
            continue
        if not budget.admit(entry, size):
            continue
        found.append(WorkflowFile(path=entry, repo_root=repo_root))
    return found


def _is_repo_root(dirpath: Path) -> bool:
    try:
        return (dirpath / ".git").exists()
    except OSError:
        return False


def discover_workflow_files(
    root: Path, *, walk: bool = False, skipped: list[str] | None = None
) -> list[WorkflowFile]:
    """Find GitHub Actions workflow files under *root*.

    Args:
        root: Directory to start from.  Resolved before use, so paths in
            findings are absolute and stable across the default scan and
            ``--project`` (which lets the caller de-duplicate them).
        walk: Also descend into *root* (``scan --project``) and read the
            workflows of every nested directory that holds a ``.git`` entry.
        skipped: Optional list that receives one message per file skipped
            for size, and one when the per-call budget runs out.

    Returns:
        :class:`WorkflowFile` objects in walk order.  Empty when there are
        none, *root* is not a readable directory, or the budget is used up.
    """
    budget = _Budget(skipped)
    try:
        root = root.resolve()
        if not root.is_dir():
            return []
    except (OSError, RuntimeError):
        return []

    found: list[WorkflowFile] = _workflow_files_in(root, root, budget)
    if not walk:
        return found

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > _WALK_MAX_DEPTH or budget.exhausted:
            return
        if depth > 0 and _is_repo_root(dirpath):
            found.extend(_workflow_files_in(dirpath, root, budget))
        try:
            children = sorted(dirpath.iterdir())
        except OSError:
            return
        for child in children:
            if child.name in _WALK_SKIP_DIRS:
                continue
            try:
                if child.is_symlink() or not child.is_dir():
                    continue
            except OSError:
                continue
            _walk(child, depth + 1)

    _walk(root, 0)
    return found
