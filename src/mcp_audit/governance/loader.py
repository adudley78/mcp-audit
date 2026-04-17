"""Load and validate a governance policy from disk.

Resolution order (when no explicit path is given):
  1. Current working directory — checks all ``POLICY_FILENAMES``
  2. Git repo root — walks up from cwd looking for ``.git``, then checks all
     ``POLICY_FILENAMES`` in that directory
  3. ``~/.config/mcp-audit/policy.yml``
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from mcp_audit.governance.models import GovernancePolicy

POLICY_FILENAMES = [
    ".mcp-audit-policy.yml",
    ".mcp-audit-policy.yaml",
    "mcp-audit-policy.yml",
]

_USER_POLICY_PATH = Path.home() / ".config" / "mcp-audit" / "policy.yml"


def _find_git_root(start: Path) -> Path | None:
    """Walk parent directories until a ``.git`` entry is found.

    Args:
        start: Directory to begin the search from.

    Returns:
        The directory containing ``.git``, or ``None`` if not found.
    """
    current = start.resolve()
    while True:
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _load_from_path(path: Path) -> GovernancePolicy:
    """Parse and validate a governance policy YAML file.

    Args:
        path: Path to the ``.mcp-audit-policy.yml`` file.

    Returns:
        Validated :class:`~mcp_audit.governance.models.GovernancePolicy`.

    Raises:
        ValueError: If the YAML is malformed or the data fails schema
            validation.  The message includes the file path and a
            human-readable description of what went wrong.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Cannot read policy file {path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in policy file {path}: {exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ValueError(
            f"Policy file {path} must be a YAML mapping, got {type(data).__name__}"
        )

    try:
        return GovernancePolicy.model_validate(data)
    except ValidationError as exc:
        # Summarise the first few errors for a readable message.
        errors = exc.errors()
        summary = "; ".join(
            f"{' → '.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in errors[:3]
        )
        if len(errors) > 3:
            summary += f" (and {len(errors) - 3} more error(s))"
        raise ValueError(
            f"Policy file {path} failed schema validation: {summary}"
        ) from exc


def load_policy(path: Path | None = None) -> GovernancePolicy | None:
    """Load a governance policy, returning ``None`` when no file is found.

    Resolution order:
    1. Explicit *path* argument (from ``--policy`` flag).
    2. Current working directory — all ``POLICY_FILENAMES`` checked in order.
    3. Git repo root — walks up from cwd.
    4. ``~/.config/mcp-audit/policy.yml``.

    Args:
        path: Explicit path override.  When provided, the file must exist;
            an error is raised if it cannot be read or fails validation.

    Returns:
        A validated :class:`~mcp_audit.governance.models.GovernancePolicy`,
        or ``None`` if no policy file was found during auto-discovery.

    Raises:
        ValueError: If an explicit *path* is given but the file is missing,
            malformed, or fails schema validation.  Also raised for
            auto-discovered files that fail validation (so misconfigured
            policies are always surfaced).
    """
    # 1. Explicit path — must succeed.
    if path is not None:
        # Security: resolve() canonicalises the path (eliminates .., symlinks)
        # before use.  No boundary check is needed here — the user may
        # legitimately point to any location on the filesystem.
        path = path.resolve()
        if not path.exists():
            raise ValueError(f"Policy file not found: {path}")
        return _load_from_path(path)

    # 2. CWD search.
    cwd = Path.cwd()
    for filename in POLICY_FILENAMES:
        candidate = cwd / filename
        if candidate.exists():
            return _load_from_path(candidate)

    # 3. Git repo root search.
    git_root = _find_git_root(cwd)
    if git_root is not None and git_root != cwd:
        for filename in POLICY_FILENAMES:
            candidate = git_root / filename
            if candidate.exists():
                return _load_from_path(candidate)

    # 4. User config.
    if _USER_POLICY_PATH.exists():
        return _load_from_path(_USER_POLICY_PATH)

    return None
