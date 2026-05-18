"""Fixer orchestrator — load config, apply fix strategies, write atomically.

Public entry point: :func:`run_fix`.

Atomic write contract
---------------------
1. Read original file bytes into ``original_text``.
2. Apply strategies in order, accumulating a modified in-memory dict.
3. Serialize to ``new_text = json.dumps(config, indent=2, ensure_ascii=False)``.
4. Validate the serialized text round-trips cleanly via ``json.loads``.
5. If ``apply=True``:
   a. Write ``original_text`` to ``<path>.bak`` (backup before any modification).
   b. Write ``new_text`` to ``<path>.tmp``.
   c. Rename ``<path>.tmp`` → ``<path>`` (atomic on POSIX; best-effort on Windows).
6. Compute and return a unified diff of ``original_text`` vs ``new_text``.
"""

from __future__ import annotations

import difflib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcp_audit.fixer.strategies.base import BaseFixStrategy
from mcp_audit.fixer.strategies.credentials import CredentialsFixStrategy
from mcp_audit.fixer.strategies.pinning import PackagePinningStrategy
from mcp_audit.fixer.strategies.transport import TransportFixStrategy
from mcp_audit.models import Finding

# Canonical fix-type labels used by --fix-type CLI filter.
FixType = Literal["credentials", "transport", "pinning"]

_ALL_FIX_TYPES: tuple[FixType, ...] = ("credentials", "transport", "pinning")

# Maps each FixType label to the finding IDs it handles.
_FIX_TYPE_IDS: dict[FixType, frozenset[str]] = {
    "credentials": frozenset({"CRED-001", "CRED-002"}),
    "transport": frozenset({"TRANSPORT-001"}),
    "pinning": frozenset({"SC-001", "SC-002"}),
}


@dataclass
class FixResult:
    """Result of a :func:`run_fix` call.

    Attributes:
        config_path: The config file that was (or would be) modified.
        fixes_applied: Human-readable description for each change made.
        skipped: Warning messages for fixes that could not be applied.
        diff: Unified diff text (original vs. proposed/applied).
        backup_path: Path to the ``.bak`` file written when ``apply=True``.
        no_fixable: ``True`` when no findings matched any strategy.
    """

    config_path: Path
    fixes_applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    diff: str = ""
    backup_path: Path | None = None
    no_fixable: bool = False


def run_fix(
    findings: list[Finding],
    config_path: Path,
    *,
    apply: bool = False,
    fix_types: list[FixType] | None = None,
    offline: bool = False,
    registry=None,  # KnownServerRegistry | None — avoids circular import at module load
) -> FixResult:
    """Apply safe remediations for *findings* to *config_path*.

    Findings that are not handled by any strategy (or are filtered out by
    *fix_types*) are silently ignored.

    Args:
        findings: List of :class:`~mcp_audit.models.Finding` objects to process.
        config_path: Absolute path to the MCP config JSON file.
        apply: When ``True``, write the modified config back to disk (with
            atomic rename) and create a ``.bak`` backup.  When ``False`` (the
            default), return the diff without touching the filesystem.
        fix_types: Optional list of fix-type labels to restrict which strategies
            run.  ``None`` (default) enables all three strategies.
        offline: When ``True``, suppress all network calls (version resolution
            for the pinning strategy is skipped with a warning).
        registry: Optional pre-loaded
            :class:`~mcp_audit.registry.loader.KnownServerRegistry` instance
            used by the pinning strategy to validate replacement package names.

    Returns:
        :class:`FixResult` describing what was (or would be) changed.

    Raises:
        FileNotFoundError: When *config_path* does not exist.
        PermissionError: When *config_path* is not readable (or not writable
            when ``apply=True``).
        ValueError: When *config_path* is not valid JSON.
    """
    result = FixResult(config_path=config_path)

    original_text = config_path.read_text(encoding="utf-8")

    try:
        config = json.loads(original_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Config file is not valid JSON: {config_path}: {exc}"
        ) from exc

    # Build the active strategy list, respecting the fix-type filter.
    active_types: tuple[FixType, ...] = (
        tuple(fix_types) if fix_types else _ALL_FIX_TYPES  # type: ignore[arg-type]
    )
    pinning_strategy = PackagePinningStrategy(registry=registry, offline=offline)
    strategies: list[tuple[FixType, BaseFixStrategy]] = []
    for ft in active_types:
        if ft == "credentials":
            strategies.append(("credentials", CredentialsFixStrategy()))
        elif ft == "transport":
            strategies.append(("transport", TransportFixStrategy()))
        elif ft == "pinning":
            strategies.append(("pinning", pinning_strategy))

    # Filter findings to those matching an active strategy.
    active_ids: frozenset[str] = frozenset(
        id_ for ft in active_types for id_ in _FIX_TYPE_IDS[ft]
    )
    fixable = [f for f in findings if f.id in active_ids]

    if not fixable:
        result.no_fixable = True
        return result

    # Apply strategies in order, collecting descriptions and warnings.
    current_config = config
    for finding in fixable:
        for _ft, strategy in strategies:
            if not strategy.can_fix(finding):
                continue
            try:
                current_config, description = strategy.apply(current_config, finding)
                result.fixes_applied.append(description)
            except ValueError as exc:
                result.skipped.append(
                    f"Skipped {finding.id} on {finding.server!r}: {exc}"
                )
            break  # only one strategy per finding

    # Collect warnings from the pinning strategy.
    result.skipped.extend(pinning_strategy.warnings)

    # Serialize the modified config.
    new_text = json.dumps(current_config, indent=2, ensure_ascii=False) + "\n"

    # Validate round-trip (guards against adversarial strategy output).
    try:
        json.loads(new_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Modified config failed JSON validation — aborting fix: {exc}"
        ) from exc

    # Build the unified diff against the original file text.
    diff_lines = list(
        difflib.unified_diff(
            original_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{config_path.name}",
            tofile=f"b/{config_path.name}",
        )
    )
    result.diff = "".join(diff_lines)

    if not apply:
        return result

    # ── Atomic write ──────────────────────────────────────────────────────────

    # Pre-flight: check write access before touching any files.
    if not os.access(config_path, os.W_OK):
        raise PermissionError(f"Config file is read-only: {config_path}")

    # 1. Write backup of original content first (before any modification).
    bak_path = config_path.with_suffix(config_path.suffix + ".bak")
    bak_path.write_text(original_text, encoding="utf-8")
    result.backup_path = bak_path

    # 2. Write new content to a temp file.
    tmp_path = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp_path.write_text(new_text, encoding="utf-8")

    # 3. Atomic rename: replaces config_path in one syscall on POSIX.
    tmp_path.replace(config_path)

    return result
