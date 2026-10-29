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
import stat
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
    "credentials": frozenset({"CRED-001", "CRED-002", "CRED-003"}),
    "transport": frozenset({"TRANSPORT-001"}),
    # VULN-UNPINNED and LOCK-004 (STORY-0070) pin an exact version; SC-001/002
    # replace a typosquatted name and pin. All three share one strategy.
    "pinning": frozenset({"SC-001", "SC-002", "VULN-UNPINNED", "LOCK-004"}),
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
    lock_doc: dict | None = None,
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
        lock_doc: Optional raw ``mcp-lock.json`` document (as returned by
            :func:`mcp_audit.lock.writer.load_existing`) for the nearest
            ancestor lock. When a server has a resolved-version entry here,
            the pinning strategy uses it instead of a live network call for
            VULN-UNPINNED / LOCK-004 fixes.

    Returns:
        :class:`FixResult` describing what was (or would be) changed.

    Raises:
        FileNotFoundError: When *config_path* does not exist.
        PermissionError: When *config_path* is not readable (or not writable
            when ``apply=True``).
        ValueError: When *config_path* is not valid JSON.
    """
    result = FixResult(config_path=config_path)

    if config_path.suffix.lower() == ".toml":
        # Codex's config.toml (STORY-0110): fix writes JSON only, and
        # rewriting TOML would drop the user's comments and layout.
        raise ValueError(
            f"{config_path} is a TOML file (Codex). mcp-audit fix edits JSON MCP"
            " configs only; apply the remediation in this file by hand."
        )

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
    pinning_strategy = PackagePinningStrategy(
        registry=registry, offline=offline, lock_doc=lock_doc
    )
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

    return _finish(result, config_path, original_text, current_config, apply)


def _finish(
    result: FixResult,
    config_path: Path,
    original_text: str,
    current_config: dict,
    apply: bool,
) -> FixResult:
    """Serialize, diff and (with *apply*) atomically write *current_config*."""
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

    # A symlinked config (dotfile managers) is edited where it lives, and the
    # file keeps its permission bits: the original may hold MCP env secrets.
    target = config_path.resolve()
    mode = stat.S_IMODE(target.stat().st_mode)

    # 1. Write backup of original content first (before any modification).  An
    # earlier backup is never overwritten: the first one is the real original.
    bak_path = target.with_suffix(target.suffix + ".bak")
    n = 0
    while bak_path.exists():
        n += 1
        bak_path = target.with_suffix(f"{target.suffix}.bak.{n}")
    _write_private(bak_path, original_text, mode)
    result.backup_path = bak_path

    # 2. Write new content to a temp file.
    tmp_path = target.with_suffix(target.suffix + ".tmp")
    _write_private(tmp_path, new_text, mode)

    # 3. Atomic rename: replaces the config in one syscall on POSIX.
    tmp_path.replace(target)

    return result


def _write_private(path: Path, text: str, mode: int) -> None:
    """Write *text* to *path* with permission bits *mode* (never wider)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    finally:
        os.chmod(path, mode)


def run_pins(
    config_path: Path,
    pins: list[tuple[str, str, str]],
    *,
    apply: bool = False,
) -> FixResult:
    """Pin servers to exact versions an advisory names (STORY-0127).

    Args:
        config_path: The MCP config JSON file.
        pins: ``(server_name, package, version)`` triples.
        apply: Write the file atomically with a ``.bak`` backup; otherwise
            return the diff only.

    Returns:
        A :class:`FixResult`. A pin that cannot be applied cleanly is listed in
        ``skipped`` and the file is left as the other pins make it; nothing is
        ever half-written for one server.

    Raises:
        FileNotFoundError, PermissionError, ValueError: as :func:`run_fix`.
    """
    from mcp_audit.fixer.strategies.pinning import pin_exact  # noqa: PLC0415

    result = FixResult(config_path=config_path)
    if config_path.suffix.lower() == ".toml":
        raise ValueError(
            f"{config_path} is a TOML file (Codex). mcp-audit edits JSON MCP "
            "configs only; apply the pin in this file by hand."
        )
    original_text = config_path.read_text(encoding="utf-8")
    try:
        config = json.loads(original_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Config file is not valid JSON: {config_path}: {exc}"
        ) from exc
    untouched = json.loads(original_text)
    for server_name, package, version in pins:
        try:
            config, description = pin_exact(config, server_name, package, version)
            result.fixes_applied.append(description)
        except ValueError as exc:
            result.skipped.append(f"Skipped {server_name!r}: {exc}")
    if config == untouched:
        # Nothing changed: leave the file (and its formatting) alone.
        return result
    return _finish(result, config_path, original_text, config, apply)
