"""Guardrail records: the ``guardrails`` section of ``mcp-lock.json``.

STORY-0143. ``mcp-audit lock`` records the *repository's own* agent settings
files so ``lock --verify`` can fail CI when one of them gets weaker than what
was reviewed: the project ``.claude/settings.json``, ``.codex/config.toml`` and
``.gemini/settings.json``.  Never ``settings.local.json`` (a person's own,
usually git-ignored file) and never a home file.

The section declares its producer and carries its own checksum, like
``tools`` (:mod:`mcp_audit.lock.tool_digests`)::

    "guardrails": {
      "_producer": "mcp-audit",
      "_schema_version": 1,
      "files": {
        ".claude/settings.json": {"digest": "sha256:...", "record": {...}}
      },
      "_checksum": "sha256:<hex>"
    }

``record`` is the normalised guardrail record of
:func:`mcp_audit.guardrails.build_record` (no secret values; hook commands
only as SHA-256), ``digest`` the SHA-256 of its RFC 8785 encoding.  The
top-level ``checksum`` keeps its ADR-0005 §10 scope, so a lock without this
section has exactly the bytes and checksum it had before, and every older
mcp-audit sees a populated section it cannot verify (reported honestly as an
unverified section) instead of reporting LOCK-005.

A lock without a ``guardrails`` section verifies exactly as before: nothing
here runs for it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from mcp_audit import guardrails
from mcp_audit.lock.tool_digests import digest

GUARDRAILS_KEY = "guardrails"
GUARDRAILS_PRODUCER = "mcp-audit"
GUARDRAILS_SCHEMA_VERSION = 1

#: Files per lock (a repository has three kinds of file; nested roots add more).
MAX_FILES = 256

_LOCKED_NAMES = frozenset({"settings.json", "config.toml"})


def is_owned(section: object) -> bool:
    """Whether *section* is a ``guardrails`` section this mcp-audit wrote.

    Ownership is declared (ADR-0005 §1): another producer's section, or one
    from a newer schema, is foreign and never touched.
    """
    return (
        isinstance(section, dict)
        and section.get("_producer") == GUARDRAILS_PRODUCER
        and section.get("_schema_version") == GUARDRAILS_SCHEMA_VERSION
    )


def section_checksum(section: dict) -> str:
    """Return the checksum of *section*, excluding its own ``_checksum``."""
    return digest({k: v for k, v in section.items() if k != "_checksum"})


def checksum_ok(section: dict) -> bool:
    """Whether *section*'s ``_checksum`` matches its content and shape."""
    files = section.get("files")
    if not isinstance(files, dict):
        return False
    return section.get("_checksum") == section_checksum(section)


def build_section(files: dict[str, dict]) -> dict | None:
    """Return a complete owned section, or ``None`` when *files* is empty."""
    if not files:
        return None
    section: dict = {
        "_producer": GUARDRAILS_PRODUCER,
        "_schema_version": GUARDRAILS_SCHEMA_VERSION,
        "files": {key: files[key] for key in sorted(files)},
    }
    section["_checksum"] = section_checksum(section)
    return section


def entry(record: dict) -> dict:
    """The lock entry for one file's *record*."""
    return {"digest": digest(record), "record": record}


def repo_files(
    root: Path, errors: list[str]
) -> list[tuple[str, guardrails.GuardrailFile]]:
    """The repository's own guardrail files under *root*, as ``(lock path, file)``.

    The project files :func:`mcp_audit.guardrails.project_guardrail_files`
    finds, without ``settings.local.json``; lock paths are POSIX paths
    relative to *root*.  Never a home file.  Never raises.
    """
    out: list[tuple[str, guardrails.GuardrailFile]] = []
    try:
        base = root.resolve()
    except (OSError, RuntimeError):
        return out
    for item in guardrails.project_guardrail_files(root, errors):
        if item.agent == guardrails.MANAGED or item.path.name not in _LOCKED_NAMES:
            continue
        try:
            rel = item.path.resolve().relative_to(base).as_posix()
        except (OSError, RuntimeError, ValueError):
            continue
        out.append((rel, item))
        if len(out) >= MAX_FILES:
            errors.append(
                f"guardrails: more than {MAX_FILES} files; the rest are not locked"
            )
            break
    return out


def current_entries(root: Path, existing: object, errors: list[str]) -> dict[str, dict]:
    """Entries to write for *root*: what its guardrail files hold now.

    A file that exists but cannot be read keeps its previous entry (from an
    owned *existing* section that passes its checksum), so a transient or
    malformed file never erases a reviewed record.  Files that are gone are
    dropped.
    """
    previous: dict = {}
    if is_owned(existing) and checksum_ok(existing):  # type: ignore[arg-type]
        previous = existing["files"]  # type: ignore[index]
    entries: dict[str, dict] = {}
    for rel, item in repo_files(root, errors):
        notes: list[str] = []
        record = guardrails.read_record(item, notes)
        errors.extend(f"guardrails: {rel}: {n}" for n in notes)
        if isinstance(record, dict):
            entries[rel] = entry(record)
        elif isinstance(record, str):
            errors.append(f"guardrails: {rel}: {record}")
            if rel in previous:
                entries[rel] = previous[rel]
    return entries


@dataclass
class Loosened:
    """One locked file that now allows more than its record."""

    path: str
    diff: guardrails.Diff
    gone: bool = False


def loosened(section: dict, root: Path, errors: list[str]) -> list[Loosened]:
    """Compare every file in an owned, checksum-valid *section* with disk.

    A file that is not in the lock is not looked at.  A locked file that is
    gone counts only for what it alone held (a deny rule or a hook), as in
    scans.  A locked file that cannot be read is reported in *errors* and
    skipped: the exit code is not changed by what could not be read.
    """
    out: list[Loosened] = []
    files = section.get("files")
    if not isinstance(files, dict):
        return out
    try:
        base = root.resolve()
    except (OSError, RuntimeError):
        return out
    for rel in sorted(files):
        locked = files[rel]
        record = locked.get("record") if isinstance(locked, dict) else None
        if not isinstance(record, dict):
            continue
        agent = record.get("agent")
        if agent not in (guardrails.CLAUDE, guardrails.CODEX, guardrails.GEMINI):
            continue
        path = base / rel
        item = guardrails.GuardrailFile(path, agent, "project", rel)
        if os.path.pardir in Path(rel).parts or Path(rel).is_absolute():
            continue
        notes: list[str] = []
        current = guardrails.read_record(item, notes)
        if isinstance(current, str):
            errors.append(f"guardrails: {rel}: {current}")
            continue
        if current is None:
            diff = guardrails.vanished_diff(record, agent)
            if diff.loosened:
                out.append(Loosened(rel, diff, gone=True))
            continue
        diff = guardrails.compare(record, current, agent)
        if diff.loosened:
            out.append(Loosened(rel, diff))
    return out
