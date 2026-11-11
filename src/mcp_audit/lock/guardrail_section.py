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
from dataclasses import dataclass, field
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
            kept = previous.get(rel)
            if isinstance(kept, dict) and guardrails.valid_record(kept.get("record")):
                # In this version's stored form: a record an older version
                # wrote may hold a secret CRED-004 redacts (STORY-0151).
                entries[rel] = entry(guardrails.stored_form(kept["record"]))
    return entries


@dataclass
class Loosened:
    """One locked file that now allows more than its record."""

    path: str
    diff: guardrails.Diff
    gone: bool = False
    #: Not in the lock at all: a guardrail file that appeared after ``lock``.
    new: bool = False


@dataclass
class Compared:
    """Outcome of :func:`compare_section`."""

    loosened: list[Loosened] = field(default_factory=list)
    #: ``(path, reason)`` for files that could not be compared: unreadable,
    #: replaced by a symlink, padded past the read cap, a malformed record, a
    #: path the section may not name.  Fail closed: ``verify`` makes each an
    #: unverified item (exit 1 unless ``--allow-unverified``).
    unverified: list[tuple[str, str]] = field(default_factory=list)


def _safe_path(base: Path, rel: str) -> tuple[Path, str] | str:
    """``(path, agent)`` for a lock path under *base*, or why it is refused.

    The path must be relative with no ``..``, name a repository guardrail file
    (``.claude/settings.json``, ``.codex/config.toml``,
    ``.gemini/settings.json``), pass through no symlink, and resolve under
    *base*: a lock is data anyone can edit and must not make verify read
    ``/etc`` or a file outside the repository (review N1).
    """
    parts = Path(rel).parts
    if not rel or Path(rel).is_absolute() or os.path.pardir in parts:
        return "path is not relative to the repository"
    path = base.joinpath(*parts)
    agent = guardrails._is_project_file(path)
    if agent is None or path.name not in _LOCKED_NAMES:
        return "not a repository guardrail file"
    cur = base
    for part in parts:
        cur = cur / part
        if os.path.islink(cur):
            return "reached through a symlink"
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        return "cannot be resolved"
    if not resolved.is_relative_to(base):
        return "resolves outside the repository"
    return path, agent


def _one(base: Path, rel: str, locked: object, out: Compared) -> None:
    record = locked.get("record") if isinstance(locked, dict) else None
    if not guardrails.valid_record(record) or record.get("agent") == guardrails.MANAGED:
        out.unverified.append((rel, "the recorded entry is malformed"))
        return
    if locked.get("digest") != digest(record):  # type: ignore[union-attr]
        out.unverified.append((rel, "the recorded digest does not match its record"))
        return
    safe = _safe_path(base, rel)
    if isinstance(safe, str):
        out.unverified.append((rel, safe))
        return
    path, agent = safe
    if agent != record["agent"]:
        out.unverified.append((rel, "the recorded agent does not match the file"))
        return
    item = guardrails.GuardrailFile(path, agent, "project", rel)
    current = guardrails.read_record(item, [])
    if isinstance(current, str):
        out.unverified.append((rel, current))
        return
    if current is None:
        diff = guardrails.vanished_diff(record, agent)
        if diff.loosened:
            out.loosened.append(Loosened(rel, diff, gone=True))
        return
    diff = guardrails.compare(record, current, agent)
    if diff.loosened:
        out.loosened.append(Loosened(rel, diff))


def compare_section(section: dict, root: Path, errors: list[str]) -> Compared:
    """Compare an owned, checksum-valid *section* with the files under *root*.

    Every recorded file is read and compared with its record.  A recorded file
    that is gone counts only for what it alone held (a deny rule or a hook).
    A guardrail file under *root* that the lock does not record is compared
    with an empty record (a file that appeared after ``lock`` and allows
    anything is a loosening).  A file that cannot be read is reported in
    :attr:`Compared.unverified`, never passed.  Never raises.
    """
    out = Compared()
    files = section.get("files")
    if not isinstance(files, dict):
        return out
    try:
        base = root.resolve()
    except (OSError, RuntimeError):
        out.unverified.append(("<root>", "the repository root cannot be resolved"))
        return out
    for rel in sorted(files):
        try:
            _one(base, rel, files[rel], out)
        except Exception as exc:  # noqa: BLE001 — one file never stops the rest
            out.unverified.append((rel, f"cannot be compared: {type(exc).__name__}"))
    try:
        for rel, item in repo_files(root, errors):
            if rel in files:
                continue
            try:
                current = guardrails.read_record(item, [])
                if isinstance(current, str):
                    out.unverified.append((rel, f"not in the lock; {current}"))
                elif isinstance(current, dict):
                    diff = guardrails.compare(
                        guardrails.empty_record(item.agent), current, item.agent
                    )
                    if diff.loosened:
                        out.loosened.append(Loosened(rel, diff, new=True))
            except Exception as exc:  # noqa: BLE001
                out.unverified.append(
                    (rel, f"cannot be compared: {type(exc).__name__}")
                )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"guardrails: listing files failed: {type(exc).__name__}")
    return out
