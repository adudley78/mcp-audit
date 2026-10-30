"""Instruction-file drift: an agent instruction file changed since the last scan.

Rug-pull state (:mod:`mcp_audit.analyzers.rug_pull`) hashes MCP *server
entries*; ``mcp-lock.json`` records servers and their tool digests.  Neither
looks at the instruction files an agent loads into every session: CLAUDE.md
tiers, AGENTS.md, ``.claude/rules``, commands, subagent definitions and
``SKILL.md``.  Claude Code loads CLAUDE.md files "at the start of every
conversation" and Claude can be asked to edit them
(https://code.claude.com/docs/en/memory), so a changed file is the place a
persistent instruction lands (Bad Memory, arXiv 2607.14611; Embrace The Red,
"Agent Commander", 2026).  STORY-0113, Q-005.

What this module does (every scan with no explicit path, ``check`` and
``scan --project`` included, beside rug-pull):

* Lists the instruction files at the user-global paths of
  :data:`~mcp_audit.agent_files.discovery.AGENT_INSTRUCTION_PATTERNS` and at
  the root of the working directory (skipped when the working directory is
  ``$HOME``).  No tree walk; no import following.
* Hashes each file's bytes (SHA-256, streamed, bounded).  Content is never
  kept, printed or written: the state file holds the digest, the size, two
  timestamps, the IDs of MEDIUM-or-higher findings about the file's own
  content, and the last few hashes with their IDs.
* Compares with the previous record for the same absolute path:

  - **INSTR-001** (INFO): the bytes changed.
  - **INSTR-002** (MEDIUM): the bytes changed *and* the file now has a
    MEDIUM-or-higher content finding ID (MEM-/SKILL-/POISON-/AGENT-/HOOK-)
    that the previous record did not have, i.e. the change brought the
    finding.  For the user's own memory files the MEM-004/005 checks run here
    (a default scan runs them on the working directory's files only); their
    IDs are recorded, not reported.  A version seen before never escalates.

  A file seen for the first time is recorded silently (every newly visited
  repository would otherwise report every file), and a file that disappeared
  is not reported.

Safety: never executes anything; reads files only.  Files at the working
directory's root that are symlinks, or that resolve outside it, are skipped
(they are TRUST-002 elsewhere and are not the repository's own); user-global
files are read through a final symlink (the dotfile-manager shape, TRUST-004
elsewhere) because that is what the agent reads.  Per-file and per-scan byte
and file budgets; every filesystem error becomes an entry in ``errors``,
never an exception.  The record file is shared by every scan: writes go
through a temporary file and ``os.replace`` under a lock file, after
re-reading the file, and a file that cannot be read is never overwritten.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from platformdirs import user_config_dir

from mcp_audit.agent_files.discovery import (
    AGENT_INSTRUCTION_PATTERNS,
    _is_symlink,
    _resolve_relative_pattern,
    _split_frontmatter,
)
from mcp_audit.agent_files.imports import READ_CAP_BYTES
from mcp_audit.agent_files.models import MEMORY_SURFACES, AgentFile, AgentFileSurface
from mcp_audit.models import Finding, Severity

#: Where the per-file records live when the caller gives no rug-pull state
#: path.  One file for every scan, keyed by absolute path, so a change in the
#: set of MCP configs (which moves rug-pull to a new state file) never resets
#: the instruction-file baselines.
DEFAULT_STATE_PATH: Path = (
    Path(user_config_dir("mcp-audit")) / "state" / "instruction-files.json"
)
_STATE_VERSION = 1

#: Claude Code loads a CLAUDE.md of up to 4 MiB and skips a larger one
#: (code.claude.com/docs/en/memory).  A file over this cap is hashed anyway,
#: streamed, up to :data:`MAX_FILE_BYTES`.
MAX_FILE_BYTES: int = 32 * 1024 * 1024
#: Per-scan budgets.  Hitting one is reported in ``errors``.
MAX_FILES: int = 5000
MAX_TOTAL_BYTES: int = 256 * 1024 * 1024
#: Records kept in the state file; the least recently seen are dropped first.
MAX_RECORDS: int = 10000
#: State files larger than this are not parsed (a fresh record is started).
MAX_STATE_BYTES: int = 16 * 1024 * 1024

#: Distinct earlier versions remembered per file, so switching back to a
#: version already seen (a branch checkout) never escalates again.
MAX_HISTORY: int = 8
#: How long a scan waits for another scan's write before giving up (seconds),
#: and when a leftover lock file is treated as stale.
LOCK_WAIT_SECONDS: float = 5.0
LOCK_STALE_SECONDS: float = 30.0

_CHUNK = 1024 * 1024
_ESCALATING = frozenset({Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL})
#: Only findings derived from a file's own content count for INSTR-002.
#: TRUST-* (symlinks, which depend on where the scan runs), budget notes and
#: anything else about the file's surroundings do not.
_CONTENT_ID_PREFIXES: tuple[str, ...] = ("MEM-", "SKILL-", "POISON-", "AGENT-", "HOOK-")


def _home() -> Path:
    """The home directory (patched in tests)."""
    return Path.home()


@dataclass(frozen=True)
class InstructionFile:
    """One instruction file to track.

    Attributes:
        path: Absolute path as the agent reads it (not resolved through a
            final symlink: a dotfile manager's link is the file's identity).
        client: Client that reads it (from the pattern table).
        scope: ``"user"`` or ``"project"``.
        display: Short name for titles (``~/.claude/CLAUDE.md``, ``AGENTS.md``).
        surface: The instruction surface (from the pattern table).
    """

    path: Path
    client: str
    scope: str
    display: str
    surface: AgentFileSurface | None = None


def _safe_resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return None


def state_path_for(rug_pull_state: Path | None) -> Path:
    """Return the instruction-file state path for a scan.

    With an explicit rug-pull state path (tests, ``scan`` callers that pass
    one), the record sits beside it so the two stay together; otherwise the
    shared :data:`DEFAULT_STATE_PATH`.
    """
    if rug_pull_state is None:
        return DEFAULT_STATE_PATH
    return rug_pull_state.with_name(f"{rug_pull_state.stem}.instruction-files.json")


def instruction_files(cwd: Path, errors: list[str]) -> list[InstructionFile]:
    """List the instruction files a default scan tracks.

    User-global patterns under :func:`_home`, then the project patterns at
    the root of *cwd* (none when *cwd* is the home directory).  A file
    reached by both (``cwd`` = ``~/.claude``) is listed once.  Never raises.
    """
    out: list[InstructionFile] = []
    seen: set[str] = set()
    home = _home()

    def _add(
        path: Path,
        client: str,
        scope: str,
        display: str,
        surface: AgentFileSurface,
    ) -> None:
        resolved = _safe_resolve(path)
        key = os.path.normcase(str(resolved if resolved is not None else path))
        if key in seen:
            return
        seen.add(key)
        out.append(
            InstructionFile(
                Path(os.path.abspath(path)), client, scope, display, surface
            )
        )

    try:
        for pattern in AGENT_INSTRUCTION_PATTERNS:
            if pattern.scope != "user":
                continue
            for match in _resolve_relative_pattern(home, pattern.relative_glob, None):
                _add(
                    match,
                    pattern.client,
                    "user",
                    "~/" + _rel(match, home),
                    pattern.surface,
                )
    except Exception as exc:  # noqa: BLE001 — never fail a scan over this
        errors.append(f"instruction drift: listing user files failed: {exc}")

    root = _safe_resolve(cwd)
    home_resolved = _safe_resolve(home)
    if root is None or (home_resolved is not None and root == home_resolved):
        return out
    try:
        for pattern in AGENT_INSTRUCTION_PATTERNS:
            if pattern.scope != "project":
                continue
            for match in _resolve_relative_pattern(root, pattern.relative_glob, root):
                if _is_symlink(match):
                    continue  # TRUST-002 elsewhere; not the repository's own
                resolved = _safe_resolve(match)
                if resolved is None or not resolved.is_relative_to(root):
                    continue  # reached through a link that leaves the folder
                _add(
                    match, pattern.client, "project", _rel(match, root), pattern.surface
                )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"instruction drift: listing project files failed: {exc}")
    return out


def _rel(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.name


class _Budget:
    def __init__(self) -> None:
        self.files = 0
        self.bytes = 0
        self.stopped = False


def hash_file(
    path: Path,
    *,
    follow_symlink: bool,
    budget: _Budget | None = None,
    head: bytearray | None = None,
) -> tuple[str, int] | str:
    """Return ``(sha256 hex, size)`` for *path*, or an error string.

    Opens without following a final symlink unless *follow_symlink*, refuses
    anything that is not a regular file (a FIFO would block a plain read),
    and reads at most :data:`MAX_FILE_BYTES` in 1 MiB chunks.  With *head*,
    the first :data:`READ_CAP_BYTES` bytes are also collected there (for the
    content checks of :func:`_content_ids`).  Never raises.
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if not follow_symlink:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return f"cannot open: {exc.strerror or type(exc).__name__}"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return "not a regular file"
        if info.st_size > MAX_FILE_BYTES:
            return f"over {MAX_FILE_BYTES} bytes; not hashed"
        if budget is not None:
            if (
                budget.files + 1 > MAX_FILES
                or budget.bytes + info.st_size > MAX_TOTAL_BYTES
            ):
                budget.stopped = True
                return "budget"
            budget.files += 1
            budget.bytes += info.st_size
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                return f"grew past {MAX_FILE_BYTES} bytes while read; not hashed"
            digest.update(chunk)
            if head is not None and len(head) < READ_CAP_BYTES:
                head.extend(chunk[: READ_CAP_BYTES - len(head)])
        return digest.hexdigest(), size
    except OSError as exc:
        return f"cannot read: {exc.strerror or type(exc).__name__}"
    finally:
        os.close(fd)


_MISSING = "missing"
_OK = "ok"
_CORRUPT = "corrupt"
_UNREADABLE = "unreadable"


def _read_state(state_path: Path) -> tuple[str, dict[str, dict]]:
    """Read the record file; return ``(status, records)``.

    ``missing``: no file yet.  ``corrupt``: the file is there but is not a
    record file mcp-audit wrote (bad JSON, wrong shape, over
    :data:`MAX_STATE_BYTES`); writes are atomic, so a scan running at the
    same time never produces this.  ``unreadable``: an operating-system error
    (permissions, a transient I/O failure); the file is left alone.
    """
    try:
        size = state_path.stat().st_size
    except FileNotFoundError:
        return _MISSING, {}
    except OSError:
        return _UNREADABLE, {}
    if size > MAX_STATE_BYTES:
        return _CORRUPT, {}
    raw: bytes | None = None
    for attempt in range(5):
        try:
            raw = state_path.read_bytes()
            break
        except FileNotFoundError:
            return _MISSING, {}
        except PermissionError:
            # Windows: the file is being replaced by another scan right now.
            if attempt == 4:
                return _UNREADABLE, {}
            time.sleep(0.02)
        except OSError:
            return _UNREADABLE, {}
    if raw is None:
        return _UNREADABLE, {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return _CORRUPT, {}
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return _CORRUPT, {}
    return _OK, {
        k: v for k, v in files.items() if isinstance(k, str) and isinstance(v, dict)
    }


def _load(state_path: Path, errors: list[str]) -> tuple[str, dict[str, dict]]:
    status, records = _read_state(state_path)
    if status == _CORRUPT:
        errors.append(
            "instruction drift: state file is not a record file; it will be"
            " kept as .corrupt and a new record started"
        )
    elif status == _UNREADABLE:
        errors.append(
            "instruction drift: cannot read state; history kept, not updated this scan"
        )
    return status, records


def _capped(records: dict[str, dict]) -> dict[str, dict]:
    if len(records) <= MAX_RECORDS:
        return records
    keep = sorted(
        records.items(),
        key=lambda kv: str(kv[1].get("last_seen", "")),
        reverse=True,
    )[:MAX_RECORDS]
    return dict(keep)


def _replace(src: Path, dst: Path) -> None:
    """``os.replace`` with a short retry for Windows sharing violations."""
    for attempt in range(5):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.05)


def save_records(records: dict[str, dict], state_path: Path) -> None:
    """Write *records* atomically: 0o700 directory, 0o600 file, capped.

    The body goes to a new temporary file in the same directory (created
    exclusively, 0o600) and replaces the record file in one step, so a reader
    sees the old file or the new one, never a partial write.  The temporary
    file is removed on any failure.
    """
    records = _capped(records)
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = json.dumps(
        {"version": _STATE_VERSION, "files": records}, indent=2, sort_keys=True
    ).encode("utf-8")
    tmp = state_path.with_name(f".{state_path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        _replace(tmp, state_path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


class _Lock:
    """An exclusive lock file beside the record file (works across processes)."""

    def __init__(self, state_path: Path) -> None:
        self.path = state_path.with_name(state_path.name + ".lock")
        self.held = False

    def acquire(self) -> bool:
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fd = os.open(
                    str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                os.close(fd)
                self.held = True
                return True
            except (FileExistsError, PermissionError):
                # Windows reports a lock file being deleted as PermissionError.
                with contextlib.suppress(OSError):
                    if time.time() - self.path.stat().st_mtime > LOCK_STALE_SECONDS:
                        self.path.unlink()
                        continue
            except OSError:
                return False
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def release(self) -> None:
        if self.held:
            with contextlib.suppress(OSError):
                self.path.unlink()
            self.held = False


def _commit(updates: dict[str, dict], state_path: Path, errors: list[str]) -> None:
    """Merge *updates* into the record file under the lock and write it.

    The file is read again under the lock, so another scan's records for
    other paths survive.  An unreadable file is left alone (history is never
    wiped because of a transient error); a file that is not a record file is
    kept as ``<name>.corrupt`` and a new one started.
    """
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        errors.append(f"instruction drift: cannot write state: {exc}")
        return
    lock = _Lock(state_path)
    if not lock.acquire():
        errors.append("instruction drift: state busy; not updated this scan")
        return
    try:
        status, current = _read_state(state_path)
        if status == _UNREADABLE:
            return
        if status == _CORRUPT:
            _replace(state_path, state_path.with_name(state_path.name + ".corrupt"))
            current = {}
        current.update(updates)
        save_records(current, state_path)
    except OSError as exc:
        errors.append(f"instruction drift: cannot write state: {exc}")
    finally:
        lock.release()


def _path_keys(path_text: str) -> set[str]:
    keys = {os.path.normcase(os.path.abspath(path_text))}
    with contextlib.suppress(OSError, ValueError):
        keys.add(os.path.normcase(os.path.realpath(path_text)))
    return keys


def _ids_by_path(findings: Iterable[Finding]) -> dict[str, set[str]]:
    """Map each finding path (absolute and real forms) to its MEDIUM+ IDs.

    Only IDs derived from the file's content count (:data:`_CONTENT_ID_PREFIXES`).
    """
    out: dict[str, set[str]] = {}
    for finding in findings:
        if finding.severity not in _ESCALATING or not finding.finding_path:
            continue
        if not finding.id.startswith(_CONTENT_ID_PREFIXES):
            continue
        for key in _path_keys(finding.finding_path):
            out.setdefault(key, set()).add(finding.id)
    return out


def _short(digest: object) -> str:
    text = str(digest) if digest else "unknown"
    return text[:16]


def instruction_drift_findings(
    tracked: list[InstructionFile],
    findings: Iterable[Finding],
    state_path: Path,
    errors: list[str],
) -> list[Finding]:
    """Compare *tracked* files with their records; update the records.

    Args:
        tracked: Files from :func:`instruction_files`.
        findings: Every finding this scan has produced so far (for INSTR-002).
        state_path: The record file (see :func:`state_path_for`).
        errors: Receives filesystem problems and budget stops.

    Returns:
        INSTR-001 / INSTR-002 findings.  Never raises.
    """
    try:
        return _drift(tracked, findings, state_path, errors)
    except Exception as exc:  # noqa: BLE001 — a scan must never fail over this
        errors.append(f"instruction drift failed: {type(exc).__name__}")
        return []


def _content_ids(item: InstructionFile, head: bytes) -> set[str]:
    """MEDIUM+ IDs the default scan's text checks give a user-global file.

    A default scan runs MEM-003/004/005 on the working directory's files
    only, so a user-global memory file (``~/.claude/CLAUDE.md``, rules,
    ``~/.codex/AGENTS.md``, OpenClaw files) gets the same MEM-004/MEM-005
    checks here, on the bytes already read for the hash.  The IDs only feed
    INSTR-002; the findings themselves are not added to the scan
    (``mcp-audit agent-files scan`` reports them).
    """
    if item.scope != "user" or item.surface not in MEMORY_SURFACES:
        return set()
    from mcp_audit.agent_files.analyzer import (  # noqa: PLC0415
        analyze_instruction_reach,
    )

    text = head.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    frontmatter, body = _split_frontmatter(text)
    af = AgentFile(
        path=item.path,
        surface=item.surface,
        client=item.client,
        scope="user",
        raw_content=text,
        body=body,
        frontmatter=frontmatter,
    )
    return {
        f.id
        for f in analyze_instruction_reach([af], _home())
        if f.severity in _ESCALATING and f.id.startswith(_CONTENT_ID_PREFIXES)
    }


def _history(record: dict | None) -> list[list]:
    if not record:
        return []
    raw = record.get("history")
    out: list[list] = []
    if isinstance(raw, list):
        for entry in raw:
            if (
                isinstance(entry, list)
                and len(entry) == 2
                and isinstance(entry[0], str)
                and isinstance(entry[1], list)
            ):
                out.append([entry[0], [i for i in entry[1] if isinstance(i, str)]])
    return out


def _drift(
    tracked: list[InstructionFile],
    findings: Iterable[Finding],
    state_path: Path,
    errors: list[str],
) -> list[Finding]:
    status, records = _load(state_path, errors)
    ids_by_path = _ids_by_path(findings)
    budget = _Budget()
    now = datetime.now(UTC).isoformat()
    out: list[Finding] = []
    updates: dict[str, dict] = {}
    for item in tracked:
        head = bytearray()
        hashed = hash_file(
            item.path,
            follow_symlink=item.scope == "user",
            budget=budget,
            head=head,
        )
        if isinstance(hashed, str):
            if hashed == "budget":
                break
            errors.append(f"instruction drift: {item.display}: {hashed}")
            continue
        digest, size = hashed
        key = os.path.normcase(str(item.path))
        current_ids: set[str] = set()
        for path_key in _path_keys(str(item.path)):
            current_ids |= ids_by_path.get(path_key, set())
        try:
            current_ids |= _content_ids(item, bytes(head))
        except Exception as exc:  # noqa: BLE001 — never fail a scan over this
            errors.append(
                f"instruction drift: {item.display}: content check failed:"
                f" {type(exc).__name__}"
            )
        previous = records.get(key)
        history = _history(previous)
        if previous is not None and previous.get("sha256") != digest:
            seen_before = any(entry[0] == digest for entry in history)
            out.append(_finding(item, previous, digest, size, current_ids, seen_before))
        history = [e for e in history if e[0] != digest]
        history.append([digest, sorted(current_ids)])
        updates[key] = {
            "sha256": digest,
            "size": size,
            "first_seen": (previous or {}).get("first_seen", now),
            "last_seen": now,
            "finding_ids": sorted(current_ids),
            "history": history[-MAX_HISTORY:],
        }
    if budget.stopped:
        errors.append(
            f"instruction drift: stopped after {MAX_FILES} files /"
            f" {MAX_TOTAL_BYTES} bytes; later files were not checked"
        )
    if status != _UNREADABLE:
        # Never write after a failed read: these updates were computed
        # without the history and would overwrite it.
        _commit(updates, state_path, errors)
    return out


def _finding(
    item: InstructionFile,
    previous: dict,
    digest: str,
    size: int,
    current_ids: set[str],
    seen_before: bool = False,
) -> Finding:
    prior_ids = previous.get("finding_ids")
    gained: list[str] = []
    if isinstance(prior_ids, list) and not seen_before:
        known = {i for i in prior_ids if isinstance(i, str)}
        gained = sorted(current_ids - known)
    evidence = (
        f"sha256 {_short(previous.get('sha256'))}… -> {digest[:16]}…;"
        f" size {previous.get('size', '?')} -> {size} bytes;"
        f" last seen {previous.get('last_seen', 'unknown')}"
    )
    where = (
        "every session of this user"
        if item.scope == "user"
        else "sessions started in this folder"
    )
    if gained:
        return Finding(
            id="INSTR-002",
            severity=Severity.MEDIUM,
            analyzer="agent_files",
            client=item.client,
            server=item.display,
            title=(
                f"Instruction file changed and now has {', '.join(gained)}:"
                f" {item.display}"
            ),
            description=(
                f"{item.display} is loaded as instructions into {where}. Its"
                " contents changed since the last scan, and this scan reports"
                f" {', '.join(gained)} on it, which the last scan did not: the"
                " change brought that finding. mcp-audit keeps only a hash of"
                " the file, so it cannot show what changed."
            ),
            evidence=evidence + f"; new findings: {', '.join(gained)}",
            remediation=(
                "Read the file and the finding(s) named above (for a file in"
                " your home folder, `mcp-audit agent-files scan` shows them)."
                " If you did not make the change, check who did (an agent"
                " session, a skill or plugin update, a sync tool) and restore"
                " the file."
            ),
            cwe="CWE-345",
            finding_path=str(item.path),
            owasp_mcp_top_10=["MCP10", "MCP03"],
        )
    return Finding(
        id="INSTR-001",
        severity=Severity.INFO,
        analyzer="agent_files",
        client=item.client,
        server=item.display,
        title=f"Instruction file changed since the last scan: {item.display}",
        description=(
            f"{item.display} is loaded as instructions into {where}. Its"
            " contents changed since the last scan. That is usually your own"
            " edit; it is reported because an agent, a skill or a sync tool can"
            " write here too. mcp-audit keeps only a hash of the file, so it"
            " cannot show what changed."
        ),
        evidence=evidence,
        remediation=(
            "If you did not change this file, read it (for a repository, `git"
            " diff` shows the change) and remove anything you did not write."
        ),
        cwe="CWE-345",
        finding_path=str(item.path),
        owasp_mcp_top_10=["MCP10"],
    )
