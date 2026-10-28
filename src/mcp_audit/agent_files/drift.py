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

What this module does (default ``scan``/``check`` only, beside rug-pull):

* Lists the instruction files at the user-global paths of
  :data:`~mcp_audit.agent_files.discovery.AGENT_INSTRUCTION_PATTERNS` and at
  the root of the working directory (skipped when the working directory is
  ``$HOME``).  No tree walk; no import following.
* Hashes each file's bytes (SHA-256, streamed, bounded).  Content is never
  kept, printed or written: the state file holds the digest, the size, two
  timestamps and the IDs of MEDIUM-or-higher findings the scan reported on
  that file.
* Compares with the previous record for the same absolute path:

  - **INSTR-001** (INFO): the bytes changed.
  - **INSTR-002** (MEDIUM): the bytes changed *and* this scan reports a
    MEDIUM-or-higher finding ID on the file that the previous record did not
    have, i.e. the change brought the finding.

  A file seen for the first time is recorded silently (every newly visited
  repository would otherwise report every file), and a file that disappeared
  is not reported.

Safety: never executes anything; reads files only.  Files at the working
directory's root that are symlinks, or that resolve outside it, are skipped
(they are TRUST-002 elsewhere and are not the repository's own); user-global
files are read through a final symlink (the dotfile-manager shape, TRUST-004
elsewhere) because that is what the agent reads.  Per-file and per-scan byte
and file budgets; every filesystem error becomes an entry in ``errors``,
never an exception.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from platformdirs import user_config_dir

from mcp_audit.agent_files.discovery import (
    AGENT_INSTRUCTION_PATTERNS,
    _is_symlink,
    _resolve_relative_pattern,
)
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

_CHUNK = 1024 * 1024
_ESCALATING = frozenset({Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL})


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
    """

    path: Path
    client: str
    scope: str
    display: str


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

    def _add(path: Path, client: str, scope: str, display: str) -> None:
        resolved = _safe_resolve(path)
        key = os.path.normcase(str(resolved if resolved is not None else path))
        if key in seen:
            return
        seen.add(key)
        out.append(InstructionFile(Path(os.path.abspath(path)), client, scope, display))

    try:
        for pattern in AGENT_INSTRUCTION_PATTERNS:
            if pattern.scope != "user":
                continue
            for match in _resolve_relative_pattern(home, pattern.relative_glob, None):
                _add(match, pattern.client, "user", "~/" + _rel(match, home))
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
                _add(match, pattern.client, "project", _rel(match, root))
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
    path: Path, *, follow_symlink: bool, budget: _Budget | None = None
) -> tuple[str, int] | str:
    """Return ``(sha256 hex, size)`` for *path*, or an error string.

    Opens without following a final symlink unless *follow_symlink*, refuses
    anything that is not a regular file (a FIFO would block a plain read),
    and reads at most :data:`MAX_FILE_BYTES` in 1 MiB chunks.  Never raises.
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
        return digest.hexdigest(), size
    except OSError as exc:
        return f"cannot read: {exc.strerror or type(exc).__name__}"
    finally:
        os.close(fd)


def load_records(state_path: Path, errors: list[str]) -> dict[str, dict]:
    """Read the per-file records; an unreadable or odd file starts afresh."""
    try:
        size = state_path.stat().st_size
    except FileNotFoundError:
        return {}
    except OSError as exc:
        errors.append(f"instruction drift: cannot read state: {exc}")
        return {}
    if size > MAX_STATE_BYTES:
        errors.append("instruction drift: state file too large; started a new record")
        return {}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        errors.append("instruction drift: state file unreadable; started a new record")
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    return {
        k: v for k, v in files.items() if isinstance(k, str) and isinstance(v, dict)
    }


def save_records(records: dict[str, dict], state_path: Path) -> None:
    """Write the records: 0o700 directory, 0o600 file, oldest dropped past the cap."""
    if len(records) > MAX_RECORDS:
        keep = sorted(
            records.items(),
            key=lambda kv: str(kv[1].get("last_seen", "")),
            reverse=True,
        )[:MAX_RECORDS]
        records = dict(keep)
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = json.dumps(
        {"version": _STATE_VERSION, "files": records}, indent=2, sort_keys=True
    ).encode("utf-8")
    fd = os.open(str(state_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(body)


def _path_keys(path_text: str) -> set[str]:
    keys = {os.path.normcase(os.path.abspath(path_text))}
    with contextlib.suppress(OSError, ValueError):
        keys.add(os.path.normcase(os.path.realpath(path_text)))
    return keys


def _ids_by_path(findings: Iterable[Finding]) -> dict[str, set[str]]:
    """Map each finding path (absolute and real forms) to its MEDIUM+ IDs."""
    out: dict[str, set[str]] = {}
    for finding in findings:
        if finding.severity not in _ESCALATING or not finding.finding_path:
            continue
        if finding.id.startswith("INSTR-"):
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


def _drift(
    tracked: list[InstructionFile],
    findings: Iterable[Finding],
    state_path: Path,
    errors: list[str],
) -> list[Finding]:
    records = load_records(state_path, errors)
    ids_by_path = _ids_by_path(findings)
    budget = _Budget()
    now = datetime.now(UTC).isoformat()
    out: list[Finding] = []
    for item in tracked:
        hashed = hash_file(
            item.path, follow_symlink=item.scope == "user", budget=budget
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
        previous = records.get(key)
        if previous is not None and previous.get("sha256") != digest:
            out.append(_finding(item, previous, digest, size, current_ids))
        records[key] = {
            "sha256": digest,
            "size": size,
            "first_seen": (previous or {}).get("first_seen", now),
            "last_seen": now,
            "finding_ids": sorted(current_ids),
        }
    if budget.stopped:
        errors.append(
            f"instruction drift: stopped after {MAX_FILES} files /"
            f" {MAX_TOTAL_BYTES} bytes; later files were not checked"
        )
    try:
        save_records(records, state_path)
    except OSError as exc:
        errors.append(f"instruction drift: cannot write state: {exc}")
    return out


def _finding(
    item: InstructionFile,
    previous: dict,
    digest: str,
    size: int,
    current_ids: set[str],
) -> Finding:
    prior_ids = previous.get("finding_ids")
    gained: list[str] = []
    if isinstance(prior_ids, list):
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
                "Read the file and the finding(s) named above. If you did not"
                " make the change, check who did (an agent session, a skill"
                " or plugin update, a sync tool) and restore the file."
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
