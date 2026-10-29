"""``affected --fleet``: answer from saved scan files, not this machine (STORY-0131).

Each file is the JSON of ``mcp-audit scan --format json`` from one machine; its
``servers`` list carries every server's launch command and arguments (already
redacted by ``ServerConfig``'s serialisers, which leave version pins intact).
The result is one row per machine x server.

The files are untrusted input: they are opened without blocking, must be
regular files, are read up to a size cap, and every failure becomes a
COULDN'T CHECK row and a warning.  ``mcp-audit merge`` output carries no
per-server data, so it is recognised and reported instead of guessed at.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from mcp_audit.affected.match import UNREADABLE, Row, Status
from mcp_audit.models import ServerConfig

MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_FLEET_FILES = 1000
MAX_SERVERS_PER_FILE = 10_000

_UNSAFE = re.compile(r"[^\x20-\x7e]")

NO_SERVER_DATA = "no-server-data"


@dataclass
class Machine:
    """One machine's servers, from one scan file."""

    machine_id: str
    source: str
    servers: list[ServerConfig] = field(default_factory=list)


def _clean(text: str, limit: int = 100) -> str:
    return _UNSAFE.sub("?", text)[:limit]


def _read(path: Path) -> tuple[dict | None, str | None]:
    """The file as a JSON object, or ``(None, why)``; never raises."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return None, f"could not be read: {exc.strerror}"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "is not a regular file"
        with os.fdopen(fd, "rb", closefd=False) as handle:
            blob = handle.read(MAX_SCAN_BYTES + 1)
    except OSError as exc:
        return None, f"could not be read: {exc.strerror}"
    finally:
        os.close(fd)
    if len(blob) > MAX_SCAN_BYTES:
        return None, f"is over {MAX_SCAN_BYTES} bytes; not read"
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError):
        return None, "is not valid JSON"
    if not isinstance(doc, dict):
        return None, "is not an mcp-audit scan (expected a JSON object)"
    return doc, None


def _machine_name(doc: dict, path: Path) -> str:
    info = doc.get("machine_info", doc.get("machine"))
    if isinstance(info, dict):
        for key in ("asset_id", "hostname"):
            value = info.get(key)
            if isinstance(value, str) and value.strip():
                return _clean(value.strip())
    return _clean(path.stem)


def load_machines(
    paths: list[Path], errors: list[str]
) -> tuple[list[Machine], list[Row]]:
    """Read the scan files; problems become rows (and warnings), not exceptions."""
    machines: list[Machine] = []
    problems: list[Row] = []
    taken: set[str] = set()
    if len(paths) > MAX_FLEET_FILES:
        errors.append(
            f"--fleet: {len(paths)} files given; only the first {MAX_FLEET_FILES} "
            "are read"
        )
        paths = paths[:MAX_FLEET_FILES]
    for path in paths:
        name = _clean(path.name)

        doc, why = _read(path)
        if doc is None:
            why = why or "could not be read"
            errors.append(f"fleet file {name} {why}")
            problems.append(
                Row(
                    f"scan file {name}",
                    Status.COULDNT_CHECK,
                    f"{name} {why}, so none of its servers were checked",
                    reason=UNREADABLE,
                )
            )
            continue
        machine_id = _machine_name(doc, path)
        if machine_id in taken:
            machine_id = f"{machine_id} ({name})"
        taken.add(machine_id)
        raw = doc.get("servers")
        if raw is None and isinstance(doc.get("machines"), list):
            problems.append(
                Row(
                    f"scan file {name}",
                    Status.COULDNT_CHECK,
                    "this is `mcp-audit merge` output, which keeps findings but "
                    "no per-server launch data; pass each machine's `scan "
                    "--format json` file instead",
                    reason=NO_SERVER_DATA,
                )
            )
            errors.append(f"fleet file {name} is merge output with no server list")
            continue
        if not isinstance(raw, list):
            problems.append(
                Row(
                    f"{machine_id}",
                    Status.COULDNT_CHECK,
                    "the scan file has no `servers` list (an older mcp-audit, or "
                    "not a scan file), so none of its servers were checked",
                    reason=NO_SERVER_DATA,
                )
            )
            errors.append(f"fleet file {name} has no servers list")
            continue
        if len(raw) > MAX_SERVERS_PER_FILE:
            errors.append(
                f"fleet file {name}: {len(raw)} servers; only the first "
                f"{MAX_SERVERS_PER_FILE} are read"
            )
            raw = raw[:MAX_SERVERS_PER_FILE]
        servers: list[ServerConfig] = []
        bad = 0
        for item in raw:
            try:
                servers.append(ServerConfig.model_validate(item))
            except (ValidationError, ValueError, TypeError, RecursionError):
                bad += 1
        if bad:
            errors.append(f"fleet file {name}: {bad} server entr(ies) skipped")
            problems.append(
                Row(
                    f"{machine_id}",
                    Status.COULDNT_CHECK,
                    f"{bad} server entr{'y' if bad == 1 else 'ies'} in the scan "
                    "file could not be read, so they were not checked",
                    reason=UNREADABLE,
                )
            )
        machines.append(Machine(machine_id, name, servers))
    return machines, problems
