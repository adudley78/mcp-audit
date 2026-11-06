"""``reach --fleet``: roll up saved ``reach --format json`` files (STORY-0145).

Each file is the JSON one machine wrote with ``mcp-audit reach --format json``.
The files are untrusted input, read the way ``affected --fleet`` reads scan
files: opened without blocking, regular files only, size-capped, a bounded
number of files, and every failure becomes an entry in ``skipped`` with a
printable reason instead of an exception.  Nothing in a file is trusted beyond
the few fields used here, and every string taken from one is cleaned before it
is shown.

The roll-up counts agents per verdict per agent name and lists the machines
that are "not safe to allow".
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.reach.models import Verdict

#: Largest reach file read.  A report is a few dozen KiB; this is generous.
MAX_FILE_BYTES = 4 * 1024 * 1024
#: Most files read from one directory.
MAX_FILES = 1000
#: Most agents read from one file.
MAX_AGENTS_PER_FILE = 200
FLEET_SCHEMA_VERSION = "1.0"

_UNSAFE = re.compile(r"[^\x20-\x7e]")
_VERDICTS = {v.value for v in Verdict}


def clean(text: object, limit: int = 100) -> str:
    """*text* as printable ASCII, cut to *limit* characters."""
    return _UNSAFE.sub("?", str(text))[:limit]


@dataclass
class FleetMachine:
    """One machine's agents, from one reach file."""

    machine: str
    source: str
    agents: list[tuple[str, Verdict]] = field(default_factory=list)
    #: Collection errors the machine's own report listed.
    errors: int = 0


@dataclass
class FleetReport:
    """The roll-up of a directory of reach files."""

    machines: list[FleetMachine] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    truncated: bool = False

    def per_agent(self) -> dict[str, dict[str, int]]:
        """Verdict counts per agent name (every verdict present, zero included)."""
        out: dict[str, dict[str, int]] = {}
        for machine in self.machines:
            for name, verdict in machine.agents:
                row = out.setdefault(name, {v.value: 0 for v in Verdict})
                row[verdict.value] += 1
        return dict(sorted(out.items()))

    def not_safe(self) -> list[tuple[str, list[str]]]:
        """Machines with an agent that is not safe to allow, and which agents."""
        found: list[tuple[str, list[str]]] = []
        for machine in self.machines:
            bad = [n for n, v in machine.agents if v is Verdict.NOT_SAFE]
            if bad:
                found.append((machine.machine, bad))
        return found

    @property
    def exit_code(self) -> int:
        """1 when any agent on any machine needs work or is not safe, else 0."""
        bad = (Verdict.NEEDS_WORK, Verdict.NOT_SAFE)
        return int(any(v in bad for m in self.machines for _n, v in m.agents))

    def fail_closed_reasons(self) -> list[str]:
        """Why ``reach --fleet --fail-closed`` refuses the fleet; empty = pass.

        Missing evidence counts as a failure: no report read, a skipped or
        unread file, a machine with no agents, an agent whose verdict is
        "couldn't check", or a machine whose report lists collection errors.
        """
        reasons: list[str] = []
        if not self.machines:
            reasons.append("no reach report was read")
        if self.skipped:
            reasons.append(f"{len(self.skipped)} file(s) skipped")
        if self.truncated:
            reasons.append(f"more than {MAX_FILES} files; the rest were not read")
        empty = [m.machine for m in self.machines if not m.agents]
        if empty:
            reasons.append("no agents found on: " + ", ".join(empty))
        unchecked = sorted(
            {
                m.machine
                for m in self.machines
                for _n, v in m.agents
                if v is Verdict.COULDNT_CHECK
            }
        )
        if unchecked:
            reasons.append("couldn't check an agent on: " + ", ".join(unchecked))
        with_errors = [m.machine for m in self.machines if m.errors]
        if with_errors:
            reasons.append("collection errors on: " + ", ".join(with_errors))
        return reasons

    def gate_exit_code(self, *, fail_closed: bool = False) -> int:
        """:attr:`exit_code`, or 1 under *fail_closed* when evidence is missing."""
        if self.exit_code:
            return self.exit_code
        return 1 if fail_closed and self.fail_closed_reasons() else 0

    def to_dict(self) -> dict:
        """The fleet roll-up as JSON (``docs/reach-fleet.schema.json``)."""
        return {
            "schema_version": FLEET_SCHEMA_VERSION,
            "kind": "fleet",
            "machines": len(self.machines),
            "per_agent": self.per_agent(),
            "not_safe_to_allow": [
                {"machine": m, "agents": a} for m, a in self.not_safe()
            ],
            "skipped": [{"file": f, "reason": r} for f, r in self.skipped],
            "truncated": self.truncated,
        }


def _read(path: Path) -> tuple[dict | None, str | None]:
    """The file as a JSON object, or ``(None, why)``.  Never raises."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    # A fleet directory is untrusted input: a symlink in it can name any file
    # on this machine, so it is not followed.
    if os.path.islink(path):
        return None, "is a symbolic link (not followed)"
    # Checked before opening too: Windows refuses to open a directory with
    # "Permission denied", which would hide the real reason.
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None, "is not a regular file"
    except OSError as exc:
        return None, f"could not be read ({exc.strerror or type(exc).__name__})"
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return None, f"could not be read ({exc.strerror or type(exc).__name__})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "is not a regular file"
        with os.fdopen(fd, "rb", closefd=False) as handle:
            blob = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        return None, f"could not be read ({exc.strerror or type(exc).__name__})"
    finally:
        os.close(fd)
    if len(blob) > MAX_FILE_BYTES:
        return None, f"is over {MAX_FILE_BYTES} bytes"
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError):
        return None, "is not valid JSON"
    if not isinstance(doc, dict):
        return None, "is not a reach report (expected a JSON object)"
    return doc, None


def _machine_name(doc: dict, path: Path) -> str:
    machine = doc.get("machine")
    if isinstance(machine, dict):
        for key in ("asset_id", "hostname"):
            value = machine.get(key)
            if isinstance(value, str) and value.strip():
                return clean(value.strip())
    return clean(path.stem)


def _agents(doc: dict) -> tuple[list[tuple[str, Verdict]] | None, str | None]:
    """The ``(name, verdict)`` pairs of a reach report, or ``(None, why)``."""
    version = doc.get("schema_version")
    if not isinstance(version, str) or version.split(".")[0] != "1":
        return None, "is not a reach report (no schema_version 1.x)"
    raw = doc.get("agents")
    if not isinstance(raw, list):
        return None, "has no agents list"
    out: list[tuple[str, Verdict]] = []
    if len(raw) > MAX_AGENTS_PER_FILE:
        return None, f"has more than {MAX_AGENTS_PER_FILE} agents (not counted)"
    for item in raw:
        if not isinstance(item, dict):
            return None, "has an agent entry that is not an object"
        name, verdict = item.get("name"), item.get("verdict")
        if not isinstance(name, str) or not name.strip():
            return None, "has an agent without a name"
        if not isinstance(verdict, str) or verdict not in _VERDICTS:
            return None, "has an agent with an unknown verdict"
        out.append((clean(name.strip()), Verdict(verdict)))
    return out, None


def load_fleet(directory: Path) -> FleetReport:
    """Read the ``*.json`` files in *directory* (not recursive).  Never raises
    for a bad file: it is listed in ``skipped``.

    Raises:
        OSError: when *directory* itself cannot be listed.
    """
    report = FleetReport()
    names = sorted(p for p in directory.iterdir() if p.name.lower().endswith(".json"))
    if len(names) > MAX_FILES:
        report.truncated = True
        names = names[:MAX_FILES]
    taken: set[str] = set()
    for path in names:
        shown = clean(path.name)
        doc, why = _read(path)
        if doc is None:
            report.skipped.append((shown, why or "could not be read"))
            continue
        agents, why = _agents(doc)
        if agents is None:
            report.skipped.append((shown, why or "is not a reach report"))
            continue
        machine = _machine_name(doc, path)
        if machine in taken:
            machine = f"{machine} ({shown})"
        taken.add(machine)
        raw_errors = doc.get("errors")
        errors = len(raw_errors) if isinstance(raw_errors, list) else 0
        report.machines.append(FleetMachine(machine, shown, agents, errors))
    return report
