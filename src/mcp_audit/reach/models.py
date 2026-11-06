"""Data model for ``mcp-audit reach`` (STORY-0145).

Pure dataclasses: no I/O, no rendering.  ``MachineReach.to_dict`` is the one
place a report becomes JSON, and it is also what the terminal and PDF
renderers read, so every string that leaves this package passes through
:func:`sanitize` exactly once, there.

``sanitize`` is the privacy choke point:

- URL userinfo and every ``SECRET_PATTERNS`` match, ``Bearer``/``Basic``
  tokens, credential headers and ``password=`` pairs are replaced by
  ``[REDACTED]`` (:func:`mcp_audit.analyzers.supply_chain.redact_command_text`);
- the home directory is replaced by ``~`` (the username never appears).
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any

from mcp_audit.analyzers.supply_chain import redact_command_text

SCHEMA_VERSION = "1.0"

#: Longest string kept in a report; longer text is cut (after redaction).
MAX_TEXT = 600
#: Errors kept in a report.
MAX_ERRORS = 50

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class Status(StrEnum):
    """The state of one question for one agent."""

    PASS = "pass"  # noqa: S105 — a status word, not a password
    FAIL = "fail"
    UNKNOWN = "couldnt_check"
    INFO = "info"


class Verdict(StrEnum):
    """The verdict for one agent against the sanctioned path."""

    READY = "ready"
    NEEDS_WORK = "needs_work"
    NOT_SAFE = "not_safe_to_allow"
    COULDNT_CHECK = "couldnt_check"


#: Display text for each verdict (terminal, PDF).
VERDICT_LABELS: dict[Verdict, str] = {
    Verdict.READY: "READY",
    Verdict.NEEDS_WORK: "NEEDS WORK",
    Verdict.NOT_SAFE: "NOT SAFE TO ALLOW",
    Verdict.COULDNT_CHECK: "COULDN'T CHECK",
}

#: Severity order for "worst verdict": higher is worse.
VERDICT_RANK: dict[Verdict, int] = {
    Verdict.READY: 0,
    Verdict.COULDNT_CHECK: 1,
    Verdict.NEEDS_WORK: 2,
    Verdict.NOT_SAFE: 3,
}

QUESTION_IDS: tuple[str, ...] = (
    "where_it_runs",
    "credentials",
    "network",
    "policy",
    "logging",
)

QUESTION_TITLES: dict[str, str] = {
    "where_it_runs": "Where does it run?",
    "credentials": "Whose credentials can it read?",
    "network": "What can it reach on the network?",
    "policy": "Is policy enforced?",
    "logging": "Is activity logged?",
}


@dataclass
class Fact:
    """One value read from one place.

    Attributes:
        key: What was read (``sandbox.enabled``).
        value: What it said, or ``"(not set)"``.
        source: Where it came from, home masked (``~/.claude/settings.json``),
            or ``None`` when no single file decides it.
    """

    key: str
    value: str
    source: str | None = None


@dataclass
class Question:
    """The answer to one of the five questions for one agent."""

    id: str
    status: Status
    summary: str
    facts: list[Fact] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        """The question as asked."""
        return QUESTION_TITLES.get(self.id, self.id)


@dataclass
class Reason:
    """Why an agent got its verdict, pointing at what produced it.

    Attributes:
        kind: ``not_safe``, ``needs_work`` or ``unknown``.
        text: One sentence.
        refs: Finding IDs (``REACH-001``) and ``file:key`` pointers
            (``~/.claude/settings.json:permissions.defaultMode``).
    """

    kind: str
    text: str
    refs: list[str] = field(default_factory=list)


@dataclass
class AgentReach:
    """Everything ``reach`` knows about one agent on this machine."""

    id: str
    name: str
    kind: str
    verdict: Verdict
    detected_in: list[str] = field(default_factory=list)
    servers: int = 0
    reasons: list[Reason] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)

    def question(self, question_id: str) -> Question | None:
        """The answer to *question_id*, if present."""
        return next((q for q in self.questions if q.id == question_id), None)

    @property
    def unanswered(self) -> int:
        """Questions that decide the verdict and could not be answered."""
        return sum(1 for r in self.reasons if r.kind == "unknown")


@dataclass
class MachineReach:
    """The reach report for one machine."""

    version: str
    generated_at: str
    hostname: str
    os: str
    os_version: str
    asset_id: str | None
    agents: list[AgentReach] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    home: Path | None = None

    def counts(self) -> dict[str, int]:
        """Agents per verdict (every verdict present, zero included)."""
        out = {v.value: 0 for v in Verdict}
        for agent in self.agents:
            out[agent.verdict.value] += 1
        return out

    @property
    def worst(self) -> Verdict | None:
        """The worst verdict across agents, or ``None`` without agents."""
        if not self.agents:
            return None
        return max((a.verdict for a in self.agents), key=lambda v: VERDICT_RANK[v])

    @property
    def exit_code(self) -> int:
        """0 when every agent is ready or couldn't-check-only, 1 otherwise."""
        bad = (Verdict.NEEDS_WORK, Verdict.NOT_SAFE)
        return 1 if any(a.verdict in bad for a in self.agents) else 0

    def fail_closed_reasons(self) -> list[str]:
        """Why ``reach --fail-closed`` refuses this machine; empty when it passes.

        Fail-closed treats missing evidence as a failure: no agent found, an
        agent whose verdict is "couldn't check", or a collection error.
        """
        reasons: list[str] = []
        if not self.agents:
            reasons.append("no agents were found")
        unchecked = [a.name for a in self.agents if a.verdict is Verdict.COULDNT_CHECK]
        if unchecked:
            reasons.append("couldn't check: " + ", ".join(unchecked))
        if self.errors:
            reasons.append(f"{len(self.errors)} collection error(s)")
        return reasons

    def gate_exit_code(self, *, fail_closed: bool = False) -> int:
        """:attr:`exit_code`, or 1 under *fail_closed* when evidence is missing."""
        if self.exit_code:
            return self.exit_code
        return 1 if fail_closed and self.fail_closed_reasons() else 0

    def summary_line(self) -> str:
        """One line: how many agents, and how many per verdict."""
        if not self.agents:
            return "No agents found on this machine."
        counts = self.counts()
        parts = [
            f"{counts[v.value]} {VERDICT_LABELS[v].lower()}"
            for v in (
                Verdict.NOT_SAFE,
                Verdict.NEEDS_WORK,
                Verdict.COULDNT_CHECK,
                Verdict.READY,
            )
            if counts[v.value]
        ]
        noun = "agent" if len(self.agents) == 1 else "agents"
        return f"{len(self.agents)} {noun}: " + ", ".join(parts)

    # ── JSON ─────────────────────────────────────────────────────────────────

    def sanitize(self, text: object) -> str:
        """*text* with credentials redacted and the home directory masked."""
        return sanitize(text, self.home)

    def to_dict(self) -> dict[str, Any]:
        """The documented JSON document (``docs/reach.schema.json``)."""
        s = self.sanitize
        counts = self.counts()
        worst = self.worst
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "mcp-audit", "version": s(self.version)},
            "generated_at": s(self.generated_at),
            "machine": {
                "hostname": s(self.hostname),
                "os": s(self.os),
                "os_version": s(self.os_version),
                "asset_id": s(self.asset_id) if self.asset_id else None,
            },
            "summary": {
                "agents": len(self.agents),
                "verdicts": counts,
                "worst_verdict": worst.value if worst is not None else None,
            },
            "agents": [
                {
                    "id": s(a.id),
                    "name": s(a.name),
                    "kind": a.kind,
                    "verdict": a.verdict.value,
                    "detected_in": [s(p) for p in a.detected_in],
                    "servers": a.servers,
                    "reasons": [
                        {
                            "kind": r.kind,
                            "text": s(r.text),
                            "refs": [s(x) for x in r.refs],
                        }
                        for r in a.reasons
                    ],
                    "questions": {
                        q.id: {
                            "title": q.title,
                            "status": q.status.value,
                            "summary": s(q.summary),
                            "facts": [
                                {
                                    "key": s(f.key),
                                    "value": s(f.value),
                                    "source": s(f.source) if f.source else None,
                                }
                                for f in q.facts
                            ],
                            "refs": [s(x) for x in q.refs],
                        }
                        for q in a.questions
                    },
                }
                for a in self.agents
            ],
            "errors": [s(e) for e in self.errors[:MAX_ERRORS]],
        }


def sanitize(text: object, home: Path | None = None) -> str:
    """Make *text* safe to print: redact credentials, mask the home directory.

    Redaction runs first, on the whole string, so a secret is recognised before
    anything is cut.  Control characters are replaced and the result is capped
    at :data:`MAX_TEXT` characters.  Never raises.
    """
    try:
        value = text if isinstance(text, str) else str(text)
        value = redact_command_text(value)
        if home is not None:
            value = _mask_home(value, home)
        value = _CONTROL.sub("?", value)
    except Exception:  # noqa: BLE001 — a printing helper must not fail a report
        return "[unprintable]"
    if len(value) > MAX_TEXT:
        value = value[: MAX_TEXT - 1] + "…"
    return value


def _mask_home(text: str, home: Path) -> str:
    """Replace the home directory (every spelling of it) with ``~``.

    Spellings: the path as given, its POSIX form, and for a Windows home
    (``C:\\Users\\Ann``) the Git-Bash/permissions-doc form ``/c/Users/Ann``.
    A Windows home matches without regard to case, as the file system does.
    """
    raw = str(home)
    spellings = {raw, home.as_posix()}
    windows = bool(re.match(r"^[A-Za-z]:[\\/]", raw)) or "\\" in raw
    with contextlib.suppress(ValueError, TypeError):
        win = PureWindowsPath(raw)
        spellings.add(win.as_posix())
        if len(win.drive) == 2 and win.drive[1] == ":":
            rest = win.as_posix()[2:]
            spellings.add(f"/{win.drive[0].lower()}{rest}")
            windows = True
    flags = re.IGNORECASE if windows else 0
    for spelling in sorted((s for s in spellings if len(s) > 3), key=len, reverse=True):
        # Not followed by a name character: /home/ann must not eat /home/anna.
        text = re.sub(re.escape(spelling) + r"(?![\w.-])", "~", text, flags=flags)
        if windows:
            alt = spelling.replace("/", "\\")
            text = re.sub(re.escape(alt) + r"(?![\w.-])", "~", text, flags=flags)
    return text
