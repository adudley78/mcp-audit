"""MEM-008: an instruction file tells the agent to change the machine, not the project.

Forever Security (Gal Weizman, Omer Samet; disclosed 2026-10-26) found an
``AGENTS.md`` planted in a customer's ``~/Downloads`` that told Codex to add an
MCP server to ``~/.codex/config.toml`` and then to run ``codex exec`` with its
approvals and sandbox off.  Three shapes in an instruction file's text reach
past the folder the agent was started in:

* **config-edit**: an instruction to write to a machine-wide agent config
  (``~/.codex/config.toml``, ``~/.claude/settings.json``, ``~/.cursor/mcp.json``,
  ``~/.gemini/settings.json``).  The path must be machine-wide (``~``,
  ``$HOME``, ``%USERPROFILE%``, ``$CODEX_HOME`` or an absolute home path): a
  project-relative ``.claude/settings.json`` is what repositories document all
  the time.  It needs an edit verb or a shell redirect before the path in the
  same sentence, and no negation ("never edit ...").
* **permissions**: run an agent with approvals off.  SKILL-006's pattern
  (:data:`~mcp_audit.agent_files.install_steps._SKIP_PERMISSIONS_RE`), reused
  through :func:`~mcp_audit.agent_files.install_steps.text_shape_hits`.
* **base-url**: set a model base URL (``ANTHROPIC_BASE_URL`` and siblings) to a
  host that is not the vendor's; SKILL-006's check, reused the same way.

Nothing here touches the filesystem or runs anything.  Every regex has bounded
quantifiers and each line is clipped before it is searched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_audit.agent_files.install_steps import LINE_CAP, text_shape_hits

_HOME = (
    r"(?:~|\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE"
    r"|/Users/[^/\s]{1,64}|/home/[^/\s]{1,64}|[A-Za-z]:[/\\]Users[/\\][^/\\\s]{1,64})"
)
_CONFIG_PATH_RE = re.compile(
    rf"{_HOME}[/\\]\.(?:codex[/\\]config\.toml|claude[/\\]settings\.json"
    r"|cursor[/\\]mcp\.json|gemini[/\\]settings\.json)(?![\w-]|\.\w)"
    r"|\$\{?CODEX_HOME\}?[/\\]config\.toml(?![\w-]|\.\w)"
)
_EDIT_RE = re.compile(
    r"\b(?:add|append|write|edit|modify|update|create|insert|put|set|configure"
    r"|register|overwrite|replace|inject|merge|echo|tee)\b",
    re.IGNORECASE,
)
#: A shell redirect straight into the path: ``echo ... >> ~/.codex/config.toml``.
_REDIRECT_RE = re.compile(r"(?:>>?|\btee(?:\s+-a)?)\s{0,3}[\"']?$")
#: What the edit has to carry for the instruction to matter: a server, a hook,
#: a command, or a change to approvals, the sandbox or trust.
_PAYLOAD_RE = re.compile(
    r"mcp[_ -]?servers?|\bhooks?\b|approval_policy|sandbox_mode|bypassPermissions"
    r"|defaultMode|trust_level|\bcommand\b\s{0,3}[=:]|\bargs\b\s{0,3}[=:]"
    r"|dangerously|--yolo|\bpermissions?\b",
    re.IGNORECASE,
)
_PAYLOAD_LINES = 8  # lines after the instruction that may hold the payload
#: The edit verb must open the sentence (after list marks and a few lead-in
#: words): "Add this to ~/.codex/config.toml" is an instruction; "The
#: installer writes to ~/.codex/config.toml" describes code.
_LEAD_RE = re.compile(
    r"^[\s>*+\-\d.)#]{0,12}"
    r"(?:(?:then|first|next|also|now|please|just|always|and|you\s+(?:must|should|need\s+to"
    r"|have\s+to)|must|should|need\s+to|to\s+\w+(?:\s+\w+){0,3},"
    r"|before\s+\w+(?:\s+\w+){0,5},|if\s+\w+(?:\s+\w+){0,5},),?\s{1,3}){0,3}$",
    re.IGNORECASE,
)
#: A line directs somebody to do it: a base-form verb on the line or just above.
_DIRECTIVE_RE = re.compile(
    r"\b(?:run|execute|launch|start|invoke|spawn|use|set|export|point|change"
    r"|override|add|put|configure|prefix|always|must|should|then)\b",
    re.IGNORECASE,
)
_DIRECTIVE_BACK = 3
_NEGATION_RE = re.compile(
    r"\b(?:never|don'?t|do\s+not|must\s+not|should\s+not|shouldn'?t|avoid|without)\b"
    r"(?:\s+\w+){0,3}\s*$",
    re.IGNORECASE,
)
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
_VERB_TO_PATH = 160  # characters between the edit verb and the path


@dataclass(frozen=True)
class InstructionHit:
    """One MEM-008 shape in a file.

    Attributes:
        line: 1-based line number.
        kind: ``"config-edit"``, ``"permissions"`` or ``"base-url"``.
        variable: The base-URL variable name, else the config path as written.
        source: The line, clipped.
    """

    line: int
    kind: str
    variable: str
    source: str


def _edit_instruction(sentence: str, path: re.Match[str]) -> bool:
    """True when *sentence* tells the reader to write to the config at *path*."""
    before = sentence[: path.start()]
    if _REDIRECT_RE.search(before[-12:]) and not _NEGATION_RE.search(before[-60:]):
        return True
    lo = max(0, path.start() - _VERB_TO_PATH)
    for verb in _EDIT_RE.finditer(sentence, lo, path.start()):
        if _LEAD_RE.match(sentence[: verb.start()]) is None:
            continue
        if _NEGATION_RE.search(sentence, max(0, verb.start() - 40), verb.end()):
            continue
        return True
    return False


def _config_edits(lines: list[str]) -> list[InstructionHit]:
    hits: list[InstructionHit] = []
    for idx, line in enumerate(lines):
        if "config" not in line and "settings" not in line and "mcp.json" not in line:
            continue
        clipped = line[:LINE_CAP]
        if clipped.lstrip().startswith("|"):  # a table row describes, not directs
            continue
        for sentence in _SENTENCE_SPLIT_RE.split(clipped):
            matches = _CONFIG_PATH_RE.finditer(sentence)
            path = next((m for m in matches if _edit_instruction(sentence, m)), None)
            if path is None:
                continue
            tail = "\n".join(lines[idx : idx + 1 + _PAYLOAD_LINES])[: 8 * LINE_CAP]
            if _PAYLOAD_RE.search(tail):
                hit = InstructionHit(idx + 1, "config-edit", path.group(0), clipped)
                hits.append(hit)
            break
    return hits


def _directed(lines: list[str], idx: int) -> bool:
    """A verb that tells someone to do it is on line *idx* or just above it."""
    window = "\n".join(lines[max(0, idx - _DIRECTIVE_BACK) : idx + 1])
    return _DIRECTIVE_RE.search(window[-4 * LINE_CAP :]) is not None


def find_instruction_hits(text: str, limit: int = 50) -> list[InstructionHit]:
    """Every MEM-008 shape in *text*, in line order, at most *limit*.

    A command or a base-URL setting that nobody is told to run or set (a table
    row, a description of what a tool does) is not a hit.

    Args:
        text: The instruction file's text.
        limit: Cap on hits returned.

    Returns:
        One hit per line and kind.
    """
    lines = text.splitlines()
    hits = _config_edits(lines)
    for shape in text_shape_hits(text, limit):
        if shape.source.lstrip().startswith("|"):  # a table row describes
            continue
        if _directed(lines, shape.line - 1):
            hits.append(
                InstructionHit(shape.line, shape.kind, shape.variable, shape.source)
            )
    hits.sort(key=lambda h: (h.line, h.kind))
    return hits[:limit]
