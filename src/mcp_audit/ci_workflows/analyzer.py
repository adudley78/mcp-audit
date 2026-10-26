"""AI agent steps in GitHub Actions workflows: WORKFLOW-001..003 (STORY-0091).

A step is an *agent step* when its ``uses:`` names one of the actions in
:data:`AGENT_ACTIONS` (exact ``owner/repo``, any ref).  Each agent step is
checked against four facts the workflow file states before anything runs:

1. **Trigger.**  The workflow runs on an event whose text a stranger can write
   (:data:`ATTACKER_TRIGGERS`): an issue, an issue or discussion comment, a
   pull-request review, or ``pull_request_target``.  A workflow that only has
   ``workflow_call`` takes the triggers of the workflows in the same directory
   that call it with ``uses: ./.github/workflows/<file>``.
2. **Secret.**  ``${{ secrets.X }}`` or ``${{ github.token }}`` reaches the
   step through its ``with:`` or ``env:``, the job's ``env:`` or the
   workflow's ``env:``.  ``secrets.GITHUB_TOKEN`` counts.
3. **Write.**  The job's effective ``permissions:`` (job-level overrides
   workflow-level) grant ``write`` on any scope (``id-token: write``
   included: it mints cloud or GitHub App credentials), or ``write-all``, or
   there is no ``permissions:`` key at all.  An absent key gets the
   repository's default token permissions, which may be write; findings say
   so rather than asserting write.
4. **Tools.**  What the agent may run, per vendor documentation (see each
   ``_*_posture`` function).  ``unrestricted`` means it can run arbitrary or
   broad shell commands; ``blocklist`` means only a deny list limits that;
   ``allowlist`` means it cannot; ``unknown`` means the input could not be
   read, which never produces a finding.

WORKFLOW-001 (HIGH) is 1 + 2 + 3 + ``unrestricted``.  WORKFLOW-002 (MEDIUM) is
1 + 2 + 3 + ``blocklist``.  WORKFLOW-003 (HIGH) is a ``run-gemini-cli`` step on
such a trigger that is pinned below the GHSA-wpqr-6v78-jr5g fix, or that sets
workspace trust after the job checked out pull-request code.

Parsing uses ``yaml.safe_load`` only.  Nothing is executed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shlex
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field

import yaml

from mcp_audit.analyzers.config_hygiene import _is_broad_allow_rule
from mcp_audit.ci_workflows import discovery as _discovery
from mcp_audit.ci_workflows.discovery import WorkflowFile
from mcp_audit.models import Finding, Severity

logger = logging.getLogger(__name__)

ANALYZER_NAME = "ci_workflow"
CLIENT_NAME = "github-actions"

# ── Agent actions ─────────────────────────────────────────────────────────────

CLAUDE_CODE_ACTION = "anthropics/claude-code-action"
CLAUDE_SECURITY_REVIEW = "anthropics/claude-code-security-review"
RUN_GEMINI_CLI = "google-github-actions/run-gemini-cli"

#: Agent actions recognised in ``uses:`` (lower-case ``owner/repo``) and the
#: label used in findings.  The Copilot coding agent is not here: its
#: workflow file (``copilot-setup-steps.yml``) only prepares the runner, and
#: GitHub starts the agent itself.  GitHub Agentic Workflows (``gh aw``) are
#: not here either; see GAPS.md.
AGENT_ACTIONS: dict[str, str] = {
    CLAUDE_CODE_ACTION: "Claude Code (anthropics/claude-code-action)",
    CLAUDE_SECURITY_REVIEW: (
        "Claude Code Security Review (anthropics/claude-code-security-review)"
    ),
    RUN_GEMINI_CLI: "Gemini CLI (google-github-actions/run-gemini-cli)",
}

#: Events whose payload carries text anyone on a public repository can write.
#: ``pull_request_target`` runs with the base repository's secrets for pull
#: requests from forks.  ``pull_request_review``/``_comment`` withhold secrets
#: for fork pull requests but not for branch pull requests, which anyone can
#: comment on.  Issue and discussion events always run on the default branch
#: with the repository's secrets.  Source: GitHub "Events that trigger
#: workflows".  Plain ``pull_request`` is not here: fork pull requests get no
#: secrets and a read-only token.
ATTACKER_TRIGGERS: frozenset[str] = frozenset(
    {
        "issues",
        "issue_comment",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
        "discussion",
        "discussion_comment",
    }
)
_REVIEW_TRIGGERS: frozenset[str] = frozenset(
    {"pull_request_review", "pull_request_review_comment"}
)

_PAPER_URL = (
    "https://oddguan.com/blog/comment-and-control-prompt-injection-credential-"
    "theft-claude-code-gemini-cli-github-copilot/"
)
_GEMINI_ADVISORY_URL = (
    "https://github.com/google-github-actions/run-gemini-cli/security/advisories/"
    "GHSA-wpqr-6v78-jr5g"
)
_CLAUDE_SECURITY_DOC = (
    "https://github.com/anthropics/claude-code-action/blob/main/docs/security.md"
)

# GHSA-wpqr-6v78-jr5g fixed versions.
_GEMINI_ACTION_FLOOR: tuple[int, int, int] = (0, 1, 22)
_GEMINI_CLI_FLOOR: tuple[int, int, int] = (0, 39, 1)
_GEMINI_CLI_PREVIEW_LINE: tuple[int, int, int] = (0, 40, 0)
_GEMINI_CLI_PREVIEW_FIXED: int = 3

# Gemini CLI documents GEMINI_CLI_TRUST_WORKSPACE; Google's advisory and
# release note name GEMINI_TRUST_WORKSPACE.  Both are read.
_TRUST_VARS: tuple[str, ...] = ("GEMINI_CLI_TRUST_WORKSPACE", "GEMINI_TRUST_WORKSPACE")

_SECRET_ACCESS_RE = re.compile(
    r"\bsecrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*['\"]([^'\"]+)['\"]\s*\])"
)
_SECRETS_WORD_RE = re.compile(r"\bsecrets\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgithub\s*\.\s*token\b")
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-preview\.(\d+))?$")
_SHELL_RULE_RE = re.compile(r"^(?:Bash|PowerShell)(?:\(\s*(?::\s*)?\*?\s*\))?$")
_GEMINI_SHELL_RE = re.compile(r"^(?:run_shell_command|ShellTool)(?:\((.*)\))?$")
_UNTRUSTED_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref|repo)"
    r"|github\.head_ref"
    r"|refs/pull/"
    r"|github\.event\.workflow_run\.head_(?:sha|branch)"
)
_GH_PR_CHECKOUT_RE = re.compile(r"\bgh\s+pr\s+checkout\b")
_GIT_FETCH_RE = re.compile(r"\bgit\s+(?:fetch|checkout|switch)\b")
_ALLOW_FLAGS: frozenset[str] = frozenset({"--allowedtools", "--allowed-tools"})
_DENY_FLAGS: frozenset[str] = frozenset({"--disallowedtools", "--disallowed-tools"})

UNRESTRICTED = "unrestricted"
BLOCKLIST = "blocklist"
ALLOWLIST = "allowlist"
UNKNOWN = "unknown"


# ── Small value helpers ───────────────────────────────────────────────────────


def _as_text(value: object) -> str:
    """Return a scalar input value as text ('' for missing or containers)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str | int | float):
        return str(value)
    return ""


def _scalar_texts(value: object) -> list[str]:
    """Return the scalar strings of a ``with:``/``env:`` block (dict or string)."""
    if isinstance(value, dict):
        return [t for t in (_as_text(v) for v in value.values()) if t]
    text = _as_text(value)
    return [text] if text else []


def _truthy(value: object) -> bool:
    """True for YAML ``true`` or the strings ``'true'``/``'1'``."""
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"true", "1"}


def _parse_uses(value: object) -> tuple[str, str] | None:
    """Return ``(owner/repo lower-case, ref)`` for a remote action reference.

    Local (``./``) and ``docker://`` references return ``None``.  An action in
    a subdirectory (``owner/repo/path@ref``) keeps its path, so it does not
    match the repository-root action of the same name.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text.startswith(("./", "../", "docker://")):
        return None
    name, _, ref = text.partition("@")
    if name.count("/") < 1:
        return None
    return name.lower(), ref.strip()


def _semver(text: str) -> tuple[int, int, int, int | None] | None:
    """Parse ``[v]X.Y.Z[-preview.N]``; ``None`` for tags like ``v0`` or a SHA."""
    m = _SEMVER_RE.match(text.strip())
    if m is None:
        return None
    pre = int(m.group(4)) if m.group(4) is not None else None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _expression_spans(text: str) -> Iterable[tuple[int, int]]:
    """Yield ``(start, end)`` of each ``${{ ... }}`` in *text*, in one pass.

    Equivalent to the non-greedy ``\\$\\{\\{(.*?)\\}\\}`` but linear: a regex
    with a lazy dot over a string of unclosed ``${{`` backtracks
    quadratically (``"${{" * 40000`` took 20 s).  Stops at the first
    ``${{`` with no closing ``}}``.
    """
    pos = 0
    while True:
        start = text.find("${{", pos)
        if start < 0:
            return
        end = text.find("}}", start + 3)
        if end < 0:
            return
        yield start, end + 2
        pos = end + 2


def _expressions(text: str) -> Iterable[str]:
    """The bodies of the ``${{ ... }}`` expressions in *text*."""
    for start, end in _expression_spans(text):
        yield text[start + 3 : end - 2]


def _replace_expressions(text: str, replacement: str) -> str:
    """*text* with every ``${{ ... }}`` replaced by *replacement*."""
    parts: list[str] = []
    pos = 0
    for start, end in _expression_spans(text):
        parts.append(text[pos:start])
        parts.append(replacement)
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


def _secret_refs(texts: Iterable[str]) -> set[str]:
    """Names of the secrets referenced inside ``${{ }}`` expressions."""
    names: set[str] = set()
    for text in texts:
        for expr in _expressions(text):
            if _GITHUB_TOKEN_RE.search(expr):
                names.add("github.token")
            accessed = False
            for m in _SECRET_ACCESS_RE.finditer(expr):
                names.add(m.group(1) or m.group(2))
                accessed = True
            if not accessed and _SECRETS_WORD_RE.search(expr):
                names.add("the whole secrets context")
    return names


def _split_rules(text: str) -> list[str]:
    """Split a tool-rule list on commas and spaces outside parentheses."""
    rules: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and (ch == "," or ch.isspace()):
            if buf:
                rules.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        rules.append("".join(buf))
    return [r.strip().strip("'\"") for r in rules if r.strip().strip("'\"")]


def _parse_settings_json(value: object) -> dict | None:
    """Parse a ``settings:`` input (a JSON string).

    ``${{ }}`` expressions are replaced by ``0`` when the text is not valid
    JSON as written (valid inside a string and as a bare value).  Returns
    ``None`` when the value is not a JSON object, for example a file path.
    """
    if isinstance(value, dict):
        return value
    text = _as_text(value).strip()
    if not text:
        return None
    for candidate in (text, _replace_expressions(text, "0")):
        try:
            parsed = json.loads(candidate)
        except (ValueError, RecursionError):
            continue
        return parsed if isinstance(parsed, dict) else None
    return None


# ── Permissions ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Permissions:
    """A job's effective ``permissions:`` as far as the file states them."""

    declared: bool
    write_scopes: tuple[str, ...] = ()

    @property
    def can_write(self) -> bool:
        """True when the token may hold a write scope (absent counts)."""
        return not self.declared or bool(self.write_scopes)

    def describe(self) -> str:
        """Plain-language summary for finding text."""
        if not self.declared:
            return (
                "no permissions: block, so the job token gets the repository's"
                " default permissions, which may include write"
            )
        if self.write_scopes == ("write-all",):
            return "permissions: write-all"
        return (
            "write permission ("
            + ", ".join(f"{s}: write" for s in self.write_scopes)
            + ")"
        )

    def short(self) -> str:
        """Compact form for evidence lines."""
        if not self.declared:
            return "none declared (repository default)"
        if not self.write_scopes:
            return "read-only"
        return ", ".join(self.write_scopes)


_ABSENT = Permissions(declared=False)


def parse_permissions(value: object) -> Permissions:
    """Parse a ``permissions:`` value present in the file."""
    if isinstance(value, str):
        if value.strip().lower() == "write-all":
            return Permissions(True, ("write-all",))
        return Permissions(True)
    if isinstance(value, dict):
        scopes = sorted(
            str(k)
            for k, v in value.items()
            if isinstance(v, str) and v.strip().lower() == "write"
        )
        return Permissions(True, tuple(scopes))
    return Permissions(True)


def _cap(callee: Permissions, caller: Permissions) -> Permissions:
    """A called workflow's token cannot exceed its caller's."""
    if not caller.declared:
        return callee
    if not callee.declared:
        return caller
    if caller.write_scopes == ("write-all",):
        return callee
    if callee.write_scopes == ("write-all",):
        return caller
    both = tuple(s for s in callee.write_scopes if s in caller.write_scopes)
    return Permissions(True, both)


def _declared_permissions(job: dict, doc: dict) -> Permissions:
    """Job-level ``permissions:`` overrides workflow-level; absent if neither."""
    if "permissions" in job:
        return parse_permissions(job["permissions"])
    if "permissions" in doc:
        return parse_permissions(doc["permissions"])
    return _ABSENT


# ── Tool posture ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Posture:
    """What the agent step may run, and the configuration that says so."""

    kind: str
    detail: str


@dataclass
class _CliFlags:
    allowed: list[str] = field(default_factory=list)
    disallowed: list[str] = field(default_factory=list)
    bypass: list[str] = field(default_factory=list)


def _cli_flags(text: str) -> _CliFlags:
    """Read the Claude Code CLI flags in a ``claude_args`` input.

    Recognised (Claude Code CLI reference): ``--allowedTools`` /
    ``--allowed-tools``, ``--disallowedTools`` / ``--disallowed-tools``,
    ``--dangerously-skip-permissions`` and ``--permission-mode
    bypassPermissions``.  Values may be space- or comma-separated.
    """
    flags = _CliFlags()
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    current: list[str] | None = None
    pending: list[str] = []
    want_mode = False

    def _flush() -> None:
        if current is not None and pending:
            current.extend(_split_rules(" ".join(pending)))
        pending.clear()

    for tok in tokens:
        if tok.startswith("-") and len(tok) > 1:
            _flush()
            name, eq, val = tok.partition("=")
            lname = name.lower()
            current = None
            want_mode = False
            if lname in _ALLOW_FLAGS:
                current = flags.allowed
            elif lname in _DENY_FLAGS:
                current = flags.disallowed
            elif lname == "--dangerously-skip-permissions":
                flags.bypass.append("--dangerously-skip-permissions")
            elif lname == "--permission-mode":
                if eq:
                    if val == "bypassPermissions":
                        flags.bypass.append(tok)
                else:
                    want_mode = True
            if eq and current is not None:
                pending.append(val)
            continue
        if want_mode:
            if tok == "bypassPermissions":
                flags.bypass.append(f"--permission-mode {tok}")
            want_mode = False
            continue
        if current is not None:
            pending.append(tok)
    _flush()
    return flags


def _opens_claude_shell(rule: str) -> bool:
    """A Claude Code allow rule that grants every or a broad shell command."""
    rule = rule.strip()
    return bool(_SHELL_RULE_RE.match(rule)) or _is_broad_allow_rule(rule)


def _opens_gemini_shell(entry: str) -> bool:
    """A Gemini CLI ``tools.core`` entry that grants every or a broad command.

    ``run_shell_command(git)`` allows every command that starts with ``git``,
    so it is read like the Claude Code rule ``Bash(git:*)``.
    """
    m = _GEMINI_SHELL_RE.match(entry.strip())
    if m is None:
        return False
    inner = (m.group(1) or "").strip()
    if not inner or inner == "*":
        return True
    return _is_broad_allow_rule(f"Bash({inner}:*)")


def _restricted_only_by(reasons: list[str], deny: list[str]) -> Posture:
    if deny:
        return Posture(
            BLOCKLIST,
            "; ".join(reasons) + ", limited only by the deny list " + ", ".join(deny),
        )
    return Posture(UNRESTRICTED, "; ".join(reasons))


def claude_code_action_posture(with_: dict) -> Posture:
    """Tool posture of an ``anthropics/claude-code-action`` step.

    The action's docs (configuration.md, "Custom Tools") say Claude gets file
    operations, comment management and basic GitHub operations by default and
    "does not have access to execute arbitrary Bash commands by default";
    ``--allowedTools`` *adds* tools to that set.  So the default counts as an
    allowlist, and the step is opened up only by a bypass permission mode or
    an allow rule for every or a broad shell command (``Bash``, ``Bash(*)``,
    or a HARNESS-005 broad command such as ``Bash(cat:*)``, which the paper's
    authors note still reads ``/proc/*/environ``).  Read from ``claude_args``,
    the v0.x ``allowed_tools``/``disallowed_tools`` inputs (still accepted
    with a deprecation warning), and ``permissions`` in the ``settings`` JSON.
    """
    flags = _cli_flags(_as_text(with_.get("claude_args")))
    allow = flags.allowed + _split_rules(_as_text(with_.get("allowed_tools")))
    deny = flags.disallowed + _split_rules(_as_text(with_.get("disallowed_tools")))
    bypass = list(flags.bypass)
    settings = _parse_settings_json(with_.get("settings"))
    perms = settings.get("permissions") if settings else None
    if isinstance(perms, dict):
        for key, bucket in (("allow", allow), ("deny", deny)):
            rules = perms.get(key)
            if isinstance(rules, list):
                bucket.extend(r for r in rules if isinstance(r, str))
        if perms.get("defaultMode") == "bypassPermissions":
            bypass.append("settings permissions.defaultMode: bypassPermissions")
    opened = sorted({r.strip() for r in allow if _opens_claude_shell(r)})
    if not bypass and not opened:
        return Posture(
            ALLOWLIST, "the action's default tool set (no arbitrary shell commands)"
        )
    reasons = bypass + [f"allowed tool {r}" for r in opened]
    return _restricted_only_by(reasons, sorted(set(deny)))


def claude_security_review_posture(with_: dict) -> Posture:
    """``anthropics/claude-code-security-review`` has no tool input at all.

    Its README lists no input that limits Claude's tools and says it "is not
    hardened against prompt injection attacks and should only be used to
    review trusted PRs".  The paper got secrets out of it through a PR title;
    the vendor's fix was an internal ``--disallowed-tools 'Bash(ps:*)'``,
    which ``cat /proc/*/environ`` gets around.
    """
    return Posture(
        UNRESTRICTED,
        "the action has no input that limits Claude's tools; its README says it"
        " is not hardened against prompt injection and should only review"
        " trusted pull requests",
    )


def run_gemini_cli_posture(with_: dict) -> Posture:
    """Tool posture of a ``google-github-actions/run-gemini-cli`` step.

    The action always runs ``gemini --yolo`` (action.yml), which approves
    every tool call, and writes the ``settings`` input to
    ``.gemini/settings.json``.  ``tools.core`` is Gemini CLI's built-in tool
    allowlist and ``tools.exclude`` removes tools (a deny list); the pre-v2
    flat keys ``coreTools``/``excludeTools`` are read too.  Since 0.39.1 the
    allowlist is enforced under ``--yolo``.  ``security.disableYoloMode``
    turns auto-approval off.
    """
    raw = with_.get("settings")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return Posture(
            UNRESTRICTED,
            "no settings input, so no tools.core allowlist; the action runs"
            " gemini --yolo, which approves every tool call",
        )
    settings = _parse_settings_json(raw)
    if settings is None:
        return Posture(UNKNOWN, "settings input is not JSON this scanner can read")
    security = settings.get("security")
    if isinstance(security, dict) and security.get("disableYoloMode") is True:
        return Posture(ALLOWLIST, "security.disableYoloMode is true")
    tools = settings.get("tools")
    tools = tools if isinstance(tools, dict) else {}
    core = tools.get("core", settings.get("coreTools"))
    exclude = tools.get("exclude", settings.get("excludeTools"))
    deny = (
        sorted({x for x in exclude if isinstance(x, str)})
        if isinstance(exclude, list)
        else []
    )
    if isinstance(core, list):
        opened = sorted(
            {t for t in core if isinstance(t, str) and _opens_gemini_shell(t)}
        )
        if not opened:
            return Posture(ALLOWLIST, f"a tools.core allowlist ({len(core)} entries)")
        reason = "tools.core allows " + ", ".join(opened)
    else:
        reason = (
            "no tools.core allowlist; the action runs gemini --yolo, which"
            " approves every tool call"
        )
    return _restricted_only_by([reason], deny)


_POSTURE_BY_ACTION = {
    CLAUDE_CODE_ACTION: claude_code_action_posture,
    CLAUDE_SECURITY_REVIEW: claude_security_review_posture,
    RUN_GEMINI_CLI: run_gemini_cli_posture,
}


# ── Workflow model ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Invocation:
    """One way a workflow runs: the triggers that start it, and the ceiling
    on its token set by the calling jobs (``None`` when it starts directly).
    ``via`` names the calling files, outermost first."""

    triggers: frozenset[str]
    ceiling: Permissions | None = None
    via: tuple[str, ...] = ()


@dataclass
class _Workflow:
    file: WorkflowFile
    doc: dict
    own_triggers: frozenset[str]
    invocations: list[_Invocation] = field(default_factory=list)


# Bounds on reusable-workflow resolution.  GitHub allows at most ten levels of
# nested workflows; the invocation cap keeps a fan-out of callers linear.
_MAX_CALL_DEPTH = 10
_MAX_INVOCATIONS = 32


# Parsed documents keyed by the SHA-256 of the file's bytes.  A long-running
# process (``watch``, a test session) scans the same checkout many times; a
# content key can never serve a stale parse, which a stat key can when an
# edit keeps the size and lands in the same timestamp tick.
_PARSE_CACHE: OrderedDict[str, dict | None] = OrderedDict()
_PARSE_CACHE_MAX = 512


def _parse(data: bytes) -> dict | None:
    """``safe_load`` *data*; ``None`` when it is not a UTF-8 YAML mapping."""
    key = hashlib.sha256(data).hexdigest()
    if key in _PARSE_CACHE:
        _PARSE_CACHE.move_to_end(key)
        return _PARSE_CACHE[key]
    doc: object = None
    try:
        doc = yaml.safe_load(data.decode("utf-8"))
    except (yaml.YAMLError, RecursionError, ValueError):
        doc = None
    result = doc if isinstance(doc, dict) else None
    _PARSE_CACHE[key] = result
    if len(_PARSE_CACHE) > _PARSE_CACHE_MAX:
        _PARSE_CACHE.popitem(last=False)
    return result


def _load(file: WorkflowFile) -> dict | None:
    """Parsed workflow mapping, or ``None`` when unreadable or not a mapping.

    The size cap is checked again here, after discovery.  The result is
    shared through the cache, so callers must not mutate it.
    """
    try:
        with file.path.open("rb") as fh:
            data = fh.read(_discovery.MAX_WORKFLOW_BYTES + 1)
    except OSError:
        return None
    if len(data) > _discovery.MAX_WORKFLOW_BYTES:
        return None
    doc = _parse(data)
    if doc is None:
        logger.debug("ci_workflows: could not parse %s", file.path)
    return doc


def parse_triggers(doc: dict) -> frozenset[str]:
    """Event names under ``on:``.

    PyYAML follows YAML 1.1, where a bare ``on`` key is the boolean ``True``,
    so both spellings of the key are read.
    """
    on = doc["on"] if "on" in doc else doc.get(True)
    if isinstance(on, str):
        return frozenset({on.strip()})
    if isinstance(on, list):
        return frozenset(x.strip() for x in on if isinstance(x, str))
    if isinstance(on, dict):
        return frozenset(k.strip() for k in on if isinstance(k, str))
    return frozenset()


def _jobs(doc: dict) -> dict:
    jobs = doc.get("jobs")
    return jobs if isinstance(jobs, dict) else {}


def _resolve_invocations(workflows: list[_Workflow]) -> None:
    """Work out every way each workflow runs.

    A workflow's own triggers (other than ``workflow_call``) are one
    invocation with no ceiling.  A job ``uses: ./.github/workflows/<file>``
    in the same repository runs the called file once per invocation of the
    caller, with the caller's triggers and a token capped at the calling
    job's permissions, which are themselves capped by that invocation's
    ceiling.  Each path is kept separately, so a step is reported only when
    one caller path has both a stranger-writable trigger and a writable
    token.  Callers in other repositories are not visible to a file scan.
    """
    by_rel = {(w.file.repo_root, w.file.rel_path): w for w in workflows}
    calls_into: dict[int, list[tuple[_Workflow, dict]]] = {}
    for caller in workflows:
        for job in _jobs(caller.doc).values():
            if not isinstance(job, dict):
                continue
            uses = job.get("uses")
            if not isinstance(uses, str) or not uses.strip().startswith("./"):
                continue
            target_rel = uses.strip()[2:].split("@", 1)[0]
            callee = by_rel.get((caller.file.repo_root, target_rel))
            if callee is None or "workflow_call" not in callee.own_triggers:
                continue
            calls_into.setdefault(id(callee), []).append((caller, job))

    memo: dict[int, list[_Invocation]] = {}

    def _of(w: _Workflow, depth: int) -> list[_Invocation]:
        if id(w) in memo:
            return memo[id(w)]
        memo[id(w)] = []  # breaks call cycles, which GitHub rejects anyway
        found: list[_Invocation] = []
        direct = w.own_triggers - {"workflow_call"}
        if direct:
            found.append(_Invocation(frozenset(direct)))
        if "workflow_call" in w.own_triggers and depth < _MAX_CALL_DEPTH:
            for caller, job in calls_into.get(id(w), []):
                job_perms = _declared_permissions(job, caller.doc)
                for inv in _of(caller, depth + 1):
                    ceiling = (
                        job_perms
                        if inv.ceiling is None
                        else _cap(job_perms, inv.ceiling)
                    )
                    found.append(
                        _Invocation(
                            inv.triggers, ceiling, inv.via + (caller.file.rel_path,)
                        )
                    )
        unique: list[_Invocation] = []
        seen: set[tuple[frozenset[str], Permissions | None]] = set()
        for inv in found:
            key = (inv.triggers, inv.ceiling)
            if key not in seen and len(unique) < _MAX_INVOCATIONS:
                seen.add(key)
                unique.append(inv)
        memo[id(w)] = unique
        return unique

    for w in workflows:
        w.invocations = _of(w, 0)


def _effective_permissions(job: dict, w: _Workflow, inv: _Invocation) -> Permissions:
    """The job's declared permissions, capped by the invocation's ceiling."""
    own = _declared_permissions(job, w.doc)
    return own if inv.ceiling is None else _cap(own, inv.ceiling)


# ── Findings ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _StepContext:
    workflow: _Workflow
    job_id: str
    job: dict
    step: dict
    index: int
    action: str
    ref: str
    with_: dict
    triggers: tuple[str, ...]
    secrets: tuple[str, ...]
    permissions: Permissions
    via: tuple[str, ...] = ()

    @property
    def step_label(self) -> str:
        name = self.step.get("name") or self.step.get("id")
        label = f"step {self.index + 1}"
        return f"{label} ({name})" if isinstance(name, str) and name.strip() else label

    @property
    def uses(self) -> str:
        return f"{self.action}@{self.ref}" if self.ref else self.action

    @property
    def path(self) -> str:
        return str(self.workflow.file.path)

    @property
    def where(self) -> str:
        via = ""
        if self.via:
            via = " (called through workflow_call from " + " → ".join(self.via) + ")"
        return f"Job '{self.job_id}' in {self.workflow.file.rel_path}{via}"

    def trigger_text(self) -> str:
        text = "on " + ", ".join(self.triggers)
        if set(self.triggers) <= _REVIEW_TRIGGERS:
            text += (
                " (GitHub withholds secrets for pull requests from forks; a review"
                " comment on a branch pull request still runs with them)"
            )
        return text


def _finding(
    ctx: _StepContext,
    *,
    finding_id: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    cwe: str,
    owasp: list[str],
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer=ANALYZER_NAME,
        client=CLIENT_NAME,
        server=ctx.job_id,
        tool=ctx.step_label,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        finding_path=ctx.path,
        owasp_mcp_top_10=owasp,
    )


def _evidence(ctx: _StepContext, tools: str) -> str:
    return (
        f"{ctx.path}: on {', '.join(ctx.triggers)} | job {ctx.job_id},"
        f" {ctx.step_label} | uses {ctx.uses} | secrets"
        f" {', '.join(ctx.secrets)} | permissions {ctx.permissions.short()}"
        f" | tools: {tools}"
    )


def _non_write_users_note(ctx: _StepContext) -> str:
    """Who can start a claude-code-action step (its docs/security.md)."""
    if ctx.action != CLAUDE_CODE_ACTION:
        return ""
    value = _as_text(ctx.with_.get("allowed_non_write_users")).strip()
    if not value:
        return (
            " By default this action starts only for users with write access;"
            " the risk is the text others wrote (an issue body, earlier"
            " comments, a pull request) that those users point it at."
        )
    return (
        f" allowed_non_write_users is set ({value}), so people without write"
        " access can start this agent directly."
    )


_REMEDIATION_001: dict[str, str] = {
    CLAUDE_CODE_ACTION: (
        "Remove the bypass flag or the broad shell allow rule and allow only the"
        " commands the job needs (for example --allowedTools"
        ' "Bash(gh issue view:*)"); give the job read-only permissions and do'
        " writes in a separate job. See " + _CLAUDE_SECURITY_DOC + "."
    ),
    CLAUDE_SECURITY_REVIEW: (
        "Run this action on pull_request, where GitHub gives fork pull requests"
        " no secrets, not on pull_request_target or issue events, and require"
        " approval before outside contributors' workflows run. It has no tool"
        " allowlist input and its README says it is not hardened against prompt"
        " injection."
    ),
    RUN_GEMINI_CLI: (
        "Add a tools.core allowlist to the settings input with only the tools the"
        ' job needs (Google\'s own examples use "tools": {"core": []}), keep'
        " GITHUB_TOKEN out of the agent step, and do writes in a separate job"
        " that reads the agent's output."
    ),
}


def _workflow_001(ctx: _StepContext, posture: Posture) -> Finding:
    agent = AGENT_ACTIONS[ctx.action]
    return _finding(
        ctx,
        finding_id="WORKFLOW-001",
        severity=Severity.HIGH,
        title=(
            "CI agent runs on text a stranger can write, with secrets, write"
            " access and unrestricted tools"
        ),
        description=(
            f"{ctx.where} runs {agent} {ctx.trigger_text()}. Anyone who can open"
            " an issue, a comment or a pull request can put instructions in the"
            " text this agent reads. The step receives"
            f" {', '.join(ctx.secrets)}, the job has {ctx.permissions.describe()},"
            f" and nothing limits its tools: {posture.detail}."
            + _non_write_users_note(ctx)
            + " In 'Comment and Control' (ACM CCS 2026) an instruction in a pull"
            " request title or an issue made Claude Code, Gemini CLI and Copilot"
            " agents post their own secrets in a comment or push them in a"
            f" commit ({_PAPER_URL})."
        ),
        evidence=_evidence(ctx, posture.detail),
        remediation=_REMEDIATION_001[ctx.action],
        cwe="CWE-1427",
        owasp=["MCP06", "MCP01"],
    )


def _workflow_002(ctx: _StepContext, posture: Posture) -> Finding:
    agent = AGENT_ACTIONS[ctx.action]
    return _finding(
        ctx,
        finding_id="WORKFLOW-002",
        severity=Severity.MEDIUM,
        title="CI agent's only tool restriction is a blocklist",
        description=(
            f"{ctx.where} runs {agent} {ctx.trigger_text()}, with"
            f" {', '.join(ctx.secrets)} and {ctx.permissions.describe()}. Its"
            f" tools are open and only a deny list limits them: {posture.detail}."
            + _non_write_users_note(ctx)
            + " A deny list names what to block, and an injected instruction can"
            " reach the same secret another way: the vendor fix in 'Comment and"
            " Control' blocked Bash(ps:*), and cat /proc/*/environ prints the"
            f" same environment ({_PAPER_URL})."
        ),
        evidence=_evidence(ctx, posture.detail),
        remediation=(
            "Replace the deny list with an allowlist of the commands this job"
            " needs, and keep write permission out of the job that reads"
            " untrusted text."
        ),
        cwe="CWE-184",
        owasp=["MCP06", "MCP01"],
    )


def _gemini_version_reasons(ctx: _StepContext) -> list[str]:
    reasons: list[str] = []
    ref = _semver(ctx.ref) if ctx.ref else None
    if ref is not None and ref[3] is None and ref[:3] < _GEMINI_ACTION_FLOOR:
        reasons.append(f"run-gemini-cli is pinned to {ctx.ref}, below 0.1.22")
    cli_text = _as_text(ctx.with_.get("gemini_cli_version")).strip()
    cli = _semver(cli_text) if cli_text else None
    if cli is not None:
        base, pre = cli[:3], cli[3]
        if pre is None:
            vulnerable = base < _GEMINI_CLI_FLOOR
        elif base == _GEMINI_CLI_PREVIEW_LINE:
            vulnerable = pre < _GEMINI_CLI_PREVIEW_FIXED
        else:
            vulnerable = base <= _GEMINI_CLI_FLOOR
        if vulnerable:
            reasons.append(
                f"gemini_cli_version is {cli_text}, below 0.39.1 / 0.40.0-preview.3"
            )
    return reasons


def _trust_override(ctx: _StepContext) -> str | None:
    scopes = (
        ("step", ctx.step.get("env")),
        ("job", ctx.job.get("env")),
        ("workflow", ctx.workflow.doc.get("env")),
    )
    for scope, env in scopes:
        if not isinstance(env, dict):
            continue
        for var in _TRUST_VARS:
            if var in env and _truthy(env[var]):
                return f"{var}={_as_text(env[var])} ({scope} env)"
    return None


def _untrusted_checkout(ctx: _StepContext) -> str | None:
    """A step before the agent that puts pull-request code in the workspace."""
    steps = ctx.job.get("steps")
    for step in steps[: ctx.index] if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        parsed = _parse_uses(step.get("uses"))
        if parsed is not None and parsed[0] == "actions/checkout":
            with_ = step.get("with")
            with_ = with_ if isinstance(with_, dict) else {}
            for key in ("ref", "repository"):
                value = _as_text(with_.get(key))
                if value and _UNTRUSTED_REF_RE.search(value):
                    return f"actions/checkout with {key}: {value}"
        run = step.get("run")
        if isinstance(run, str):
            for line in run.splitlines():
                if _GH_PR_CHECKOUT_RE.search(line) or (
                    _GIT_FETCH_RE.search(line) and _UNTRUSTED_REF_RE.search(line)
                ):
                    return f"run: {line.strip()}"
    return None


def _workflow_003(ctx: _StepContext) -> Finding | None:
    reasons = _gemini_version_reasons(ctx)
    version_hit = bool(reasons)
    trust = _trust_override(ctx)
    checkout = _untrusted_checkout(ctx) if trust else None
    if trust and checkout:
        reasons.append(
            f"workspace trust is on ({trust}) after the job checked out pull"
            f" request code ({checkout})"
        )
    if not reasons:
        return None
    return _finding(
        ctx,
        finding_id="WORKFLOW-003",
        severity=Severity.HIGH,
        title=(
            "Gemini CLI step exposed to the CVSS 10.0 workspace-trust flaw"
            " (GHSA-wpqr-6v78-jr5g)"
        ),
        description=(
            f"{ctx.where} runs Gemini CLI {ctx.trigger_text()}: "
            + "; ".join(reasons)
            + ". Before run-gemini-cli 0.1.22 and Gemini CLI 0.39.1, headless"
            " runs trusted the workspace and loaded its .gemini/ settings and"
            " environment before the sandbox started, and --yolo ignored the tool"
            " allowlist, so untrusted input could run commands on the runner."
            " Trusting a workspace that holds pull request code reopens the first"
            f" half on a fixed version ({_GEMINI_ADVISORY_URL})."
        ),
        evidence=(
            f"{ctx.path}: on {', '.join(ctx.triggers)} | job {ctx.job_id},"
            f" {ctx.step_label} | uses {ctx.uses} | " + "; ".join(reasons)
        ),
        remediation=(
            "Use run-gemini-cli 0.1.22 or later with Gemini CLI 0.39.1 or later"
            " (the floating @v0 tag and the default 'latest' CLI qualify), and set"
            " GEMINI_CLI_TRUST_WORKSPACE only in jobs whose workspace holds no"
            " pull request code."
        ),
        cwe="CWE-1395" if version_hit else "CWE-829",
        owasp=["MCP05", "MCP04"],
    )


@dataclass(frozen=True)
class _AgentStep:
    job_id: str
    job: dict
    step: dict
    index: int
    action: str
    ref: str
    with_: dict
    secrets: tuple[str, ...]


def _agent_steps(w: _Workflow) -> list[_AgentStep]:
    """The workflow's agent steps, with the secret names that reach each.

    Workflow- and job-level ``env:`` are read once, not once per step.
    """
    wf_secrets = _secret_refs(_scalar_texts(w.doc.get("env")))
    found: list[_AgentStep] = []
    for job_id, job in _jobs(w.doc).items():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        job_secrets: set[str] | None = None
        for index, step in enumerate(job["steps"]):
            if not isinstance(step, dict):
                continue
            parsed = _parse_uses(step.get("uses"))
            if parsed is None or parsed[0] not in AGENT_ACTIONS:
                continue
            if job_secrets is None:
                job_secrets = wf_secrets | _secret_refs(_scalar_texts(job.get("env")))
            with_ = step.get("with")
            with_ = with_ if isinstance(with_, dict) else {}
            step_secrets = _secret_refs(
                _scalar_texts(with_) + _scalar_texts(step.get("env"))
            )
            found.append(
                _AgentStep(
                    job_id=str(job_id),
                    job=job,
                    step=step,
                    index=index,
                    action=parsed[0],
                    ref=parsed[1],
                    with_=with_,
                    secrets=tuple(sorted(job_secrets | step_secrets)),
                )
            )
    return found


def _step_contexts(w: _Workflow) -> Iterable[_StepContext]:
    """One context per (stranger-triggered invocation, agent step)."""
    steps = _agent_steps(w)
    if not steps:
        return
    for inv in w.invocations:
        triggers = tuple(sorted(inv.triggers & ATTACKER_TRIGGERS))
        if not triggers:
            continue
        for st in steps:
            yield _StepContext(
                workflow=w,
                job_id=st.job_id,
                job=st.job,
                step=st.step,
                index=st.index,
                action=st.action,
                ref=st.ref,
                with_=st.with_,
                triggers=triggers,
                secrets=st.secrets,
                permissions=_effective_permissions(st.job, w, inv),
                via=inv.via,
            )


def _analyze_step(ctx: _StepContext) -> list[Finding]:
    findings: list[Finding] = []
    if ctx.secrets and ctx.permissions.can_write:
        posture = _POSTURE_BY_ACTION[ctx.action](ctx.with_)
        if posture.kind == UNRESTRICTED:
            findings.append(_workflow_001(ctx, posture))
        elif posture.kind == BLOCKLIST:
            findings.append(_workflow_002(ctx, posture))
    if ctx.action == RUN_GEMINI_CLI:
        f003 = _workflow_003(ctx)
        if f003 is not None:
            findings.append(f003)
    return findings


def analyze_workflow_files(files: Iterable[WorkflowFile]) -> list[Finding]:
    """Return WORKFLOW-001..003 findings for *files*.

    Files that cannot be read or parsed are skipped.  Findings come out in
    file, job and step order (YAML mappings keep their order), so output is
    deterministic.

    Args:
        files: Workflow files from
            :func:`~mcp_audit.ci_workflows.discovery.discover_workflow_files`.

    Returns:
        One finding per (ID, agent step) at most.
    """
    workflows: list[_Workflow] = []
    for file in files:
        doc = _load(file)
        if doc is None:
            continue
        workflows.append(
            _Workflow(file=file, doc=doc, own_triggers=parse_triggers(doc))
        )
    try:
        _resolve_invocations(workflows)
    except Exception:  # noqa: BLE001 — odd content must not stop the scan
        logger.debug("ci_workflows: could not link reusable workflows", exc_info=True)
        for w in workflows:
            direct = w.own_triggers - {"workflow_call"}
            w.invocations = [_Invocation(frozenset(direct))] if direct else []

    findings: list[Finding] = []
    for w in workflows:
        # Each (ID, job, step) is reported once: for the first invocation
        # (direct triggers first, then callers) that makes it fire.
        seen: set[tuple[str, str, int]] = set()
        try:
            for ctx in _step_contexts(w):
                for finding in _analyze_step(ctx):
                    key = (finding.id, ctx.job_id, ctx.index)
                    if key not in seen:
                        seen.add(key)
                        findings.append(finding)
        except Exception:  # noqa: BLE001 — one odd file must not stop the scan
            logger.debug("ci_workflows: skipped %s", w.file.path, exc_info=True)
    return findings
