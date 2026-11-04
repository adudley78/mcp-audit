"""Codex: the reach questions answered from ``config.toml``.

Reads the user's ``$CODEX_HOME/config.toml`` (``~/.codex/config.toml``) and the
working directory's ``.codex/config.toml`` as data (``tomllib``); never runs
Codex.

Vendor facts (fetched 2026-11-04):

- OpenAI Codex configuration reference,
  https://developers.openai.com/codex/config-reference (now served from
  https://learn.chatgpt.com/docs/config-file/config-reference):
  ``sandbox_mode`` is ``read-only | workspace-write | danger-full-access``;
  ``approval_policy`` is ``on-request | never | { granular = {...} }`` ("untrusted
  is unsupported, and on-failure is deprecated");
  ``sandbox_workspace_write.network_access`` is a boolean ("Allow outbound
  network access inside the workspace-write sandbox"); ``default_permissions``
  must not be combined with ``sandbox_mode``; ``otel.exporter`` is
  ``none | otlp-http | otlp-grpc``.
- Agent approvals and security,
  https://learn.chatgpt.com/docs/agent-approvals-security : "the default
  workspace-write sandbox mode keeps network access turned off unless you
  enable it in your configuration"; ``danger-full-access`` is "No sandbox; no
  approvals".

- Advanced configuration, https://learn.chatgpt.com/docs/config-file/config-advanced :
  "In Codex 0.134.0 and later, ``--profile`` no longer reads
  ``[profiles.profile-name]`` from ``config.toml``, and the top-level
  ``profile = "profile-name"`` selector is no longer supported."  A profile is
  ``~/.codex/profile-name.config.toml``, selected with ``--profile`` on the
  command line.  Project ``.codex/config.toml`` files ignore ``profile`` and
  ``profiles``.  So ``[profiles.*]`` and ``profile`` are shown as legacy and
  ignored, and a profile file is a fact that makes the answer COULDN'T CHECK
  (the command line decides whether it applies).

What is deliberately not answered: which credentials Codex can read (not
modelled yet: Q-065/Q-066), managed configuration (``requirements.toml``,
admin-managed config: not read), the default for an unset ``sandbox_mode`` or
``otel.exporter`` (the reference does not state them), and anything given on
the command line, including which ``--profile`` is used.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.reach.common import Assessment, network_status
from mcp_audit.reach.context import Env, read_capped
from mcp_audit.reach.models import Fact, Question, Reason, Status
from mcp_audit.reach.network import NetworkView

REFERENCE = "https://developers.openai.com/codex/config-reference"
APPROVALS = "https://learn.chatgpt.com/docs/agent-approvals-security"

CLIENTS = frozenset({"codex", "codex-project"})

_SANDBOX_MODES = ("read-only", "workspace-write", "danger-full-access")
#: A built-in permission profile name that means no sandbox.
_DANGER_PERMISSIONS = ":danger-full-access"
_MAX_PROFILE_FILES = 50
_OTLP = ("otlp-http", "otlp-grpc")
_NOT_SET = "(not set)"


@dataclass
class CodexFile:
    """One parsed ``config.toml``."""

    path: Path
    scope: str
    data: dict


def load_files(env: Env) -> tuple[list[CodexFile], list[str]]:
    """The Codex config files that exist and parse; and those that do not.

    Returns ``(files, unreadable)`` where *unreadable* holds ``"<masked path>
    <why>"`` for a file that exists but cannot be used.  Never raises.
    """
    files: list[CodexFile] = []
    bad: list[str] = []
    candidates = [("user", env.codex_config)]
    project = env.cwd / ".codex" / "config.toml"
    if _ident(project) != _ident(env.codex_config):
        candidates.append(("project", project))
    for scope, path in candidates:
        raw, why = read_capped(path)
        if why is not None:
            bad.append(f"{env.mask(path)} {why}")
            continue
        if raw is None:
            continue
        try:
            data = tomllib.loads(raw.decode("utf-8-sig", errors="replace"))
        except (tomllib.TOMLDecodeError, RecursionError, ValueError):
            bad.append(f"{env.mask(path)} is not valid TOML")
            continue
        files.append(CodexFile(path, scope, data))
    return files, bad


def _ident(path: Path) -> str:
    try:
        return str(path.resolve())
    except (OSError, RuntimeError):
        return str(path)


def _d(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _values(files: list[CodexFile], key: str) -> list[tuple[object, CodexFile, str]]:
    """Every file's value for top-level *key*, as ``(value, file, key)``.

    ``[profiles.*]`` and a top-level ``profile`` are not read: Codex 0.134.0
    and later ignores both (see the module docstring).
    """
    return [(f.data[key], f, key) for f in files if key in f.data]


def _shown(value: object) -> str:
    """A config value for display: a string as is, anything else by kind only.

    A table or list can hold a token; its contents are never printed.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, dict):
        return "(table)"
    if isinstance(value, list):
        return "(list)"
    return "(non-string value)"


def _legacy_profiles(files: list[CodexFile], mask) -> list[Fact]:  # noqa: ANN001
    """Facts for ``profile`` / ``[profiles.*]``, which Codex 0.134.0+ ignores."""
    out: list[Fact] = []
    for f in files:
        if "profile" in f.data:
            out.append(
                Fact(
                    "profile",
                    "legacy: not read since Codex 0.134.0, ignored here",
                    f"{mask(f.path)}:profile",
                )
            )
        if "profiles" in f.data:
            out.append(
                Fact(
                    "[profiles.*]",
                    "legacy: not read since Codex 0.134.0, ignored here",
                    f"{mask(f.path)}:profiles",
                )
            )
    return out


def _profile_files(env: Env) -> list[str]:
    """Masked paths of ``<name>.config.toml`` profile files next to the user config."""
    found: list[str] = []
    try:
        for path in sorted(env.codex_config.parent.iterdir()):
            if path.name.endswith(".config.toml") and path.name != "config.toml":
                found.append(env.mask(path))
                if len(found) >= _MAX_PROFILE_FILES:
                    break
    except OSError:
        return found
    return found


def _exporter_kinds(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(k) for k in value]
    return []


def assess(*, env: Env, net: NetworkView) -> Assessment:
    """Answer the five questions for Codex."""
    files, unreadable = load_files(env)
    reasons: list[Reason] = []
    mask = env.mask

    # ── Where it runs ────────────────────────────────────────────────────────
    sandbox_vals = _values(files, "sandbox_mode")
    approval_vals = _values(files, "approval_policy")
    perm_vals = _values(files, "default_permissions")
    facts: list[Fact] = []
    refs: list[str] = []
    danger = [(v, f, w) for v, f, w in sandbox_vals if v == "danger-full-access"]
    danger += [(v, f, w) for v, f, w in perm_vals if v == _DANGER_PERMISSIONS]
    never = [(v, f, w) for v, f, w in approval_vals if v == "never"]
    bad_sandbox = [v for v, _f, _w in sandbox_vals if v not in _SANDBOX_MODES]

    for v, f, w in sandbox_vals:
        facts.append(Fact("sandbox_mode", _shown(v), f"{mask(f.path)}:{w}"))
    for v, f, w in approval_vals:
        shown = "granular" if isinstance(v, dict) else _shown(v)
        facts.append(Fact("approval_policy", shown, f"{mask(f.path)}:{w}"))
    for v, f, w in perm_vals:
        facts.append(Fact("default_permissions", _shown(v), f"{mask(f.path)}:{w}"))
    facts += _legacy_profiles(files, mask)
    profile_files = _profile_files(env)
    for shown_path in profile_files:
        facts.append(Fact("profile file", shown_path, None))
    if not sandbox_vals:
        facts.append(Fact("sandbox_mode", _NOT_SET, None))
    if not approval_vals:
        facts.append(Fact("approval_policy", _NOT_SET, None))
    for bad in unreadable:
        facts.append(Fact("config file", bad, None))

    where_status = Status.PASS
    texts: list[str] = []
    if danger:
        _v, f, w = danger[0]
        ref = f"{mask(f.path)}:{w}"
        refs.append(ref)
        reasons.append(
            Reason(
                "not_safe",
                f'{w} is "{_v}": no sandbox, no approvals ({APPROVALS})',
                [ref],
            )
        )
        where_status = Status.FAIL
        texts.append("danger-full-access: commands run with no sandbox")
    if never:
        _v, f, w = never[0]
        ref = f"{mask(f.path)}:{w}"
        refs.append(ref)
        reasons.append(
            Reason(
                "not_safe",
                'approval_policy is "never": Codex runs commands without asking',
                [ref],
            )
        )
        where_status = Status.FAIL
        texts.append('approval_policy "never": no approval prompts')
    if not danger:
        if unreadable:
            reasons.append(
                Reason(
                    "unknown",
                    "a Codex config file could not be read: " + "; ".join(unreadable),
                    [],
                )
            )
            where_status = (
                Status.UNKNOWN if where_status is Status.PASS else where_status
            )
            texts.append("a config file could not be read")
        elif perm_vals:
            reasons.append(
                Reason(
                    "unknown",
                    "default_permissions selects a permission profile, which"
                    " reach does not model, so the sandbox is not known",
                    [f"{mask(f.path)}:{w}" for _v, f, w in perm_vals],
                )
            )
            where_status = (
                Status.UNKNOWN if where_status is Status.PASS else where_status
            )
            texts.append("a permission profile is selected (not modelled)")
        elif not sandbox_vals or bad_sandbox:
            why = (
                "no sandbox_mode is set in the files read, and the Codex"
                " reference does not state the default"
                if not sandbox_vals
                else (
                    "sandbox_mode has an unrecognised value"
                    f" ({_shown(bad_sandbox[0])!r})"
                )
            )
            reasons.append(
                Reason("unknown", why, [f"{mask(env.codex_config)}:sandbox_mode"])
            )
            where_status = (
                Status.UNKNOWN if where_status is Status.PASS else where_status
            )
            texts.append(why)
        else:
            texts.insert(0, f"sandbox_mode {sandbox_vals[-1][0]}")
    if profile_files:
        reasons.append(
            Reason(
                "unknown",
                "Codex profile file(s) exist and --profile on the command line"
                " decides whether one applies, which is not readable here",
                [],
            )
        )
        if where_status is Status.PASS:
            where_status = Status.UNKNOWN
        texts.append("a profile file exists (selected on the command line)")
    where_q = Question(
        "where_it_runs", where_status, "; ".join(texts) or "sandboxed", facts, refs
    )

    # ── Credentials ──────────────────────────────────────────────────────────
    cred_q = Question(
        "credentials",
        Status.UNKNOWN,
        "which credentials Codex can read is not modelled yet (Q-065/Q-066);"
        " REACH-001..003 describe Claude Code's reads only",
        [],
        [],
    )
    reasons.append(
        Reason("unknown", "credentials question unanswered - " + cred_q.summary, [])
    )

    # ── Network ──────────────────────────────────────────────────────────────
    net_facts: list[Fact] = []
    state, state_text = _network_state(
        files, sandbox_vals, danger, bad_sandbox, net_facts, mask
    )
    net_facts += [
        Fact("network-capable server", v.describe(), v.ref) for v in net.reaching
    ]
    net_facts += [
        Fact("server with no declared capabilities", v.name, v.ref)
        for v in net.unclassified
    ]
    net_q, net_reasons = network_status(net, state, state_text, net_facts)
    reasons.extend(net_reasons)

    # ── Policy ───────────────────────────────────────────────────────────────
    policy_q = Question(
        "policy",
        Status.UNKNOWN,
        "Codex managed configuration (requirements.toml, admin-managed config)"
        " is not read yet",
        [],
    )

    # ── Logging ──────────────────────────────────────────────────────────────
    log_q = _logging(files, env)
    if log_q.status is Status.FAIL:
        reasons.append(
            Reason("needs_work", "activity is not logged: " + log_q.summary, log_q.refs)
        )
    elif log_q.status is Status.UNKNOWN:
        reasons.append(Reason("unknown", "logging: " + log_q.summary, log_q.refs))

    return Assessment([where_q, cred_q, net_q, policy_q, log_q], reasons)


def _network_state(
    files: list[CodexFile],
    sandbox_vals: list[tuple[object, CodexFile, str]],
    danger: list[tuple[object, CodexFile, str]],
    bad_sandbox: list[object],
    facts: list[Fact],
    mask,  # noqa: ANN001 — Env.mask
) -> tuple[str, str]:
    """The sandbox network state for :func:`network_status`."""
    if danger:
        return "open", "danger-full-access has no network restriction"
    if not sandbox_vals or bad_sandbox:
        return "unknown", "the sandbox mode is not known"
    mode = sandbox_vals[-1][0]
    if mode == "read-only":
        return "strict", "read-only sandbox: no network access by default"
    for f in files:
        value = _d(f.data.get("sandbox_workspace_write")).get("network_access")
        if value is not None:
            facts.append(
                Fact(
                    "sandbox_workspace_write.network_access",
                    _shown(value),
                    f"{mask(f.path)}:sandbox_workspace_write.network_access",
                )
            )
        if value is True:
            return "open", "sandbox_workspace_write.network_access is true"
        if value is not None and value is not False:
            return "unknown", "sandbox_workspace_write.network_access is not a boolean"
    return "strict", "workspace-write sandbox: network access is off unless enabled"


def _logging(files: list[CodexFile], env: Env) -> Question:
    """Question 5: the user's ``[otel]`` exporter.  Project files are not counted."""
    user = next((f for f in files if f.scope == "user"), None)
    facts: list[Fact] = []
    project_otel = any(f.scope == "project" and "otel" in f.data for f in files)
    if project_otel:
        facts.append(
            Fact(
                "[otel] in the project file",
                "not counted (the user's file decides)",
                None,
            )
        )
    otel = _d(user.data.get("otel")) if user is not None else {}
    source = f"{env.mask(user.path)}:otel.exporter" if user is not None else None
    if "exporter" not in otel:
        facts.append(Fact("otel.exporter", _NOT_SET, None))
        return Question(
            "logging",
            Status.UNKNOWN,
            "no [otel] exporter is set in the user's config.toml; the Codex"
            f" reference ({REFERENCE}) does not state the default",
            facts,
            [f"{env.mask(env.codex_config)}:otel.exporter"],
        )
    kinds = _exporter_kinds(otel["exporter"])
    facts.append(Fact("otel.exporter", ", ".join(kinds) or "(unrecognised)", source))
    refs = [source] if source else []
    if any(k in _OTLP for k in kinds):
        exporter = otel["exporter"]
        endpoint = any(
            isinstance(_d(_d(exporter).get(k)).get("endpoint"), str)
            and _d(_d(exporter).get(k)).get("endpoint", "").strip()
            for k in kinds
            if k in _OTLP
        )
        if not endpoint:
            facts.append(Fact("otel endpoint", _NOT_SET, None))
            return Question(
                "logging",
                Status.UNKNOWN,
                "[otel] exporter is "
                + ", ".join(k for k in kinds if k in _OTLP)
                + f" but no endpoint is set; the Codex reference ({REFERENCE})"
                " does not state a default, so where events go is not known",
                facts,
                refs,
            )
        facts.append(Fact("otel endpoint", "set", None))
        return Question(
            "logging",
            Status.PASS,
            "[otel] exporter is "
            + ", ".join(k for k in kinds if k in _OTLP)
            + "; Codex sends its events to that collector",
            facts,
            refs,
        )
    if kinds == ["none"]:
        return Question(
            "logging",
            Status.FAIL,
            'otel.exporter is "none": no events are exported',
            facts,
            refs,
        )
    return Question(
        "logging",
        Status.UNKNOWN,
        "otel.exporter has a value the Codex reference does not list"
        " (none, otlp-http, otlp-grpc)",
        facts,
        refs,
    )


def detected_files(env: Env) -> list[str]:
    """Masked paths of the Codex config files that exist."""
    out: list[str] = []
    for path in (env.codex_config, env.cwd / ".codex" / "config.toml"):
        try:
            if path.is_file():
                out.append(env.mask(path))
        except OSError:
            continue
    return list(dict.fromkeys(out))
