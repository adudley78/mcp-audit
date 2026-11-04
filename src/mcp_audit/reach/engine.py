"""The reach engine: a finished default scan in, a :class:`MachineReach` out.

``build_machine_reach`` does not scan.  It takes the :class:`ScanResult` of one
default scan (``run_scan()`` with no explicit path), the settings readers in
:mod:`mcp_audit.reach.claude` and :mod:`mcp_audit.reach.codex`, and composes
what they say into one card per agent.  It re-implements no detection: the
credential answer is REACH-001..003, the network answer is
:func:`mcp_audit.analyzers.toxic_flow.tag_server`, an existing CRITICAL finding
is read off the scan.

Verdict (:func:`verdict_of`), worst first:

1. **not safe to allow**: bypass mode in effect (Claude Code), Codex
   ``danger-full-access`` or ``approval_policy = "never"``, a readable
   credential store plus a network-capable server, or an existing CRITICAL
   finding attributed to the agent.
2. **needs work**: an item on the sanctioned path (sandbox on, scoped
   credentials, network denied by default, logging on) fails.
3. **couldn't check**: nothing fails, but a question that decides the verdict
   could not be answered.  Unknown is never upgraded to ready.
4. **ready**: all four items pass.

A failing item outranks an unanswered one, so the card never hides a known
problem behind "couldn't check"; the unanswered questions are listed in the
reasons either way.  Pure: no I/O beyond the settings readers it calls.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.models import Finding, ScanResult, ServerConfig, Severity
from mcp_audit.reach import claude, codex
from mcp_audit.reach.common import Assessment, network_status
from mcp_audit.reach.context import Env, default_env
from mcp_audit.reach.models import (
    AgentReach,
    Fact,
    MachineReach,
    Question,
    Reason,
    Status,
    Verdict,
)
from mcp_audit.reach.network import NetworkView, classify

#: Agents with their own entry, in display order.
HARNESSES: tuple[tuple[str, str], ...] = (
    ("claude-code", "Claude Code"),
    ("codex", "Codex"),
    ("gemini-cli", "Gemini CLI"),
    ("opencode", "OpenCode"),
)
_HARNESS_NAMES = dict(HARNESSES)
_FRIENDLY = {
    "claude-desktop": "Claude Desktop",
    "cursor": "Cursor",
    "vscode": "VS Code",
    "windsurf": "Windsurf",
    "zed": "Zed",
    "amazon-q": "Amazon Q Developer",
    "copilot-cli": "GitHub Copilot CLI",
    "augment": "Augment",
}

#: At most this many CRITICAL findings are quoted per agent.
_MAX_CRITICAL = 5


def agent_of_client(client: str) -> str:
    """The agent a discovered ``client`` name belongs to.

    ``claude-code-project``/``-plugin``/``-agent``/``-managed`` are Claude Code;
    ``codex-project`` is Codex; ``opencode`` (any variant) is OpenCode; any other
    client is its own agent with a ``-project`` suffix removed.
    """
    c = client.strip().lower()
    for prefix, _display in HARNESSES:
        if c == prefix or c.startswith(prefix + "-"):
            return prefix
    return c.removesuffix("-project") or c


def agent_name(agent_id: str) -> str:
    """Display name of an agent."""
    if agent_id in _HARNESS_NAMES:
        return _HARNESS_NAMES[agent_id]
    if agent_id in _FRIENDLY:
        return _FRIENDLY[agent_id]
    return agent_id.replace("-", " ").title() or agent_id


def verdict_of(reasons: list[Reason]) -> Verdict:
    """The verdict the reasons add up to (see the module docstring)."""
    kinds = {r.kind for r in reasons}
    if "not_safe" in kinds:
        return Verdict.NOT_SAFE
    if "needs_work" in kinds:
        return Verdict.NEEDS_WORK
    if "unknown" in kinds:
        return Verdict.COULDNT_CHECK
    return Verdict.READY


def _other_assessment(name: str, net: NetworkView) -> Assessment:
    """An agent whose settings ``reach`` does not read yet: servers only."""
    unmodelled = f"{name}'s settings are not modelled yet"
    where = Question("where_it_runs", Status.UNKNOWN, unmodelled)
    creds = Question(
        "credentials",
        Status.UNKNOWN,
        "which credentials it can read is not modelled yet (Q-065/Q-066)",
    )
    policy = Question("policy", Status.UNKNOWN, unmodelled)
    logging = Question("logging", Status.UNKNOWN, unmodelled)
    facts = [Fact("network-capable server", v.describe(), v.ref) for v in net.reaching]
    facts += [
        Fact("server with no declared capabilities", v.name, v.ref)
        for v in net.unclassified
    ]
    net_q, net_reasons = network_status(
        net, "unknown", f"{name}'s sandbox or network restriction is not read", facts
    )
    reasons = [
        Reason("unknown", f"where it runs is not known - {unmodelled}", []),
        Reason("unknown", f"credentials question unanswered - {creds.summary}", []),
        *net_reasons,
        Reason("unknown", f"logging is not known - {unmodelled}", []),
    ]
    return Assessment([where, creds, net_q, policy, logging], reasons)


def _attributed_critical(
    agent_id: str, servers: list[ServerConfig], findings: list[Finding], env: Env
) -> list[Reason]:
    """CRITICAL findings on this agent's config (cross-server ones by server name)."""
    names = {s.name for s in servers}
    reasons: list[Reason] = []
    for f in findings:
        if f.severity is not Severity.CRITICAL:
            continue
        mine = agent_of_client(f.client) == agent_id
        if not mine and f.client == "multiple":
            mine = any(part.strip() in names for part in f.server.split(" + "))
        if not mine:
            continue
        where = f" in {env.mask(f.finding_path)}" if f.finding_path else ""
        refs = [f.id] + ([env.mask(f.finding_path)] if f.finding_path else [])
        reasons.append(
            Reason(
                "not_safe", f"existing CRITICAL finding {f.id}: {f.title}{where}", refs
            )
        )
        if len(reasons) >= _MAX_CRITICAL:
            break
    return reasons


def _exists(path: Path) -> bool:
    """True for anything at *path*, including a file that cannot be read.

    A config that exists but is unusable (a FIFO, a directory, no permission)
    still means the agent is there, and its answers are COULDN'T CHECK.
    """
    try:
        return os.path.lexists(path)
    except (OSError, ValueError):
        return False


def _present_without_servers(env: Env) -> list[str]:
    """Harness ids whose own config exists although no server was discovered."""
    found: list[str] = []
    if env.config_dir.is_dir() or _exists(env.home / ".claude.json"):
        found.append("claude-code")
    if _exists(env.codex_config) or _exists(env.cwd / ".codex" / "config.toml"):
        found.append("codex")
    if _exists(env.gemini_config):
        found.append("gemini-cli")
    return found


def build_machine_reach(
    result: ScanResult,
    *,
    env: Env | None = None,
    registry: object | None = None,
    now: datetime | None = None,
) -> MachineReach:
    """Compose the reach report of one machine from a default scan.

    Args:
        result: The :class:`ScanResult` of ``run_scan()`` with no explicit path
            (REACH-001..003 and MANAGED-* only exist in a default scan).
        env: The directories to read; this machine's by default.
        registry: The shared known-server registry for ``tag_server``; without
            it the in-module fallback table and keyword heuristics are used.
        now: Report timestamp (UTC); the current time by default.

    Returns:
        The report.  Never raises for a missing or unreadable file: those
        become ``errors`` and COULDN'T CHECK answers.
    """
    env = env if env is not None else default_env()
    stamp = (now or datetime.now(UTC)).replace(microsecond=0).isoformat()

    by_agent: dict[str, list[ServerConfig]] = {}
    for server in result.servers:
        by_agent.setdefault(agent_of_client(server.client), []).append(server)
    for agent_id in _present_without_servers(env):
        by_agent.setdefault(agent_id, [])

    order = [a for a, _ in HARNESSES if a in by_agent]
    order += sorted(a for a in by_agent if a not in _HARNESS_NAMES)

    agents: list[AgentReach] = []
    for agent_id in order:
        agents.append(_agent(agent_id, by_agent[agent_id], result, env, registry))

    machine = result.machine
    errors = list(result.errors) + [e for e in env.errors if e not in result.errors]
    return MachineReach(
        version=__version__,
        generated_at=stamp,
        hostname=machine.hostname,
        os=machine.os,
        os_version=machine.os_version,
        asset_id=machine.asset_id,
        agents=agents,
        errors=errors,
        home=env.home,
    )


def _with_claude_extras(
    servers: list[ServerConfig], env: Env
) -> tuple[list[ServerConfig], list[str]]:
    """Add the servers Claude Code loads that default discovery does not return.

    Per-project servers in ``~/.claude.json`` and the managed servers
    (``managed-mcp.json``, ``managedMcpServers``).  Under exclusive control of
    ``managed-mcp.json`` only the managed servers load, so the user's are
    dropped.  A file that cannot be read becomes a note and an ``unread`` entry.
    """
    try:
        extra, exclusive, problems = claude.extra_servers(env)
    except Exception as exc:  # noqa: BLE001 — reported, never raised
        env.note(f"reach: Claude Code extra servers: {type(exc).__name__}")
        return servers, ["Claude Code's other MCP sources could not be read"]
    for problem in problems:
        env.note(f"reach: {problem}")
    if exclusive:
        return [s for s in extra if s.client == claude.MANAGED_CLIENT], problems
    return servers + extra, problems


def _agent(
    agent_id: str,
    servers: list[ServerConfig],
    result: ScanResult,
    env: Env,
    registry: object | None,
) -> AgentReach:
    unread: list[str] = []
    if agent_id == "claude-code":
        servers, unread = _with_claude_extras(servers, env)
    net = classify(servers, registry, env)
    net.unread = unread
    name = agent_name(agent_id)
    detected: list[str] = []
    try:
        if agent_id == "claude-code":
            assessment = claude.assess(
                env=env, findings=result.findings, net=net, scan_errors=result.errors
            )
            detected += claude.detected_files(env)
        elif agent_id == "codex":
            assessment = codex.assess(env=env, net=net)
            detected += codex.detected_files(env)
        else:
            assessment = _other_assessment(name, net)
    except Exception as exc:  # noqa: BLE001 — one agent's failure never drops the rest
        env.note(f"reach: {name} could not be assessed: {type(exc).__name__}")
        assessment = _other_assessment(name, net)
        assessment.reasons.insert(
            0,
            Reason(
                "unknown", f"{name} could not be assessed ({type(exc).__name__})", []
            ),
        )
    reasons = list(assessment.reasons)
    reasons += _attributed_critical(agent_id, servers, result.findings, env)
    reasons = _ordered(reasons)
    for server in servers:
        detected.append(env.mask(server.config_path))
    return AgentReach(
        id=agent_id,
        name=name,
        kind="harness" if agent_id in _HARNESS_NAMES else "client",
        verdict=verdict_of(reasons),
        detected_in=list(dict.fromkeys(detected)),
        servers=len(servers),
        reasons=reasons,
        questions=assessment.questions,
    )


_KIND_ORDER = {"not_safe": 0, "needs_work": 1, "unknown": 2}


def _ordered(reasons: list[Reason]) -> list[Reason]:
    """Reasons worst first, each distinct reason once."""
    seen: set[tuple[str, str]] = set()
    unique: list[Reason] = []
    for r in reasons:
        key = (r.kind, r.text)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return sorted(unique, key=lambda r: _KIND_ORDER.get(r.kind, 9))
