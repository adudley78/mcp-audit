"""Shared by the per-agent assessors: the result type and the network question."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_audit.reach.models import Fact, Question, Reason, Status
from mcp_audit.reach.network import NetworkView


@dataclass
class Assessment:
    """One agent's five answers and the reasons that decide its verdict.

    ``reasons`` carry ``kind`` ``not_safe``, ``needs_work`` or ``unknown``;
    :func:`mcp_audit.reach.engine.verdict_of` turns them into a verdict.
    """

    questions: list[Question]
    reasons: list[Reason] = field(default_factory=list)


def network_status(
    net: NetworkView,
    state: str,
    state_text: str,
    facts: list[Fact],
    extra: list[Fact] | None = None,
    *,
    unknown_routes: list[Fact] | None = None,
    unknown_why: list[str] | None = None,
) -> tuple[Question, list[Reason]]:
    """Shared by every agent that has a sandbox network state.

    ``extra`` are other routes out that are not MCP servers (a hook that runs
    ``curl``): each is a fact with the file it is in as its source.
    """
    reasons: list[Reason] = []
    unknown_routes = unknown_routes or []
    unknown_why = list(unknown_why or [])
    if unknown_routes:
        facts = facts + unknown_routes
        unknown_why.append(
            f"{len(unknown_routes)} hook, apiKeyHelper or statusLine command(s)"
            " run outside the sandbox and are not known to be local, so what"
            " they reach is not known"
        )
    for why in unknown_why:
        reasons.append(
            Reason("unknown", why, [r.source for r in unknown_routes[:5] if r.source])
        )
    refs = [v.ref for v in net.reaching]
    routes = extra or []
    if routes:
        names = ", ".join(f"{r.key} ({r.value})" for r in routes[:5])
        reasons.append(
            Reason(
                "needs_work",
                f"commands that run outside the sandbox can reach the network: {names}",
                [r.source for r in routes[:5] if r.source],
            )
        )
        facts = facts + routes
    if net.unread:
        reasons.append(
            Reason(
                "unknown",
                "an MCP config file could not be read, so its servers are not"
                " known: " + "; ".join(net.unread[:3]),
                [],
            )
        )
    if net.reaching:
        names = ", ".join(v.describe() for v in net.reaching[:5])
        reasons.append(
            Reason(
                "needs_work",
                f"MCP server(s) that reach the network, outside any sandbox: {names}",
                refs[:5],
            )
        )
    if state == "open":
        reasons.append(
            Reason("needs_work", f"network is not restricted: {state_text}", [])
        )
    if state == "unknown":
        reasons.append(Reason("unknown", f"network restriction: {state_text}", []))
    if net.reaching or routes or state == "open":
        parts = []
        if routes:
            parts.append(
                f"{len(routes)} command(s) outside the sandbox reach the network"
            )
        if net.reaching:
            parts.append(f"{len(net.reaching)} MCP server(s) reach the network")
        if state == "open":
            parts.append(state_text)
        return Question("network", Status.FAIL, "; ".join(parts), facts, refs), reasons
    if state == "unknown" or net.unclassified or net.unread or unknown_why:
        if net.unclassified:
            names = ", ".join(v.name for v in net.unclassified[:5])
            reasons.append(
                Reason(
                    "unknown",
                    "MCP server(s) the registry has no declared capabilities for,"
                    f" so their reach is not known: {names}",
                    [v.ref for v in net.unclassified[:5]],
                )
            )
        if state == "unknown":
            why = state_text
        elif unknown_why:
            why = unknown_why[0]
        elif net.unclassified:
            why = f"{len(net.unclassified)} MCP server(s) have no declared capabilities"
        else:
            why = "an MCP config file could not be read"
        return Question("network", Status.UNKNOWN, why, facts, refs), reasons
    return (
        Question(
            "network",
            Status.PASS,
            f"no MCP server reaches the network; {state_text}",
            facts,
            refs,
        ),
        reasons,
    )
