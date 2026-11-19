"""Detect tool-name collisions across connected MCP servers (COLLIDE-001).

When multiple servers advertise a tool with the same name, the AI agent's
tie-breaking behaviour is undocumented and order-dependent.  An attacker who
can publish or inject a server with a colliding tool name can shadow a trusted
tool — the agentic analogue of PATH poisoning.

Detection strategy:
  1. Collect all (ServerConfig, ServerEnumeration) pairs from a live --connect
     run.  Only pairs without enumeration errors are considered.
  2. Build a ``{tool_name: {server_identity: ServerConfig}}`` index.
  3. Any tool name claimed by two or more *distinct* server identities is a
     collision.  MEDIUM severity by default; HIGH when one claimant is in the
     known-server registry and at least one is not (unknown server shadowing a
     trusted one).

Scope: requires ``--connect``.  Static configs do not carry tool lists, so
this check cannot run without live enumeration.  This boundary is documented
in ``GAPS.md``.

Research basis:
  NSA Cybersecurity Information Sheet "Generative AI and LLM Cybersecurity
  Risks" (April 2025), item 5 — Namespace Shadowing / Tool Collision.
  https://media.defense.gov/2025/Apr/14/2003500458/-1/-1/0/CSI-CYBERSECURITY-FOR-AI.PDF

  OWASP MCP Top 10: MCP01 (Token Mismanagement — agent picks attacker's tool),
  MCP09 (Shadow MCP Servers — rogue server shadows trusted one).
"""

from __future__ import annotations

import re

from mcp_audit.models import Finding, ServerConfig, ServerEnumeration, Severity
from mcp_audit.registry.loader import KnownServerRegistry


def _server_identity(server: ServerConfig) -> tuple:
    """Return a stable tuple that identifies the *logical* server.

    Two ``ServerConfig`` objects with the same identity represent the same
    logical server configured in multiple MCP client config files.  They should
    not be counted as independent claimants for the same tool name.

    The identity is derived from the observable launch/connect characteristics
    (name, command, args, URL) — not from the config-file path, which differs
    per client.

    Args:
        server: The server configuration to fingerprint.

    Returns:
        Hashable tuple ``(name, command, args_tuple, url)``.
    """
    return (
        server.name,
        server.command or "",
        tuple(server.args),
        server.url or "",
    )


def _is_registry_known(server: ServerConfig, registry: KnownServerRegistry) -> bool:
    """Return ``True`` if any token in *server* maps to a registry entry.

    Checks the command, each arg, and the server name — mirrors the lookup
    pattern used by :func:`~mcp_audit.analyzers.toxic_flow.tag_server` and
    the supply-chain analyzer so the same registry semantics apply.

    Args:
        server: Server configuration to check.
        registry: Pre-loaded :class:`~mcp_audit.registry.loader.KnownServerRegistry`.

    Returns:
        ``True`` when at least one token resolves to a known-legitimate entry.
    """
    for token in [server.command or "", *server.args, server.name]:
        if token and registry.is_known(token):
            return True
    return False


def detect_tool_collisions(
    pairs: list[tuple[ServerConfig, ServerEnumeration]],
    registry: KnownServerRegistry | None = None,
) -> list[Finding]:
    """Detect tool-name collisions across live-connected MCP servers.

    Called by :func:`~mcp_audit.scanner.run_scan_async` after all
    ``--connect`` enumerations complete, before
    :func:`~mcp_audit.scanner._run_static_pipeline`.

    Algorithm:

    1. Filter to successfully connected pairs (``enumeration.error is None``).
    2. Build ``tool_name → {server_identity: ServerConfig}`` index.
    3. Emit ``COLLIDE-001`` for each tool name claimed by ≥ 2 distinct
       server identities.
    4. Severity = HIGH when any claimant is registry-known and at least one
       is not (unknown server shadowing a trusted name).  MEDIUM otherwise.

    Deduplication: the same logical server configured in multiple MCP client
    config files (same ``name``/``command``/``args``/``url``) is counted as
    one claimant.  Tool-name comparison is case-sensitive.

    Args:
        pairs: All ``(ServerConfig, ServerEnumeration)`` pairs from the
            ``--connect`` loop.  Pairs with enumeration errors are ignored.
        registry: Optional pre-loaded registry for severity tiering.  When
            ``None``, all collisions are reported at MEDIUM.

    Returns:
        List of ``COLLIDE-001`` :class:`~mcp_audit.models.Finding` objects.
        Empty when there are fewer than two successfully connected servers,
        when all tool names are unique, or when every collision involves only
        duplicates of the same logical server.
    """
    # ── Filter to successful enumerations ─────────────────────────────────────
    live = [(s, e) for s, e in pairs if not e.error]
    if len(live) < 2:
        return []

    # ── Build tool → {identity: server} index ─────────────────────────────────
    # outer key: tool name (case-sensitive)
    # inner key: server identity tuple (for deduplication)
    # inner value: first ServerConfig seen with that identity (for reporting)
    tool_index: dict[str, dict[tuple, ServerConfig]] = {}
    for server, enum in live:
        identity = _server_identity(server)
        for tool in enum.tools:
            if tool.name not in tool_index:
                tool_index[tool.name] = {}
            # First config seen for this identity wins (deterministic reporting).
            tool_index[tool.name].setdefault(identity, server)

    # ── Emit a finding for each colliding tool name ────────────────────────────
    findings: list[Finding] = []
    for tool_name, identity_map in sorted(tool_index.items()):
        if len(identity_map) < 2:
            continue  # unique name — no collision

        claimants = list(identity_map.values())

        # Severity tiering by registry membership.
        if registry is not None:
            known_flags = [_is_registry_known(s, registry) for s in claimants]
            # HIGH when the tool name is claimed by both a registry-verified
            # server and an unknown server — the unknown one may be a shadow.
            severity = (
                Severity.HIGH
                if any(known_flags) and not all(known_flags)
                else Severity.MEDIUM
            )
        else:
            severity = Severity.MEDIUM

        # Use the first claimant's config path as the finding path.
        primary = claimants[0]
        server_names = ", ".join(f"'{s.name}'" for s in claimants)

        findings.append(
            Finding(
                id="COLLIDE-001",
                severity=severity,
                analyzer="collision",
                client=(
                    primary.client
                    if len({s.client for s in claimants}) == 1
                    else "multiple"
                ),
                server=" + ".join(s.name for s in claimants),
                title=f"Tool name collision: '{tool_name}' claimed by multiple servers",
                description=(
                    f"The tool '{tool_name}' is advertised by"
                    f" {len(claimants)} servers: "
                    f"{server_names}.  When an AI agent calls this tool, the "
                    "tie-breaking behaviour is undocumented and order-dependent — "
                    "exactly the condition an attacker exploits to perform namespace "
                    "shadowing (the agentic analogue of PATH poisoning).  A malicious "
                    "or compromised server can shadow a trusted tool, intercepting "
                    "calls and their arguments without the agent or user noticing.  "
                    "NSA CSI item 5; OWASP MCP01 + MCP09."
                ),
                evidence=(
                    f"Tool '{tool_name}' claimed by: {server_names} "
                    f"(detected via --connect live enumeration)"
                ),
                remediation=(
                    f"Ensure '{tool_name}' is provided by exactly one server.  "
                    "Remove or rename the duplicate server, or prefix tool names "
                    "with the server's namespace (e.g. 'filesystem::read_file') "
                    "if both tools are intentionally present.  Verify the "
                    "unexpected server was not injected by a supply-chain attack."
                ),
                cwe="CWE-694",
                owasp_mcp_top_10=["MCP01", "MCP09"],
                finding_path=str(primary.config_path),
            )
        )

    return findings


# ── COLLIDE-002: a tool named after another server's tool (STORY-0173) ────────
#
# COLLIDE-001 needs the same name on two servers.  The Function Overlapping
# and Preference Manipulation cases of MCP-SafetyBench (arXiv 2512.15163) add
# a tool whose name is another server's tool name in other dress:
# ``Playwright_Navigate`` beside ``playwright_navigate``, or
# ``best_playwright_navigate``, ``playwright_navigate_enhanced``.  A scanner
# that reads one description at a time cannot see this; it needs the session.

#: Words that dress a copied name up as the better tool.  A name that adds
#: only these words to another server's tool name is a decorated copy.
_DECORATION_WORDS: frozenset[str] = frozenset(
    [
        "best",
        "premium",
        "enhanced",
        "advanced",
        "ultimate",
        "pro",
        "plus",
        "v2",
        "v3",
        "improved",
        "better",
        "fast",
        "faster",
        "secure",
        "safe",
        "official",
        "optimized",
        "super",
        "smart",
        "turbo",
        "max",
        "ultra",
        "original",
        "verified",
        "trusted",
    ]
)
#: Decoration words that only praise.  A copy that adds only these is HIGH.
#: The other decoration words have a use in honest names ("secure", "safe",
#: "verified", "max", "v2": ``send_secure_message`` beside ``send_message``),
#: so a copy that adds one of them is MEDIUM.
_PROMOTION_WORDS: frozenset[str] = frozenset(
    [
        "best",
        "premium",
        "enhanced",
        "ultimate",
        "improved",
        "better",
        "super",
        "turbo",
        "ultra",
    ]
)
#: Findings one scan reports.  A hostile server chooses its tool names.
MAX_NAME_COPY_FINDINGS = 100
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_NOT_ALNUM = re.compile(r"[^A-Za-z0-9]+")
#: Tool names longer than this are not compared (a name is a few words).
_MAX_NAME_CHARS = 200


def _name_tokens(name: str) -> tuple[str, ...]:
    """Return the lowercase words of a tool name (``getPage`` → get, page)."""
    spaced = _CAMEL_BOUNDARY.sub(r"\1_\2", name[:_MAX_NAME_CHARS])
    return tuple(t for t in _NOT_ALNUM.split(spaced.lower()) if t)


def detect_tool_name_squats(
    pairs: list[tuple[ServerConfig, ServerEnumeration]],
) -> list[Finding]:
    """Report a tool whose name copies another server's tool name (COLLIDE-002).

    Two shapes, compared on the words of the names:

    - **Decorated copy.** The name is another server's tool name of two or
      more words plus only decoration words: ``best_get_stock_info`` beside
      ``get_stock_info``.  HIGH when each added word only praises ("best",
      "premium", "enhanced"); MEDIUM when one has a use in honest names
      ("secure", "v2").  The finding is on the decorated tool.
    - **Spelling variant (MEDIUM).** The same words in another spelling on
      two servers: ``searchEmails`` and ``search-emails``.  The agent sees two
      tools that read as one.  One finding names both.

    The same name on two servers is COLLIDE-001 and is not reported here.
    Runs after COLLIDE-001 on the same ``--connect`` pairs; reads names only.

    Args:
        pairs: ``(ServerConfig, ServerEnumeration)`` from the ``--connect`` loop.
            Pairs with enumeration errors are ignored.

    Returns:
        ``COLLIDE-002`` findings: at most one spelling finding per set of
        words, one decorated finding per server and set of words, and
        ``MAX_NAME_COPY_FINDINGS`` in all.  Each server counts with the first
        spelling it lists.
    """
    live = [(s, e) for s, e in pairs if not e.error]
    if len(live) < 2:
        return []
    by_identity: dict[tuple, ServerConfig] = {}
    # words of a name -> server -> the first spelling that server lists.  One
    # spelling per server keeps the work linear in the number of tools: a
    # server that lists 10,000 spellings of one name counts once.
    index: dict[tuple[str, ...], dict[tuple, str]] = {}
    for server, enum in live:
        identity = _server_identity(server)
        by_identity.setdefault(identity, server)
        for tool in enum.tools:
            tokens = _name_tokens(tool.name)
            if tokens:
                index.setdefault(tokens, {}).setdefault(identity, tool.name)

    findings: list[Finding] = []

    def emit(
        kind: str,
        a: tuple[tuple, str],
        b: tuple[tuple, str],
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        """Add one finding for tool *a*, which copies tool *b*."""
        (ida, name_a), (idb, name_b) = a, b
        sa, sb = by_identity[ida], by_identity[idb]
        decorated = kind == "decorated"
        findings.append(
            Finding(
                id="COLLIDE-002",
                severity=severity,
                analyzer="collision",
                client=sa.client if sa.client == sb.client else "multiple",
                server=sa.name if decorated else f"{sa.name} + {sb.name}",
                tool=name_a,
                title=(
                    f"Tool '{name_a}' is named as a better copy of '{name_b}'"
                    if decorated
                    else f"'{name_a}' and '{name_b}' are one name in two spellings"
                ),
                description=(
                    f"Server '{sa.name}' lists the tool '{name_a}'.  Server"
                    f" '{sb.name}' lists '{name_b}'.  "
                    + (
                        "The first name is the second name plus words such as"
                        " 'best' or 'enhanced'.  A server that wants the"
                        " agent to call its tool in the place of a trusted one"
                        " names it this way."
                        if decorated
                        else "The two names have the same words.  The agent can"
                        " take one tool for the other."
                    )
                ),
                evidence=(
                    f"'{name_a}' ({sa.name}) and '{name_b}' ({sb.name})"
                    " (detected via --connect live enumeration)"
                ),
                remediation=(
                    f"Check that you installed '{sa.name}' on purpose and that"
                    f" '{name_a}' does what its name says.  Remove the server"
                    " if you did not expect a second tool for this job."
                    if decorated
                    else "Check that both servers are the ones you expect."
                    " If both are, no action is needed."
                ),
                cwe="CWE-694",
                owasp_mcp_top_10=["MCP03", "MCP09"],
                finding_path=str(sa.config_path),
            )
        )

    for tokens, members in sorted(index.items()):
        if len(findings) >= MAX_NAME_COPY_FINDINGS:
            break
        # Spelling variant: same words, different text, different servers.
        # One finding per set of words, for the first two spellings.
        spellings: dict[str, tuple] = {}
        for identity, name in members.items():
            spellings.setdefault(name, identity)
        if len(spellings) >= 2:
            (name_a, ida), (name_b, idb) = sorted(spellings.items())[:2]
            emit("variant", (ida, name_a), (idb, name_b))
        # Decorated copy: drop the decoration words and look the rest up.
        core = tuple(t for t in tokens if t not in _DECORATION_WORDS)
        if core == tokens or len(core) < 2:
            continue
        originals = index.get(core, {})
        added = {t for t in tokens if t in _DECORATION_WORDS}
        severity = Severity.HIGH if added <= _PROMOTION_WORDS else Severity.MEDIUM
        for identity, name in members.items():
            other = next((i for i in originals if i != identity), None)
            if other is not None:
                emit("decorated", (identity, name), (other, originals[other]), severity)
    return findings[:MAX_NAME_COPY_FINDINGS]
