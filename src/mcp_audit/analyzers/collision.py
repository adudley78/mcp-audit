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
      "premium", "enhanced") and stands before or after the whole name;
      MEDIUM when one has a use in honest names ("secure", "v2") or stands
      inside the name (``get_best_price``).  The finding is on the
      decorated tool.
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
        ``MAX_NAME_COPY_FINDINGS`` in all, HIGH first.  Each server counts
        with the first spelling it lists; a spelling finding names two
        servers.
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

    # Collect light records first, HIGH before MEDIUM, and build Finding
    # objects only for the ones that fit under the cap.  A server that lists
    # many MEDIUM copies cannot push a HIGH copy out of the report.
    high: list[tuple[str, tuple[tuple, str], tuple[tuple, str]]] = []
    medium: list[tuple[str, tuple[tuple, str], tuple[tuple, str]]] = []
    for tokens, members in sorted(index.items()):
        # Spelling variant: same words, different text, different servers.
        # One finding per set of words, for the first two spellings.
        spellings: dict[str, tuple] = {}
        for identity, name in members.items():
            spellings.setdefault(name, identity)
        if len(spellings) >= 2:
            (name_a, ida), (name_b, idb) = sorted(spellings.items())[:2]
            medium.append(("variant", (ida, name_a), (idb, name_b)))
        # Decorated copy: drop the decoration words and look the rest up.
        core = tuple(t for t in tokens if t not in _DECORATION_WORDS)
        if core == tokens or len(core) < 2:
            continue
        originals = index.get(core, {})
        if not originals:
            continue
        # HIGH needs words that only praise, put before or after the whole
        # name: "best_get_price".  Inside the name they are often part of an
        # honest phrase: "get_best_price", "list_premium_plans".
        added = {t for t in tokens if t in _DECORATION_WORDS}
        start = next(i for i, t in enumerate(tokens) if t not in _DECORATION_WORDS)
        around = tokens[start : start + len(core)] == core
        bucket = high if around and added <= _PROMOTION_WORDS else medium
        for identity, name in members.items():
            other = next((i for i in originals if i != identity), None)
            if other is not None:
                bucket.append(
                    ("decorated", (identity, name), (other, originals[other]))
                )
    for kind, a, b in high[:MAX_NAME_COPY_FINDINGS]:
        emit(kind, a, b, Severity.HIGH)
    for kind, a, b in medium[: MAX_NAME_COPY_FINDINGS - len(findings)]:
        emit(kind, a, b)
    return findings


# ── COLLIDE-003: a tool that carries another server's tool description ────────
#
# STORY-0174.  The word lists of COLLIDE-002 and POISON-083 caught none of the
# name-overlap and preference cases of MCP Security Bench (arXiv 2510.15994):
# a copy there is ``execute_command_v1``, and the text that sells it is in
# another order of words.  What each of those cases shares is not a word.  The
# copy carries the description of the tool it copies.  That text is honest, so
# a check that reads one description cannot see it; a check that reads the
# session can.

#: Findings one scan reports.
MAX_DESCRIPTION_COPY_FINDINGS = 100
#: A description is read to this many characters and this many sentences.
_MAX_DESCRIPTION_CHARS = 20_000
_MAX_SENTENCES = 64
#: Tools that may share one first sentence in the index.
_MAX_OWNERS_PER_SENTENCE = 8
#: Sentence comparisons one scan may make.  A hostile server chooses its text.
_COPY_WORK_BUDGET = 2_000_000
#: A sentence of this many words or more is a "long" sentence.
_LONG_SENTENCE_WORDS = 5
#: A copy needs this many words in the long sentences of the copied text ...
_MIN_COPIED_WORDS = 10
#: ... or this many words in all, when the name is also the other name plus
#: one or two words.
_MIN_COPIED_WORDS_WITH_NAME = 4
#: The copy has "added text" when it has this many words more.
_ADDED_WORDS = 3
_SENTENCE_END = re.compile(r"[.\n!?;:]+")
_SPACES = re.compile(r"\s+")


def _sentences(text: str | None) -> list[str]:
    """Return the lowercase sentences of a description, spaces collapsed."""
    out: list[str] = []
    for part in _SENTENCE_END.split((text or "")[:_MAX_DESCRIPTION_CHARS]):
        sentence = _SPACES.sub(" ", part).strip().lower()
        if sentence:
            out.append(sentence)
            if len(out) >= _MAX_SENTENCES:
                break
    return out


def _is_name_plus_words(longer: str, shorter: str) -> bool:
    """Is *longer* the name *shorter* (two or more words) plus one or two words?"""
    long_tokens, short_tokens = _name_tokens(longer), _name_tokens(shorter)
    extra = len(long_tokens) - len(short_tokens)
    if len(short_tokens) < 2 or not 1 <= extra <= 2:
        return False
    rest = iter(long_tokens)
    return all(any(token == other for other in rest) for token in short_tokens)


class _Described:
    """One tool with the parts of its description that the check compares."""

    __slots__ = ("identity", "name", "all", "long", "long_words", "words")

    def __init__(self, identity: tuple, name: str, description: str | None) -> None:
        self.identity = identity
        self.name = name
        self.all = _sentences(description)
        self.long = [s for s in self.all if s.count(" ") + 1 >= _LONG_SENTENCE_WORDS]
        self.long_words = sum(s.count(" ") + 1 for s in self.long)
        self.words = sum(s.count(" ") + 1 for s in self.all)


def detect_description_copies(
    pairs: list[tuple[ServerConfig, ServerEnumeration]],
    errors: list[str] | None = None,
) -> list[Finding]:
    """Report a tool that carries another server's tool description (COLLIDE-003).

    Tool A on one server copies tool B on another server when the two names
    differ and each long sentence of B's description is a sentence of A's
    description (B's long sentences hold ten words or more).  When A's name is
    also B's name plus one or two words, four words of description are enough
    and each sentence of B must be in A.

    - **HIGH**: the description is copied and the name is the other name plus
      one or two words (``execute_command_v1`` beside ``execute_command``).
    - **MEDIUM**: the description is copied under a name of its own, with or
      without added text.  Servers of one vendor share tools this way.

    The same name on two servers is COLLIDE-001 and is not reported here.
    Reads names and descriptions only.  The copied text itself is not put in
    the finding.

    Args:
        pairs: ``(ServerConfig, ServerEnumeration)`` from the ``--connect`` loop.
        errors: When given, gets one line if the scan left comparisons out.

    Returns:
        ``COLLIDE-003`` findings, one per copying tool at most,
        ``MAX_DESCRIPTION_COPY_FINDINGS`` in all, HIGH first.
    """
    live = [(s, e) for s, e in pairs if not e.error]
    if len(live) < 2:
        return []
    by_identity: dict[tuple, ServerConfig] = {}
    tools: list[_Described] = []
    for server, enum in live:
        identity = _server_identity(server)
        by_identity.setdefault(identity, server)
        tools.extend(_Described(identity, t.name, t.description) for t in enum.tools)

    by_long: dict[str, list[_Described]] = {}
    by_first: dict[str, list[_Described]] = {}
    for tool in tools:
        if tool.long and tool.long_words >= _MIN_COPIED_WORDS:
            # The longest sentence says most about which tool this is.
            owners = by_long.setdefault(max(tool.long, key=len), [])
            if len(owners) < _MAX_OWNERS_PER_SENTENCE:
                owners.append(tool)
        if tool.all and tool.words >= _MIN_COPIED_WORDS_WITH_NAME:
            owners = by_first.setdefault(tool.all[0], [])
            if len(owners) < _MAX_OWNERS_PER_SENTENCE:
                owners.append(tool)

    budget = _COPY_WORK_BUDGET
    high: list[tuple[_Described, _Described, str]] = []
    medium: list[tuple[_Described, _Described, str]] = []
    reported: set[tuple[tuple, str]] = set()

    def record(a: _Described, b: _Described, long_copy: bool) -> None:
        """Add the pair once, on the tool that is the copy."""
        if b.words - a.words >= _ADDED_WORDS:
            return  # b holds a's text and more: seen with the roles the other way
        added = a.words - b.words >= _ADDED_WORDS
        if _is_name_plus_words(a.name, b.name):
            copy, original, bucket = a, b, high
            kind = "added text, name" if added else "name"
        elif not added and long_copy and _is_name_plus_words(b.name, a.name):
            copy, original, bucket, kind = b, a, high, "name"
        elif long_copy:
            copy, original, bucket = a, b, medium
            kind = "added text" if added else "same text"
        else:
            return
        key = (copy.identity, copy.name)
        mirror = (original.identity, original.name)
        if key in reported or (kind == "same text" and mirror in reported):
            return
        reported.add(key)
        bucket.append((copy, original, kind))

    for a in tools:
        if budget <= 0:
            break
        sentences = set(a.all)
        for sentence in a.all:
            for b in by_long.get(sentence, ()):
                budget -= len(b.long)
                if (
                    b.identity != a.identity
                    and b.name != a.name
                    and all(s in sentences for s in b.long)
                ):
                    record(a, b, True)
            for b in by_first.get(sentence, ()):
                budget -= len(b.all)
                if (
                    b.identity != a.identity
                    and b.name != a.name
                    and all(s in sentences for s in b.all)
                ):
                    record(a, b, False)
    if budget <= 0 and errors is not None:
        errors.append(
            "COLLIDE-003: too many tool descriptions to compare; some were left out"
        )

    findings: list[Finding] = []
    chosen = [(c, o, k, Severity.HIGH) for c, o, k in high]
    chosen += [(c, o, k, Severity.MEDIUM) for c, o, k in medium]
    if len(chosen) > MAX_DESCRIPTION_COPY_FINDINGS and errors is not None:
        errors.append(
            "COLLIDE-003: more description copies than"
            f" {MAX_DESCRIPTION_COPY_FINDINGS}; the rest are not listed"
        )
    for copy, original, kind, severity in chosen[:MAX_DESCRIPTION_COPY_FINDINGS]:
        sa, sb = by_identity[copy.identity], by_identity[original.identity]
        named = severity == Severity.HIGH
        findings.append(
            Finding(
                id="COLLIDE-003",
                severity=severity,
                analyzer="collision",
                client=sa.client if sa.client == sb.client else "multiple",
                server=sa.name,
                tool=copy.name,
                title=(
                    f"Tool '{copy.name}' carries the description of"
                    f" '{original.name}' on another server"
                ),
                description=(
                    f"Server '{sa.name}' lists the tool '{copy.name}'.  Its"
                    f" description holds the description of '{original.name}'"
                    f" on server '{sb.name}'"
                    + (" with more text added.  " if "added" in kind else ".  ")
                    + (
                        "Its name is also the other name plus one or two"
                        " words.  A server that wants the agent to call its"
                        " tool in the place of a trusted one copies the tool"
                        " this way.  The copied text is honest, so a check of"
                        " one description does not see it."
                        if named
                        else "The agent sees two tools that say they do the"
                        " same job.  Servers of one vendor can share a tool;"
                        " a server you did not expect to copy another one"
                        " should not."
                    )
                ),
                evidence=(
                    f"'{copy.name}' ({sa.name}) holds the {original.words}-word"
                    f" description of '{original.name}' ({sb.name});"
                    f" its own description has {copy.words} words"
                    " (detected via --connect live enumeration)"
                ),
                remediation=(
                    f"Check that you installed '{sa.name}' on purpose and"
                    f" compare what '{copy.name}' and '{original.name}' do."
                    "  Remove the server that you did not expect."
                    if named
                    else "Check that both servers are the ones you expect."
                    "  If they are from one vendor, no action is needed."
                ),
                cwe="CWE-694",
                owasp_mcp_top_10=["MCP03", "MCP09"],
                finding_path=str(sa.config_path),
            )
        )
    return findings
