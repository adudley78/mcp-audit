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
from collections.abc import Callable, Iterator

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
#: Tools of one server, and servers, that may share one sentence in the index.
#: The cap is per server: a server cannot fill the index for another server.
_MAX_OWNERS_PER_SERVER = 4
_MAX_SERVERS_PER_SENTENCE = 32
#: Sentences one scan keeps in its index (memory).
_MAX_INDEX_ENTRIES = 400_000
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

    __slots__ = (
        "server",
        "identity",
        "name",
        "all",
        "known",
        "long",
        "long_words",
        "words",
    )

    def __init__(self, server: ServerConfig, name: str, text: str | None) -> None:
        self.server = server
        self.identity = _server_identity(server)
        self.name = name
        self.all = _sentences(text)
        self.known = frozenset(self.all)
        self.long = [s for s in self.all if s.count(" ") + 1 >= _LONG_SENTENCE_WORDS]
        self.long_words = sum(s.count(" ") + 1 for s in self.long)
        self.words = sum(s.count(" ") + 1 for s in self.all)


class DescriptionCopy:
    """*holder*'s description holds the description of *held* (another server)."""

    __slots__ = ("holder", "held", "added_text", "names_differ_by_words")

    def __init__(self, holder: _Described, held: _Described) -> None:
        self.holder = holder
        self.held = held
        #: The holder has text that the held tool does not have.
        self.added_text = holder.words - held.words >= _ADDED_WORDS
        #: One name is the other name plus one or two words.
        self.names_differ_by_words = _is_name_plus_words(
            holder.name, held.name
        ) or _is_name_plus_words(held.name, holder.name)


def find_description_copies(
    pairs: list[tuple[ServerConfig, ServerEnumeration]],
    errors: list[str] | None = None,
    *,
    same_names: bool = False,
) -> list[DescriptionCopy]:
    """Return each pair of tools on two servers where one text holds the other.

    Tool A holds tool B's description when the names differ and each long
    sentence of B (five words or more, ten or more in all) is a sentence of
    A.  When one name is the other name plus one or two words, four words of
    description are enough and each sentence of B must be in A.

    The result says that two tools carry one description.  It cannot say
    which tool was first: a hostile server can take the short name and copy
    the text of an honest tool with a longer name.  Callers that need a
    direction use a fact from outside the text and outside what a server
    chooses: which tool the user approved before.

    With *same_names*, two tools with one name are compared too (COLLIDE-001
    reports those in a scan; the lock guard needs them).

    Work is bounded: ``_COPY_WORK_BUDGET`` sentence comparisons, and
    ``_MAX_OWNERS_PER_SERVER`` tools of one server under one sentence.  When a
    bound leaves something out, *errors* gets one line.
    """
    live = [(s, e) for s, e in pairs if not e.error]
    if len(live) < 2:
        return []
    tools = [
        _Described(server, t.name, t.description)
        for server, enum in live
        for t in enum.tools
    ]
    by_long: dict[str, dict[tuple, list[_Described]]] = {}
    by_first: dict[str, dict[tuple, list[_Described]]] = {}
    dropped = False
    entries = 0

    def add(
        index: dict[str, dict[tuple, list[_Described]]], key: str, tool: _Described
    ) -> bool:
        nonlocal entries
        if entries >= _MAX_INDEX_ENTRIES:
            return False
        entries += 1
        servers = index.setdefault(key, {})
        owners = servers.get(tool.identity)
        if owners is None:
            if len(servers) >= _MAX_SERVERS_PER_SENTENCE:
                return False
            owners = servers[tool.identity] = []
        if len(owners) >= _MAX_OWNERS_PER_SERVER:
            return False
        owners.append(tool)
        return True

    for tool in tools:
        if tool.long_words >= _MIN_COPIED_WORDS:
            # Under each long sentence: a copy that leaves a sentence out
            # still meets the tool under one that it kept.
            for sentence in dict.fromkeys(tool.long):
                dropped |= not add(by_long, sentence, tool)
        if tool.all and tool.words >= _MIN_COPIED_WORDS_WITH_NAME:
            dropped |= not add(by_first, tool.all[0], tool)

    budget = _COPY_WORK_BUDGET
    found: list[DescriptionCopy] = []
    seen: set[frozenset[int]] = set()
    tested: set[frozenset[int]] = set()
    tested_short: set[tuple[frozenset[int], str]] = set()

    def candidates(
        index: dict[str, dict[tuple, list[_Described]]], a: _Described, key: str
    ) -> Iterator[_Described]:
        for identity, owners in index.get(key, {}).items():
            if identity != a.identity:
                yield from owners

    def holds(holder: _Described, held: _Described, parts: list[str]) -> bool:
        return all(s in holder.known for s in parts)

    for a in tools:
        if budget <= 0:
            break
        for sentence in dict.fromkeys(a.all):
            for b in candidates(by_long, a, sentence):
                pair = frozenset((id(a), id(b)))
                if pair in tested or (b.name == a.name and not same_names):
                    continue
                tested.add(pair)
                # Either tool can be the one that holds the other: only one of
                # the two needs to be in the index (a server can fill its own
                # slots with decoys, never another server's).
                budget -= len(b.long) + len(a.long)
                if holds(a, b, b.long):
                    seen.add(pair)
                    # When each holds the other's long sentences, the one
                    # with more words is the holder (it has the added text).
                    if b.words > a.words and holds(b, a, a.long):
                        found.append(DescriptionCopy(b, a))
                    else:
                        found.append(DescriptionCopy(a, b))
                elif a.long_words >= _MIN_COPIED_WORDS and holds(b, a, a.long):
                    seen.add(pair)
                    found.append(DescriptionCopy(b, a))
            for b in candidates(by_first, a, sentence):
                pair = frozenset((id(a), id(b)))
                if pair in seen:
                    continue
                if not (
                    (same_names and a.name == b.name)
                    or _is_name_plus_words(a.name, b.name)
                    or _is_name_plus_words(b.name, a.name)
                ):
                    continue
                if (pair, "name") in tested_short:
                    continue
                tested_short.add((pair, "name"))
                budget -= len(b.all) + len(a.all)
                if holds(a, b, b.all):
                    seen.add(pair)
                    found.append(DescriptionCopy(a, b))
                elif a.words >= _MIN_COPIED_WORDS_WITH_NAME and holds(b, a, a.all):
                    seen.add(pair)
                    found.append(DescriptionCopy(b, a))
    if errors is not None:
        if budget <= 0:
            errors.append(
                "COLLIDE-003: too many tool descriptions to compare; some were left out"
            )
        if dropped:
            errors.append(
                "COLLIDE-003: many tools share one sentence, or the servers"
                " list very much tool text; some pairs were not compared"
            )
    return found


def detect_description_copies(
    pairs: list[tuple[ServerConfig, ServerEnumeration]],
    errors: list[str] | None = None,
) -> list[Finding]:
    """Report two tools on two servers that carry one description (COLLIDE-003).

    The agent cannot tell such tools apart by what they say.  A server that
    wants its tool called in the place of a trusted one copies the trusted
    tool's description; the copied text is honest, so a check of one
    description does not see it.

    The finding is MEDIUM and names both tools.  The fact is the same for an
    attack and for an honest duplicate (two servers of one vendor, a gateway
    beside the server that it fronts, a fork), and the text does not say
    which tool was first.  Nothing that a server chooses (its name, its
    arguments, its tool names) raises or lowers the severity.  The lock gives
    the direction: see :func:`copies_of_approved_tools`.

    The same name on two servers is COLLIDE-001 and is not reported here.
    The copied text is not put in the finding.

    Args:
        pairs: ``(ServerConfig, ServerEnumeration)`` from the ``--connect`` loop.
        errors: When given, gets one line if the scan left comparisons out.

    Returns:
        ``COLLIDE-003`` findings, one per pair of tools,
        ``MAX_DESCRIPTION_COPY_FINDINGS`` in all.
    """
    copies = find_description_copies(pairs, errors)
    if len(copies) > MAX_DESCRIPTION_COPY_FINDINGS and errors is not None:
        errors.append(
            "COLLIDE-003: more description copies than"
            f" {MAX_DESCRIPTION_COPY_FINDINGS}; the rest are not listed"
        )
    findings: list[Finding] = []
    for copy in copies[:MAX_DESCRIPTION_COPY_FINDINGS]:
        first, second = copy.holder, copy.held
        sa, sb = first.server, second.server
        how = (
            f"'{first.name}' holds the {second.words}-word description of"
            f" '{second.name}' and {first.words - second.words} more words"
            if copy.added_text
            else f"the two descriptions share {second.long_words or second.words}"
            " words of whole sentences"
        )
        names = (
            "  One name is the other name plus one or two words."
            if copy.names_differ_by_words
            else ""
        )
        findings.append(
            Finding(
                id="COLLIDE-003",
                severity=Severity.MEDIUM,
                analyzer="collision",
                client=sa.client if sa.client == sb.client else "multiple",
                server=f"{sa.name} + {sb.name}",
                tool=first.name,
                title=(
                    f"Tools '{first.name}' and '{second.name}' on two"
                    " servers carry one description"
                ),
                description=(
                    f"Server '{sa.name}' lists '{first.name}' and server"
                    f" '{sb.name}' lists '{second.name}': {how}.{names}  The"
                    " agent cannot tell the two tools apart by what they say."
                    "  The text does not show which tool was first.  Two"
                    " servers of one vendor, a gateway and the server that it"
                    " fronts, or a fork can share a tool this way; so can a"
                    " server that copies a trusted tool."
                ),
                evidence=(
                    f"'{first.name}' ({sa.name}) and '{second.name}'"
                    f" ({sb.name}): {how}"
                    " (detected via --connect live enumeration)"
                ),
                remediation=(
                    "Check that you installed both servers on purpose and that"
                    " you expect both tools.  Remove the server that you did"
                    " not expect.  `credenzo lock --connect` does not approve"
                    " a new tool that copies a tool you approved before."
                ),
                cwe="CWE-694",
                owasp_mcp_top_10=["MCP03", "MCP09"],
                finding_path=str(sa.config_path),
            )
        )
    return findings


def copies_of_approved_tools(
    pairs: list[tuple[ServerConfig, ServerEnumeration]],
    is_approved: Callable[[ServerConfig, str], bool],
    errors: list[str] | None = None,
) -> list[tuple[ServerConfig, str, ServerConfig, str]]:
    """Return each tool that is not approved and copies an approved tool.

    The text of two tools does not show which was first.  The lock does: a
    tool that the user approved before is the original, and a tool that is
    new and carries its description (under the same name or another name) is
    the copy.  A hostile server cannot change that order by the names it
    picks.

    Only the approved tools are indexed, each under each of its long
    sentences and with no cap: the user's lock bounds them, and a new server
    cannot fill an approved tool's place.  Each new tool is then tested
    against the approved tools that share a sentence with it, in both
    directions (the copy can hold more text or less).

    No launch detail excuses a pair.  A package name, a command line or an
    environment that looks like the approved server's can still run other
    code (``--package``, ``--registry``, another version, ``NODE_OPTIONS``).
    The user allows an honest duplicate one time (``lock --allow-copies``).

    Args:
        pairs: ``(ServerConfig, ServerEnumeration)`` of the servers to lock.
        is_approved: Whether the lock already holds this tool of this server.
        errors: Gets one line when the work budget ran out.

    Returns:
        ``(server, tool, original server, original tool)`` for each copy.
        When the work budget ran out, each new tool that was not tested is
        returned too, with ``""`` as the original tool: a tool that could not
        be compared is not approved.
    """
    approved: list[_Described] = []
    new: list[_Described] = []
    for server, enum in pairs:
        if enum.error:
            continue
        for tool in enum.tools:
            described = _Described(server, tool.name, tool.description)
            (approved if is_approved(server, tool.name) else new).append(described)
    if not approved or not new:
        return []
    by_long: dict[str, list[_Described]] = {}
    by_first: dict[str, list[_Described]] = {}
    for tool in approved:
        if tool.long_words >= _MIN_COPIED_WORDS:
            for sentence in dict.fromkeys(tool.long):
                by_long.setdefault(sentence, []).append(tool)
        if tool.all and tool.words >= _MIN_COPIED_WORDS_WITH_NAME:
            by_first.setdefault(tool.all[0], []).append(tool)

    def holds(holder: _Described, parts: list[str]) -> bool:
        return all(s in holder.known for s in parts)

    budget = _COPY_WORK_BUDGET
    out: list[tuple[ServerConfig, str, ServerConfig, str]] = []
    untested = 0
    for tool in new:
        if budget <= 0:
            untested += 1
            out.append((tool.server, tool.name, tool.server, ""))
            continue
        original: _Described | None = None
        tested: set[int] = set()
        for sentence in dict.fromkeys(tool.all):
            for other in by_long.get(sentence, ()):
                if other.identity == tool.identity or id(other) in tested:
                    continue
                tested.add(id(other))
                budget -= len(other.long) + len(tool.long)
                if holds(tool, other.long) or (
                    tool.long_words >= _MIN_COPIED_WORDS and holds(other, tool.long)
                ):
                    original = other
                    break
            if original is not None:
                break
            for other in by_first.get(sentence, ()):
                if other.identity == tool.identity or not (
                    other.name == tool.name
                    or _is_name_plus_words(tool.name, other.name)
                    or _is_name_plus_words(other.name, tool.name)
                ):
                    continue
                budget -= len(other.all) + len(tool.all)
                if holds(tool, other.all) or (
                    tool.words >= _MIN_COPIED_WORDS_WITH_NAME and holds(other, tool.all)
                ):
                    original = other
                    break
            if original is not None:
                break
        if original is not None:
            out.append((tool.server, tool.name, original.server, original.name))
    if untested and errors is not None:
        errors.append(
            f"COLLIDE-003: too much tool text to compare; {untested} new"
            " tool(s) were not compared with the approved tools"
        )
    return out
