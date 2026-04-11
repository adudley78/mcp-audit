"""Detect dangerous cross-server capability combinations (toxic flows).

Two MCP servers may each be safe in isolation, but together enable an
end-to-end attack path — for example, a file-reading server paired with a
network-capable server creates a file-exfiltration path that neither server
creates alone.

Detection strategy:
1. Tag each server with capability labels (FILE_READ, NETWORK_OUT, etc.) using
   three layers: known-package lookup → keyword matching on command/args →
   tool-name matching from live enumeration data.
2. Check every ordered server pair (including self-pairs) for dangerous
   capability combinations defined in TOXIC_PAIRS.
3. Emit a finding naming both servers for each detected combination.

Research basis:
  "Compromising LLM-Integrated Applications with Indirect Prompt Injection"
  Greshake et al., arXiv 2023 §4 — multi-tool attack chaining
  https://arxiv.org/abs/2302.12173

  "LLM Tool Use and the New Attack Surface", Trail of Bits 2024
  https://blog.trailofbits.com/2024/09/12/llm-tool-use/
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity


class Capability(StrEnum):
    """Coarse-grained capability labels for MCP servers."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_OUT = "network_out"
    SHELL_EXEC = "shell_exec"
    DATABASE = "database"
    EMAIL = "email"
    BROWSER = "browser"
    GIT = "git"
    SECRETS = "secrets"


@dataclass(frozen=True)
class ToxicPair:
    """A dangerous capability combination that should be flagged when detected."""

    source: Capability
    sink: Capability
    finding_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    cwe: str | None = None


@dataclass(frozen=True)
class KeywordRule:
    """Maps keywords found in server config strings to capability labels."""

    keywords: tuple[str, ...]
    capabilities: frozenset[Capability]


# ── Known server registry ─────────────────────────────────────────────────────

KNOWN_SERVERS: dict[str, frozenset[Capability]] = {
    "@modelcontextprotocol/server-filesystem": frozenset(
        {Capability.FILE_READ, Capability.FILE_WRITE}
    ),
    "@modelcontextprotocol/server-fetch": frozenset({Capability.NETWORK_OUT}),
    "@modelcontextprotocol/server-github": frozenset(
        {Capability.GIT, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-git": frozenset(
        {Capability.GIT, Capability.FILE_READ}
    ),
    "@modelcontextprotocol/server-postgres": frozenset({Capability.DATABASE}),
    "@modelcontextprotocol/server-sqlite": frozenset({Capability.DATABASE}),
    "@modelcontextprotocol/server-brave-search": frozenset({Capability.NETWORK_OUT}),
    "@modelcontextprotocol/server-puppeteer": frozenset(
        {Capability.BROWSER, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-slack": frozenset({Capability.NETWORK_OUT}),
    "@modelcontextprotocol/server-gdrive": frozenset(
        {Capability.FILE_READ, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-gmail": frozenset(
        {Capability.EMAIL, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-memory": frozenset(),
    "@modelcontextprotocol/server-sequentialthinking": frozenset(),
    "@modelcontextprotocol/server-everything": frozenset(
        {
            Capability.FILE_READ,
            Capability.FILE_WRITE,
            Capability.NETWORK_OUT,
            Capability.SHELL_EXEC,
        }
    ),
}

# ── Keyword matching rules ────────────────────────────────────────────────────

KEYWORD_RULES: list[KeywordRule] = [
    KeywordRule(
        keywords=("filesystem", "file-system", "file_system", "file", " fs "),
        capabilities=frozenset({Capability.FILE_READ, Capability.FILE_WRITE}),
    ),
    KeywordRule(
        keywords=("fetch", "http", "https", "request", "curl", "wget", "network"),
        capabilities=frozenset({Capability.NETWORK_OUT}),
    ),
    KeywordRule(
        keywords=("exec", "shell", "bash", " sh ", "terminal", "command", "spawn"),
        capabilities=frozenset({Capability.SHELL_EXEC}),
    ),
    KeywordRule(
        keywords=(
            "postgres", "postgresql", "mysql", "mariadb", "sqlite",
            "mongo", "mongodb", "database", " db ", "sql",
        ),
        capabilities=frozenset({Capability.DATABASE}),
    ),
    KeywordRule(
        keywords=("gmail", "email", " mail", "smtp", "sendgrid", "mailgun", " ses "),
        capabilities=frozenset({Capability.EMAIL}),
    ),
    KeywordRule(
        keywords=("browser", "puppeteer", "playwright", "selenium", "chrome", "webkit"),
        capabilities=frozenset({Capability.BROWSER}),
    ),
    KeywordRule(
        keywords=("github", "gitlab", "bitbucket", " git"),
        capabilities=frozenset({Capability.GIT}),
    ),
    KeywordRule(
        keywords=("vault", "secret", "credential", "keychain", "1password", "password"),
        capabilities=frozenset({Capability.SECRETS}),
    ),
]

# ── Toxic pair definitions ────────────────────────────────────────────────────

TOXIC_PAIRS: list[ToxicPair] = [
    ToxicPair(
        source=Capability.FILE_READ,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-001",
        severity=Severity.HIGH,
        title="File read + network exfiltration path",
        description=(
            "One server can read local files while another can make outbound "
            "network requests. An attacker or prompt injection could chain these "
            "to exfiltrate sensitive files."
        ),
        remediation=(
            "Review whether both servers are necessary. Consider restricting "
            "file access paths or network destinations."
        ),
        cwe="CWE-200",
    ),
    ToxicPair(
        source=Capability.FILE_READ,
        sink=Capability.EMAIL,
        finding_id="TOXIC-002",
        severity=Severity.HIGH,
        title="File read + email exfiltration path",
        description=(
            "One server can read local files while another can send emails. "
            "Sensitive files could be exfiltrated via email."
        ),
        remediation=(
            "Review whether both servers need these capabilities. "
            "Restrict file access or email recipients."
        ),
        cwe="CWE-200",
    ),
    ToxicPair(
        source=Capability.SECRETS,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-003",
        severity=Severity.CRITICAL,
        title="Secret access + network exfiltration path",
        description=(
            "One server can access credential stores while another can make "
            "outbound requests. Credentials could be exfiltrated."
        ),
        remediation=(
            "Isolate secret-accessing servers from any server with network "
            "capabilities."
        ),
        cwe="CWE-522",
    ),
    ToxicPair(
        source=Capability.FILE_READ,
        sink=Capability.SHELL_EXEC,
        finding_id="TOXIC-004",
        severity=Severity.HIGH,
        title="File read + shell execution path",
        description=(
            "One server can read files while another can execute shell commands. "
            "Malicious content could be read from a file and executed."
        ),
        remediation=(
            "Review whether both servers are necessary. "
            "Restrict shell execution scope."
        ),
        cwe="CWE-78",
    ),
    ToxicPair(
        source=Capability.DATABASE,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-005",
        severity=Severity.HIGH,
        title="Database access + network exfiltration path",
        description=(
            "One server can query databases while another can make outbound "
            "requests. Database contents could be exfiltrated."
        ),
        remediation=(
            "Review whether both servers need these capabilities. "
            "Restrict database queries or network destinations."
        ),
        cwe="CWE-200",
    ),
    ToxicPair(
        source=Capability.SHELL_EXEC,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-006",
        severity=Severity.CRITICAL,
        title="Shell execution + network exfiltration path",
        description=(
            "One server can execute shell commands while another can make "
            "outbound requests. This combination enables arbitrary command "
            "execution with data exfiltration."
        ),
        remediation=(
            "This is a high-risk combination. Remove one server or implement "
            "strict sandboxing."
        ),
        cwe="CWE-78",
    ),
    ToxicPair(
        source=Capability.GIT,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-007",
        severity=Severity.MEDIUM,
        title="Git access + network exfiltration path",
        description=(
            "One server can access git repositories while another can make "
            "outbound requests. Source code or commit history could be "
            "exfiltrated."
        ),
        remediation=(
            "Review whether both servers are necessary. "
            "Consider read-only git access."
        ),
        cwe="CWE-200",
    ),
]


# ── Capability tagging ────────────────────────────────────────────────────────


def tag_server(server: ServerConfig) -> frozenset[Capability]:
    """Assign capability labels to a server using a three-layer approach.

    Layers applied in order (results are unioned — all matches contribute):

    1. **Known-package lookup** — exact match of any arg against
       :data:`KNOWN_SERVERS`.
    2. **Keyword matching** — scan command name, server name, and all args for
       keywords defined in :data:`KEYWORD_RULES`.
    3. **Tool-name matching** — if the server's ``raw`` dict contains a
       ``"tools"`` key (populated by live ``--connect`` enumeration), apply the
       same keyword rules to tool names and descriptions.

    Args:
        server: The server configuration to tag.

    Returns:
        An immutable set of :class:`Capability` values.
    """
    caps: set[Capability] = set()

    # Layer 1 — known server registry (check all args for package names).
    for token in [server.command or "", *server.args, server.name]:
        if token in KNOWN_SERVERS:
            caps.update(KNOWN_SERVERS[token])

    # Layer 2 — keyword matching on the full token string.
    search_text = " " + " ".join(
        t for t in [server.command or "", server.name, *server.args] if t
    ).lower() + " "

    for rule in KEYWORD_RULES:
        for kw in rule.keywords:
            if kw in search_text:
                caps.update(rule.capabilities)
                break  # One keyword match per rule is enough.

    # Layer 3 — tool-name matching from live enumeration data.
    tools: list[dict] = server.raw.get("tools", []) if server.raw else []
    if tools:
        tool_text = " " + " ".join(
            f"{t.get('name', '')} {t.get('description', '')}"
            for t in tools
            if isinstance(t, dict)
        ).lower() + " "

        for rule in KEYWORD_RULES:
            for kw in rule.keywords:
                if kw in tool_text:
                    caps.update(rule.capabilities)
                    break

    return frozenset(caps)


# ── Analyzer ──────────────────────────────────────────────────────────────────


class ToxicFlowAnalyzer(BaseAnalyzer):
    """Detect dangerous cross-server capability combinations.

    Operates across all servers collectively — the single-server
    :meth:`analyze` always returns an empty list.  The orchestrator
    must call :meth:`analyze_all` instead.
    """

    @property
    def name(self) -> str:
        return "toxic_flow"

    @property
    def description(self) -> str:
        return "Detect dangerous capability combinations across MCP servers"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """No-op for single-server analysis — toxic flow is cross-server.

        The scanner calls :meth:`analyze_all` with the full server list.
        """
        return []

    def analyze_all(self, servers: list[ServerConfig]) -> list[Finding]:
        """Check all server pairs for dangerous capability combinations.

        Considers both cross-server pairs and single-server self-pairs (a
        server that alone has both the source and sink capability is at least
        as dangerous as a two-server combination).

        For each unordered pair ``{A, B}`` (including ``{A, A}``):
        - Cross-pair: emit a finding if A has the toxic-pair's source
          capability and B has the sink capability, *or* vice-versa.
          Only one finding is emitted per (pair, rule) combination.
        - Self-pair: emit a finding if the single server has both
          the source and sink capabilities.

        Args:
            servers: All MCP servers discovered in the current scan.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects, one per
            detected toxic pair.  Empty when no dangerous combinations exist.
        """
        findings: list[Finding] = []
        n = len(servers)
        # Cache tags so each server is only tagged once.
        caps: list[frozenset[Capability]] = [tag_server(s) for s in servers]

        for i in range(n):
            for j in range(i, n):
                caps_a, caps_b = caps[i], caps[j]

                for tp in TOXIC_PAIRS:
                    if i == j:
                        # Self-pair: one server holds both ends of the path.
                        if tp.source in caps_a and tp.sink in caps_a:
                            findings.append(
                                self._make_finding(tp, servers[i], servers[i])
                            )
                    else:
                        # Cross-pair: check forward direction first; fall back
                        # to reverse so only one finding is emitted per pair.
                        if tp.source in caps_a and tp.sink in caps_b:
                            findings.append(
                                self._make_finding(tp, servers[i], servers[j])
                            )
                        elif tp.source in caps_b and tp.sink in caps_a:
                            findings.append(
                                self._make_finding(tp, servers[j], servers[i])
                            )

        return findings

    @staticmethod
    def _make_finding(
        tp: ToxicPair,
        source_server: ServerConfig,
        sink_server: ServerConfig,
    ) -> Finding:
        """Build a :class:`~mcp_audit.models.Finding` for a detected toxic pair.

        Args:
            tp: The toxic pair rule that triggered.
            source_server: Server providing the source capability (or same as
                ``sink_server`` for self-pairs).
            sink_server: Server providing the sink capability.

        Returns:
            A fully populated :class:`~mcp_audit.models.Finding`.
        """
        is_self = source_server is sink_server

        if is_self:
            server_label = source_server.name
            client_label = source_server.client
            evidence = (
                f"{source_server.name!r} has both "
                f"{tp.source!r} and {tp.sink!r} capabilities"
            )
            config_path = str(source_server.config_path)
        else:
            server_label = f"{source_server.name} + {sink_server.name}"
            client_label = (
                source_server.client
                if source_server.client == sink_server.client
                else "multiple"
            )
            evidence = (
                f"{source_server.name!r} has {tp.source!r}; "
                f"{sink_server.name!r} has {tp.sink!r}"
            )
            config_path = str(source_server.config_path)

        return Finding(
            id=tp.finding_id,
            severity=tp.severity,
            analyzer="toxic_flow",
            client=client_label,
            server=server_label,
            title=tp.title,
            description=tp.description,
            evidence=evidence,
            remediation=tp.remediation,
            cwe=tp.cwe,
            finding_path=config_path,
        )
