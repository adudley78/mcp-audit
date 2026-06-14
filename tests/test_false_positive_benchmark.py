"""False-positive benchmark for mcp-audit analyzers.

Runs the poisoning and credentials analyzers against realistic configs for
the top real-world MCP servers and asserts zero spurious findings.

This is the regression baseline for detection quality. A test failure here
means a pattern change introduced a false positive on a legitimate server —
that must be fixed (by narrowing the pattern) before merging.

Acceptable findings — NOT false positives, these are correct signals:
- TRANSPORT-003: runtime package fetching via npx/uvx (expected, by design)
- COMM-010: npx used without pinned version (LOW, intentional signal)
- SC-001/SC-002: only if a community server name is actually close to a
  known-malicious name (correct behaviour, not a false positive)

The tests here assert ZERO poisoning findings and ZERO credential findings
on all legitimate server configs with empty or absent env var values.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.analyzers.credentials import CredentialsAnalyzer
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import DiscoveredConfig

REAL_SERVERS = Path(__file__).parent / "fixtures" / "real_servers"


def _load(filename: str) -> list:
    """Parse a real-server fixture and return all ServerConfig objects."""
    cfg = DiscoveredConfig(
        client_name="test",
        root_key="mcpServers",
        path=REAL_SERVERS / filename,
    )
    return parse_config(cfg)


# ---------------------------------------------------------------------------
# Official @modelcontextprotocol/* servers
# ---------------------------------------------------------------------------

OFFICIAL_SERVER_NAMES = [
    "filesystem",
    "github",
    "brave-search",
    "memory",
    "fetch",
    "puppeteer",
    "slack",
    "postgres",
    "git",
    "gitlab",
    "google-drive",
    "google-maps",
]

COMMUNITY_SERVER_NAMES = [
    "linear",
    "stripe",
    "mcp-server-sqlite",
    "aws-kb-retrieval",
    "mcp-server-qdrant",
    "exa",
    "mcp-server-kubernetes",
    "mcp-server-docker",
    "notion",
    "mcp-perplexity",
]


class TestOfficialServersFalsePositives:
    """Official Anthropic-maintained servers must produce zero poisoning findings.

    Any poisoning finding against these servers is a false positive that would
    surface immediately on launch day — these are the first configs every user
    will scan.
    """

    def setup_method(self):
        self.poison = PoisoningAnalyzer()
        self.creds = CredentialsAnalyzer()
        self.servers = _load("official_mcp_servers.json")

    def test_all_official_servers_loaded(self):
        names = {s.name for s in self.servers}
        missing = set(OFFICIAL_SERVER_NAMES) - names
        assert not missing, f"Fixture missing servers: {missing}"

    @pytest.mark.parametrize("server_name", OFFICIAL_SERVER_NAMES)
    def test_no_poisoning_findings(self, server_name):
        server = next(s for s in self.servers if s.name == server_name)
        findings = self.poison.analyze(server)
        assert findings == [], (
            f"FALSE POSITIVE — PoisoningAnalyzer fired on official"
            f" server '{server_name}':\n"
            + "\n".join(
                f"  {f.id} ({f.severity}): {f.title} — evidence: {f.evidence}"
                for f in findings
            )
        )

    @pytest.mark.parametrize(
        "server_name",
        [
            # Servers with no env vars or only empty-value env vars
            "filesystem",
            "memory",
            "fetch",
            "puppeteer",
            "postgres",
            "git",
            "google-drive",
        ],
    )
    def test_no_credential_findings_on_empty_env(self, server_name):
        """Servers with no actual secrets must not trigger credential detection."""
        server = next(s for s in self.servers if s.name == server_name)
        findings = self.creds.analyze(server)
        assert findings == [], (
            f"FALSE POSITIVE — CredentialsAnalyzer fired on '{server_name}'"
            " with empty/no env:\n"
            + "\n".join(f"  {f.id}: {f.title}" for f in findings)
        )


class TestCommunityServersFalsePositives:
    """Popular community servers must produce zero poisoning findings.

    These are the servers developers encounter most often in the wild. False
    positives here will be reported as bugs immediately after launch.
    """

    def setup_method(self):
        self.poison = PoisoningAnalyzer()
        self.creds = CredentialsAnalyzer()
        self.servers = _load("community_mcp_servers.json")

    def test_all_community_servers_loaded(self):
        names = {s.name for s in self.servers}
        missing = set(COMMUNITY_SERVER_NAMES) - names
        assert not missing, f"Fixture missing servers: {missing}"

    @pytest.mark.parametrize("server_name", COMMUNITY_SERVER_NAMES)
    def test_no_poisoning_findings(self, server_name):
        server = next(s for s in self.servers if s.name == server_name)
        findings = self.poison.analyze(server)
        assert findings == [], (
            f"FALSE POSITIVE — PoisoningAnalyzer fired on community"
            f" server '{server_name}':\n"
            + "\n".join(
                f"  {f.id} ({f.severity}): {f.title} — evidence: {f.evidence}"
                for f in findings
            )
        )

    @pytest.mark.parametrize(
        "server_name",
        [
            "mcp-server-sqlite",
            "mcp-server-kubernetes",
            "mcp-server-docker",
        ],
    )
    def test_no_credential_findings_on_no_env(self, server_name):
        server = next(s for s in self.servers if s.name == server_name)
        findings = self.creds.analyze(server)
        assert findings == [], (
            f"FALSE POSITIVE — CredentialsAnalyzer fired on '{server_name}'"
            " with no env:\n" + "\n".join(f"  {f.id}: {f.title}" for f in findings)
        )


class TestBenchmarkSummary:
    """Aggregate assertions across the full 22-server benchmark set.

    These are the numbers to quote when claiming a known false-positive rate.
    If either assertion fails, a pattern change introduced a regression.
    """

    def setup_method(self):
        self.poison = PoisoningAnalyzer()
        self.creds = CredentialsAnalyzer()
        self.official = _load("official_mcp_servers.json")
        self.community = _load("community_mcp_servers.json")
        self.all_servers = self.official + self.community

    def test_benchmark_covers_minimum_server_count(self):
        """Benchmark must cover at least 20 distinct server configs."""
        assert len(self.all_servers) >= 20, (
            f"Benchmark only covers {len(self.all_servers)} servers — "
            "add more fixtures to reach a statistically meaningful sample"
        )

    def test_zero_poisoning_false_positives_across_full_benchmark(self):
        """Poisoning FP rate must be 0/22 across all legitimate server configs."""
        false_positives = []
        for server in self.all_servers:
            findings = self.poison.analyze(server)
            for f in findings:
                false_positives.append((server.name, f))

        assert not false_positives, (
            f"Poisoning false positives on {len(false_positives)} findings "
            f"across {len(self.all_servers)} legitimate servers:\n"
            + "\n".join(
                f"  [{name}] {f.id} ({f.severity}): {f.title} — {f.evidence}"
                for name, f in false_positives
            )
        )

    def test_false_positive_rate_is_documented(self):
        """Meta-test: confirms the rate is 0% and prints a summary for GAPS.md."""
        poison_counts = {}
        for server in self.all_servers:
            findings = self.poison.analyze(server)
            poison_counts[server.name] = len(findings)

        total = len(self.all_servers)
        fp_servers = [name for name, count in poison_counts.items() if count > 0]
        fp_rate = len(fp_servers) / total * 100

        # This assertion is the documented claim: 0% FP rate on this benchmark.
        assert fp_rate == 0.0, (
            f"Poisoning FP rate is {fp_rate:.1f}% ({len(fp_servers)}/{total} servers): "
            + ", ".join(fp_servers)
        )


# ---------------------------------------------------------------------------
# Agent-file false-positive benchmark
# Zero FPs on benign agent instruction and memory files is the ship bar.
# ---------------------------------------------------------------------------


BENIGN_SKILL_BODIES = [
    # Typical deploy skill
    (
        "deploy_staging",
        "# Deploy to Staging\n\nRun the deployment pipeline for staging.\n\n"
        "```bash\n./scripts/deploy.sh --env staging --confirm\n```\n\n"
        "Wait for the health check before proceeding.",
    ),
    # Git workflow skill
    (
        "git_workflow",
        "# Create a PR\n\nCreate a pull request for the current branch.\n\n"
        "1. Run `git push origin HEAD`\n2. Use `gh pr create` with a summary.\n"
        "3. Add reviewers from the CODEOWNERS file.",
    ),
    # Test runner skill
    (
        "run_tests",
        "# Run Tests\n\nExecute the full test suite and report results.\n\n"
        "```bash\nuv run pytest tests/ -q\n```\n\nFix any failures before merging.",
    ),
    # Cursor rule: TypeScript conventions
    (
        "ts_conventions",
        "---\napplyTo: '**/*.ts'\n---\n"
        "# TypeScript Conventions\n\n"
        "- Use strict TypeScript (`strict: true` in tsconfig)\n"
        "- Prefer `const` over `let`\n"
        "- Use named exports over default exports\n",
    ),
    # Copilot instruction: Python style
    (
        "python_style",
        "# Python coding standards\n\n"
        "Use Black for formatting and Ruff for linting.\n"
        "All functions must have type hints and docstrings.\n"
        "Use pytest for testing. Minimum coverage: 80%%.",
    ),
    # Copilot scoped instruction
    (
        "backend_instructions",
        "# Backend Instructions\n\n"
        "Apply to all Python files in `src/`.\n\n"
        "- Use FastAPI for new endpoints\n"
        "- Always return `JSONResponse` with appropriate status codes\n"
        "- Log at INFO level; use structlog\n",
    ),
    # Copilot prompt template
    (
        "fix_bug_prompt",
        "# Fix Bug\n\nAnalyze the following code and identify the bug:\n\n"
        "```\n$SELECTION\n```\n\n"
        "Provide a corrected version with an explanation of what was wrong.",
    ),
]

BENIGN_MEMORY_BODIES = [
    # Typical project CLAUDE.md
    (
        "project_context",
        "# mcp-audit\n\n"
        "## Stack\n- Python 3.11+, managed with uv\n- CLI: Typer + Rich\n\n"
        "## Conventions\nRun `uv run pytest` after each change.\n"
        "Run `uv run ruff check src/ tests/` before committing.\n\n"
        "## Key directories\n"
        "- `src/mcp_audit/` — main package\n"
        "- `tests/` — test suite\n",
    ),
    # Frontend project memory
    (
        "frontend_context",
        "# Frontend Project\n\n"
        "## Stack\nNext.js 14, TypeScript, Tailwind CSS, Shadcn/ui.\n\n"
        "## Commands\n- `npm run dev` — start dev server\n"
        "- `npm run build` — production build\n"
        "- `npm test` — run Jest suite\n\n"
        "## Conventions\nUse named exports. Co-locate tests with components.",
    ),
    # Large project memory (should not trigger length-based MEM findings)
    (
        "large_benign_memory",
        "# Large Project\n\n"
        + "## Module notes\n\n"
        + "".join(
            f"### module_{i}\n\nHandles subsystem {i}.\nNo special notes.\n\n"
            for i in range(40)
        ),
    ),
]


class TestAgentFileFalsePositives:
    """Zero-FP benchmark for the agent-file analyzer on benign content."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from mcp_audit.agent_files.analyzer import analyze_agent_files
        from mcp_audit.agent_files.models import AgentFile, AgentFileSurface

        self.analyze = analyze_agent_files
        self.AgentFile = AgentFile
        self.AgentFileSurface = AgentFileSurface

    def _skill(self, name: str, body: str):
        return self.AgentFile(
            path=Path(f"/tmp/{name}.md"),  # noqa: S108
            surface=self.AgentFileSurface.CLAUDE_COMMAND,
            client="claude-code",
            scope="user",
            raw_content=body,
            body=body,
        )

    def _memory(self, name: str, body: str):
        return self.AgentFile(
            path=Path(f"/tmp/{name}.md"),  # noqa: S108
            surface=self.AgentFileSurface.CLAUDE_MEMORY,
            client="claude-code",
            scope="project",
            raw_content=body,
            body=body,
        )

    def test_benign_skills_zero_fp(self):
        """All benign skill/instruction bodies → zero findings."""
        false_positives = []
        for name, body in BENIGN_SKILL_BODIES:
            af = self._skill(name, body)
            findings = self.analyze([af])
            for f in findings:
                false_positives.append((name, f))

        assert not false_positives, (
            f"Agent-file skill FPs on {len(false_positives)} finding(s) "
            f"across {len(BENIGN_SKILL_BODIES)} benign files:\n"
            + "\n".join(
                f"  [{name}] {f.id} ({f.severity}): {f.title} — {f.evidence}"
                for name, f in false_positives
            )
        )

    def test_benign_memory_zero_fp(self):
        """All benign CLAUDE.md bodies → zero findings."""
        false_positives = []
        for name, body in BENIGN_MEMORY_BODIES:
            af = self._memory(name, body)
            findings = self.analyze([af])
            for f in findings:
                false_positives.append((name, f))

        assert not false_positives, (
            f"Agent-file memory FPs on {len(false_positives)} finding(s) "
            f"across {len(BENIGN_MEMORY_BODIES)} benign files:\n"
            + "\n".join(
                f"  [{name}] {f.id} ({f.severity}): {f.title} — {f.evidence}"
                for name, f in false_positives
            )
        )
