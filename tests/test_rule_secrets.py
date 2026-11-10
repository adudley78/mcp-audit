"""CRED-004: secrets saved inside Claude Code permission rules (STORY-0149)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from mcp_audit.analyzers import sandbox as sb
from mcp_audit.analyzers.rule_secrets import (
    MAX_RULE_CHARS,
    MAX_RULES_PER_LIST,
    holds_secret,
    redact_rule,
    rule_secret_hits,
)
from mcp_audit.config_parser import DiscoveredConfig
from mcp_audit.models import Finding, Severity

# Built from pieces so the repository holds no token-shaped literal.
GH_TOKEN = "gh" + "p_" + "a" * 36
STRIPE_KEY = "sk" + "_live_" + "b" * 24
NPM_TOKEN = "np" + "m_" + "c" * 36
DB_PASSWORD = "hunter2" + "secret"
SECRETS = (GH_TOKEN, STRIPE_KEY, NPM_TOKEN, DB_PASSWORD)

#: Rules as Claude Code saves them after "Yes, and don't ask again".
LEAKY_RULES = [
    f'Bash(curl -H "Authorization: Bearer {GH_TOKEN}" https://api.github.com/user)',
    f"Bash(PGPASSWORD={DB_PASSWORD} psql -h db -U app)",
    f"Bash(stripe charges list --api-key {STRIPE_KEY})",
    f"Bash(psql postgresql://app:{DB_PASSWORD}@db/prod)",
    f"Bash(npm config set //registry.npmjs.org/:_authToken={NPM_TOKEN})",
    f"Bash(curl -u admin:{DB_PASSWORD} https://example.com)",
    f'Bash(curl -s "https://api.example.com/v1?api_key={DB_PASSWORD}")',
    f"Bash(DB_PASSWD={DB_PASSWORD} ./migrate)",
    f"Bash(GITHUB_TOKEN={GH_TOKEN} gh pr list)",
    f"WebFetch(https://user:{DB_PASSWORD}@example.com/)",
    f"Bash(echo {GH_TOKEN})",
]

#: Rules that name a secret without holding one, and ordinary rules.
CLEAN_RULES = [
    "Bash(npm run test:*)",
    "Bash(npm test *)",
    "Bash(git push origin main)",
    "Bash(export API_KEY=$API_KEY)",
    "Bash(DB_PASSWORD=${DB_PASSWORD} ./x)",
    'Bash(MYSQL_PWD="$PW" mysql)',
    'Bash(curl -H "Authorization: Bearer $TOKEN" https://example.com)',
    "Bash(TOKEN=* ./run.sh)",
    "Bash(npm test -- --password=*)",
    "Bash(PASSWORD=${{ secrets.DB_PASSWORD }} ./deploy)",
    'Bash(echo "API_KEY=" >> .env)',
    "Bash(sed -i s/password=old/password=new/ config.ini)",
    "Bash(uv run pytest -k token)",
    "Bash(gh api repos/x --jq .token)",
    "Read(~/.aws/credentials)",
    "Read(./.env)",
    "WebFetch(domain:github.com)",
    "mcp__github__create_issue",
    "Bash(*)",
    "Edit",
]


class TestRedactRule:
    @pytest.mark.parametrize("rule", LEAKY_RULES)
    def test_secret_is_found_and_never_left_in_the_quote(self, rule: str) -> None:
        assert holds_secret(rule)
        quoted = redact_rule(rule)
        assert "[REDACTED]" in quoted
        assert not any(secret in quoted for secret in SECRETS)

    @pytest.mark.parametrize("rule", CLEAN_RULES)
    def test_reference_wildcard_and_plain_rules_are_not_secrets(
        self, rule: str
    ) -> None:
        assert not holds_secret(rule)
        assert redact_rule(rule) == rule

    def test_tool_wrapper_is_kept(self) -> None:
        assert redact_rule(LEAKY_RULES[0]).startswith("Bash(curl -H ")
        assert redact_rule(LEAKY_RULES[0]).endswith(")")

    def test_mixed_reference_and_literal_reports_the_literal(self) -> None:
        rule = f"Bash(A_TOKEN={GH_TOKEN} B_PASSWORD=$P run)"
        assert redact_rule(rule) == "Bash(A_TOKEN=[REDACTED] B_PASSWORD=$P run)"

    def test_huge_rule_is_fast(self) -> None:
        start = time.perf_counter()
        rule = "Bash(" + "PASSWORD=x " * 400 + "a=" * 2000 + ")"
        redact_rule(rule[:MAX_RULE_CHARS])
        assert time.perf_counter() - start < 2


class TestRuleSecretHits:
    def test_every_list_is_read_with_locations(self) -> None:
        raw = {
            "permissions": {
                "allow": ["Bash(npm test *)", LEAKY_RULES[1]],
                "ask": [LEAKY_RULES[2]],
                "deny": [LEAKY_RULES[0]],
            }
        }
        scan = rule_secret_hits(raw)
        assert [h.location for h in scan.hits] == [
            "permissions.allow[1]",
            "permissions.ask[0]",
            "permissions.deny[0]",
        ]
        assert not scan.truncated

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            [],
            "text",
            {},
            {"permissions": []},
            {"permissions": {"allow": "Bash(x)"}},
            {"permissions": {"allow": [1, None, {"a": GH_TOKEN}, ["x"]]}},
            {"env": {"TOKEN": GH_TOKEN}},  # env is CRED-001's, not a rule
        ],
    )
    def test_malformed_or_absent_rules_give_nothing(self, raw: object) -> None:
        assert rule_secret_hits(raw).hits == []

    def test_oversized_lists_and_rules_are_cut_and_reported(self) -> None:
        many = {"permissions": {"allow": ["Bash(ls)"] * (MAX_RULES_PER_LIST + 1)}}
        assert rule_secret_hits(many).truncated
        long_rule = "Bash(" + "x" * (MAX_RULE_CHARS + 10) + ")"
        assert rule_secret_hits({"permissions": {"allow": [long_rule]}}).truncated


# ── Through pipeline step 0b ──────────────────────────────────────────────────


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setattr(Path, "home", lambda: path)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return path


@pytest.fixture
def repo(tmp_path: Path, home: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git" / "info").mkdir(parents=True)
    (root / ".claude").mkdir()
    return root


LEAKY = {"permissions": {"allow": ["Bash(npm test *)", *LEAKY_RULES[:3]]}}


def _write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _config(path: Path, raw: object) -> DiscoveredConfig:
    return DiscoveredConfig(
        client_name="claude-code-project", root_key="mcpServers", path=path, raw=raw
    )


def _cred(path: Path, raw: object = LEAKY) -> list[Finding]:
    findings, _errors = sb.analyze_sandbox_files([_config(path, raw)])
    return [f for f in findings if f.id == "CRED-004"]


class TestSeverityFollowsGit:
    def test_unignored_local_file_is_high(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.local.json", LEAKY)
        (finding,) = _cred(path)
        assert finding.severity == Severity.HIGH
        assert "3 permission rule(s)" in finding.description
        assert "no ignore file covers it" in finding.description
        assert finding.cwe == "CWE-312"
        assert finding.owasp_mcp_top_10 == ["MCP01"]
        assert finding.evidence.count("permissions.allow[") == 3

    def test_ignored_local_file_is_medium(self, repo: Path) -> None:
        (repo / ".gitignore").write_text(".claude/settings.local.json\n")
        path = _write(repo / ".claude" / "settings.local.json", LEAKY)
        (finding,) = _cred(path)
        assert finding.severity == Severity.MEDIUM
        assert "Git ignores it" in finding.description

    def test_shared_project_file_is_high(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.json", LEAKY)
        (finding,) = _cred(path)
        assert finding.severity == Severity.HIGH

    def test_local_file_outside_a_work_tree_is_medium(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "loose" / ".claude" / "settings.local.json", LEAKY)
        (finding,) = _cred(path)
        assert finding.severity == Severity.MEDIUM

    def test_user_settings_are_medium(self, home: Path) -> None:
        path = _write(home / ".claude" / "settings.json", LEAKY)
        (finding,) = _cred(path)
        assert finding.severity == Severity.MEDIUM
        assert "your own settings file" in finding.description

    def test_no_secret_no_finding(self, repo: Path) -> None:
        raw = {"permissions": {"allow": CLEAN_RULES}}
        path = _write(repo / ".claude" / "settings.local.json", raw)
        assert _cred(path, raw) == []

    def test_secret_never_appears_in_any_finding(self, repo: Path) -> None:
        raw = {
            "permissions": {
                "defaultMode": "acceptEdits",
                "allow": [*LEAKY_RULES, "Bash(*)"],
                "ask": [f"Bash(rm PGPASSWORD={DB_PASSWORD} *)"],
                "deny": [f"Bash(curl * {GH_TOKEN})"],
            }
        }
        path = _write(repo / ".claude" / "settings.local.json", raw)
        findings, _errors = sb.analyze_sandbox_files([_config(path, raw)])
        assert any(f.id == "CRED-004" for f in findings)
        for finding in findings:
            text = finding.model_dump_json()
            assert not any(secret in text for secret in SECRETS), finding.id

    def test_more_than_twenty_rules_are_capped_in_evidence(self, repo: Path) -> None:
        rules = [f"Bash(GITHUB_TOKEN={GH_TOKEN} gh api /{n})" for n in range(25)]
        raw = {"permissions": {"allow": rules}}
        path = _write(repo / ".claude" / "settings.local.json", raw)
        (finding,) = _cred(path, raw)
        assert "25 permission rule(s)" in finding.description
        assert "(+5 more)" in finding.evidence


class TestPermQuotesAreRedacted:
    """PERM-* evidence quoted rules as written (fixed with STORY-0149)."""

    def test_perm_findings_redact_rules(self, repo: Path) -> None:
        from mcp_audit.analyzers.config_hygiene import (  # noqa: PLC0415
            ConfigHygieneAnalyzer,
        )

        raw = {
            "permissions": {
                "ask": [f"Bash(rm PGPASSWORD={DB_PASSWORD} *)"],
                "deny": [f"Bash(curl * {GH_TOKEN})"],
            }
        }
        path = _write(repo / ".claude" / "settings.local.json", raw)
        findings = ConfigHygieneAnalyzer().analyze_config(
            raw, path, "claude-code-project"
        )
        perm = [f for f in findings if f.id.startswith("PERM-")]
        assert perm, "fixture should produce a PERM finding"
        for finding in perm:
            text = finding.model_dump_json()
            assert not any(secret in text for secret in SECRETS)
            assert "[REDACTED]" in text


class TestShippedConfigsAreSilent:
    def test_no_settings_file_in_the_repository_fires(self) -> None:
        root = Path(__file__).resolve().parent.parent
        hits = []
        for path in sorted(root.glob("**/.claude/settings*.json")):
            if ".git" in path.parts or "node_modules" in path.parts:
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            hits += [(str(path), h.location) for h in rule_secret_hits(raw).hits]
        assert hits == []


class TestMeasuredFalsePositives:
    """Shapes from the 2026-11-10 measurement on 360 public settings files."""

    @pytest.mark.parametrize(
        "rule",
        [
            # A PR body: a secret word earlier, then ">= 44px", and "**Bold:**".
            'Bash(gh pr create --body "auth flow done\n- [x] targets >= 44px\n'
            '**Modified:**\n- a.ts")',
            "Bash(export ANSIBLE_VAULT_PASSWORD_FILE=~/.vault_pass)",
            "Bash(ANSIBLE_VAULT_PASSWORD_FILE=.vault git push)",
        ],
    )
    def test_not_a_secret(self, rule: str) -> None:
        assert redact_rule(rule) == rule

    def test_token_with_a_colon_secret_is_redacted_whole(self) -> None:
        rule = f'Bash(curl -H "Authorization: token abcd1234:{DB_PASSWORD}" x)'
        assert DB_PASSWORD not in redact_rule(rule)
