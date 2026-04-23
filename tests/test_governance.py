"""Tests for the governance policy engine (mcp_audit.governance)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.governance.evaluator import evaluate_governance
from mcp_audit.governance.loader import POLICY_FILENAMES, load_policy
from mcp_audit.governance.models import (
    ApprovedServerEntry,
    ApprovedServers,
    ClientOverride,
    FindingPolicy,
    GovernancePolicy,
    PolicyMode,
    RegistryPolicy,
    ScoreThreshold,
    TransportPolicy,
)
from mcp_audit.models import (
    Finding,
    ScanResult,
    ScanScore,
    ServerConfig,
    Severity,
    TransportType,
)

runner = CliRunner()

# ── Shared helpers ────────────────────────────────────────────────────────────


def _make_server(
    name: str = "test-server",
    client: str = "cursor",
    transport: TransportType = TransportType.STDIO,
    command: str | None = "npx",
    url: str | None = None,
    config_path: Path | None = None,
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path or Path("/tmp/test-mcp.json"),  # noqa: S108
        transport=transport,
        command=command,
        url=url,
    )


def _make_scan_result(
    findings: list[Finding] | None = None,
    score: int = 80,
    grade: str = "B",
) -> ScanResult:
    result = ScanResult()
    result.findings = findings or []
    result.score = ScanScore(
        numeric_score=score,
        grade=grade,
        positive_signals=[],
        deductions=[],
    )
    return result


def _make_finding(
    severity: Severity = Severity.HIGH,
    analyzer: str = "poisoning",
    server: str = "server1",
    client: str = "cursor",
) -> Finding:
    return Finding(
        id="TEST-001",
        severity=severity,
        analyzer=analyzer,
        client=client,
        server=server,
        title="Test finding",
        description="Test description",
        evidence="test evidence",
        remediation="test remediation",
    )


def _write_policy(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data), encoding="utf-8")


# ── TestPolicyLoading ─────────────────────────────────────────────────────────


class TestPolicyLoading:
    def test_load_from_explicit_path(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "my-policy.yml"
        _write_policy(policy_file, {"version": 1, "name": "test"})
        result = load_policy(policy_file)
        assert result is not None
        assert result.name == "test"

    def test_load_from_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy_file = tmp_path / POLICY_FILENAMES[0]
        _write_policy(policy_file, {"version": 1, "name": "cwd-policy"})
        monkeypatch.chdir(tmp_path)
        result = load_policy()
        assert result is not None
        assert result.name == "cwd-policy"

    def test_load_returns_none_when_no_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        # Ensure user config path doesn't exist in test.
        with patch(
            "mcp_audit.governance.loader._USER_POLICY_PATH",
            tmp_path / "nonexistent.yml",
        ):
            result = load_policy()
        assert result is None

    def test_invalid_yaml_raises_value_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("{ invalid: yaml: [", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_policy(bad_file)

    def test_schema_validation_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad-schema.yml"
        # version must be int, not a list.
        _write_policy(bad_file, {"version": ["not", "an", "int"]})
        with pytest.raises(ValueError, match="schema validation"):
            load_policy(bad_file)

    def test_explicit_path_missing_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.yml"
        with pytest.raises(ValueError, match="not found"):
            load_policy(missing)

    def test_empty_yaml_loads_defaults(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.yml"
        empty_file.write_text("", encoding="utf-8")
        result = load_policy(empty_file)
        assert result is not None
        assert result.version == 1

    def test_load_from_git_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Create a fake git root one level up from cwd.
        git_root = tmp_path / "repo"
        git_root.mkdir()
        (git_root / ".git").mkdir()
        cwd = git_root / "subdir"
        cwd.mkdir()
        policy_file = git_root / POLICY_FILENAMES[0]
        _write_policy(policy_file, {"name": "from-git-root"})
        monkeypatch.chdir(cwd)
        with patch(
            "mcp_audit.governance.loader._USER_POLICY_PATH",
            tmp_path / "nonexistent.yml",
        ):
            result = load_policy()
        assert result is not None
        assert result.name == "from-git-root"


# ── TestApprovedServersEvaluation ─────────────────────────────────────────────


class TestApprovedServersEvaluation:
    def _policy(
        self,
        mode: PolicyMode = PolicyMode.ALLOWLIST,
        entries: list[dict] | None = None,
    ) -> GovernancePolicy:
        raw_entries = [ApprovedServerEntry(**e) for e in (entries or [])]
        return GovernancePolicy(
            approved_servers=ApprovedServers(mode=mode, entries=raw_entries)
        )

    def test_allowlist_pass(self) -> None:
        server = _make_server(name="allowed-server")
        policy = self._policy(
            entries=[{"name": "allowed-server"}],
        )
        findings = evaluate_governance([server], policy)
        assert not findings

    def test_allowlist_violation(self) -> None:
        server = _make_server(name="unknown-server")
        policy = self._policy(entries=[{"name": "other-server"}])
        findings = evaluate_governance([server], policy)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].analyzer == "governance"
        assert "unknown-server" in findings[0].title

    def test_denylist_pass(self) -> None:
        server = _make_server(name="safe-server")
        policy = self._policy(
            mode=PolicyMode.DENYLIST,
            entries=[{"name": "dangerous-server"}],
        )
        findings = evaluate_governance([server], policy)
        assert not findings

    def test_denylist_violation(self) -> None:
        server = _make_server(name="dangerous-server")
        policy = self._policy(
            mode=PolicyMode.DENYLIST,
            entries=[{"name": "dangerous-server"}],
        )
        findings = evaluate_governance([server], policy)
        assert len(findings) == 1
        assert "dangerous-server" in findings[0].title

    def test_glob_pattern_match(self) -> None:
        server = _make_server(name="@modelcontextprotocol/server-filesystem")
        policy = self._policy(entries=[{"name": "@modelcontextprotocol/*"}])
        findings = evaluate_governance([server], policy)
        assert not findings

    def test_glob_pattern_no_match(self) -> None:
        server = _make_server(name="evil-org/filesystem")
        policy = self._policy(entries=[{"name": "@modelcontextprotocol/*"}])
        findings = evaluate_governance([server], policy)
        assert len(findings) == 1

    def test_source_filter(self) -> None:
        # Entry requires npm source; server uses pip (python command).
        server = _make_server(name="my-server", command="python")
        policy = self._policy(entries=[{"name": "my-server", "source": "npm"}])
        findings = evaluate_governance([server], policy)
        assert len(findings) == 1  # npm entry doesn't match pip server

    def test_empty_allowlist_flags_all_servers(self) -> None:
        servers = [
            _make_server(name="s1"),
            _make_server(name="s2"),
        ]
        policy = self._policy(entries=[])  # empty allowlist
        findings = evaluate_governance(servers, policy)
        assert len(findings) == 2


# ── TestScoreThresholdEvaluation ──────────────────────────────────────────────


class TestScoreThresholdEvaluation:
    def _policy(self, minimum: int = 75, severity: str = "medium") -> GovernancePolicy:
        return GovernancePolicy(
            score_threshold=ScoreThreshold(minimum=minimum, violation_severity=severity)
        )

    def test_score_above_threshold_no_finding(self) -> None:
        server = _make_server()
        policy = self._policy(minimum=75)
        result = _make_scan_result(score=85)
        findings = evaluate_governance([server], policy, scan_result=result)
        assert not findings

    def test_score_below_threshold_finding(self) -> None:
        server = _make_server()
        policy = self._policy(minimum=75)
        result = _make_scan_result(score=60, grade="D")
        findings = evaluate_governance([server], policy, scan_result=result)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "60" in findings[0].description
        assert "75" in findings[0].description

    def test_score_exactly_at_threshold_no_finding(self) -> None:
        server = _make_server()
        policy = self._policy(minimum=75)
        result = _make_scan_result(score=75)
        findings = evaluate_governance([server], policy, scan_result=result)
        assert not findings

    def test_no_scan_result_skips_check(self) -> None:
        server = _make_server()
        policy = self._policy(minimum=75)
        findings = evaluate_governance([server], policy, scan_result=None)
        assert not findings


# ── TestTransportPolicyEvaluation ─────────────────────────────────────────────


class TestTransportPolicyEvaluation:
    def _policy(self, **kwargs: object) -> GovernancePolicy:
        return GovernancePolicy(transport_policy=TransportPolicy(**kwargs))

    def test_http_blocked_produces_finding(self) -> None:
        server = _make_server(
            transport=TransportType.STREAMABLE_HTTP,
            url="http://localhost:8080",
        )
        policy = self._policy(block_http=True)
        findings = evaluate_governance([server], policy)
        # block_http + unencrypted http → finding
        assert any("unencrypted" in f.title.lower() for f in findings)

    def test_http_allowed_no_finding(self) -> None:
        server = _make_server(
            transport=TransportType.STREAMABLE_HTTP,
            url="http://localhost:8080",
        )
        policy = self._policy(allow_http=True, block_http=False, require_tls=False)
        findings = evaluate_governance([server], policy)
        # allow_http=True, no block or tls requirements — no unencrypted finding
        unencrypted = [f for f in findings if "unencrypted" in f.title.lower()]
        assert not unencrypted

    def test_stdio_blocked_produces_finding(self) -> None:
        server = _make_server(transport=TransportType.STDIO)
        policy = self._policy(allow_stdio=False)
        findings = evaluate_governance([server], policy)
        assert any("stdio" in f.title.lower() for f in findings)

    def test_stdio_allowed_no_finding(self) -> None:
        server = _make_server(transport=TransportType.STDIO)
        policy = self._policy(allow_stdio=True)
        findings = evaluate_governance([server], policy)
        stdio_findings = [f for f in findings if "stdio" in f.title.lower()]
        assert not stdio_findings

    def test_require_tls_on_https_no_finding(self) -> None:
        server = _make_server(
            transport=TransportType.STREAMABLE_HTTP,
            url="https://secure.example.com",
        )
        policy = self._policy(require_tls=True)
        findings = evaluate_governance([server], policy)
        unencrypted = [f for f in findings if "unencrypted" in f.title.lower()]
        assert not unencrypted


# ── TestRegistryPolicyEvaluation ──────────────────────────────────────────────


class TestRegistryPolicyEvaluation:
    def _mock_registry(
        self, known: list[str], verified: dict[str, bool] | None = None
    ) -> MagicMock:
        registry = MagicMock()
        registry.is_known.side_effect = lambda name: name in known
        # Simulate _name_index for verified check.
        index: dict[str, MagicMock] = {}
        for name in known:
            entry = MagicMock()
            entry.verified = (verified or {}).get(name, True)
            index[name.lower()] = entry
        registry._name_index = index
        return registry

    def test_require_known_unknown_server_finding(self) -> None:
        server = _make_server(name="unknown-pkg")
        policy = GovernancePolicy(registry_policy=RegistryPolicy(require_known=True))
        registry = self._mock_registry(known=["other-pkg"])
        findings = evaluate_governance([server], policy, registry=registry)
        assert len(findings) == 1
        assert "Known-Server Registry" in findings[0].title

    def test_require_known_known_server_no_finding(self) -> None:
        server = _make_server(name="known-pkg")
        policy = GovernancePolicy(registry_policy=RegistryPolicy(require_known=True))
        registry = self._mock_registry(known=["known-pkg"])
        findings = evaluate_governance([server], policy, registry=registry)
        assert not findings

    def test_require_verified_unverified_finding(self) -> None:
        server = _make_server(name="known-unverified")
        policy = GovernancePolicy(
            registry_policy=RegistryPolicy(require_known=False, require_verified=True)
        )
        registry = self._mock_registry(
            known=["known-unverified"],
            verified={"known-unverified": False},
        )
        findings = evaluate_governance([server], policy, registry=registry)
        assert any("not verified" in f.title for f in findings)

    def test_no_registry_skips_check(self) -> None:
        server = _make_server(name="any-server")
        policy = GovernancePolicy(registry_policy=RegistryPolicy(require_known=True))
        findings = evaluate_governance([server], policy, registry=None)
        assert not findings


# ── TestFindingPolicyEvaluation ───────────────────────────────────────────────


class TestFindingPolicyEvaluation:
    def _policy(self, **kwargs: object) -> GovernancePolicy:
        return GovernancePolicy(finding_policy=FindingPolicy(**kwargs))

    def test_under_limit_no_finding(self) -> None:
        server = _make_server()
        policy = self._policy(max_critical=2)
        existing = [_make_finding(severity=Severity.CRITICAL)]
        result = _make_scan_result(findings=existing)
        findings = evaluate_governance([server], policy, scan_result=result)
        gov = [f for f in findings if f.analyzer == "governance"]
        fp = [f for f in gov if "finding_policy" in f.evidence]
        assert not fp

    def test_at_limit_no_finding(self) -> None:
        server = _make_server()
        policy = self._policy(max_critical=2)
        existing = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.CRITICAL),
        ]
        result = _make_scan_result(findings=existing)
        findings = evaluate_governance([server], policy, scan_result=result)
        gov = [f for f in findings if f.analyzer == "governance"]
        fp = [f for f in gov if "finding_policy" in f.evidence]
        assert not fp

    def test_over_limit_produces_finding(self) -> None:
        server = _make_server()
        policy = self._policy(max_critical=2)
        existing = [_make_finding(severity=Severity.CRITICAL) for _ in range(3)]
        result = _make_scan_result(findings=existing)
        findings = evaluate_governance([server], policy, scan_result=result)
        gov_fp = [
            f
            for f in findings
            if f.analyzer == "governance" and "finding_policy" in f.evidence
        ]
        assert len(gov_fp) == 1
        assert "3" in gov_fp[0].title
        assert "2" in gov_fp[0].title

    def test_none_limit_no_finding(self) -> None:
        server = _make_server()
        policy = self._policy(max_critical=None)
        existing = [_make_finding(severity=Severity.CRITICAL) for _ in range(100)]
        result = _make_scan_result(findings=existing)
        findings = evaluate_governance([server], policy, scan_result=result)
        gov_fp = [
            f
            for f in findings
            if f.analyzer == "governance" and "finding_policy" in f.evidence
        ]
        assert not gov_fp


# ── TestClientOverrides ───────────────────────────────────────────────────────


class TestClientOverrides:
    def test_override_approved_servers(self) -> None:
        # Base policy allows nothing; cursor override adds an extra server.
        cursor_server = _make_server(name="cursor-only-tool", client="cursor")
        vscode_server = _make_server(name="cursor-only-tool", client="vscode")

        policy = GovernancePolicy(
            approved_servers=ApprovedServers(
                mode=PolicyMode.ALLOWLIST,
                entries=[],
            ),
            client_overrides={
                "cursor": ClientOverride(
                    approved_servers=ApprovedServers(
                        mode=PolicyMode.ALLOWLIST,
                        entries=[ApprovedServerEntry(name="cursor-only-tool")],
                    )
                )
            },
        )
        findings = evaluate_governance([cursor_server, vscode_server], policy)
        # cursor-only-tool is approved for cursor but not vscode
        gov = [f for f in findings if f.analyzer == "governance"]
        clients_with_violation = {f.client for f in gov}
        assert "vscode" in clients_with_violation
        assert "cursor" not in clients_with_violation

    def test_override_transport_policy(self) -> None:
        # Base allows all; claude-desktop override blocks SSE.
        sse_server = _make_server(
            name="sse-server",
            client="claude-desktop",
            transport=TransportType.SSE,
            url="https://example.com/sse",
        )
        policy = GovernancePolicy(
            transport_policy=TransportPolicy(allow_sse=True),
            client_overrides={
                "claude-desktop": ClientOverride(
                    transport_policy=TransportPolicy(allow_sse=False)
                )
            },
        )
        findings = evaluate_governance([sse_server], policy)
        gov = [f for f in findings if f.analyzer == "governance"]
        assert any("sse" in f.title.lower() for f in gov)

    def test_override_does_not_affect_other_clients(self) -> None:
        # cursor override blocks SSE; vscode server with SSE is unaffected.
        vscode_sse = _make_server(
            name="sse-tool",
            client="vscode",
            transport=TransportType.SSE,
            url="https://example.com/sse",
        )
        policy = GovernancePolicy(
            transport_policy=TransportPolicy(allow_sse=True),
            client_overrides={
                "cursor": ClientOverride(
                    transport_policy=TransportPolicy(allow_sse=False)
                )
            },
        )
        findings = evaluate_governance([vscode_sse], policy)
        sse_violations = [
            f
            for f in findings
            if f.analyzer == "governance" and "sse" in f.title.lower()
        ]
        assert not sse_violations

    def test_unknown_client_key_uses_base_policy(self) -> None:
        # Server from a client with no override uses base policy.
        server = _make_server(name="some-server", client="augment")
        policy = GovernancePolicy(
            approved_servers=ApprovedServers(
                mode=PolicyMode.ALLOWLIST,
                entries=[],  # empty → everything a violation
            ),
            client_overrides={
                "cursor": ClientOverride(
                    approved_servers=ApprovedServers(
                        mode=PolicyMode.ALLOWLIST,
                        entries=[ApprovedServerEntry(name="some-server")],
                    )
                )
            },
        )
        findings = evaluate_governance([server], policy)
        gov = [
            f for f in findings if f.analyzer == "governance" and f.client == "augment"
        ]
        assert len(gov) == 1  # augment uses base policy → violation


# ── TestGovernanceCLI ─────────────────────────────────────────────────────────


class TestGovernanceCLI:
    def test_policy_validate_valid_file(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yml"
        _write_policy(policy_file, {"version": 1, "name": "test-policy"})
        result = runner.invoke(app, ["policy", "validate", str(policy_file)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_policy_validate_invalid_yaml(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("{ invalid: yaml: [", encoding="utf-8")
        result = runner.invoke(app, ["policy", "validate", str(bad_file)])
        assert result.exit_code == 2

    def test_policy_validate_missing_file(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.yml"
        result = runner.invoke(app, ["policy", "validate", str(missing)])
        assert result.exit_code == 2

    def test_policy_init_creates_file(self, tmp_path: Path) -> None:
        output_file = tmp_path / "new-policy.yml"
        with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
            result = runner.invoke(
                app, ["policy", "init", "--output", str(output_file)]
            )
        assert result.exit_code == 0
        assert output_file.exists()
        assert output_file.stat().st_size > 0

    def test_policy_init_refuses_to_overwrite(self, tmp_path: Path) -> None:
        existing = tmp_path / "existing.yml"
        existing.write_text("name: existing", encoding="utf-8")
        with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
            result = runner.invoke(app, ["policy", "init", "--output", str(existing)])
        assert result.exit_code == 2
        assert "already exists" in result.output.lower()

    def test_scan_with_policy_flag(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yml"
        _write_policy(
            policy_file,
            {
                "version": 1,
                "score_threshold": {"minimum": 0},  # always passes
            },
        )
        result = runner.invoke(
            app,
            ["scan", "--policy", str(policy_file), "--format", "json"],
        )
        # Tool runs without crashing; exit 0 (no findings) or exit 1 (findings
        # found). Exit 2 means a hard error.
        assert result.exit_code != 2

    def test_scan_auto_discovers_policy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy_file = tmp_path / POLICY_FILENAMES[0]
        _write_policy(
            policy_file,
            {"version": 1, "score_threshold": {"minimum": 0}},
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scan", "--format", "json"])
        assert result.exit_code != 2


# ── TestGovernanceFindingFormat ───────────────────────────────────────────────


class TestGovernanceFindingFormat:
    def test_finding_has_governance_analyzer_tag(self) -> None:
        server = _make_server(name="bad-server")
        policy = GovernancePolicy(
            approved_servers=ApprovedServers(mode=PolicyMode.ALLOWLIST, entries=[])
        )
        findings = evaluate_governance([server], policy)
        assert all(f.analyzer == "governance" for f in findings)

    def test_finding_id_is_deterministic(self) -> None:
        server = _make_server(name="bad-server", client="cursor")
        policy = GovernancePolicy(
            approved_servers=ApprovedServers(mode=PolicyMode.ALLOWLIST, entries=[])
        )
        findings1 = evaluate_governance([server], policy)
        findings2 = evaluate_governance([server], policy)
        assert len(findings1) == 1
        assert len(findings2) == 1
        assert findings1[0].id == findings2[0].id

    def test_message_template_substitution_server_name(self) -> None:
        server = _make_server(name="my-cool-server")
        policy = GovernancePolicy(
            approved_servers=ApprovedServers(
                mode=PolicyMode.ALLOWLIST,
                entries=[],
                message="Server {server_name} is not approved",
            )
        )
        findings = evaluate_governance([server], policy)
        assert len(findings) == 1
        assert "my-cool-server" in findings[0].description

    def test_message_template_substitution_score(self) -> None:
        server = _make_server()
        policy = GovernancePolicy(
            score_threshold=ScoreThreshold(
                minimum=90,
                message="Scored {score} ({grade}), need {minimum}",
            )
        )
        result = _make_scan_result(score=50, grade="F")
        findings = evaluate_governance([server], policy, scan_result=result)
        assert len(findings) == 1
        desc = findings[0].description
        assert "50" in desc
        assert "F" in desc
        assert "90" in desc
