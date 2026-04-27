"""Tests for the policy-as-code rule engine (mcp_audit.rules.engine)."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from mcp_audit.models import ServerConfig, Severity, TransportType
from mcp_audit.rules.engine import (
    CompoundOperator,
    MatchCondition,
    MatchField,
    MatchType,
    PolicyRule,
    RuleEngine,
    RuleMatch,
    load_bundled_community_rules,
    load_rules_from_dir,
    load_rules_from_file,
    merge_rules,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_server(
    name: str = "test-server",
    command: str | None = "node",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    url: str | None = None,
    transport: TransportType = TransportType.STDIO,
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client="test-client",
        config_path=Path("/tmp/test.json"),  # noqa: S108
        command=command,
        args=args or [],
        env=env or {},
        url=url,
        transport=transport,
    )


def _make_rule(
    rule_id: str = "TEST-001",
    field: MatchField = MatchField.COMMAND,
    pattern: str = "node",
    match_type: MatchType = MatchType.EXACT,
    negate: bool = False,
    severity: Severity = Severity.MEDIUM,
    enabled: bool = True,
    message: str = "Matched server '{server_name}': {matched_value}",
) -> PolicyRule:
    return PolicyRule(
        id=rule_id,
        name=f"Test rule {rule_id}",
        description="A test rule",
        severity=severity,
        category="test",
        match=RuleMatch(field=field, pattern=pattern, type=match_type, negate=negate),
        message=message,
        enabled=enabled,
    )


def _write_rule_yaml(path: Path, rule_dict: dict) -> None:
    path.write_text(yaml.dump(rule_dict), encoding="utf-8")


# ── load_rules_from_file ──────────────────────────────────────────────────────


class TestLoadRulesFromFile:
    def test_loads_single_rule(self, tmp_path: Path) -> None:
        rule_file = tmp_path / "rule.yml"
        _write_rule_yaml(
            rule_file,
            {
                "id": "SINGLE-001",
                "name": "Single rule",
                "description": "Test",
                "severity": "HIGH",
                "category": "test",
                "match": {"field": "command", "pattern": "evil", "type": "exact"},
                "message": "Found {server_name}",
            },
        )
        rules = load_rules_from_file(rule_file)
        assert len(rules) == 1
        assert rules[0].id == "SINGLE-001"
        assert rules[0].severity == Severity.HIGH

    def test_loads_multi_rule_yaml_with_rules_key(self, tmp_path: Path) -> None:
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text(
            yaml.dump(
                {
                    "rules": [
                        {
                            "id": "MULTI-001",
                            "name": "Multi rule 1",
                            "description": "Test",
                            "severity": "LOW",
                            "category": "test",
                            "match": {
                                "field": "command",
                                "pattern": "a",
                                "type": "exact",
                            },
                            "message": "msg",
                        },
                        {
                            "id": "MULTI-002",
                            "name": "Multi rule 2",
                            "description": "Test",
                            "severity": "HIGH",
                            "category": "test",
                            "match": {
                                "field": "command",
                                "pattern": "b",
                                "type": "exact",
                            },
                            "message": "msg",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        rules = load_rules_from_file(rule_file)
        assert len(rules) == 2
        assert {r.id for r in rules} == {"MULTI-001", "MULTI-002"}

    def test_skips_invalid_rules_does_not_crash(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        rule_file = tmp_path / "mixed.yml"
        rule_file.write_text(
            yaml.dump(
                {
                    "rules": [
                        {
                            "id": "VALID-001",
                            "name": "Valid",
                            "description": "OK",
                            "severity": "LOW",
                            "category": "test",
                            "match": {
                                "field": "command",
                                "pattern": "x",
                                "type": "exact",
                            },
                            "message": "msg",
                        },
                        {"id": "INVALID-001", "name": "Missing required fields"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        with caplog.at_level(logging.WARNING, logger="mcp_audit.rules.engine"):
            rules = load_rules_from_file(rule_file)

        assert len(rules) == 1
        assert rules[0].id == "VALID-001"
        assert any("INVALID-001" in msg for msg in caplog.messages)

    def test_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
        rules = load_rules_from_file(tmp_path / "nonexistent.yml")
        assert rules == []

    def test_returns_empty_for_bad_yaml(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text(":\n  :\n    :\nbroken: [unclosed", encoding="utf-8")
        rules = load_rules_from_file(bad_file)
        assert rules == []


# ── load_rules_from_dir ───────────────────────────────────────────────────────


class TestLoadRulesFromDir:
    def _make_rule_file(self, directory: Path, rule_id: str, name: str) -> None:
        (directory / f"{rule_id}.yml").write_text(
            yaml.dump(
                {
                    "id": rule_id,
                    "name": name,
                    "description": "Test",
                    "severity": "LOW",
                    "category": "test",
                    "match": {"field": "command", "pattern": "x", "type": "exact"},
                    "message": "msg",
                }
            ),
            encoding="utf-8",
        )

    def test_loads_all_yaml_files(self, tmp_path: Path) -> None:
        self._make_rule_file(tmp_path, "DIR-001", "Rule 1")
        self._make_rule_file(tmp_path, "DIR-002", "Rule 2")
        rules = load_rules_from_dir(tmp_path)
        assert len(rules) == 2
        assert {r.id for r in rules} == {"DIR-001", "DIR-002"}

    def test_loads_both_yml_and_yaml_extensions(self, tmp_path: Path) -> None:
        self._make_rule_file(tmp_path, "EXT-001", "YML rule")
        yaml_file = tmp_path / "EXT-002.yaml"
        yaml_file.write_text(
            yaml.dump(
                {
                    "id": "EXT-002",
                    "name": "YAML rule",
                    "description": "Test",
                    "severity": "LOW",
                    "category": "test",
                    "match": {"field": "command", "pattern": "x", "type": "exact"},
                    "message": "msg",
                }
            ),
            encoding="utf-8",
        )
        rules = load_rules_from_dir(tmp_path)
        assert {r.id for r in rules} == {"EXT-001", "EXT-002"}

    def test_deduplicates_by_id_keeps_first_alphabetical(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # A-rule.yml comes before B-rule.yml alphabetically
        (tmp_path / "A-rule.yml").write_text(
            yaml.dump(
                {
                    "id": "DUP-001",
                    "name": "First definition",
                    "description": "Test",
                    "severity": "HIGH",
                    "category": "test",
                    "match": {"field": "command", "pattern": "x", "type": "exact"},
                    "message": "msg",
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "B-rule.yml").write_text(
            yaml.dump(
                {
                    "id": "DUP-001",
                    "name": "Second definition",
                    "description": "Test",
                    "severity": "LOW",
                    "category": "test",
                    "match": {"field": "command", "pattern": "y", "type": "exact"},
                    "message": "msg",
                }
            ),
            encoding="utf-8",
        )
        with caplog.at_level(logging.WARNING, logger="mcp_audit.rules.engine"):
            rules = load_rules_from_dir(tmp_path)

        assert len(rules) == 1
        assert rules[0].name == "First definition"
        assert any("DUP-001" in msg for msg in caplog.messages)

    def test_returns_empty_for_missing_directory(self, tmp_path: Path) -> None:
        rules = load_rules_from_dir(tmp_path / "nonexistent")
        assert rules == []

    def test_non_recursive(self, tmp_path: Path) -> None:
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        self._make_rule_file(subdir, "SUB-001", "Subdir rule")
        self._make_rule_file(tmp_path, "TOP-001", "Top rule")
        rules = load_rules_from_dir(tmp_path)
        ids = {r.id for r in rules}
        assert "TOP-001" in ids
        assert "SUB-001" not in ids


# ── RuleEngine.match_server ───────────────────────────────────────────────────


class TestRuleEngineMatchServer:
    def test_exact_match_fires(self) -> None:
        rule = _make_rule(
            field=MatchField.COMMAND, pattern="nc", match_type=MatchType.EXACT
        )
        engine = RuleEngine([rule])
        server = _make_server(command="nc")
        findings = engine.match_server(server)
        assert len(findings) == 1
        assert findings[0].id == "TEST-001"
        assert findings[0].analyzer == "rules"

    def test_exact_match_no_fire_on_mismatch(self) -> None:
        rule = _make_rule(
            field=MatchField.COMMAND, pattern="nc", match_type=MatchType.EXACT
        )
        engine = RuleEngine([rule])
        server = _make_server(command="node")
        assert engine.match_server(server) == []

    def test_regex_match_fires(self) -> None:
        rule = _make_rule(
            field=MatchField.COMMAND,
            pattern="^(nc|socat)$",
            match_type=MatchType.REGEX,
        )
        engine = RuleEngine([rule])
        assert len(engine.match_server(_make_server(command="nc"))) == 1
        assert len(engine.match_server(_make_server(command="socat"))) == 1
        assert engine.match_server(_make_server(command="node")) == []

    def test_contains_match_fires(self) -> None:
        rule = _make_rule(
            field=MatchField.ARGS,
            pattern="--no-sandbox",
            match_type=MatchType.CONTAINS,
        )
        engine = RuleEngine([rule])
        server = _make_server(args=["--headless", "--no-sandbox"])
        assert len(engine.match_server(server)) == 1

    def test_glob_match_fires(self) -> None:
        rule = _make_rule(
            field=MatchField.COMMAND,
            pattern="py*",
            match_type=MatchType.GLOB,
        )
        engine = RuleEngine([rule])
        assert len(engine.match_server(_make_server(command="python3"))) == 1
        assert engine.match_server(_make_server(command="node")) == []

    def test_negate_inverts_match(self) -> None:
        # negate=True: fires when command is NOT "python"
        rule = _make_rule(
            field=MatchField.COMMAND,
            pattern="python",
            match_type=MatchType.EXACT,
            negate=True,
        )
        engine = RuleEngine([rule])
        # "node" != "python" → negation succeeds → finding produced
        assert len(engine.match_server(_make_server(command="node"))) == 1
        # "python" == "python" → match succeeds → negation inverts → no finding
        assert engine.match_server(_make_server(command="python")) == []

    def test_compound_and_both_must_match(self) -> None:
        rule = PolicyRule(
            id="COMP-AND",
            name="Compound AND",
            description="Test",
            severity=Severity.HIGH,
            category="test",
            match=RuleMatch(
                operator=CompoundOperator.AND,
                conditions=[
                    MatchCondition(
                        field=MatchField.COMMAND,
                        pattern="^python",
                        type=MatchType.REGEX,
                    ),
                    MatchCondition(
                        field=MatchField.ARGS,
                        pattern="--no-sandbox",
                        type=MatchType.CONTAINS,
                    ),
                ],
            ),
            message="Both matched: {server_name}",
        )
        engine = RuleEngine([rule])

        # Both match → finding
        server_both = _make_server(command="python3", args=["--no-sandbox"])
        assert len(engine.match_server(server_both)) == 1

        # Only one matches → no finding
        server_only_cmd = _make_server(command="python3", args=["--other"])
        assert engine.match_server(server_only_cmd) == []

        server_only_arg = _make_server(command="node", args=["--no-sandbox"])
        assert engine.match_server(server_only_arg) == []

    def test_compound_or_one_sufficient(self) -> None:
        rule = PolicyRule(
            id="COMP-OR",
            name="Compound OR",
            description="Test",
            severity=Severity.MEDIUM,
            category="test",
            match=RuleMatch(
                operator=CompoundOperator.OR,
                conditions=[
                    MatchCondition(
                        field=MatchField.COMMAND, pattern="nc", type=MatchType.EXACT
                    ),
                    MatchCondition(
                        field=MatchField.COMMAND, pattern="socat", type=MatchType.EXACT
                    ),
                ],
            ),
            message="OR matched: {server_name}",
        )
        engine = RuleEngine([rule])
        assert len(engine.match_server(_make_server(command="nc"))) == 1
        assert len(engine.match_server(_make_server(command="socat"))) == 1
        assert engine.match_server(_make_server(command="node")) == []

    def test_disabled_rule_produces_no_finding(self) -> None:
        rule = _make_rule(enabled=False, pattern="node")
        engine = RuleEngine([rule])
        assert engine.match_server(_make_server(command="node")) == []

    def test_invalid_regex_logs_warning_no_crash(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        rule = _make_rule(pattern="[unclosed", match_type=MatchType.REGEX)
        engine = RuleEngine([rule])
        with caplog.at_level(logging.WARNING, logger="mcp_audit.rules.engine"):
            findings = engine.match_server(_make_server(command="node"))
        assert findings == []
        assert any(
            "Invalid regex" in msg or "invalid regex" in msg.lower()
            for msg in caplog.messages
        )

    def test_matched_value_interpolated_in_description(self) -> None:
        rule = _make_rule(
            field=MatchField.COMMAND,
            pattern="^(nc|socat)$",
            match_type=MatchType.REGEX,
            message="Server '{server_name}' uses: {matched_value}",
        )
        engine = RuleEngine([rule])
        server = _make_server(name="my-server", command="nc")
        findings = engine.match_server(server)
        assert len(findings) == 1
        assert "my-server" in findings[0].description
        assert "nc" in findings[0].description

    def test_server_name_interpolated_in_description(self) -> None:
        rule = _make_rule(
            field=MatchField.COMMAND,
            pattern="node",
            match_type=MatchType.EXACT,
            message="Server '{server_name}' matched",
        )
        engine = RuleEngine([rule])
        server = _make_server(name="important-server", command="node")
        findings = engine.match_server(server)
        assert "important-server" in findings[0].description

    def test_rule_id_in_evidence(self) -> None:
        rule = _make_rule(rule_id="TRACEABLE-001")
        engine = RuleEngine([rule])
        server = _make_server(command="node")
        findings = engine.match_server(server)
        assert len(findings) == 1
        assert "TRACEABLE-001" in findings[0].evidence

    def test_env_field_matches_key_names_only(self) -> None:
        rule = _make_rule(
            field=MatchField.ENV,
            pattern="SSH_AUTH_SOCK",
            match_type=MatchType.CONTAINS,
        )
        engine = RuleEngine([rule])

        # Key present → should fire
        server_with_key = _make_server(env={"SSH_AUTH_SOCK": "/run/user/1000/ssh"})
        assert len(engine.match_server(server_with_key)) == 1

        # Only value contains the string, key does not → should NOT fire
        server_value_only = _make_server(env={"OTHER_VAR": "SSH_AUTH_SOCK_VALUE"})
        assert engine.match_server(server_value_only) == []

    def test_env_aws_key_names_only(self) -> None:
        rule = _make_rule(
            field=MatchField.ENV,
            pattern="AWS_SESSION_TOKEN",
            match_type=MatchType.CONTAINS,
        )
        engine = RuleEngine([rule])

        server_with_key = _make_server(env={"AWS_SESSION_TOKEN": "AQo..."})
        assert len(engine.match_server(server_with_key)) == 1

        server_value_only = _make_server(env={"SOME_VAR": "contains_AWS_SESSION_TOKEN"})
        assert engine.match_server(server_value_only) == []

    def test_url_field_skipped_when_none(self) -> None:
        rule = _make_rule(
            field=MatchField.URL,
            pattern="http://",
            match_type=MatchType.CONTAINS,
        )
        engine = RuleEngine([rule])
        server = _make_server(url=None)
        assert engine.match_server(server) == []

    def test_url_field_matches_when_set(self) -> None:
        rule = _make_rule(
            field=MatchField.URL,
            pattern="http://",
            match_type=MatchType.CONTAINS,
        )
        engine = RuleEngine([rule])
        server = _make_server(
            url="http://localhost:3000",
            command=None,
            transport=TransportType.STREAMABLE_HTTP,
        )
        assert len(engine.match_server(server)) == 1


# ── Community rules ────────────────────────────────────────────────────────────


class TestCommunityRules:
    def test_all_13_community_rules_load(self) -> None:
        rules = load_bundled_community_rules()
        assert len(rules) == 13, f"Expected 13 community rules, got {len(rules)}"

    def test_community_rule_ids_are_unique(self) -> None:
        rules = load_bundled_community_rules()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs in community rules"

    def test_comm_001_matches_netcat(self) -> None:
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        for cmd in ("nc", "ncat", "socat", "netcat"):
            server = _make_server(command=cmd)
            findings = engine.match_server(server)
            comm001 = [f for f in findings if f.id == "COMM-001"]
            assert comm001, f"COMM-001 should fire for command={cmd!r}"

    def test_comm_001_does_not_fire_for_node(self) -> None:
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(command="node")
        findings = [f for f in engine.match_server(server) if f.id == "COMM-001"]
        assert not findings

    def test_comm_008_ssh_fires_on_key_name(self) -> None:
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(env={"SSH_AUTH_SOCK": "/tmp/ssh.sock"})  # noqa: S108
        findings = [f for f in engine.match_server(server) if f.id == "COMM-008"]
        assert findings

    def test_comm_008_ssh_does_not_fire_on_value_only(self) -> None:
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(env={"MY_VAR": "contains_SSH_AUTH_SOCK_text"})
        findings = [f for f in engine.match_server(server) if f.id == "COMM-008"]
        assert not findings

    def test_comm_009_aws_fires_on_key_name(self) -> None:
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(env={"AWS_SESSION_TOKEN": "AQo..."})
        findings = [f for f in engine.match_server(server) if f.id == "COMM-009"]
        assert findings

    def test_comm_009_aws_does_not_fire_on_value_only(self) -> None:
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(env={"OTHER": "AWS_SESSION_TOKEN_VALUE"})
        findings = [f for f in engine.match_server(server) if f.id == "COMM-009"]
        assert not findings

    def test_all_community_rule_ids_present(self) -> None:
        rules = load_bundled_community_rules()
        expected_ids = {f"COMM-{i:03d}" for i in range(1, 14)}
        actual_ids = {r.id for r in rules}
        assert actual_ids == expected_ids

    def test_comm_004_declares_registry_exemption(self) -> None:
        """COMM-004 must opt into the registry exemption to avoid 100% FPR."""
        rules = {r.id: r for r in load_bundled_community_rules()}
        comm004 = rules["COMM-004"]
        assert comm004.exempt_known_servers is True, (
            "COMM-004 must set exempt_known_servers=True or it will fire on "
            "every legitimate stdio MCP server (signal-to-noise regression)."
        )

    def test_comm_004_does_not_fire_on_known_registry_server(self) -> None:
        """Registry-known stdio servers must not produce COMM-004 findings."""
        from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

        registry = load_registry()
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules, registry=registry)

        server = _make_server(
            name="filesystem",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],  # noqa: S108
            transport=TransportType.STDIO,
        )
        findings = [f for f in engine.match_server(server) if f.id == "COMM-004"]
        assert findings == [], (
            "COMM-004 must not fire for the official "
            "@modelcontextprotocol/server-filesystem package"
        )

    def test_comm_004_fires_on_unrecognized_stdio_server(self) -> None:
        """COMM-004 must still fire for unknown stdio binaries — the signal case."""
        from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

        registry = load_registry()
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules, registry=registry)

        server = _make_server(
            name="my-local-thing",
            command="node",
            args=["safe.js"],
            transport=TransportType.STDIO,
        )
        findings = [f for f in engine.match_server(server) if f.id == "COMM-004"]
        assert len(findings) == 1, (
            "COMM-004 must fire on unrecognized stdio servers — removing this "
            "signal would leave the rule pointless."
        )

    def test_comm_004_without_registry_falls_back_to_matching(self) -> None:
        """Without a registry the exemption short-circuits and every stdio hits."""
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules, registry=None)

        server = _make_server(
            name="filesystem",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
            transport=TransportType.STDIO,
        )
        findings = [f for f in engine.match_server(server) if f.id == "COMM-004"]
        assert len(findings) == 1, (
            "Without a registry COMM-004 must retain its historical "
            "match-everything behaviour (no silent exemption)."
        )

    def test_comm_013_fires_on_npx_with_yes_flag(self) -> None:
        """COMM-013 must fire when npx/bunx is called with --yes."""
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(command="npx", args=["--yes", "@some/package"])
        findings = [f for f in engine.match_server(server) if f.id == "COMM-013"]
        assert findings, "COMM-013 should fire for npx --yes"
        assert findings[0].severity == Severity.HIGH

    def test_comm_013_fires_on_bunx_with_short_flag(self) -> None:
        """COMM-013 must fire for bunx with -y."""
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(command="bunx", args=["-y", "@some/pkg"])
        findings = [f for f in engine.match_server(server) if f.id == "COMM-013"]
        assert findings, "COMM-013 should fire for bunx -y"

    def test_comm_013_does_not_fire_without_auto_confirm(self) -> None:
        """COMM-013 must not fire when --yes/-y is absent."""
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(command="npx", args=["@some/package"])
        findings = [f for f in engine.match_server(server) if f.id == "COMM-013"]
        assert not findings

    def test_comm_013_carries_ox_cve_list(self) -> None:
        """COMM-013 finding must include all six OX CVE identifiers."""
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(command="npx", args=["--yes", "@some/package"])
        findings = [f for f in engine.match_server(server) if f.id == "COMM-013"]
        assert findings
        expected_cves = {
            "CVE-2025-49596",
            "CVE-2026-22252",
            "CVE-2026-22688",
            "CVE-2025-54994",
            "CVE-2025-54136",
            "CVE-2026-30615",
        }
        assert set(findings[0].cve) == expected_cves

    def test_comm_012_carries_mcpwn_cve(self) -> None:
        """COMM-012 finding must reference CVE-2026-33032 (MCPwn)."""
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(
            command="python",
            args=["server.py", "--host", "0.0.0.0"],  # noqa: S104
        )
        findings = [f for f in engine.match_server(server) if f.id == "COMM-012"]
        assert findings
        assert "CVE-2026-33032" in findings[0].cve

    def test_comm_010_carries_ox_cve(self) -> None:
        """COMM-010 finding must reference CVE-2025-49596."""
        rules = load_bundled_community_rules()
        engine = RuleEngine(rules)
        server = _make_server(command="npx", args=["@some/package"])
        findings = [f for f in engine.match_server(server) if f.id == "COMM-010"]
        assert findings
        assert "CVE-2025-49596" in findings[0].cve


class TestCveField:
    """Tests for the `cve` field on Finding and PolicyRule models."""

    def test_finding_default_cve_is_empty_list(self) -> None:
        """Finding.cve defaults to an empty list when not supplied."""
        from mcp_audit.models import Finding, Severity  # noqa: PLC0415

        f = Finding(
            id="X-001",
            severity=Severity.LOW,
            analyzer="test",
            client="c",
            server="s",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
        )
        assert f.cve == []

    def test_finding_cve_roundtrips_through_json(self) -> None:
        """Finding with cve list serialises and deserialises correctly."""
        from mcp_audit.models import Finding, Severity  # noqa: PLC0415

        cves = ["CVE-2026-33032", "CVE-2025-49596"]
        f = Finding(
            id="X-001",
            severity=Severity.HIGH,
            analyzer="test",
            client="c",
            server="s",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
            cve=cves,
        )
        serialised = f.model_dump()
        assert serialised["cve"] == cves
        restored = Finding.model_validate(serialised)
        assert restored.cve == cves

    def test_policy_rule_cve_propagated_to_finding(self, tmp_path: Path) -> None:
        """A rule YAML with cve: list must produce a Finding with that CVE list."""
        rule_yaml = tmp_path / "cve_rule.yml"
        rule_yaml.write_text(
            (
                "id: CVE-TEST-001\n"
                "name: CVE test rule\n"
                "description: Test CVE propagation\n"
                "severity: HIGH\n"
                "category: test\n"
                "match:\n"
                "  field: command\n"
                "  pattern: badcmd\n"
                "  type: exact\n"
                "message: '{server_name}'\n"
                "cve:\n"
                "  - CVE-2026-33032\n"
                "  - CVE-2025-49596\n"
            ),
            encoding="utf-8",
        )
        rules = load_rules_from_file(rule_yaml)
        assert len(rules) == 1
        assert rules[0].cve == ["CVE-2026-33032", "CVE-2025-49596"]

        engine = RuleEngine(rules)
        server = _make_server(command="badcmd")
        findings = engine.match_server(server)
        assert len(findings) == 1
        assert findings[0].cve == ["CVE-2026-33032", "CVE-2025-49596"]

    def test_policy_rule_without_cve_field_defaults_to_empty(
        self, tmp_path: Path
    ) -> None:
        """A rule YAML without a cve: field must produce a Finding with cve=[]."""
        rule_yaml = tmp_path / "no_cve_rule.yml"
        rule_yaml.write_text(
            (
                "id: NO-CVE-001\n"
                "name: No CVE rule\n"
                "description: No CVE\n"
                "severity: LOW\n"
                "category: test\n"
                "match:\n"
                "  field: command\n"
                "  pattern: node\n"
                "  type: exact\n"
                "message: '{server_name}'\n"
            ),
            encoding="utf-8",
        )
        rules = load_rules_from_file(rule_yaml)
        assert rules[0].cve == []
        engine = RuleEngine(rules)
        findings = engine.match_server(_make_server(command="node"))
        assert findings[0].cve == []


class TestExemptKnownServersPrimitive:
    """`exempt_known_servers: true` is a reusable rule-engine primitive."""

    def test_custom_rule_respects_exemption(self) -> None:
        from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

        rule = PolicyRule(
            id="TEST-EXEMPT-001",
            name="Exempt me",
            description="Rule that should skip known servers",
            severity=Severity.LOW,
            category="test",
            match=RuleMatch(
                field=MatchField.COMMAND,
                pattern="npx",
                type=MatchType.EXACT,
            ),
            message="Matched {server_name}",
            exempt_known_servers=True,
        )
        registry = load_registry()
        engine = RuleEngine([rule], registry=registry)

        # Known package → exempt.
        known = _make_server(
            name="filesystem",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
        )
        assert engine.match_server(known) == []

        # Unknown package → fires.
        unknown = _make_server(
            name="mystery",
            command="npx",
            args=["-y", "@random-user/mystery-package"],
        )
        findings = engine.match_server(unknown)
        assert len(findings) == 1
        assert findings[0].id == "TEST-EXEMPT-001"

    def test_exemption_off_by_default(self) -> None:
        """Rules without exempt_known_servers must not silently skip anything."""
        from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

        rule = _make_rule(
            field=MatchField.COMMAND,
            pattern="npx",
            match_type=MatchType.EXACT,
        )
        assert rule.exempt_known_servers is False

        registry = load_registry()
        engine = RuleEngine([rule], registry=registry)
        server = _make_server(
            name="filesystem",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
        )
        assert len(engine.match_server(server)) == 1


# ── Integration: community rules in scan pipeline ─────────────────────────────


class TestScanPipelineIntegration:
    def test_comm_001_appears_in_scan_output(self, tmp_path: Path) -> None:
        """Community rules run for all users without a license."""
        import json  # noqa: PLC0415

        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        config_file = tmp_path / "mcp.json"
        config_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "netcat-server": {
                            "command": "nc",
                            "args": ["-l", "4444"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = run_scan(
                extra_paths=[config_file],
                skip_rug_pull=True,
            )

        rule_findings = [f for f in result.findings if f.analyzer == "rules"]
        comm001 = [f for f in rule_findings if f.id == "COMM-001"]
        assert comm001, "COMM-001 should fire for 'nc' command even without a license"

    def test_scan_of_only_registry_servers_produces_no_comm_004(
        self, tmp_path: Path
    ) -> None:
        """A config populated only with registry-known servers must not raise COMM-004.

        The rule engine receives the scan's shared registry via scanner.py,
        so this is the end-to-end proof that official MCP servers don't
        trigger COMM-004 (the signal-to-noise regression that justified
        the rescope).
        """
        import json  # noqa: PLC0415

        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        config_file = tmp_path / "mcp.json"
        config_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "filesystem": {
                            "command": "npx",
                            "args": [
                                "-y",
                                "@modelcontextprotocol/server-filesystem",
                                "/tmp",  # noqa: S108
                            ],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = run_scan(extra_paths=[config_file], skip_rug_pull=True)

        comm004 = [f for f in result.findings if f.id == "COMM-004"]
        assert comm004 == [], (
            "COMM-004 must not fire for registry-known servers in a full scan"
        )

    def test_rules_run_unconditionally(self, tmp_path: Path) -> None:
        """Community rules must run for every scan (no gating)."""
        import json  # noqa: PLC0415

        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        config_file = tmp_path / "mcp.json"
        config_file.write_text(
            json.dumps(
                {"mcpServers": {"curl-server": {"command": "curl", "args": []}}}
            ),
            encoding="utf-8",
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = run_scan(
                extra_paths=[config_file],
                skip_rug_pull=True,
            )

        rule_findings = [f for f in result.findings if f.analyzer == "rules"]
        assert rule_findings, "Rule findings should always appear on matching configs"


# ── merge_rules ────────────────────────────────────────────────────────────────


class TestMergeRules:
    def test_primary_takes_precedence_on_id_conflict(self) -> None:
        primary = [_make_rule(rule_id="SHARED-001", pattern="primary")]
        secondary = [_make_rule(rule_id="SHARED-001", pattern="secondary")]
        merged = merge_rules(primary, secondary)
        assert len(merged) == 1
        assert merged[0].match.pattern == "primary"

    def test_non_conflicting_rules_combined(self) -> None:
        primary = [_make_rule(rule_id="P-001")]
        secondary = [_make_rule(rule_id="S-001")]
        merged = merge_rules(primary, secondary)
        assert len(merged) == 2


# ── CLI commands ──────────────────────────────────────────────────────────────


class TestRuleValidateCLI:
    def test_valid_file_exits_0(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        rule_file = tmp_path / "rule.yml"
        _write_rule_yaml(
            rule_file,
            {
                "id": "CLI-001",
                "name": "CLI test rule",
                "description": "Test",
                "severity": "LOW",
                "category": "test",
                "match": {"field": "command", "pattern": "x", "type": "exact"},
                "message": "msg",
            },
        )

        runner = CliRunner()
        result = runner.invoke(app, ["rule", "validate", str(rule_file)])

        assert result.exit_code == 0
        assert "Valid" in result.output

    def test_invalid_file_exits_1(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        rule_file = tmp_path / "bad_rule.yml"
        rule_file.write_text("id: BAD\nname: broken\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(app, ["rule", "validate", str(rule_file)])

        assert result.exit_code == 1


class TestRuleTestCLI:
    def test_shows_all_rules_x_servers_table(self, tmp_path: Path) -> None:
        import json  # noqa: PLC0415

        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        rule_file = tmp_path / "rule.yml"
        _write_rule_yaml(
            rule_file,
            {
                "id": "RT-001",
                "name": "Test exact",
                "description": "Test",
                "severity": "LOW",
                "category": "test",
                "match": {"field": "command", "pattern": "nc", "type": "exact"},
                "message": "Matched {server_name}",
            },
        )

        config_file = tmp_path / "mcp.json"
        config_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "server-a": {"command": "nc", "args": []},
                        "server-b": {"command": "node", "args": []},
                    }
                }
            ),
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["rule", "test", str(rule_file), "--against", str(config_file)],
        )

        assert result.exit_code == 0
        assert "server-a" in result.output
        assert "server-b" in result.output
        assert "RT-001" in result.output


class TestRuleListCLI:
    def test_shows_bundled_rules(self) -> None:
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        runner = CliRunner()
        result = runner.invoke(app, ["rule", "list"])

        assert result.exit_code == 0
        assert "COMM-001" in result.output
        assert "12" in result.output or "bundled" in result.output


class TestRulesDirOptIn:
    """``extra_rules_dirs`` must be explicitly supplied for custom rules to load.

    Historically this was enforced by a Pro gate in the CLI.  Gating is gone,
    but the scanner API contract is unchanged: passing ``extra_rules_dirs=None``
    yields community rules only.
    """

    def test_rules_dir_findings_absent_when_not_passed(self, tmp_path: Path) -> None:
        import json  # noqa: PLC0415

        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "CUSTOM-001.yml").write_text(
            yaml.dump(
                {
                    "id": "CUSTOM-001",
                    "name": "Custom rule",
                    "description": "Should not appear when not explicitly loaded",
                    "severity": "HIGH",
                    "category": "test",
                    "match": {"field": "command", "pattern": "node", "type": "exact"},
                    "message": "Custom fired for {server_name}",
                }
            ),
            encoding="utf-8",
        )

        config_file = tmp_path / "mcp.json"
        config_file.write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": []}}}),
            encoding="utf-8",
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = run_scan(
                extra_paths=[config_file],
                skip_rug_pull=True,
                extra_rules_dirs=None,
            )

        custom_findings = [f for f in result.findings if f.id == "CUSTOM-001"]
        assert not custom_findings, (
            "Custom rules must not appear when extra_rules_dirs is None"
        )


# ── Missing-file error handling ───────────────────────────────────────────────


class TestRuleValidateMissingFile:
    """``rule validate`` / ``rule test`` must exit 2 with a clear message when
    the supplied file does not exist (regression from an earlier revision where
    a gate ran before the existence check and masked the real error)."""

    def test_rule_validate_nonexistent_path_exits_2(self, tmp_path: Path) -> None:
        """rule validate /no/such/file.yml must exit 2 with 'not found'."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        missing = tmp_path / "does-not-exist-rule.yml"
        runner = CliRunner()
        result = runner.invoke(app, ["rule", "validate", str(missing)])

        assert result.exit_code == 2, (
            f"Expected exit 2 (file not found), got {result.exit_code}. "
            f"Output: {result.output!r}"
        )
        assert "not found" in result.output.lower(), (
            f"Expected 'not found' in output, got: {result.output!r}"
        )

    def test_rule_test_nonexistent_rule_file_exits_2(self, tmp_path: Path) -> None:
        """rule test /no/rule.yml --against config.json must exit 2 for missing rule."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        missing_rule = tmp_path / "no-such-rule.yml"

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["rule", "test", str(missing_rule), "--against", str(config)],
        )

        assert result.exit_code == 2, (
            f"Expected exit 2 (rule file not found), got {result.exit_code}. "
            f"Output: {result.output!r}"
        )
