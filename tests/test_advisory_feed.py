"""Tests for advisory construction and feed materialisation."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from mcp_audit.advisory.classify import (
    CVSS_BY_CLASS,
    CVSS_BY_SEVERITY,
    NON_ADVISORY_IDS,
    cvss_base_score,
    cvss_for,
    finding_class_for,
    is_advisable,
    observation_for,
)
from mcp_audit.advisory.feed import (
    FEED_VERSION,
    PackageRef,
    build_advisories,
    build_advisory,
    load_feed,
    normalize_location,
    redact,
    resolve_package,
    write_feed,
)
from mcp_audit.advisory.schema import OBSERVATION_DEPLOYMENT, OBSERVATION_PACKAGE
from mcp_audit.advisory.validate import validate_osv
from mcp_audit.models import (
    Finding,
    ScanResult,
    ServerConfig,
    Severity,
    TransportType,
)

FIXED_NOW = "2026-07-30T12:00:00Z"


def _server(
    name: str = "github",
    command: str = "npx",
    args: list[str] | None = None,
    client: str = "claude-desktop",
    transport: TransportType = TransportType.STDIO,
    config_path: Path = Path("/fake/mcp.json"),
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path,
        command=command,
        args=args if args is not None else ["-y", "@example/mcp-github@1.4.2"],
        transport=transport,
    )


def _finding(
    finding_id: str = "CRED-001",
    severity: Severity = Severity.HIGH,
    server: str = "github",
    client: str = "claude-desktop",
    **overrides,
) -> Finding:
    kwargs = {
        "id": finding_id,
        "severity": severity,
        "analyzer": "credentials",
        "client": client,
        "server": server,
        "title": "GitHub credential in environment",
        "description": "GitHub Token found in env var 'GITHUB_TOKEN'",
        "evidence": "env.GITHUB_TOKEN matches GitHub Token pattern",
        "remediation": "Use a credential manager or vault.",
        "cwe": "CWE-798",
        "owasp_mcp_top_10": ["MCP01"],
    }
    kwargs.update(overrides)
    return Finding(**kwargs)


# ── Package resolution ────────────────────────────────────────────────────────


class TestResolvePackage:
    @pytest.mark.parametrize("command", ["npx", "bunx", "pnpx"])
    def test_npm_runners(self, command: str) -> None:
        ref = resolve_package(_server(command=command))
        assert ref == PackageRef("npm", "@example/mcp-github", "1.4.2")

    def test_yarn_dlx(self) -> None:
        ref = resolve_package(
            _server(command="yarn", args=["dlx", "@example/mcp-github@1.4.2"])
        )
        assert ref == PackageRef("npm", "@example/mcp-github", "1.4.2")

    def test_unscoped_npm_package(self) -> None:
        ref = resolve_package(_server(args=["-y", "mcp-remote@0.1.29"]))
        assert ref == PackageRef("npm", "mcp-remote", "0.1.29")

    def test_unpinned_package_has_no_version(self) -> None:
        ref = resolve_package(_server(args=["-y", "@example/mcp-github"]))
        assert ref == PackageRef("npm", "@example/mcp-github", None)

    def test_pypi_runner_normalizes_the_name(self) -> None:
        ref = resolve_package(
            _server(command="uvx", args=["MCP_Server_Git@0.6.2"]),
        )
        assert ref == PackageRef("PyPI", "mcp-server-git", "0.6.2")

    def test_absolute_path_to_a_runner_still_resolves(self) -> None:
        ref = resolve_package(_server(command="/usr/local/bin/npx"))
        assert ref == PackageRef("npm", "@example/mcp-github", "1.4.2")

    @pytest.mark.parametrize(
        "server",
        [
            _server(command="node", args=["./local-server.js"]),
            _server(command="python", args=["server.py"]),
            _server(command="docker", args=["run", "example/mcp"]),
            _server(command=""),
        ],
    )
    def test_servers_without_a_published_package_resolve_to_none(
        self, server: ServerConfig
    ) -> None:
        """OSV records are keyed by package; there is nothing honest to key these on."""
        assert resolve_package(server) is None


# ── Classification ────────────────────────────────────────────────────────────


class TestClassification:
    @pytest.mark.parametrize(
        ("finding_id", "expected"),
        [
            ("CRED-001", "hardcoded-secret"),
            ("CRED-002", "hardcoded-secret"),
            ("COMM-015", "command-injection"),
            ("COMM-034", "excessive-scope"),
            ("TRANSPORT-002", "excessive-scope"),
            ("POISON-001", "tool-poisoning"),
            ("SC-001", "typosquat"),
            ("SC-004", "known-vulnerability"),
            ("AUTH-001", "missing-authentication"),
            ("TOXIC-003", "toxic-flow"),
            ("HOOK-001", "hook-execution"),
            ("SAST-ABC123DEF456", "source-vulnerability"),
        ],
    )
    def test_known_ids_map_to_their_class(self, finding_id: str, expected: str) -> None:
        assert finding_class_for(finding_id) == expected

    def test_exact_id_beats_prefix(self) -> None:
        """CFHYG-003 is a plaintext secret; its siblings are file-permission issues."""
        assert finding_class_for("CFHYG-003") == "hardcoded-secret"
        assert finding_class_for("CFHYG-001") == "config-hygiene"

    def test_unknown_id_falls_back_rather_than_raising(self) -> None:
        """A new detection rule must never crash advisory generation."""
        assert finding_class_for("BRANDNEW-999") == "unclassified"

    @pytest.mark.parametrize(
        ("finding_id", "expected"),
        [
            ("POISON-001", OBSERVATION_PACKAGE),
            ("SC-001", OBSERVATION_PACKAGE),
            ("ATTEST-012", OBSERVATION_PACKAGE),
            ("CRED-001", OBSERVATION_DEPLOYMENT),
            ("TRANSPORT-001", OBSERVATION_DEPLOYMENT),
            ("GOV-abc12345", OBSERVATION_DEPLOYMENT),
        ],
    )
    def test_observation_separates_package_defects_from_misconfiguration(
        self, finding_id: str, expected: str
    ) -> None:
        assert observation_for(finding_id) == expected

    def test_unknown_id_is_treated_as_deployment(self) -> None:
        """Conservative default: never assert a defect in someone else's package."""
        assert observation_for("BRANDNEW-999") == OBSERVATION_DEPLOYMENT

    def test_class_template_wins_when_it_agrees_with_the_severity(self) -> None:
        vector, basis = cvss_for("hardcoded-secret", Severity.CRITICAL)
        assert basis == "finding-class-template"
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"

    def test_unmapped_class_falls_back_to_the_severity_band(self) -> None:
        vector, basis = cvss_for("unclassified", Severity.CRITICAL)
        assert basis == "severity-band"
        assert vector == CVSS_BY_SEVERITY[Severity.CRITICAL]

    @pytest.mark.parametrize("severity", list(Severity))
    def test_every_severity_has_a_vector(self, severity: Severity) -> None:
        vector, _ = cvss_for("unclassified", severity)
        assert vector.startswith("CVSS:3.1/")


class TestCvssScoring:
    """CVSS 3.1 base scoring, and the guard that stops advisories over-claiming."""

    # Vectors and scores published by NVD / the CVSS 3.1 specification examples.
    @pytest.mark.parametrize(
        ("vector", "expected"),
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
            ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_matches_published_scores(self, vector: str, expected: float) -> None:
        assert cvss_base_score(vector) == pytest.approx(expected)

    @pytest.mark.parametrize("vector", ["", "CVSS:3.0/AV:N", "not-a-vector"])
    def test_rejects_vectors_it_cannot_score(self, vector: str) -> None:
        with pytest.raises(ValueError):
            cvss_base_score(vector)

    def test_rejects_a_vector_missing_a_base_metric(self) -> None:
        with pytest.raises(ValueError, match="missing"):
            cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_inflated_class_template_is_discarded(self) -> None:
        """A LOW finding must never publish a High CVSS score.

        `unpinned-dependency` has a class template scoring 8.3, but COMM-010 fires at
        LOW. Publishing 8.3 would make the feed less trustworthy than no feed.
        """
        assert cvss_base_score(CVSS_BY_CLASS["unpinned-dependency"]) > 7.0
        vector, basis = cvss_for("unpinned-dependency", Severity.LOW)
        assert basis == "severity-band"
        assert cvss_base_score(vector) < 4.0

    @pytest.mark.parametrize("finding_class", sorted(CVSS_BY_CLASS))
    @pytest.mark.parametrize("severity", list(Severity))
    def test_published_score_never_exceeds_its_severity_band(
        self, finding_class: str, severity: Severity
    ) -> None:
        """The invariant the whole reconciliation exists to hold."""
        ceilings = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.9,
            Severity.MEDIUM: 6.9,
            Severity.LOW: 3.9,
            Severity.INFO: 0.0,
        }
        vector, _ = cvss_for(finding_class, severity)
        assert cvss_base_score(vector) <= ceilings[severity]

    @pytest.mark.parametrize("finding_id", sorted(NON_ADVISORY_IDS))
    def test_informational_findings_are_not_advisable(self, finding_id: str) -> None:
        assert not is_advisable(finding_id)

    def test_real_findings_are_advisable(self) -> None:
        assert is_advisable("CRED-001")

    def test_removed_server_drift_is_not_advisable(self) -> None:
        """Regression: DRIFT-* ids can't sit in the static NON_ADVISORY_IDS set.

        `_drift_to_findings` mints a content-derived id per event (see its
        docstring), so a removed server is recognised by its stable prefix rather
        than an exact id — it is the drift-pipeline equivalent of RUGPULL-003
        (benign bookkeeping, not a vulnerability).
        """
        assert not is_advisable("DRIFT-SERVER_REMOVED-a1b2c3d4e5f6")

    def test_other_drift_types_remain_advisable(self) -> None:
        """Only SERVER_REMOVED is benign; a changed command is a real signal."""
        assert is_advisable("DRIFT-COMMAND_CHANGED-a1b2c3d4e5f6")


# ── Redaction ─────────────────────────────────────────────────────────────────


class TestRedaction:
    def test_a_leaked_token_never_reaches_an_advisory(self) -> None:
        """An advisory is published; a secret that reaches it cannot be un-published."""
        text = "found ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 in config"
        assert "ghp_" not in redact(text)
        assert "[REDACTED]" in redact(text)

    def test_aws_keys_are_redacted(self) -> None:
        assert "AKIA" not in redact("key AKIAIOSFODNN7EXAMPLE here")

    def test_benign_text_is_untouched(self) -> None:
        assert redact("Use a credential manager.") == "Use a credential manager."

    def test_redaction_applies_to_generated_advisories(self) -> None:
        finding = _finding(
            evidence="value was ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        )
        advisory = build_advisory(finding, _server(), now=FIXED_NOW)
        assert "ghp_" not in advisory.details


# ── Local path redaction ──────────────────────────────────────────────────────


class TestLocalPathRedaction:
    """CFHYG-001/002/005 (config_hygiene.py) embed the real, absolute scanned path
    in evidence/remediation text — correct for `scan` output, but an advisory
    copies that text verbatim into a document published to the world. This is the
    RFC 8785 float bug's failure mode wearing different clothes: the same finding
    canonicalizes to different bytes depending on where the scanning host's
    checkout happens to live, on top of leaking the operator's home-directory
    username. See ``feed.py::_redact_local_paths``.
    """

    def test_absolute_config_path_becomes_cwd_relative(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cwd under $HOME (the case every documented mcp-audit invocation
        produces — running from inside a checkout or project directory under the
        operator's home) uses cwd-relative, so two same-named config files in
        different directories stay distinguishable rather than collapsing to a
        bare filename.
        """
        home = tmp_path / "home"
        cwd = home / "checkout"
        cwd.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.chdir(cwd)
        config_path = cwd / "project" / "mcp.json"
        config_path.parent.mkdir(parents=True)

        finding = _finding(
            id="CFHYG-001",
            evidence="Config file permissions: 0o100644",
            remediation=f"Run: chmod 600 {config_path}",
        )
        server = _server(config_path=config_path)
        advisory = build_advisory(finding, server, now=FIXED_NOW)

        assert str(config_path) not in advisory.details
        assert "project/mcp.json" in advisory.details

    def test_home_directory_itself_becomes_tilde(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.chdir(tmp_path)
        config_path = home / "mcp.json"

        finding = _finding(
            id="CFHYG-002",
            evidence=f"Parent directory {home} is world-writable",
            remediation=f"Move the config file to {home}",
        )
        server = _server(config_path=config_path)
        advisory = build_advisory(finding, server, now=FIXED_NOW)

        assert str(home) not in advisory.details
        assert "~" in advisory.details

    def test_no_username_leaks_when_cwd_is_a_sibling_of_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The realistic case: cwd is some project directory, home is elsewhere.

        ``os.path.relpath`` only ever emits ``..`` segments to climb from cwd up to
        the shared ancestor, never the ancestor's own name — this covers every
        topology mcp-audit's own CLI invocation actually produces (run from inside
        a checkout, never from ``/`` or ``/Users`` — see the docstring on
        ``_redact_local_paths`` for the one topology this does not cover).
        """
        home = tmp_path / "users" / "someusername"
        home.mkdir(parents=True)
        cwd = tmp_path / "checkouts" / "mcp-audit"
        cwd.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.chdir(cwd)
        config_path = home / "Library" / "mcp.json"
        config_path.parent.mkdir(parents=True)

        finding = _finding(
            id="CFHYG-001",
            remediation=f"Run: chmod 600 {config_path}",
        )
        server = _server(config_path=config_path)
        advisory = build_advisory(finding, server, now=FIXED_NOW)

        assert "someusername" not in advisory.details
        assert "~" in advisory.details

    def test_climbing_never_reaches_the_filesystem_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: a config file outside $HOME must not make "/" a redaction
        key. "/" is one character — replacing it globally would mangle every
        unrelated path separator in the rest of the advisory text (e.g. inside an
        npm scoped package name like "@modelcontextprotocol/server-filesystem").
        """
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
        monkeypatch.chdir(tmp_path)
        config_path = Path("/etc/mcp/config.json")

        finding = _finding(
            id="CFHYG-001",
            evidence="Command: npx -y @modelcontextprotocol/server-filesystem",
            remediation=f"Run: chmod 600 {config_path}",
        )
        server = _server(config_path=config_path)
        advisory = build_advisory(finding, server, now=FIXED_NOW)

        assert "@modelcontextprotocol/server-filesystem" in advisory.details

    def test_content_unrelated_to_the_config_path_is_untouched(self) -> None:
        """A path embedded in *scanned config content* (not the scan path itself)
        must survive — it is fixture/deployment data, not a machine artifact.
        """
        finding = _finding(
            id="TRANSPORT-003",
            evidence=(
                "Command: npx -y @modelcontextprotocol/server-filesystem /Users/shared"
            ),
        )
        advisory = build_advisory(finding, _server(), now=FIXED_NOW)
        assert "/Users/shared" in advisory.details

    def test_path_redaction_does_not_change_the_advisory_id(self) -> None:
        """Regression: redacting evidence/remediation text must never perturb
        ``stable_id()``. It doesn't today because ``location`` is derived solely
        from ``finding.tool`` (see ``normalize_location``'s docstring), which
        ``config_hygiene.py`` never sets — so this pins that invariant rather than
        relying on it being true by accident.
        """
        leaky = _finding(
            id="CFHYG-001",
            remediation="Run: chmod 600 /Users/someone/project/mcp.json",
        )
        clean = _finding(id="CFHYG-001", remediation="Run: chmod 600 mcp.json")
        server = _server(config_path=Path("/Users/someone/project/mcp.json"))

        leaky_advisory = build_advisory(leaky, server, now=FIXED_NOW)
        clean_advisory = build_advisory(clean, server, now=FIXED_NOW)

        assert leaky_advisory.id == clean_advisory.id
        assert "/Users/someone" not in leaky_advisory.details


# ── build_advisory ────────────────────────────────────────────────────────────


class TestBuildAdvisory:
    def test_maps_a_finding_onto_its_package(self) -> None:
        advisory = build_advisory(_finding(), _server(), now=FIXED_NOW)
        assert advisory.package.ecosystem == "npm"
        assert advisory.package.name == "@example/mcp-github"
        assert advisory.introduced == "1.4.2"
        assert advisory.mcp_audit_rule_id == "CRED-001"
        assert advisory.finding_class == "hardcoded-secret"
        assert advisory.mcp_transport == "stdio"

    def test_returns_none_without_a_package(self) -> None:
        server = _server(command="node", args=["./server.js"])
        assert build_advisory(_finding(), server, now=FIXED_NOW) is None

    def test_owasp_codes_come_from_the_finding(self) -> None:
        finding = _finding(finding_id="POISON-001", owasp_mcp_top_10=["MCP03", "MCP01"])
        advisory = build_advisory(finding, _server(), now=FIXED_NOW)
        assert advisory.owasp_mcp == ["MCP03", "MCP01"]

    def test_unmapped_finding_yields_empty_codes(self) -> None:
        finding = _finding(finding_id="RUGPULL-001", owasp_mcp_top_10=[])
        advisory = build_advisory(finding, _server(), now=FIXED_NOW)
        assert advisory.owasp_mcp == []

    def test_cwe_and_cve_are_carried_through(self) -> None:
        finding = _finding(cve=["CVE-2026-12345"])
        advisory = build_advisory(finding, _server(), now=FIXED_NOW)
        assert advisory.cwe_ids == ["CWE-798"]
        assert advisory.aliases == ["CVE-2026-12345"]

    def test_cve_mentioned_in_prose_becomes_an_alias(self) -> None:
        finding = _finding(description="Tracked as CVE-2026-30615 upstream.")
        advisory = build_advisory(finding, _server(), now=FIXED_NOW)
        assert "CVE-2026-30615" in advisory.aliases
        urls = [ref.url for ref in advisory.references]
        assert "https://nvd.nist.gov/vuln/detail/CVE-2026-30615" in urls

    def test_details_include_evidence_remediation_and_provenance(self) -> None:
        advisory = build_advisory(_finding(), _server(), now=FIXED_NOW)
        assert "Evidence:" in advisory.details
        assert "Remediation:" in advisory.details
        assert "CRED-001" in advisory.details

    def test_unknown_transport_is_null_not_guessed(self) -> None:
        server = _server(transport=TransportType.UNKNOWN)
        assert build_advisory(_finding(), server, now=FIXED_NOW).mcp_transport is None

    def test_location_uses_the_tool_name(self) -> None:
        finding = _finding(tool="run_query")
        assert build_advisory(finding, _server(), now=FIXED_NOW).location == "run_query"

    def test_location_never_contains_a_filesystem_path(self) -> None:
        """IDs must be identical on every host; mcp-audit is also privacy-first."""
        assert normalize_location(_finding()) == ""
        advisory = build_advisory(_finding(), _server(), now=FIXED_NOW)
        assert "/fake/mcp.json" not in json.dumps(advisory.to_osv())

    def test_output_validates_against_the_osv_schema(self) -> None:
        validate_osv(build_advisory(_finding(), _server(), now=FIXED_NOW).to_osv())


# ── Determinism ───────────────────────────────────────────────────────────────


class TestDeterminism:
    def test_same_finding_produces_a_byte_identical_advisory(self) -> None:
        first = build_advisory(_finding(), _server(), now=FIXED_NOW)
        second = build_advisory(_finding(), _server(), now=FIXED_NOW)
        assert first.to_canonical_json() == second.to_canonical_json()
        assert first.id == second.id

    def test_id_is_independent_of_the_scanning_host(self) -> None:
        """Two machines observing the same issue must mint the same advisory ID."""
        here = build_advisory(_finding(), _server(), now=FIXED_NOW)
        there = build_advisory(
            _finding(client="cursor", server="gh"),
            _server(name="gh", client="cursor"),
            now=FIXED_NOW,
        )
        assert here.id == there.id

    def test_canonical_json_has_sorted_keys(self) -> None:
        canonical = build_advisory(_finding(), _server(), now=FIXED_NOW)
        keys = list(json.loads(canonical.to_canonical_json()))
        assert keys == sorted(keys)

    def test_whole_feed_is_reproducible(self, tmp_path: Path) -> None:
        result = _scan_result()
        first = tmp_path / "a"
        second = tmp_path / "b"
        write_feed(build_advisories(result, now=FIXED_NOW).advisories, first)
        write_feed(build_advisories(result, now=FIXED_NOW).advisories, second)

        for path in sorted(first.rglob("*")):
            if path.is_file():
                mirror = second / path.relative_to(first)
                assert path.read_bytes() == mirror.read_bytes(), path.name

    def test_osv_zip_is_byte_reproducible(self, tmp_path: Path) -> None:
        """ZipFile stamps members with the current time unless told otherwise."""
        result = _scan_result()
        a = write_feed(
            build_advisories(result, now=FIXED_NOW).advisories, tmp_path / "a"
        )
        b = write_feed(
            build_advisories(result, now=FIXED_NOW).advisories, tmp_path / "b"
        )
        assert a.osv_zip_path.read_bytes() == b.osv_zip_path.read_bytes()
        for left, right in zip(
            a.ecosystem_zip_paths, b.ecosystem_zip_paths, strict=True
        ):
            assert left.read_bytes() == right.read_bytes(), left.parent.name


# ── build_advisories ──────────────────────────────────────────────────────────


def _scan_result() -> ScanResult:
    servers = [
        _server(),
        _server(name="local", command="node", args=["./server.js"]),
    ]
    findings = [
        _finding("CRED-001", Severity.HIGH),
        _finding("COMM-034", Severity.MEDIUM, title="Overprivileged credential"),
        _finding("SC-001", Severity.CRITICAL, title="Possible typosquatting"),
        _finding("POISON-050", Severity.LOW, title="Excessive description length"),
        _finding("RUGPULL-000", Severity.INFO, title="Baseline recorded"),
        _finding("CRED-001", Severity.HIGH, server="local"),
        _finding("CRED-001", Severity.HIGH, server="ghost"),
    ]
    return ScanResult(servers=servers, findings=findings, servers_found=len(servers))


class TestBuildAdvisories:
    def test_reports_every_finding_it_did_not_publish(self) -> None:
        report = build_advisories(_scan_result(), now=FIXED_NOW, min_severity=None)
        published = len(report.advisories)
        accounted = (
            published
            + report.skipped_no_package
            + report.skipped_no_server
            + report.skipped_non_advisory
            + report.merged_duplicates
        )
        assert accounted == 7

    def test_findings_on_unpackaged_servers_are_skipped(self) -> None:
        report = build_advisories(_scan_result(), now=FIXED_NOW, min_severity=None)
        assert report.skipped_no_package == 1

    def test_findings_for_unknown_servers_are_skipped(self) -> None:
        report = build_advisories(_scan_result(), now=FIXED_NOW, min_severity=None)
        assert report.skipped_no_server == 1

    def test_informational_findings_are_never_published(self) -> None:
        report = build_advisories(_scan_result(), now=FIXED_NOW, min_severity=None)
        assert report.skipped_non_advisory == 1
        assert all(a.mcp_audit_rule_id != "RUGPULL-000" for a in report.advisories)

    def test_severity_threshold_filters(self) -> None:
        report = build_advisories(
            _scan_result(), now=FIXED_NOW, min_severity=Severity.HIGH
        )
        assert {a.mcp_audit_rule_id for a in report.advisories} == {
            "CRED-001",
            "SC-001",
        }

    def test_duplicate_findings_collapse_into_one_advisory(self) -> None:
        result = _scan_result()
        result.findings.append(_finding("CRED-001", Severity.HIGH))
        report = build_advisories(result, now=FIXED_NOW, min_severity=None)
        assert report.merged_duplicates >= 1
        ids = [a.id for a in report.advisories]
        assert len(ids) == len(set(ids))

    def test_observation_filter_selects_package_defects(self) -> None:
        report = build_advisories(
            _scan_result(),
            now=FIXED_NOW,
            min_severity=None,
            only_observation=OBSERVATION_PACKAGE,
        )
        assert {a.mcp_audit_rule_id for a in report.advisories} == {
            "SC-001",
            "POISON-050",
        }

    def test_advisories_are_sorted_by_id(self) -> None:
        report = build_advisories(_scan_result(), now=FIXED_NOW, min_severity=None)
        ids = [a.id for a in report.advisories]
        assert ids == sorted(ids)


# ── write_feed ────────────────────────────────────────────────────────────────


class TestWriteFeed:
    @pytest.fixture
    def feed(self, tmp_path: Path):
        advisories = build_advisories(_scan_result(), now=FIXED_NOW).advisories
        return write_feed(advisories, tmp_path / "feed"), advisories

    def test_writes_one_file_per_advisory(self, feed) -> None:
        manifest, advisories = feed
        assert len(manifest.advisory_paths) == len(advisories)
        for advisory in advisories:
            assert (manifest.out_dir / "advisories" / f"{advisory.id}.json").is_file()

    def test_every_written_record_validates(self, feed) -> None:
        manifest, _ = feed
        for record in load_feed(manifest.out_dir):
            validate_osv(record)

    def test_records_round_trip_through_a_stock_json_parser(self, feed) -> None:
        manifest, advisories = feed
        for path, advisory in zip(manifest.advisory_paths, advisories, strict=True):
            assert json.loads(path.read_text(encoding="utf-8")) == advisory.to_osv()

    def test_index_lists_the_required_fields(self, feed) -> None:
        manifest, advisories = feed
        index = json.loads(manifest.index_path.read_text(encoding="utf-8"))
        assert index["feed_version"] == FEED_VERSION
        assert index["count"] == len(advisories)
        assert index["updated"] == FIXED_NOW
        for entry in index["advisories"]:
            for key in (
                "id",
                "modified",
                "summary",
                "severity",
                "owasp_mcp",
                "affected",
            ):
                assert key in entry

    def test_index_binds_each_advisory_by_digest(self, feed) -> None:
        manifest, _ = feed
        index = json.loads(manifest.index_path.read_text(encoding="utf-8"))
        assert all(len(e["canonical_sha256"]) == 64 for e in index["advisories"])

    def test_osv_json_export_is_a_flat_array(self, feed) -> None:
        manifest, advisories = feed
        records = json.loads(manifest.osv_json_path.read_text(encoding="utf-8"))
        assert isinstance(records, list)
        assert [r["id"] for r in records] == [a.id for a in advisories]

    def test_osv_zip_holds_one_record_per_advisory(self, feed) -> None:
        manifest, advisories = feed
        with zipfile.ZipFile(manifest.osv_zip_path) as archive:
            names = sorted(archive.namelist())
            assert names == sorted(f"{a.id}.json" for a in advisories)
            first = json.loads(archive.read(names[0]))
            validate_osv(first)

    def test_osv_scanner_db_uses_the_layout_osv_scanner_looks_for(self, feed) -> None:
        """osv-scanner resolves `{cache}/osv-scanner/{ecosystem}/all.zip`.

        Getting this path wrong means a consumer has to shuffle files by hand before
        the feed is usable, so the layout is pinned rather than left to documentation.
        """
        manifest, advisories = feed
        ecosystems = {a.package.ecosystem for a in advisories}
        expected = {
            manifest.out_dir / "osv" / "osv-scanner" / eco / "all.zip"
            for eco in ecosystems
        }
        assert set(manifest.ecosystem_zip_paths) == expected
        assert all(path.is_file() for path in expected)

    def test_each_ecosystem_archive_holds_only_its_own_records(self, feed) -> None:
        manifest, advisories = feed
        for path in manifest.ecosystem_zip_paths:
            ecosystem = path.parent.name
            with zipfile.ZipFile(path) as archive:
                records = [json.loads(archive.read(n)) for n in archive.namelist()]
            assert records, f"{ecosystem} archive is empty"
            for record in records:
                assert record["affected"][0]["package"]["ecosystem"] == ecosystem

    def test_every_advisory_appears_in_exactly_one_ecosystem_archive(
        self, feed
    ) -> None:
        manifest, advisories = feed
        exported: list[str] = []
        for path in manifest.ecosystem_zip_paths:
            with zipfile.ZipFile(path) as archive:
                exported.extend(n.removesuffix(".json") for n in archive.namelist())
        assert sorted(exported) == sorted(a.id or "" for a in advisories)

    def test_signable_paths_cover_advisories_and_index(self, feed) -> None:
        manifest, advisories = feed
        assert manifest.signable_paths[-1] == manifest.index_path
        assert len(manifest.signable_paths) == len(advisories) + 1

    def test_empty_feed_is_still_well_formed(self, tmp_path: Path) -> None:
        manifest = write_feed([], tmp_path / "feed")
        index = json.loads(manifest.index_path.read_text(encoding="utf-8"))
        assert index["count"] == 0
        assert index["advisories"] == []
        assert load_feed(manifest.out_dir) == []

    def test_load_feed_of_a_missing_directory_is_empty(self, tmp_path: Path) -> None:
        assert load_feed(tmp_path / "nope") == []
