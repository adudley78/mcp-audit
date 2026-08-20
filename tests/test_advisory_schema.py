"""Tests for the Advisory data model and its OSV 1.6.0 serialization.

The build must fail on schema drift: if a change to :mod:`mcp_audit.advisory.schema`
produces a record the published OSV schema rejects, the feed stops being consumable by
osv-scanner and every downstream integration breaks silently. These tests are the gate.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
from pathlib import Path

import jsonschema
import pytest

import mcp_audit.advisory
from mcp_audit.advisory.classify import owasp_codes_for
from mcp_audit.advisory.schema import (
    FINDING_CLASS_TO_OWASP,
    ID_PREFIX,
    OBSERVATION_DEPLOYMENT,
    OBSERVATION_PACKAGE,
    SCHEMA_VERSION,
    Advisory,
    Package,
    Reference,
    Severity,
    VerifiedPatch,
    owasp_for,
)
from mcp_audit.advisory.validate import load_osv_schema, osv_schema_path, validate_osv
from mcp_audit.owasp_mcp import OWASP_MCP_TOP_10, is_valid_code

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_ADVISORY = REPO_ROOT / "examples" / "advisory.sample.json"

FIXED_NOW = "2026-07-30T12:00:00Z"


def _advisory(**overrides) -> Advisory:
    kwargs = {
        "package": Package(ecosystem="npm", name="example-weather-mcp"),
        "summary": "Hard-coded API token in server configuration",
        "details": "The server ships a long-lived provider API token in its config.",
        "finding_class": "hardcoded-secret",
        "mcp_audit_rule_id": "CRED-001",
        "mcp_transport": "stdio",
        "severity": [Severity(score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N")],
        "published": FIXED_NOW,
        "modified": FIXED_NOW,
    }
    kwargs.update(overrides)
    return Advisory(**kwargs)


# ── OSV schema conformance ────────────────────────────────────────────────────


class TestOsvSchemaConformance:
    def test_vendored_schema_is_present_and_parseable(self) -> None:
        assert osv_schema_path().is_file()
        schema = load_osv_schema()
        assert schema["title"] == "Open Source Vulnerability"

    def test_minimal_advisory_validates(self) -> None:
        validate_osv(_advisory().to_osv())

    def test_fully_populated_advisory_validates(self) -> None:
        advisory = _advisory(
            fixed="2.1.0",
            owasp_mcp=["MCP01", "MCP04"],
            references=[
                Reference(url="https://example.test/advisory", type="ADVISORY"),
                Reference(url="https://example.test/fix", type="FIX"),
            ],
            verified_patch=VerifiedPatch(
                fixed_version="2.1.0",
                pr_url="https://github.test/org/repo/pull/1",
                cosign_bundle="sha256:abc",
            ),
            aliases=["CVE-2026-11111"],
            cwe_ids=["CWE-798"],
            cvss_basis="finding-class-template",
            location="run_query",
        )
        validate_osv(advisory.to_osv())

    @pytest.mark.parametrize("finding_class", ["unclassified", "brand-new-class"])
    def test_unmapped_class_still_validates(self, finding_class: str) -> None:
        """A brand-new detection rule must never produce a schema-invalid record."""
        validate_osv(_advisory(finding_class=finding_class, owasp_mcp=[]).to_osv())

    def test_committed_sample_validates(self) -> None:
        """examples/advisory.sample.json is the reference record consumers copy."""
        record = json.loads(SAMPLE_ADVISORY.read_text(encoding="utf-8"))
        validate_osv(record)

    def test_schema_rejects_a_malformed_record(self) -> None:
        """Guard against the validator silently accepting anything."""
        record = _advisory().to_osv()
        record["modified"] = "yesterday"
        with pytest.raises(jsonschema.ValidationError):
            validate_osv(record)

    def test_schema_rejects_unknown_top_level_field(self) -> None:
        record = _advisory().to_osv()
        record["mcp_transport"] = "stdio"  # belongs under database_specific
        with pytest.raises(jsonschema.ValidationError):
            validate_osv(record)


# ── Core OSV fields ───────────────────────────────────────────────────────────


class TestOsvFields:
    def test_schema_version_is_pinned(self) -> None:
        assert _advisory().to_osv()["schema_version"] == SCHEMA_VERSION == "1.6.0"

    def test_core_fields_are_reused_verbatim(self) -> None:
        record = _advisory().to_osv()
        for key in ("id", "modified", "published", "summary", "details", "affected"):
            assert key in record

    def test_severity_uses_cvss_v3_type(self) -> None:
        entry = _advisory().to_osv()["severity"][0]
        assert entry["type"] == "CVSS_V3"
        assert entry["score"].startswith("CVSS:3.1/")

    def test_package_carries_ecosystem_name_and_purl(self) -> None:
        package = _advisory().to_osv()["affected"][0]["package"]
        assert package == {
            "ecosystem": "npm",
            "name": "example-weather-mcp",
            "purl": "pkg:npm/example-weather-mcp",
        }

    def test_pypi_purl_uses_lowercase_type(self) -> None:
        package = Package(ecosystem="PyPI", name="mcp-server-git")
        assert package.purl == "pkg:pypi/mcp-server-git"

    def test_fixed_version_adds_a_range_event(self) -> None:
        events = _advisory(fixed="2.1.0").to_osv()["affected"][0]["ranges"][0]["events"]
        assert events == [{"introduced": "0"}, {"fixed": "2.1.0"}]

    def test_omitted_optional_arrays_are_absent_not_empty(self) -> None:
        record = _advisory(severity=[], references=[]).to_osv()
        assert "severity" not in record
        assert "references" not in record

    def test_aliases_are_sorted(self) -> None:
        record = _advisory(aliases=["CVE-2026-9", "CVE-2026-1"]).to_osv()
        assert record["aliases"] == ["CVE-2026-1", "CVE-2026-9"]


# ── database_specific ─────────────────────────────────────────────────────────


class TestDatabaseSpecific:
    def test_required_keys_are_present(self) -> None:
        specific = _advisory().to_osv()["affected"][0]["database_specific"]
        for key in (
            "owasp_mcp",
            "mcp_transport",
            "finding_class",
            "mcp_audit_rule_id",
            "verified_patch",
        ):
            assert key in specific

    def test_verified_patch_is_null_until_a_fix_lands(self) -> None:
        specific = _advisory().to_osv()["affected"][0]["database_specific"]
        assert specific["verified_patch"] == {
            "fixed_version": None,
            "pr_url": None,
            "cosign_bundle": None,
        }

    def test_verified_patch_reports_patched_state(self) -> None:
        assert not VerifiedPatch().is_patched
        assert VerifiedPatch(fixed_version="1.2.3").is_patched

    def test_fixable_class_backfills_its_owasp_code(self) -> None:
        specific = _advisory().to_osv()["affected"][0]["database_specific"]
        assert specific["owasp_mcp"] == ["MCP01"]

    def test_unmapped_finding_gets_empty_codes_and_a_todo(self) -> None:
        """Never invent a code: an empty list plus an explicit TODO is the contract."""
        specific = _advisory(
            finding_class="rug-pull",
            mcp_audit_rule_id="RUGPULL-001",
            owasp_mcp=[],
        ).to_osv()["affected"][0]["database_specific"]
        assert specific["owasp_mcp"] == []
        assert specific["owasp_mcp_todo"].startswith("TODO:")

    def test_mapped_finding_has_no_todo(self) -> None:
        specific = _advisory().to_osv()["affected"][0]["database_specific"]
        assert "owasp_mcp_todo" not in specific

    def test_observation_defaults_to_deployment(self) -> None:
        specific = _advisory().to_osv()["affected"][0]["database_specific"]
        assert specific["observation"] == OBSERVATION_DEPLOYMENT

    def test_observation_can_mark_a_package_defect(self) -> None:
        specific = _advisory(observation=OBSERVATION_PACKAGE).to_osv()["affected"][0][
            "database_specific"
        ]
        assert specific["observation"] == OBSERVATION_PACKAGE

    def test_location_is_exported_when_set(self) -> None:
        specific = _advisory(location="run_query").to_osv()["affected"][0][
            "database_specific"
        ]
        assert specific["mcp_location"] == "run_query"

    def test_transport_may_be_null(self) -> None:
        specific = _advisory(mcp_transport=None).to_osv()["affected"][0][
            "database_specific"
        ]
        assert specific["mcp_transport"] is None


# ── Identifiers ───────────────────────────────────────────────────────────────


class TestStableIds:
    def test_id_uses_the_experimental_osv_namespace(self) -> None:
        """OSV reserves un-prefixed IDs for registered databases; `x_` is ours today."""
        assert _advisory().id.startswith(f"{ID_PREFIX}-2026-")

    def test_id_is_derived_from_the_publication_year(self) -> None:
        assert _advisory(published="2031-01-01T00:00:00Z").id.startswith(
            f"{ID_PREFIX}-2031-"
        )

    def test_same_inputs_produce_the_same_id(self) -> None:
        assert _advisory().id == _advisory().id

    def test_id_ignores_the_timestamp_within_a_year(self) -> None:
        """Two hosts scanning at different moments must mint the same advisory."""
        early = _advisory(published="2026-01-01T00:00:00Z")
        late = _advisory(published="2026-12-31T23:59:59Z")
        assert early.id == late.id

    @pytest.mark.parametrize(
        "overrides",
        [
            {"package": Package(ecosystem="npm", name="other-server")},
            {"package": Package(ecosystem="PyPI", name="example-weather-mcp")},
            {"mcp_audit_rule_id": "CRED-002"},
            {"finding_class": "command-injection"},
            {"introduced": "1.0.0"},
            {"location": "run_query"},
        ],
    )
    def test_id_changes_when_identity_changes(self, overrides: dict) -> None:
        assert _advisory(**overrides).id != _advisory().id

    def test_id_ignores_fields_that_are_not_identity(self) -> None:
        """Prose and scoring must not fork an advisory into two records."""
        assert _advisory(summary="Rewritten summary", details="Rewritten").id == (
            _advisory().id
        )

    def test_explicit_id_is_preserved(self) -> None:
        assert (
            _advisory(id="x_MCPSA-2026-deadbeefcafe").id == "x_MCPSA-2026-deadbeefcafe"
        )


# ── OWASP mapping ─────────────────────────────────────────────────────────────


class TestOwaspMapping:
    """The feed must not hold a second definition of the OWASP MCP Top 10.

    `mcp_audit.owasp_mcp` is the repo's single source of truth. A private copy inside
    the advisory package would drift against `scripts/validate_owasp_mapping.py`, which
    CI runs against `docs/owasp-mapping.json`, and would publish codes that no longer
    join to mcp-audit's own SARIF output.
    """

    def test_the_advisory_package_defines_no_owasp_codes_of_its_own(self) -> None:
        """No module may hold a private copy of the taxonomy.

        Only *code* is inspected, not docstrings: `classify.owasp_codes_for` documents
        that it accepts the year-suffixed form on input, and saying so is correct.
        """
        advisory_pkg = Path(mcp_audit.advisory.__file__).parent
        offenders: dict[str, list[str]] = {}
        for path in sorted(advisory_pkg.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = {
                ast.get_docstring(node, clean=False)
                for node in ast.walk(tree)
                if isinstance(
                    node,
                    ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
                )
            }
            hits = [
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value not in docstrings
                and re.search(r"MCP\d{2}:\d{4}", node.value)
            ]
            if hits:
                offenders[path.name] = hits
        assert not offenders, f"year-suffixed OWASP codes reintroduced in {offenders}"

    def test_the_deleted_private_owasp_module_stays_deleted(self) -> None:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("mcp_audit.advisory.owasp")

    def test_every_publishable_code_is_defined_by_the_repo_source_of_truth(
        self,
    ) -> None:
        """The behavioural form of the same invariant, independent of source text."""
        publishable = set(owasp_codes_for([f"MCP{n:02d}" for n in range(1, 21)]))
        assert publishable == set(OWASP_MCP_TOP_10)

    def test_published_codes_are_the_bare_repo_wide_form(self) -> None:
        assert set(OWASP_MCP_TOP_10) == {f"MCP{n:02d}" for n in range(1, 11)}

    @pytest.mark.parametrize(
        ("finding_class", "expected"),
        [
            ("hardcoded-secret", "MCP01"),
            ("excessive-scope", "MCP02"),
            ("command-injection", "MCP05"),
        ],
    )
    def test_fixable_classes_map_to_their_published_codes(
        self, finding_class: str, expected: str
    ) -> None:
        assert owasp_for(finding_class) == expected

    def test_every_fixable_mapping_targets_a_real_category(self) -> None:
        for code in FINDING_CLASS_TO_OWASP.values():
            assert is_valid_code(code), code

    def test_unknown_class_raises_rather_than_guessing(self) -> None:
        with pytest.raises(ValueError, match="No OWASP MCP mapping"):
            owasp_for("not-a-real-class")

    def test_finding_codes_pass_through_unchanged(self) -> None:
        """Finding.owasp_mcp_top_10 stores "MCP01"; the feed publishes "MCP01"."""
        assert owasp_codes_for(["MCP01", "MCP05"]) == ["MCP01", "MCP05"]

    def test_year_suffixed_input_is_normalised(self) -> None:
        """OWASP publishes "MCP01:2025"; a caller may pass that form in."""
        assert owasp_codes_for(["MCP01:2025"]) == ["MCP01"]

    def test_invented_codes_are_dropped(self) -> None:
        assert owasp_codes_for(["MCP-A01", "MCP99", "", "MCP03"]) == ["MCP03"]

    def test_duplicate_codes_collapse(self) -> None:
        assert owasp_codes_for(["MCP01", "MCP01:2025"]) == ["MCP01"]

    def test_an_advisory_cannot_carry_an_unknown_code(self) -> None:
        with pytest.raises(ValueError, match="Unknown OWASP MCP Top 10 code"):
            Advisory(
                package=Package(ecosystem="npm", name="x"),
                summary="s",
                details="d",
                finding_class="unclassified",
                mcp_audit_rule_id="X-1",
                owasp_mcp=["MCP01:2025"],
            )
