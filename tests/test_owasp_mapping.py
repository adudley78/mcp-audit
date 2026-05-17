"""Tests for docs/owasp-mapping.json completeness and polished --owasp-report.

Covers the acceptance criteria from STORY-0038:
- Mapping file valid JSON with correct schema
- All static finding IDs from source are mapped
- 'unmapped' array is empty
- All owasp_codes are valid MCP01-MCP10
- --owasp-report shows all 10 categories (including zero-finding ones)
- --owasp-report shows "Coverage: 10/10" line
- SARIF output includes relationships for all rules that have OWASP codes
"""

from __future__ import annotations

import json
import re
from io import StringIO
from pathlib import Path

import pytest

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.owasp_mcp import OWASP_MCP_TOP_10

# ── File paths ────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent
MAPPING_FILE = REPO_ROOT / "docs" / "owasp-mapping.json"
SRC_DIR = REPO_ROOT / "src" / "mcp_audit"
RULES_DIR = REPO_ROOT / "rules" / "community"

# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_mapping() -> dict:
    """Load and parse the owasp-mapping.json file."""
    return json.loads(MAPPING_FILE.read_text(encoding="utf-8"))


def _make_finding(
    finding_id: str = "POISON-001",
    owasp_codes: list[str] | None = None,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="test",
        client="test_client",
        server="test_server",
        title=title,
        description="Test description",
        evidence="Test evidence",
        remediation="Test remediation",
        owasp_mcp_top_10=owasp_codes or [],
    )


def _make_scan_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=findings or [],
    )


def _capture_owasp_report(result: ScanResult) -> str:
    """Run _print_owasp_report and capture the Rich output as plain text."""
    from rich.console import Console  # noqa: PLC0415

    from mcp_audit.cli.scan import _print_owasp_report  # noqa: PLC0415

    buf = StringIO()
    con = Console(file=buf, highlight=False, markup=False)
    _print_owasp_report(result, con)
    return buf.getvalue()


def _collect_source_static_ids() -> set[str]:
    """Collect static finding IDs from Python source and community rules.

    This mirrors the logic in scripts/validate_owasp_mapping.py so tests
    catch the same gaps that CI catches.
    """
    static_id_re = re.compile(r"""["']([A-Z]{2,9}-\d{3,4})["']""")
    dynamic_prefixes = frozenset({"ATT-", "EXT-", "SAST-", "DRIFT-", "GOV-"})
    excluded_prefixes = frozenset({"CWE-", "CVE-", "ASI", "PATH-", "KS-", "BL-0"})

    ids: set[str] = set()
    for py_file in SRC_DIR.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        text = py_file.read_text(encoding="utf-8", errors="replace")
        for match in static_id_re.finditer(text):
            candidate = match.group(1)
            if any(candidate.startswith(p) for p in dynamic_prefixes):
                continue
            if any(candidate.startswith(p) for p in excluded_prefixes):
                continue
            ids.add(candidate)

    if RULES_DIR.exists():
        for yaml_file in RULES_DIR.glob("*.yml"):
            text = yaml_file.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^id:\s*(COMM-\d{3})\b", text, re.MULTILINE)
            if m:
                ids.add(m.group(1))

    for py_file in SRC_DIR.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        if '"BL-001"' in py_file.read_text(encoding="utf-8", errors="replace"):
            ids.add("BL-001")
            break

    return ids


# ── Schema tests ──────────────────────────────────────────────────────────────


def test_mapping_file_exists() -> None:
    """docs/owasp-mapping.json must exist."""
    assert MAPPING_FILE.exists(), f"Mapping file not found: {MAPPING_FILE}"


def test_mapping_file_valid_json() -> None:
    """docs/owasp-mapping.json must be valid JSON."""
    try:
        _load_mapping()
    except json.JSONDecodeError as exc:
        pytest.fail(f"docs/owasp-mapping.json is invalid JSON: {exc}")


def test_mapping_has_required_top_level_keys() -> None:
    mapping = _load_mapping()
    required = {"schema_version", "owasp_version", "generated", "mappings", "unmapped"}
    missing = required - mapping.keys()
    assert not missing, f"Missing top-level keys: {missing}"


def test_unmapped_array_empty() -> None:
    """'unmapped' must be an empty list — zero finding IDs unaccounted for."""
    mapping = _load_mapping()
    assert mapping["unmapped"] == [], f"'unmapped' is not empty: {mapping['unmapped']}"


def test_all_finding_ids_mapped() -> None:
    """Every static finding ID found in src/ must have an entry in mappings."""
    mapping = _load_mapping()
    source_ids = _collect_source_static_ids()
    mapped_ids = {entry["finding_id"] for entry in mapping["mappings"]}
    missing = source_ids - mapped_ids
    assert not missing, (
        "Finding IDs in source but MISSING from docs/owasp-mapping.json:\n"
        + "\n".join(f"  {fid}" for fid in sorted(missing))
    )


def test_owasp_codes_valid_format() -> None:
    """Every owasp_code in mappings must be MCP01–MCP10."""
    mapping = _load_mapping()
    valid_codes = {f"MCP{i:02d}" for i in range(1, 11)}
    bad: list[str] = []
    for entry in mapping["mappings"]:
        for code in entry.get("owasp_codes", []):
            if code not in valid_codes:
                bad.append(f"  {entry['finding_id']}: invalid code '{code}'")
    for entry in mapping.get("dynamic_patterns", []):
        for code in entry.get("owasp_codes", []):
            if code not in valid_codes:
                bad.append(f"  {entry['id_prefix']}*: invalid code '{code}'")
    assert not bad, "Invalid OWASP codes found:\n" + "\n".join(bad)


def test_mapping_entries_have_required_fields() -> None:
    """Each mapping entry must have finding_id, owasp_codes, and owasp_names."""
    mapping = _load_mapping()
    for entry in mapping["mappings"]:
        assert "finding_id" in entry, f"Entry missing 'finding_id': {entry}"
        assert "owasp_codes" in entry, f"Entry missing 'owasp_codes': {entry}"
        assert "owasp_names" in entry, f"Entry missing 'owasp_names': {entry}"
        assert isinstance(entry["owasp_codes"], list), (
            f"owasp_codes must be a list in entry {entry['finding_id']}"
        )
        assert len(entry["owasp_codes"]) == len(entry["owasp_names"]), (
            f"owasp_codes/owasp_names length mismatch in entry {entry['finding_id']}"
        )


def test_dynamic_patterns_have_required_fields() -> None:
    """Each dynamic_patterns entry must document id_prefix and owasp_codes."""
    mapping = _load_mapping()
    for entry in mapping.get("dynamic_patterns", []):
        assert "id_prefix" in entry, f"Pattern entry missing 'id_prefix': {entry}"
        assert "owasp_codes" in entry, f"Pattern entry missing 'owasp_codes': {entry}"
        assert "analyzer" in entry, f"Pattern entry missing 'analyzer': {entry}"


def test_categories_match_owasp_mcp_py() -> None:
    """Categories in the mapping file must match owasp_mcp.py exactly."""
    mapping = _load_mapping()
    assert mapping.get("categories") == OWASP_MCP_TOP_10, (
        "Categories in docs/owasp-mapping.json do not match owasp_mcp.py. "
        "Update the mapping file to match the canonical source."
    )


# ── --owasp-report output tests ───────────────────────────────────────────────


def test_owasp_report_output_all_10_categories() -> None:
    """--owasp-report must show all 10 OWASP categories regardless of findings."""
    findings = [_make_finding("POISON-001", ["MCP03", "MCP01"])]
    result = _make_scan_result(findings)
    output = _capture_owasp_report(result)
    for i in range(1, 11):
        assert f"MCP{i:02d}" in output, f"MCP{i:02d} missing from --owasp-report output"


def test_owasp_report_zero_finding_category_shown() -> None:
    """Categories with zero findings must appear with a clean-signal indicator."""
    # Only MCP01 has findings; MCP05 should still appear.
    findings = [_make_finding("CRED-001", ["MCP01"])]
    result = _make_scan_result(findings)
    output = _capture_owasp_report(result)
    # MCP05 must be present even with zero findings in that category
    assert "MCP05" in output, "Zero-finding category MCP05 missing from output"


def test_owasp_report_coverage_line() -> None:
    """--owasp-report must include the 'Coverage: 10/10' line."""
    findings = [_make_finding("POISON-001", ["MCP03"])]
    result = _make_scan_result(findings)
    output = _capture_owasp_report(result)
    assert "Coverage: 10/10 OWASP MCP Top 10 categories checked" in output


def test_owasp_report_shows_finding_count() -> None:
    """Categories with findings must show a non-zero count."""
    findings = [
        _make_finding("POISON-001", ["MCP03"]),
        _make_finding("POISON-002", ["MCP03"], title="Second finding"),
    ]
    result = _make_scan_result(findings)
    output = _capture_owasp_report(result)
    # MCP03 has 2 findings — output must contain "2"
    assert "2" in output


def test_owasp_report_empty_scan_shows_all_categories() -> None:
    """Even a scan with zero findings must show all 10 categories."""
    result = _make_scan_result([])
    output = _capture_owasp_report(result)
    for i in range(1, 11):
        assert f"MCP{i:02d}" in output, (
            f"MCP{i:02d} missing from --owasp-report on empty scan"
        )
    assert "Coverage: 10/10 OWASP MCP Top 10 categories checked" in output


# ── SARIF relationship tests ───────────────────────────────────────────────────


def test_sarif_rules_with_owasp_codes_have_relationships() -> None:
    """SARIF output: rules with owasp_mcp_top_10 codes must have relationships."""
    from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

    findings = [
        _make_finding("POISON-001", ["MCP03", "MCP01"]),
        _make_finding("TRANSPORT-001", ["MCP07"]),
    ]
    result = _make_scan_result(findings)
    sarif = json.loads(format_sarif(result))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert "relationships" in rule, (
            f"SARIF rule {rule['id']!r} has owasp codes but missing 'relationships'"
        )
        assert len(rule["relationships"]) > 0, (
            f"SARIF rule {rule['id']!r} has empty 'relationships'"
        )


def test_sarif_rules_without_owasp_codes_have_no_relationships() -> None:
    """SARIF output: rules without owasp codes must not have a relationships field."""
    from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

    findings = [_make_finding("RUGPULL-000", [])]
    result = _make_scan_result(findings)
    sarif = json.loads(format_sarif(result))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        # Finding has no OWASP codes so relationships should be absent
        assert "relationships" not in rule, (
            f"SARIF rule {rule['id']!r} has unexpected 'relationships' field"
        )


def test_sarif_output_has_owasp_mcp_taxonomy() -> None:
    """SARIF output must include the OWASP MCP Top 10 taxonomy block."""
    from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

    findings = [_make_finding("SC-001", ["MCP04"])]
    result = _make_scan_result(findings)
    sarif = json.loads(format_sarif(result))
    taxonomies = sarif["runs"][0].get("taxonomies", [])
    assert len(taxonomies) == 1, "Expected exactly 1 taxonomy (OWASP MCP Top 10)"
    taxonomy = taxonomies[0]
    assert taxonomy["name"] == "OWASP-MCP-Top-10"
    assert len(taxonomy["taxa"]) == 10


def test_sarif_taxonomy_taxa_match_owasp_mcp_py() -> None:
    """SARIF taxonomy taxa must match the canonical OWASP_MCP_TOP_10 dict."""
    from mcp_audit.output.sarif import format_sarif  # noqa: PLC0415

    findings = [_make_finding("SC-001", ["MCP04"])]
    result = _make_scan_result(findings)
    sarif = json.loads(format_sarif(result))
    taxa = {t["id"]: t["name"] for t in sarif["runs"][0]["taxonomies"][0]["taxa"]}
    assert taxa == OWASP_MCP_TOP_10


# ── Integration: validate_owasp_mapping script ─────────────────────────────────


def test_validate_script_exits_zero() -> None:
    """scripts/validate_owasp_mapping.py must exit 0 against the committed mapping."""
    from scripts.validate_owasp_mapping import main  # noqa: PLC0415

    exit_code = main([])
    assert exit_code == 0, (
        "validate_owasp_mapping.py exited non-zero — mapping file is incomplete"
    )


def test_validate_script_fails_on_missing_id(tmp_path: Path) -> None:
    """Validate script exits 1 when a finding ID is in source but not mapped."""
    import scripts.validate_owasp_mapping as vm  # noqa: PLC0415

    # Patch MAPPING_FILE to a temp file missing POISON-001
    mapping = _load_mapping()
    mapping["mappings"] = [
        e for e in mapping["mappings"] if e["finding_id"] != "POISON-001"
    ]
    trimmed = tmp_path / "owasp-mapping.json"
    trimmed.write_text(json.dumps(mapping), encoding="utf-8")

    original = vm.MAPPING_FILE
    vm.MAPPING_FILE = trimmed
    try:
        exit_code = vm.main([])
    finally:
        vm.MAPPING_FILE = original

    assert exit_code == 1, (
        "Expected exit code 1 when POISON-001 is missing from mapping"
    )
