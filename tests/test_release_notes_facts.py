"""Assert facts, not prose, between the evergreen release-notes template and README.

`.github/release-notes-template.md` is the GitHub Release body (see
`scripts/compose_release_notes.py`), so it duplicates a slice of README.md's
Install / coverage / integrations copy — the release page has to carry install
instructions inline, there is no include mechanism on a GitHub Release body.
Nothing has ever verified that duplicated copy stays accurate, and this
project has been bitten by that exact shape of drift three times in one
month on other files (see CHANGELOG.md).

This module does NOT diff paragraphs — a reworded sentence must not fail
these tests. It extracts the handful of concrete facts that actually go
stale (a package name, an asset filename, a host, a count) and asserts the
extracted *values* agree, so a renamed asset or a dropped host does fail.

Test counts are already patched by ``scripts/update_test_count.py`` from a
live ``pytest --collect-only`` count; this module does not re-derive that
count, it only asserts the template and README, both patched from that one
source, still agree with each other.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = ROOT / ".github" / "release-notes-template.md"
README_PATH = ROOT / "README.md"

TEMPLATE_TEXT = TEMPLATE_PATH.read_text(encoding="utf-8")
README_TEXT = README_PATH.read_text(encoding="utf-8")

SPEC_FILES = sorted(ROOT.glob("mcp-audit-*.spec"))


def _extract(pattern: str, text: str, path: Path, fact: str) -> tuple[str, ...]:
    """Return the captured group(s) of ``pattern`` in ``text``, or fail loudly."""
    match = re.search(pattern, text)
    assert match, (
        f"Could not find {fact!r} in {path} using /{pattern}/ — "
        "the doc text changed shape; update this test's regex to match it."
    )
    return match.groups()


def _assert_fact_matches(
    fact: str, template_value: object, readme_value: object
) -> None:
    assert template_value == readme_value, (
        f"{fact} drifted between the release-notes template and README.md:\n"
        f"  {TEMPLATE_PATH} says: {template_value!r}\n"
        f"  {README_PATH} says:   {readme_value!r}\n"
        "Update whichever one is now wrong."
    )


# ---------------------------------------------------------------------------
# Package / CLI identity
# ---------------------------------------------------------------------------


def test_pypi_package_name_matches() -> None:
    (template_val,) = _extract(
        r"pip install --upgrade (\S+)",
        TEMPLATE_TEXT,
        TEMPLATE_PATH,
        "PyPI package name",
    )
    (readme_val,) = _extract(
        r"pip install (\S+)", README_TEXT, README_PATH, "PyPI package name"
    )
    _assert_fact_matches("PyPI package name", template_val, readme_val)


def test_cli_command_name_matches() -> None:
    (template_val,) = _extract(
        r"CLI command: (\S+)", TEMPLATE_TEXT, TEMPLATE_PATH, "CLI command name"
    )
    (readme_val,) = _extract(
        r"CLI command is still `([^`]+)`", README_TEXT, README_PATH, "CLI command name"
    )
    _assert_fact_matches("CLI command name", template_val, readme_val)


# ---------------------------------------------------------------------------
# Binary asset filenames — ground truth is the PyInstaller specs that
# actually produce them, not README (README never enumerates them; it just
# points at the GitHub Releases page and docs/building-binaries.md).
# ---------------------------------------------------------------------------


def _spec_derived_binary_names() -> set[str]:
    assert SPEC_FILES, f"No mcp-audit-*.spec files found under {ROOT}"
    names = set()
    for spec in SPEC_FILES:
        text = spec.read_text(encoding="utf-8")
        (name,) = _extract(
            r"name=['\"](mcp-audit-[\w.-]+)['\"]", text, spec, "PyInstaller EXE name"
        )
        if "windows" in name:
            name += ".exe"
        names.add(name)
    return names


def test_binary_asset_filenames_match_pyinstaller_specs() -> None:
    template_names = set(
        re.findall(r"`(mcp-audit-(?:darwin|linux|windows)[\w.-]*)`", TEMPLATE_TEXT)
    )
    expected = _spec_derived_binary_names()
    assert template_names == expected, (
        "Binary asset filenames in the release template's Install table don't "
        "match the PyInstaller spec files that actually produce them:\n"
        f"  {TEMPLATE_PATH} lists: {sorted(template_names)}\n"
        f"  *.spec files under {ROOT} produce: {sorted(expected)}\n"
        "Update the template's Install table, or the affected .spec file(s)."
    )


# ---------------------------------------------------------------------------
# SBOM asset filename patterns
# ---------------------------------------------------------------------------


def test_sbom_asset_filename_patterns_match() -> None:
    # README wraps this in a blockquote, so continuation lines start with
    # "> " — tolerate an optional "> " wherever a line break may fall.
    pattern = r"SBOM per binary\s*\(`([^`]+)`\)\s*(?:>\s*)?plus\s*`([^`]+)`"
    per_binary_template, wheel_template = _extract(
        pattern, TEMPLATE_TEXT, TEMPLATE_PATH, "SBOM asset filename patterns"
    )
    per_binary_readme, wheel_readme = _extract(
        pattern, README_TEXT, README_PATH, "SBOM asset filename patterns"
    )
    _assert_fact_matches(
        "Per-binary SBOM filename pattern", per_binary_template, per_binary_readme
    )
    _assert_fact_matches("Wheel SBOM filename", wheel_template, wheel_readme)


# ---------------------------------------------------------------------------
# Supported host list — the template's tagline names a few clients by
# example ("...and any MCP-compatible host"); it is not meant to be
# exhaustive, so this asserts every host it *does* name is a real,
# discovered client per README's "## Supported clients" table, not that the
# two lists are equal in length.
# ---------------------------------------------------------------------------


def _readme_supported_hosts() -> set[str]:
    section = README_TEXT.split("## Supported clients", 1)[1]
    section = section.split("\n## ", 1)[0]
    hosts = set()
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|") or "---" in line or line.startswith("| Client"):
            continue
        cell = line.split("|")[1].strip()
        if cell:
            hosts.add(cell)
    return hosts


def test_hosts_named_in_template_tagline_are_real_supported_clients() -> None:
    match = re.search(
        r"across (.+?), and any MCP-compatible host", TEMPLATE_TEXT, re.DOTALL
    )
    assert match, (
        "Could not find 'supported host list' in "
        f"{TEMPLATE_PATH} — the doc text changed shape; update this test's regex."
    )
    (host_list,) = match.groups()
    template_hosts = {h.strip() for h in host_list.split(",")}
    readme_hosts = _readme_supported_hosts()
    missing = template_hosts - readme_hosts
    assert not missing, (
        "Host(s) named in the release template's tagline are not in README.md's "
        f"'## Supported clients' table: {sorted(missing)}\n"
        f"  {TEMPLATE_PATH} tagline names: {sorted(template_hosts)}\n"
        f"  {README_PATH} table lists:     {sorted(readme_hosts)}\n"
        "Either the template is claiming support for a client mcp-audit doesn't "
        "discover, or README's table is missing an entry."
    )


# ---------------------------------------------------------------------------
# Test count — cross-checked against README, not re-derived. Both files are
# patched from the same pytest --collect-only count by
# scripts/update_test_count.py; this only proves they still agree.
# ---------------------------------------------------------------------------


def test_test_count_matches_readme() -> None:
    (template_val,) = _extract(
        r"([\d,]+) tests · Apache 2\.0", TEMPLATE_TEXT, TEMPLATE_PATH, "test count"
    )
    (readme_val,) = _extract(
        r"([\d,]+) tests validate", README_TEXT, README_PATH, "test count"
    )
    _assert_fact_matches("Test count", template_val, readme_val)


# ---------------------------------------------------------------------------
# Detection coverage counts
# ---------------------------------------------------------------------------


def test_poisoning_pattern_count_matches() -> None:
    (template_val,) = _extract(
        r"tool poisoning\*\* — (\d+) patterns",
        TEMPLATE_TEXT,
        TEMPLATE_PATH,
        "tool poisoning pattern count",
    )
    (readme_val,) = _extract(
        r"Tool poisoning detection\*\* — (\d+) regex patterns",
        README_TEXT,
        README_PATH,
        "tool poisoning pattern count",
    )
    _assert_fact_matches("Tool poisoning pattern count", template_val, readme_val)


def test_credential_pattern_count_matches() -> None:
    (template_val,) = _extract(
        r"Credential exposure\*\* — (\d+) patterns",
        TEMPLATE_TEXT,
        TEMPLATE_PATH,
        "credential pattern count",
    )
    (readme_val,) = _extract(
        r"Credential exposure\*\* — (\d+) patterns",
        README_TEXT,
        README_PATH,
        "credential pattern count",
    )
    _assert_fact_matches("Credential pattern count", template_val, readme_val)


def test_sast_rule_counts_match() -> None:
    template_vals = _extract(
        r"SAST\*\* — (\d+) rules across Python \((\d+)\) and TypeScript \((\d+)\)",
        TEMPLATE_TEXT,
        TEMPLATE_PATH,
        "SAST rule counts",
    )
    readme_vals = _extract(
        r"SAST rule pack\*\* — (\d+) Semgrep rules \((\d+) Python, (\d+) TypeScript\)",
        README_TEXT,
        README_PATH,
        "SAST rule counts",
    )
    _assert_fact_matches(
        "SAST rule counts (total, Python, TypeScript)", template_vals, readme_vals
    )


def test_exploit_fixture_count_matches() -> None:
    (template_val,) = _extract(
        r"(\d+) real-world exploit fixtures",
        TEMPLATE_TEXT,
        TEMPLATE_PATH,
        "exploit fixture count",
    )
    (readme_val,) = _extract(
        r"validated against (\d+) published exploit PoCs",
        README_TEXT,
        README_PATH,
        "exploit fixture count",
    )
    _assert_fact_matches("Exploit fixture count", template_val, readme_val)


def test_false_positive_benchmark_server_count_matches() -> None:
    (template_val,) = _extract(
        r"(\d+)-server false-positive benchmark",
        TEMPLATE_TEXT,
        TEMPLATE_PATH,
        "false-positive benchmark server count",
    )
    (readme_val,) = _extract(
        r"(\d+)-server benchmark",
        README_TEXT,
        README_PATH,
        "false-positive benchmark server count",
    )
    _assert_fact_matches(
        "False-positive benchmark server count", template_val, readme_val
    )
