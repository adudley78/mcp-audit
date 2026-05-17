#!/usr/bin/env python3
"""Validate that every finding ID in the mcp-audit source has an OWASP mapping entry.

Run from the repository root:
    python scripts/validate_owasp_mapping.py

Exits 0 and prints "All N finding IDs mapped." on success.
Exits 1 and lists missing IDs on failure.

Used in CI (ubuntu/py3.12 leg) to enforce that any PR adding a new finding ID
also updates docs/owasp-mapping.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent
MAPPING_FILE = REPO_ROOT / "docs" / "owasp-mapping.json"
SRC_DIR = REPO_ROOT / "src" / "mcp_audit"
RULES_DIR = REPO_ROOT / "rules" / "community"

# ── Patterns that produce static finding IDs in Python source ─────────────────

# Matches: id="POISON-001"  id='SC-002'  "CFHYG-001"  'COMM-010'
# Anchored to word boundaries to avoid matching within variable names or comments
_STATIC_ID_RE = re.compile(r"""["']([A-Z]{2,9}-\d{3,4})["']""")

# These prefixes are generated dynamically at runtime and cannot be enumerated
# from source constants.  They are instead documented in the "dynamic_patterns"
# array of the mapping file.
_DYNAMIC_PREFIXES: frozenset[str] = frozenset(
    {"ATT-", "EXT-", "SAST-", "DRIFT-", "GOV-"}
)

# IDs that look like finding IDs but are not — exclude them from the audit.
# CWE-* are vulnerability taxonomies, not mcp-audit finding IDs.
# PATH-* and KS-* belong to AttackPath / KillChainStep models, not Finding.
_EXCLUDED_PREFIXES: frozenset[str] = frozenset(
    {"CWE-", "CVE-", "ASI", "PATH-", "KS-", "BL-0"}  # BL-0 handled explicitly below
)
# BL-001 IS a finding ID — only exclude BL-0 as a false-positive guard
# (re-add BL-001 explicitly)
_EXPLICIT_INCLUSIONS: frozenset[str] = frozenset({"BL-001"})


def _collect_source_ids() -> set[str]:
    """Scan Python source and community YAML rules for static finding ID strings.

    Returns:
        Set of unique finding ID strings (e.g. ``{"POISON-001", "SC-002", ...}``).
    """
    ids: set[str] = set()

    # Python source files
    for py_file in SRC_DIR.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        text = py_file.read_text(encoding="utf-8", errors="replace")
        for match in _STATIC_ID_RE.finditer(text):
            candidate = match.group(1)
            # Skip dynamic-prefix IDs (ATT-, EXT-, etc.) — can't enumerate at rest
            if any(candidate.startswith(p) for p in _DYNAMIC_PREFIXES):
                continue
            # Skip non-finding taxonomies and model IDs
            if any(candidate.startswith(p) for p in _EXCLUDED_PREFIXES):
                continue
            ids.add(candidate)

    # Community YAML rules — their `id:` field is the finding ID
    if RULES_DIR.exists():
        for yaml_file in RULES_DIR.glob("*.yml"):
            text = yaml_file.read_text(encoding="utf-8", errors="replace")
            # Match: ^id: COMM-001  (only the top-level id field)
            m = re.search(r"^id:\s*(COMM-\d{3})\b", text, re.MULTILINE)
            if m:
                ids.add(m.group(1))

    # BL-001 is in scan.py; the exclusion above guards against false BL-0xx
    # matches from other strings — re-add it explicitly if present in source
    for py_file in SRC_DIR.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        if '"BL-001"' in py_file.read_text(encoding="utf-8", errors="replace"):
            ids.add("BL-001")
            break

    return ids


def _collect_mapped_ids(mapping: dict) -> set[str]:
    """Return the set of static finding IDs recorded in the mapping file.

    Args:
        mapping: Parsed ``docs/owasp-mapping.json`` dict.

    Returns:
        Set of ``finding_id`` strings from the ``mappings`` array.
    """
    return {entry["finding_id"] for entry in mapping.get("mappings", [])}


def _collect_dynamic_prefixes(mapping: dict) -> set[str]:
    """Return the set of dynamic ID prefixes documented in the mapping file.

    Args:
        mapping: Parsed ``docs/owasp-mapping.json`` dict.

    Returns:
        Set of ``id_prefix`` strings from the ``dynamic_patterns`` array.
    """
    return {entry["id_prefix"] for entry in mapping.get("dynamic_patterns", [])}


def _validate_owasp_codes(mapping: dict) -> list[str]:
    """Check that every owasp_code in mappings and dynamic_patterns is MCP01–MCP10.

    Args:
        mapping: Parsed ``docs/owasp-mapping.json`` dict.

    Returns:
        List of error strings; empty list when all codes are valid.
    """
    valid_codes = {f"MCP{i:02d}" for i in range(1, 11)}
    errors: list[str] = []

    for entry in mapping.get("mappings", []):
        for code in entry.get("owasp_codes", []):
            if code not in valid_codes:
                errors.append(f"  {entry['finding_id']}: invalid OWASP code '{code}'")

    for entry in mapping.get("dynamic_patterns", []):
        for code in entry.get("owasp_codes", []):
            if code not in valid_codes:
                errors.append(f"  {entry['id_prefix']}*: invalid OWASP code '{code}'")

    return errors


def main(argv: list[str] | None = None) -> int:
    """Entry point for the validation script.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code: 0 on success, 1 on validation failure, 2 on file-not-found.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Same as default behaviour (kept for parity with update_test_count.py).",
    )
    args = parser.parse_args(argv)
    _ = args  # --check is a no-op; validation always runs

    # ── Load mapping file ─────────────────────────────────────────────────────
    if not MAPPING_FILE.exists():
        print(f"ERROR: Mapping file not found: {MAPPING_FILE}", file=sys.stderr)
        return 2

    try:
        mapping = json.loads(MAPPING_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: Mapping file is not valid JSON: {exc}", file=sys.stderr)
        return 2

    # ── Schema checks ─────────────────────────────────────────────────────────
    schema_errors: list[str] = []

    if mapping.get("unmapped") != []:
        schema_errors.append(
            "  'unmapped' array is not empty — all IDs must be mapped."
        )

    code_errors = _validate_owasp_codes(mapping)
    if code_errors:
        schema_errors.extend(code_errors)

    if schema_errors:
        print("SCHEMA ERRORS in docs/owasp-mapping.json:")
        for e in schema_errors:
            print(e)
        return 1

    # ── Dynamic prefix coverage ───────────────────────────────────────────────
    documented_dynamic = _collect_dynamic_prefixes(mapping)
    missing_dynamic = _DYNAMIC_PREFIXES - documented_dynamic
    if missing_dynamic:
        print("DYNAMIC PATTERNS not documented in docs/owasp-mapping.json:")
        for prefix in sorted(missing_dynamic):
            print(f"  {prefix}*")
        return 1

    # ── Static ID coverage ────────────────────────────────────────────────────
    source_ids = _collect_source_ids()
    mapped_ids = _collect_mapped_ids(mapping)

    missing = source_ids - mapped_ids
    orphaned = mapped_ids - source_ids

    errors_found = False

    if missing:
        print("FINDING IDs in source but MISSING from docs/owasp-mapping.json:")
        for fid in sorted(missing):
            print(f"  {fid}")
        errors_found = True

    if orphaned:
        # Orphaned entries are a warning (the ID may have been removed from source)
        print(
            "WARNING: IDs in docs/owasp-mapping.json but NOT found in source "
            "(may be stale):"
        )
        for fid in sorted(orphaned):
            print(f"  {fid}")
        # Orphaned entries do NOT cause a failure — removing an ID from source
        # without cleaning the mapping is acceptable (stale entries are harmless).

    if errors_found:
        return 1

    total = len(source_ids)
    print(f"All {total} finding IDs mapped. docs/owasp-mapping.json is complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
