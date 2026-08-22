#!/usr/bin/env python3
"""CI gate over ``scripts/audit_registry.py`` JSON output.

Read-only. Never writes ``registry/known-servers.json`` and never invokes
``--stamp``. Fail the process on either:

* any entry classified ``MISSING`` — we are vouching for a name that no
  longer exists (the 2026-04 exposure).
* any entry with ``attestation_expected: true`` classified
  ``NO_PROVENANCE`` — every user who scans that package gets a MEDIUM
  finding for a condition that is not true.

Do **not** fail on ``THIN`` (``@playwright/mcp`` is legitimately ``0.0.79``)
or on a stale ``last_verified``. Staleness is not drift; failing on it is
what produces unattended mutation.

Usage::

    python scripts/audit_registry.py --refresh --out /tmp/raw.json
    python scripts/check_registry_drift.py --raw /tmp/raw.json --report /tmp/report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

BUCKETS = ("OK", "MISSING", "UNCLAIMABLE_MISMATCH", "THIN", "UNCHECKED")
PROVENANCE = ("HAS_PROVENANCE", "NO_PROVENANCE", "UNCHECKED")

INVESTIGATE = "python scripts/audit_registry.py"
REMEDIATE_MISSING = (
    "remove the entry from registry/known-servers.json (do not --stamp a MISSING name)"
)
REMEDIATE_NO_PROVENANCE = (
    "python scripts/audit_registry.py --stamp"
    "  # human act: clears the false attestation_expected flag"
)


def _ecosystem(result: dict[str, Any]) -> str:
    ecos = result.get("declared_ecosystem") or []
    if isinstance(ecos, list) and ecos:
        return "/".join(str(e) for e in ecos)
    src = result.get("declared_source")
    return str(src) if src else "unknown"


def collect_failures(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Return gate failures. Empty list means the job should pass."""
    failures: list[dict[str, str]] = []
    for result in results:
        name = str(result.get("name") or "")
        eco = _ecosystem(result)
        bucket = str(result.get("bucket") or "")
        if bucket == "MISSING":
            failures.append(
                {
                    "name": name,
                    "ecosystem": eco,
                    "condition": "MISSING",
                    "why": (
                        "package no longer resolves in its declared ecosystem; "
                        "the registry is vouching for a name anyone could register"
                    ),
                    "remediate": REMEDIATE_MISSING,
                }
            )
        if (
            result.get("declared_attestation_expected")
            and result.get("provenance") == "NO_PROVENANCE"
        ):
            failures.append(
                {
                    "name": name,
                    "ecosystem": eco,
                    "condition": "attestation_expected+NO_PROVENANCE",
                    "why": (
                        "attestation_expected is true but the latest release "
                        "publishes no SLSA/PEP 740 provenance; every scan of "
                        "this package gets a false MEDIUM ATTEST-013"
                    ),
                    "remediate": REMEDIATE_NO_PROVENANCE,
                }
            )
    return failures


def build_report(
    results: list[dict[str, Any]],
    run_date: str,
) -> dict[str, Any]:
    """Machine-readable counts for the workflow artifact (the time series)."""
    buckets = Counter(str(r.get("bucket") or "UNCHECKED") for r in results)
    flagged = [r for r in results if r.get("declared_attestation_expected")]
    provenance = Counter(str(r.get("provenance") or "NOT_CHECKED") for r in flagged)
    return {
        "run_date": run_date,
        "total_entries": len(results),
        "buckets": {k: buckets.get(k, 0) for k in BUCKETS},
        "attestation_expected": {
            "flagged": len(flagged),
            **{k: provenance.get(k, 0) for k in PROVENANCE},
        },
        "failures": collect_failures(results),
    }


def format_failure_message(failures: list[dict[str, str]]) -> str:
    """Human-readable failure text. Actionable without opening the script."""
    missing = [f for f in failures if f["condition"] == "MISSING"]
    no_prov = [
        f for f in failures if f["condition"] == "attestation_expected+NO_PROVENANCE"
    ]
    lines = [
        "REGISTRY DRIFT: the registry is lying.",
        "",
        f"Investigate: {INVESTIGATE}",
        "Stamping remains a human act: python scripts/audit_registry.py --stamp",
        "This job never writes registry/known-servers.json.",
        "",
    ]
    if missing:
        lines.append(
            "MISSING fired — we vouch for a name that does not exist "
            "(same class as the 2026-04 exposure):"
        )
        for f in missing:
            lines.append(f"  - {f['ecosystem']}  {f['name']}")
            lines.append(f"      {f['why']}")
            lines.append(f"      Remediate: {f['remediate']}")
        lines.append("")
    if no_prov:
        lines.append(
            "attestation_expected + NO_PROVENANCE fired — every scan of "
            "these packages gets a MEDIUM finding for a condition that is not true:"
        )
        for f in no_prov:
            lines.append(f"  - {f['ecosystem']}  {f['name']}")
            lines.append(f"      {f['why']}")
            lines.append(f"      Remediate: {f['remediate']}")
        lines.append("")
    lines.append(
        "Not failures: THIN (e.g. @playwright/mcp at 0.0.x) and stale "
        "last_verified. Staleness is not drift."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw",
        type=Path,
        required=True,
        help="JSON array written by scripts/audit_registry.py --out",
    )
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="Where to write the machine-readable counts (workflow artifact)",
    )
    parser.add_argument(
        "--run-date",
        default=date.today().isoformat(),
        help="ISO date recorded in the report (default: today)",
    )
    args = parser.parse_args(argv)

    results = json.loads(args.raw.read_text(encoding="utf-8"))
    if not isinstance(results, list):
        print("ERROR: --raw must be a JSON array of audit results", file=sys.stderr)
        return 2

    report = build_report(results, args.run_date)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote drift report to {args.report}", file=sys.stderr)
    print(
        json.dumps(
            {
                "run_date": report["run_date"],
                "total_entries": report["total_entries"],
                "buckets": report["buckets"],
                "attestation_expected": report["attestation_expected"],
                "failure_count": len(report["failures"]),
            },
            indent=2,
        ),
        file=sys.stderr,
    )

    failures = report["failures"]
    if failures:
        print(format_failure_message(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
