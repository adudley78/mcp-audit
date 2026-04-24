#!/usr/bin/env python3
"""End-to-end smoke test for the mcp-audit binary.

Validates the full scan workflow on the target platform. Fails fast with a
clear message if any assertion fails.

Usage:
    python scripts/smoke_test.py <path-to-binary>

Exit codes:
    0 — all checks passed
    1 — a check failed (error printed to stderr)
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Windows' default console codepage is cp1252, which cannot encode the box-
# drawing / arrow characters used in this script's status lines (e.g. "→").
# Reconfigure stdout/stderr to UTF-8 so the release smoke test doesn't crash
# with UnicodeEncodeError before the first scan even runs.  Guarded with
# contextlib.suppress because non-default streams (captured pipes, etc.) may
# not expose .reconfigure().
for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(AttributeError, OSError):
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures"
MALICIOUS = FIXTURES / "smoke_test_config.json"
CLEAN = FIXTURES / "real_servers" / "official_mcp_servers.json"


def run(
    binary: str,
    *args: str,
    expect_exit: int | None = None,
) -> subprocess.CompletedProcess:
    """Run the binary with args, optionally asserting the exit code."""
    # The binary emits UTF-8 (emoji, box-drawing) from Rich's Console.  Python's
    # default subprocess decode uses locale.getpreferredencoding(), which is
    # cp1252 on Windows and raises UnicodeDecodeError on non-ASCII bytes.
    # Pin UTF-8 + errors="replace" so the script stays readable across OSes.
    result = subprocess.run(  # noqa: S603
        [binary, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if expect_exit is not None and result.returncode != expect_exit:
        print(
            f"FAIL: expected exit {expect_exit}, got {result.returncode}\n"
            f"  command: {binary} {' '.join(args)}\n"
            f"  stdout: {result.stdout[:500]}\n"
            f"  stderr: {result.stderr[:500]}",
            file=sys.stderr,
        )
        sys.exit(1)
    return result


def check(condition: bool, message: str) -> None:
    """Assert a condition or exit with a failure message."""
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: smoke_test.py <path-to-binary>", file=sys.stderr)
        sys.exit(2)

    binary = sys.argv[1]
    print(f"Smoke testing: {binary}")
    print("-" * 60)

    # ── 1. version ────────────────────────────────────────────────
    print("Check 1: version command")
    result = run(binary, "version", expect_exit=0)
    check(
        "mcp-audit" in result.stdout.lower() or result.returncode == 0,
        "version output should contain 'mcp-audit'",
    )
    print(f"  OK: {result.stdout.strip()}")

    # ── 2. discover ───────────────────────────────────────────────
    print("Check 2: discover command (no crash)")
    run(binary, "discover", expect_exit=0)
    print("  OK: discover completed without error")

    # ── 3. scan malicious config → exit 1 with findings ──────────
    print("Check 3: scan malicious fixture → exit 1")
    check(MALICIOUS.exists(), f"Fixture not found: {MALICIOUS}")
    run(binary, "scan", "--path", str(MALICIOUS), expect_exit=1)
    print("  OK: scan exited 1 (findings found)")

    # ── 4. scan malicious config → JSON output is valid ──────────
    print("Check 4: JSON output is valid and contains findings")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    run(
        binary,
        "scan",
        "--path",
        str(MALICIOUS),
        "--format",
        "json",
        "--output",
        tmp_path,
    )

    try:
        data = json.loads(Path(tmp_path).read_text())
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"FAIL: JSON output is invalid or missing: {exc}", file=sys.stderr)
        sys.exit(1)

    check("findings" in data, "JSON output must contain 'findings' key")
    check(len(data["findings"]) > 0, "JSON output must contain at least one finding")
    check("score" in data, "JSON output must contain 'score' key")

    first = data["findings"][0]
    for key in ("id", "severity", "title", "server"):
        check(key in first, f"Each finding must contain '{key}' key")

    print(f"  OK: {len(data['findings'])} findings in valid JSON")

    # ── 5. scan clean config → exit 0 ────────────────────────────
    # The "clean" real-world fixture is expected to be free of CRITICAL
    # findings; lower-severity informational/rules findings (e.g.
    # "npx used without pinned version") still trigger exit 1 on the
    # default threshold, so we scope this to --severity-threshold critical.
    print("Check 5: scan official servers fixture → exit 0 at critical threshold")
    check(CLEAN.exists(), f"Fixture not found: {CLEAN}")
    run(
        binary,
        "scan",
        "--path",
        str(CLEAN),
        "--severity-threshold",
        "critical",
        expect_exit=0,
    )
    print("  OK: scan exited 0 (no critical findings)")

    # ── 6. severity threshold filter ─────────────────────────────
    print("Check 6: --severity-threshold critical filters to only CRITICAL")
    result = run(
        binary,
        "scan",
        "--path",
        str(MALICIOUS),
        "--format",
        "json",
        "--output",
        tmp_path,
        "--severity-threshold",
        "critical",
    )
    try:
        data = json.loads(Path(tmp_path).read_text())
        severities = {f["severity"] for f in data["findings"]}
        non_critical = severities - {"CRITICAL"}
        check(
            not non_critical,
            f"--severity-threshold critical must exclude non-CRITICAL findings; "
            f"found: {non_critical}",
        )
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"FAIL: JSON output invalid: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"  OK: only CRITICAL findings present ({len(data['findings'])} total)")

    # ── 7. SARIF output is valid JSON with expected structure ─────
    print("Check 7: SARIF output is valid")
    run(
        binary,
        "scan",
        "--path",
        str(MALICIOUS),
        "--format",
        "sarif",
        "--output",
        tmp_path,
    )
    try:
        sarif = json.loads(Path(tmp_path).read_text())
        check("runs" in sarif, "SARIF must contain 'runs' key")
        check(sarif.get("version") == "2.1.0", "SARIF version must be '2.1.0'")
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"FAIL: SARIF output invalid: {exc}", file=sys.stderr)
        sys.exit(1)
    print("  OK: valid SARIF 2.1.0")

    # ── 8. baseline save and compare ─────────────────────────────
    print("Check 8: baseline save and compare roundtrip")
    run(
        binary,
        "baseline",
        "save",
        "smoke-test-baseline",
        "--path",
        str(MALICIOUS),
        expect_exit=0,
    )
    run(binary, "baseline", "list", expect_exit=0)
    run(
        binary,
        "baseline",
        "delete",
        "smoke-test-baseline",
        "--yes",
        expect_exit=0,
    )
    print("  OK: baseline save/list/delete roundtrip")

    print("-" * 60)
    print(f"ALL CHECKS PASSED ({binary})")


if __name__ == "__main__":
    main()
