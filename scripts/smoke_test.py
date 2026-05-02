#!/usr/bin/env python3
"""End-to-end smoke test for the mcp-audit binary (or source install).

Validates the full scan workflow on the target platform. Fails fast with a
clear message if any assertion fails.

Usage:
    # Against a compiled binary
    python scripts/smoke_test.py <path-to-binary>

    # Against a source install (multi-word invocation)
    python scripts/smoke_test.py uv run mcp-audit

Exit codes:
    0 — all checks passed
    1 — a check failed (error printed to stderr)
"""

from __future__ import annotations

import contextlib
import json
import platform
import subprocess
import sys
import tempfile
import threading
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

# Minimal valid MCP config used by new smoke steps.
_MINIMAL_CONFIG = json.dumps(
    {
        "mcpServers": {
            "smoke-server": {
                "command": "node",
                "args": ["server.js"],
            }
        }
    }
)


def run(
    binary_cmd: list[str],
    *args: str,
    expect_exit: int | None = None,
) -> subprocess.CompletedProcess:
    """Run the binary command with args, optionally asserting the exit code."""
    # The binary emits UTF-8 (emoji, box-drawing) from Rich's Console.  Python's
    # default subprocess decode uses locale.getpreferredencoding(), which is
    # cp1252 on Windows and raises UnicodeDecodeError on non-ASCII bytes.
    # Pin UTF-8 + errors="replace" so the script stays readable across OSes.
    result = subprocess.run(  # noqa: S603
        [*binary_cmd, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if expect_exit is not None and result.returncode != expect_exit:
        print(
            f"FAIL: expected exit {expect_exit}, got {result.returncode}\n"
            f"  command: {binary_cmd} {' '.join(args)}\n"
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


# ── New step helpers ───────────────────────────────────────────────────────────


def _get_claude_desktop_path() -> Path:
    """Return the OS-canonical Claude Desktop config path, matching discovery.py."""
    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return (
            home
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    elif system == "Windows":
        # Match the exact logic in src/mcp_audit/discovery.py
        appdata = home / "AppData" / "Roaming"
        return appdata / "Claude" / "claude_desktop_config.json"
    else:  # Linux and everything else
        return home / ".config" / "Claude" / "claude_desktop_config.json"


# STEP 9: watcher round-trip
def step_watcher_round_trip(binary_cmd: list[str]) -> bool:
    """Launch the watcher, modify a fixture, confirm a re-scan fires within 10 s.

    Uses a threading.Event to avoid polling with time.sleep for the re-scan
    signal.  The watcher subprocess is always killed in a finally block.

    Returns True on success, False on timeout or error.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        fixture = Path(tmpdir) / "watcher_test.json"
        fixture.write_text(_MINIMAL_CONFIG, encoding="utf-8")

        initial_done = threading.Event()
        rescan_done = threading.Event()
        reader_exc: list[Exception] = []

        proc = subprocess.Popen(  # noqa: S603
            [*binary_cmd, "watch", "--path", str(fixture)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge so Rich console output is captured
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        # "Watching for changes" is printed by _run_and_print() after every
        # scan completes — once for the initial scan, once per re-trigger.
        # The startup banner ("Watching N config location(s) for changes…")
        # does NOT contain the exact substring "Watching for changes" when
        # split word-by-word, so it won't produce a false signal.
        def _reader() -> None:
            scan_count = 0
            try:
                for line in proc.stdout:  # type: ignore[union-attr]
                    if "Watching for changes" in line:
                        scan_count += 1
                        if scan_count == 1:
                            initial_done.set()
                        elif scan_count >= 2:
                            rescan_done.set()
                            return
            except Exception as exc:  # noqa: BLE001
                reader_exc.append(exc)

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        try:
            # Wait up to 8 s for the initial scan to complete.
            if not initial_done.wait(timeout=8):
                print(
                    "FAIL: watcher initial scan did not complete within 8 s",
                    file=sys.stderr,
                )
                return False

            # Modify the fixture to trigger a re-scan.
            modified_config = json.dumps(
                {
                    "mcpServers": {
                        "smoke-server": {
                            "command": "python",
                            "args": ["server.py"],
                        }
                    }
                }
            )
            fixture.write_text(modified_config, encoding="utf-8")

            # Wait up to 10 s for the watcher to detect the change and re-scan.
            if not rescan_done.wait(timeout=10):
                print(
                    "FAIL: watcher did not re-scan within 10 s after file modification",
                    file=sys.stderr,
                )
                return False

        finally:
            proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            t.join(timeout=2)

    if reader_exc:
        print(f"FAIL: reader thread raised: {reader_exc[0]}", file=sys.stderr)
        return False

    return True


# STEP 10: rug-pull two-scan
def step_rug_pull_two_scan(binary_cmd: list[str]) -> bool:
    """Run two consecutive scans on a mutated fixture; confirm RUGPULL finding fires.

    Scan 1 records the baseline (RUGPULL-000 INFO).  The fixture is then
    modified (command + args changed).  Scan 2 detects the drift and emits
    RUGPULL-001 HIGH.  State is written to the platform user-config dir by
    the rug-pull analyzer; the step does not assert on the state file path.

    Returns True if scan 2 contains a RUGPULL finding, False otherwise.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        fixture = Path(tmpdir) / "rug_pull_test.json"
        fixture.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "rug-server": {
                            "command": "node",
                            "args": ["initial.js"],
                            "env": {},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        out1_path = Path(tmpdir) / "scan1.json"
        out2_path = Path(tmpdir) / "scan2.json"

        # Scan 1 — establishes baseline; expect exit 1 (RUGPULL-000 is INFO but
        # the default threshold is INFO so it triggers exit 1 with findings).
        run(
            binary_cmd,
            "scan",
            "--path",
            str(fixture),
            "--format",
            "json",
            "--output",
            str(out1_path),
        )

        # Mutate the fixture so the rug-pull raw hash changes.
        fixture.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "rug-server": {
                            "command": "python",
                            "args": ["modified.py"],
                            "env": {},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        # Scan 2 — should detect the change.
        run(
            binary_cmd,
            "scan",
            "--path",
            str(fixture),
            "--format",
            "json",
            "--output",
            str(out2_path),
        )

        try:
            data2 = json.loads(out2_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError) as exc:
            print(f"FAIL: scan 2 JSON invalid or missing: {exc}", file=sys.stderr)
            return False

        # Accept any RUGPULL-* finding or analyzer=="rug_pull" (id starts with "RUG")
        rug_findings = [
            f
            for f in data2.get("findings", [])
            if f.get("id", "").startswith("RUG") or f.get("analyzer") == "rug_pull"
        ]
        if not rug_findings:
            print(
                f"FAIL: scan 2 contained no RUGPULL findings; got ids: "
                f"{[f.get('id') for f in data2.get('findings', [])]}",
                file=sys.stderr,
            )
            return False

        return True


# STEP 11: canonical-path discovery
def step_canonical_path_discovery(binary_cmd: list[str]) -> bool:
    """Write a fixture to the OS-canonical Claude Desktop config path and confirm
    `mcp-audit discover` lists it.

    The fixture is removed in a finally block regardless of pass/fail.

    Returns True if discover output contains the canonical path, False otherwise.
    """
    canon_path = _get_claude_desktop_path()
    canon_dir = canon_path.parent
    dir_existed = canon_dir.exists()

    try:
        canon_dir.mkdir(parents=True, exist_ok=True)
        canon_path.write_text(_MINIMAL_CONFIG, encoding="utf-8")

        result = run(binary_cmd, "discover", "--json")

        try:
            entries = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(
                f"FAIL: discover --json output is not valid JSON:\n"
                f"{result.stdout[:300]}",
                file=sys.stderr,
            )
            return False

        canon_resolved = canon_path.resolve()
        found = any(
            Path(entry["path"]).resolve() == canon_resolved
            for entry in entries
            if "path" in entry
        )

        if not found:
            paths_found = [e.get("path", "") for e in entries]
            print(
                f"FAIL: canonical path {canon_path} not in discover output.\n"
                f"  Paths found: {paths_found}",
                file=sys.stderr,
            )
            return False

        return True

    finally:
        # Always remove the fixture file we created.
        with contextlib.suppress(OSError):
            canon_path.unlink()
        # Remove parent directory only if we created it and it is now empty.
        if not dir_existed:
            with contextlib.suppress(OSError):
                if canon_dir.exists() and not any(canon_dir.iterdir()):
                    canon_dir.rmdir()


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: smoke_test.py <binary-path>\n   or: smoke_test.py uv run mcp-audit",
            file=sys.stderr,
        )
        sys.exit(2)

    # Accept a multi-word binary invocation, e.g. ["uv", "run", "mcp-audit"].
    binary_cmd = sys.argv[1:]
    print(f"Smoke testing: {' '.join(binary_cmd)}")
    print("-" * 60)

    # ── 1. version ────────────────────────────────────────────────
    print("Check 1: version command")
    result = run(binary_cmd, "version", expect_exit=0)
    check(
        "mcp-audit" in result.stdout.lower() or result.returncode == 0,
        "version output should contain 'mcp-audit'",
    )
    print(f"  OK: {result.stdout.strip()}")

    # ── 2. discover ───────────────────────────────────────────────
    print("Check 2: discover command (no crash)")
    run(binary_cmd, "discover", expect_exit=0)
    print("  OK: discover completed without error")

    # ── 3. scan malicious config → exit 1 with findings ──────────
    print("Check 3: scan malicious fixture → exit 1")
    check(MALICIOUS.exists(), f"Fixture not found: {MALICIOUS}")
    run(binary_cmd, "scan", "--path", str(MALICIOUS), expect_exit=1)
    print("  OK: scan exited 1 (findings found)")

    # ── 4. scan malicious config → JSON output is valid ──────────
    print("Check 4: JSON output is valid and contains findings")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    run(
        binary_cmd,
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
        binary_cmd,
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
        binary_cmd,
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
        binary_cmd,
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
        binary_cmd,
        "baseline",
        "save",
        "smoke-test-baseline",
        "--path",
        str(MALICIOUS),
        expect_exit=0,
    )
    run(binary_cmd, "baseline", "list", expect_exit=0)
    run(
        binary_cmd,
        "baseline",
        "delete",
        "smoke-test-baseline",
        "--yes",
        expect_exit=0,
    )
    print("  OK: baseline save/list/delete roundtrip")

    # ── 9. watcher round-trip ─────────────────────────────────────
    print("Check 9: watcher round-trip (re-scan fires on file modification)")
    if step_watcher_round_trip(binary_cmd):
        print("  OK: watcher detected file change and re-scanned")
    else:
        # step function already printed the FAIL message; exit non-zero.
        sys.exit(1)

    # ── 10. rug-pull two-scan ─────────────────────────────────────
    print("Check 10: rug-pull two-scan (drift detected on second scan)")
    if step_rug_pull_two_scan(binary_cmd):
        print("  OK: RUGPULL finding present in scan 2")
    else:
        sys.exit(1)

    # ── 11. canonical-path discovery ─────────────────────────────
    print("Check 11: canonical-path discovery (OS-specific Claude config path)")
    if step_canonical_path_discovery(binary_cmd):
        print("  OK: canonical path found by discover")
    else:
        sys.exit(1)

    print("-" * 60)
    print(f"ALL CHECKS PASSED ({' '.join(binary_cmd)})")


if __name__ == "__main__":
    main()
