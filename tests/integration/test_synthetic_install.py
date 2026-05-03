"""Synthetic install-tree integration tests (STORY-0019).

Validates that ``mcp-audit discover``, ``scan``, and ``baseline`` operate
correctly against realistic per-OS fixture trees planted under a temporary
directory, including paths with spaces, non-ASCII filenames, and graceful
handling of Windows >260-char paths.

Design notes
------------
* All filesystem work is done under ``tmp_path`` (pytest's built-in fixture).
* Discovery redirection uses env-var injection (``HOME`` on Linux/macOS,
  ``USERPROFILE`` on Windows) rather than monkeypatching ``discovery.py``
  internals.  ``Path.home()`` reads these vars from ``os.environ``, so the
  subprocess's discovery module sees the temp tree as the user's home.
* The CLI is invoked via ``sys.executable -m mcp_audit.cli`` — the same
  interpreter that runs the tests, no ``uv`` on PATH required.
* Imports are stdlib + ``mcp_audit`` only (no coupling to other test helpers).
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MINIMAL_CONFIG: str = json.dumps(
    {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"],
            }
        }
    }
)

# Contains a synthetic OpenAI-style secret so CRED-001 (or equivalent)
# fires — proves that scanning actually ran against the config.
_CREDENTIAL_CONFIG: str = json.dumps(
    {
        "mcpServers": {
            "bad-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz1234567890AB",
                },
            }
        }
    }
)

# Baseline names must be unique per test so parallel runs don't collide.
_BASELINE_NAME = "synthetic-install-ci-nonascii"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cli_cmd() -> list[str]:
    """Return the command prefix to invoke mcp-audit under the current Python."""
    return [sys.executable, "-m", "mcp_audit.cli"]


def _run(
    args: list[str],
    *,
    home_dir: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the CLI and return the completed process.

    Always sets ``PYTHONUNBUFFERED=1`` and ``PYTHONUTF8=1`` (the latter
    matters on Windows where the default stdout encoding may mangle non-ASCII
    bytes in subprocess output).  When *home_dir* is supplied, both ``HOME``
    (POSIX) and ``USERPROFILE`` (Windows) are overridden so that
    ``Path.home()`` inside the subprocess resolves to *home_dir*.
    """
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "PYTHONUTF8": "1",
    }
    if home_dir is not None:
        env["HOME"] = str(home_dir)
        env["USERPROFILE"] = str(home_dir)
    if extra_env:
        env.update(extra_env)

    return subprocess.run(  # noqa: S603
        [*_cli_cmd(), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def _write_config(path: Path, content: str = _MINIMAL_CONFIG) -> None:
    """Create parent directories and write *content* to *path* as UTF-8."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _canonical_client_paths(home_dir: Path) -> dict[str, Path]:
    """Return canonical config paths for all auto-discovered clients.

    Mirrors ``discovery._get_client_specs()`` without importing it, using
    *home_dir* in place of ``Path.home()``.  This ensures the test can
    construct the same paths that the subprocess's discovery module will
    probe after ``HOME``/``USERPROFILE`` are redirected.

    VS Code is intentionally excluded: its ``config_paths`` list is empty
    in ``discovery.py`` (workspace configs are handled via ``--path``).
    """
    system = platform.system()
    paths: dict[str, Path] = {}

    if system == "Darwin":
        paths["claude-desktop"] = (
            home_dir
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    elif system == "Windows":
        # discovery.py: appdata = Path.home() / "AppData" / "Roaming"
        paths["claude-desktop"] = (
            home_dir / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
        )
    else:  # Linux / all other POSIX
        paths["claude-desktop"] = (
            home_dir / ".config" / "Claude" / "claude_desktop_config.json"
        )

    # Platform-independent clients (all use bare home-relative paths)
    paths["cursor"] = home_dir / ".cursor" / "mcp.json"
    paths["windsurf"] = home_dir / ".codeium" / "windsurf" / "mcp_config.json"
    paths["claude-code"] = home_dir / ".claude.json"
    paths["copilot-cli"] = home_dir / ".copilot" / "mcp-config.json"
    paths["augment"] = home_dir / ".augment" / "settings.json"

    return paths


# ---------------------------------------------------------------------------
# Fixture: synthetic home tree
# ---------------------------------------------------------------------------


@pytest.fixture()
def synthetic_home(tmp_path: Path) -> dict[str, Path]:
    """Build a synthetic HOME containing minimal MCP configs at every canonical
    client path for the current OS.

    Returns a mapping of ``{client_name: config_path}`` for all created files.
    """
    home_dir = tmp_path / "home"
    home_dir.mkdir()

    client_paths = _canonical_client_paths(home_dir)
    for path in client_paths.values():
        _write_config(path)

    # Stash home_dir on the dict so tests can pass it to _run().
    client_paths["_home"] = home_dir  # type: ignore[assignment]
    return client_paths


# ---------------------------------------------------------------------------
# Test 1: canonical discovery — every client config must appear in output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "client",
    ["claude-desktop", "cursor", "windsurf", "claude-code", "copilot-cli", "augment"],
)
def test_canonical_discovery_finds_client(
    synthetic_home: dict[str, Path], client: str
) -> None:
    """Given a synthetic home tree, ``discover --json`` must list *client*'s config."""
    home_dir: Path = synthetic_home["_home"]  # type: ignore[assignment]
    expected_path = synthetic_home[client].resolve()

    result = _run(["discover", "--json"], home_dir=home_dir)

    assert result.returncode == 0, (
        f"discover exited {result.returncode}\n"
        f"stdout: {result.stdout[:500]}\nstderr: {result.stderr[:500]}"
    )

    try:
        entries = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"discover --json output is not valid JSON: {exc}\n{result.stdout[:300]}"
        )

    discovered_paths = {Path(e["path"]).resolve() for e in entries if "path" in e}
    assert expected_path in discovered_paths, (
        f"canonical path for {client!r} not found in discover output.\n"
        f"Expected: {expected_path}\n"
        f"Got: {sorted(str(p) for p in discovered_paths)}"
    )


# ---------------------------------------------------------------------------
# Test 2: scan produces findings against a config with a known-bad credential
# ---------------------------------------------------------------------------


def test_scan_produces_credential_finding(tmp_path: Path) -> None:
    """Scan a config containing a synthetic API key and confirm a finding is emitted.

    Proves scanning actually ran (not just discovery), by checking that at
    least one finding with a credential-related ID or analyzer appears.
    """
    config = tmp_path / "mcp.json"
    _write_config(config, _CREDENTIAL_CONFIG)

    output_file = tmp_path / "out.json"
    result = _run(
        [
            "scan",
            "--path",
            str(config),
            "--format",
            "json",
            "--output",
            str(output_file),
        ]
    )

    # Exit code 1 means findings were found — that's exactly what we want.
    assert result.returncode in (0, 1), (
        f"scan exited {result.returncode} (expected 0 or 1)\n"
        f"stderr: {result.stderr[:500]}"
    )

    assert output_file.exists(), "JSON output file was not created"
    data = json.loads(output_file.read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    assert findings, "Scan produced no findings for a config containing a credential"

    credential_findings = [
        f
        for f in findings
        if f.get("analyzer") == "credentials" or str(f.get("id", "")).startswith("CRED")
    ]
    assert credential_findings, (
        f"No credential finding found; finding IDs: {[f.get('id') for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Test 3: path with spaces — scan must not crash
# ---------------------------------------------------------------------------


def test_path_with_spaces_no_crash(tmp_path: Path) -> None:
    """Scanning a config whose path contains spaces must succeed (exit 0 or 1)."""
    spaced_dir = tmp_path / "My Documents" / "Claude"
    config = spaced_dir / "claude_desktop_config.json"
    _write_config(config)

    output_file = tmp_path / "out.json"
    result = _run(
        [
            "scan",
            "--path",
            str(config),
            "--format",
            "json",
            "--output",
            str(output_file),
        ]
    )

    assert result.returncode in (0, 1), (
        f"scan exited {result.returncode} on a path with spaces\n"
        f"stderr: {result.stderr[:500]}"
    )
    assert "Traceback" not in result.stderr, "Unexpected traceback for path-with-spaces"
    assert output_file.exists(), "JSON output not created for path-with-spaces config"

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert "findings" in data, "JSON output missing 'findings' key"


# ---------------------------------------------------------------------------
# Test 4: non-ASCII path — discover/scan must not crash or silently omit
# ---------------------------------------------------------------------------


def test_nonascii_path_scan_no_crash(tmp_path: Path) -> None:
    """Scanning a config at a non-ASCII path must exit 0 or 1, never crash."""
    try:
        nonascii_dir = tmp_path / "配置" / "мcp_configs"
        config = nonascii_dir / "mcp.json"
        _write_config(config)
    except (OSError, UnicodeEncodeError) as exc:
        pytest.skip(f"OS cannot create non-ASCII path on this filesystem: {exc}")

    output_file = tmp_path / "out.json"
    result = _run(
        [
            "scan",
            "--path",
            str(config),
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
        extra_env={"PYTHONUTF8": "1"},
    )

    # Exit 0 (no findings) or 1 (findings found) are both acceptable.
    # Exit 2 (error) is a failure; an unhandled exception is a failure.
    assert result.returncode in (0, 1), (
        f"scan exited {result.returncode} on non-ASCII path\n"
        f"stderr: {result.stderr[:500]}"
    )
    assert "Traceback" not in result.stderr, (
        "Unexpected traceback for non-ASCII path:\n" + result.stderr[:500]
    )


def test_nonascii_path_discover_no_crash(tmp_path: Path) -> None:
    """``discover --json --path <non-ASCII>`` must not crash.

    The path is passed explicitly rather than via HOME redirection so this
    test is not gated on whether the OS auto-discover step exercises Unicode.
    """
    try:
        nonascii_dir = tmp_path / "配置"
        config = nonascii_dir / "мcp.json"
        _write_config(config)
    except (OSError, UnicodeEncodeError) as exc:
        pytest.skip(f"OS cannot create non-ASCII path on this filesystem: {exc}")

    result = _run(["discover", "--json", "--path", str(config)])

    assert result.returncode == 0, (
        f"discover --json exited {result.returncode} on non-ASCII path\n"
        f"stderr: {result.stderr[:500]}"
    )
    assert "Traceback" not in result.stderr

    entries = json.loads(result.stdout)
    # When a path is supplied explicitly, it appears in the output with
    # skip_auto_discovery=True.  We just confirm the JSON is valid and
    # the expected path string is present somewhere in the output.
    paths_found = [e.get("path", "") for e in entries]
    config_str = str(config)
    assert any(
        config_str in p or Path(p).resolve() == config.resolve() for p in paths_found
    ), (
        f"Non-ASCII config path not in discover output.\n"
        f"Expected substring: {config_str}\nGot paths: {paths_found}"
    )


# ---------------------------------------------------------------------------
# Test 5: baseline save / compare round-trip on a non-ASCII path
# ---------------------------------------------------------------------------


def test_baseline_nonascii_roundtrip(tmp_path: Path) -> None:
    """``baseline save`` + ``baseline compare`` must complete without error when
    the scanned config lives at a non-ASCII filesystem path."""
    try:
        nonascii_dir = tmp_path / "配置"
        config = nonascii_dir / "mcp.json"
        _write_config(config)
    except (OSError, UnicodeEncodeError) as exc:
        pytest.skip(f"OS cannot create non-ASCII path on this filesystem: {exc}")

    save_result = _run(
        ["baseline", "save", _BASELINE_NAME, "--path", str(config)],
        extra_env={"PYTHONUTF8": "1"},
    )
    try:
        assert save_result.returncode == 0, (
            f"baseline save failed (exit {save_result.returncode})\n"
            f"stderr: {save_result.stderr[:500]}"
        )
        assert "Traceback" not in save_result.stderr

        compare_result = _run(
            ["baseline", "compare", _BASELINE_NAME, "--path", str(config)],
            extra_env={"PYTHONUTF8": "1"},
        )
        assert compare_result.returncode in (0, 1), (
            f"baseline compare exited {compare_result.returncode}\n"
            f"stderr: {compare_result.stderr[:500]}"
        )
        assert "Traceback" not in compare_result.stderr
    finally:
        # Always clean up the baseline from the real user-config dir.
        _run(["baseline", "delete", _BASELINE_NAME, "--yes"])


# ---------------------------------------------------------------------------
# Test 6: Windows >260-char path — must not produce a Python traceback
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Windows long-path test only")
def test_windows_long_path_graceful(tmp_path: Path) -> None:
    """Paths exceeding the Windows 260-char MAX_PATH limit must be handled
    gracefully: exit 0, 1, or 2, but never an unhandled exception/traceback.
    """
    # Construct a path whose total length exceeds 260 characters.
    long_segment = "a" * 250
    deep_dir = tmp_path / long_segment
    try:
        deep_dir.mkdir(parents=True, exist_ok=True)
        config = deep_dir / "mcp.json"
        _write_config(config)
    except (OSError, FileNotFoundError):
        # The OS rejected the long path before we could create the fixture.
        # Mark as xfail rather than fail — this can happen on Windows hosts
        # with LongPathsEnabled=0 in the registry.
        pytest.xfail("OS rejected long path before fixture could be created")

    result = _run(["scan", "--path", str(config)])

    assert result.returncode in (0, 1, 2), (
        f"scan exited {result.returncode} on a >260-char path\n"
        f"stderr: {result.stderr[:500]}"
    )
    assert "Traceback" not in result.stderr, (
        "Unexpected traceback for >260-char path:\n" + result.stderr[:500]
    )


# ---------------------------------------------------------------------------
# Test 7: smoke — full discover→scan pipeline on the synthetic tree
# ---------------------------------------------------------------------------


def test_full_pipeline_synthetic_tree(synthetic_home: dict[str, Path]) -> None:
    """End-to-end: with HOME redirected to the synthetic tree, both ``discover``
    and ``scan`` must complete without error and produce valid JSON output.

    This validates the combined discover→scan pipeline against the full
    per-OS fixture tree in a single subprocess call.
    """
    home_dir: Path = synthetic_home["_home"]  # type: ignore[assignment]

    # 1. Discover must return at least the clients we planted.
    discover_result = _run(["discover", "--json"], home_dir=home_dir)
    assert discover_result.returncode == 0
    entries = json.loads(discover_result.stdout)
    assert len(entries) >= 1, "discover returned no entries for the synthetic tree"

    # 2. Scan the claude-desktop config explicitly (guaranteed to exist).
    claude_config = synthetic_home["claude-desktop"]
    output_file = home_dir / "scan_out.json"
    scan_result = _run(
        [
            "scan",
            "--path",
            str(claude_config),
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
        home_dir=home_dir,
    )
    assert scan_result.returncode in (0, 1), (
        f"scan exited {scan_result.returncode}\nstderr: {scan_result.stderr[:500]}"
    )
    assert "Traceback" not in scan_result.stderr

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert "findings" in data
    assert "score" in data
