"""Tests for the ``mcp-audit`` entry dispatcher and the lean ``run`` path."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.runtime.cli import parse_command

#: Modules that must never load on the ``run`` launch path (EPIC-0009:
#: "run must not import the scanner, analyzers or registry loader").
HEAVY = (
    "mcp_audit.cli",
    "mcp_audit.scanner",
    "mcp_audit.analyzers",
    "mcp_audit.registry.loader",
    "typer",
    "rich",
    "pydantic",
    "importlib.metadata",
)


def test_run_path_imports_nothing_heavy() -> None:
    probe = (
        "import json, os, sys\n"
        "sys.argv = ['mcp-audit', 'run', '--', sys.executable, '-c', 'pass']\n"
        "from mcp_audit import _entry\n"
        "os._exit = sys.exit\n"  # `run` leaves with os._exit; keep the probe alive
        "try:\n"
        "    _entry.main()\n"
        "except SystemExit:\n"
        "    pass\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    loaded = json.loads(out.stdout.splitlines()[-1])
    offenders = [
        m for m in loaded if any(m == h or m.startswith(h + ".") for h in HEAVY)
    ]
    assert offenders == []


def test_other_commands_still_dispatch_to_typer() -> None:
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_audit._entry", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",  # Rich output is UTF-8; Windows defaults to cp1252
        timeout=60,
    )
    assert out.returncode == 0
    assert "scan" in out.stdout


def test_typer_run_command_forwards_to_lean_path() -> None:
    # Driven through the Typer app directly (not the dispatcher), in a real
    # process so the relay has real stdio descriptors.
    probe = (
        "import sys\n"
        "from mcp_audit.cli import app\n"
        "sys.argv = ['mcp-audit', 'run', '--', sys.executable, '-c',\n"
        "            'import sys; print(sys.argv[1:]); sys.exit(4)', '--help']\n"
        "app()\n"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert out.returncode == 4
    assert out.stdout.strip() == "['--help']"


def test_run_listed_in_typer_help() -> None:
    names = {cmd.name for cmd in app.registered_commands}
    assert "run" in names
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--", "npx", "-y", "pkg"], ["npx", "-y", "pkg"]),
        (["npx", "-y", "pkg"], ["npx", "-y", "pkg"]),
        (["--", "srv", "--", "x"], ["srv", "--", "x"]),
        (["--", "srv", "--help"], ["srv", "--help"]),
        ([], None),
    ],
)
def test_parse_command(argv: list[str], expected: list[str] | None) -> None:
    assert parse_command(argv) == expected


def test_unknown_wrapper_flag_rejected() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_command(["--bogus", "--", "srv"])
    assert exc.value.code == 2


def test_version_still_resolves_lazily() -> None:
    import mcp_audit
    from mcp_audit import __version__

    assert __version__ == mcp_audit.__version__
    assert __version__ != ""
    with pytest.raises(AttributeError):
        _ = mcp_audit.no_such_attribute  # type: ignore[attr-defined]


def test_run_leaves_without_tearing_the_interpreter_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A server that exits at once must not crash the wrapper at exit.

    ``run`` loads the poisoning check on a daemon thread; a normal exit while
    that thread still imports extension modules died with SIGABRT or SIGSEGV
    (4 of 200 launches on a loaded machine).  The entry point leaves with
    ``os._exit`` and the server's own exit code.
    """
    from mcp_audit import _entry

    left: list[int] = []

    def fake_exit(code: int) -> None:
        left.append(code)
        raise SystemExit(code)

    monkeypatch.setattr("os._exit", fake_exit)
    monkeypatch.setattr("mcp_audit.runtime.cli.main", lambda argv: 7)
    monkeypatch.setattr(sys, "argv", ["credenzo", "run", "--", "server"])
    with pytest.raises(SystemExit):
        _entry.main()
    assert left == [7]


def test_other_commands_exit_the_normal_way(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_audit import _entry

    def fail(code: int) -> None:  # pragma: no cover - must not be called
        raise AssertionError("os._exit called for a non-run command")

    monkeypatch.setattr("os._exit", fail)
    monkeypatch.setattr(sys, "argv", ["credenzo", "version"])
    with pytest.raises(SystemExit) as stop:
        _entry.main()
    assert stop.value.code in (0, None)
