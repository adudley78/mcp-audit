"""Tests for ``mcp_audit._gate.gate`` — now a no-op pass-through.

mcp-audit is fully open source (Apache 2.0) and every feature is available
to every user.  ``gate()`` is retained solely so the many existing call
sites of the form ``if not gate("feature", console): ...`` keep compiling
and fall through to the feature implementation.

These tests pin that contract: whatever is passed in, ``gate`` returns
``True`` and prints nothing.
"""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from mcp_audit._gate import gate


def _make_console() -> tuple[Console, StringIO]:
    """Return a Rich console that writes into a ``StringIO`` buffer."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, color_system=None, width=120)
    return console, buf


class TestGateNoop:
    def test_returns_true_for_any_feature(self) -> None:
        console, buf = _make_console()

        assert gate("sast", console) is True
        assert gate("nucleus", console) is True
        assert gate("fleet_merge", console) is True
        assert gate("definitely_not_a_feature_key", console) is True
        assert buf.getvalue() == ""

    def test_returns_true_without_console(self) -> None:
        """The console argument is optional now that gate prints nothing."""
        assert gate("sast") is True
        assert gate("nucleus", None) is True

    def test_message_is_ignored(self) -> None:
        """The legacy ``message=`` argument is accepted but never rendered."""
        console, buf = _make_console()

        assert gate("sast", console, message="--sast skipped.") is True
        assert buf.getvalue() == ""
