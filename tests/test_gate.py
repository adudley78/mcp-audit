"""Tests for ``mcp_audit._gate.gate`` — the shared Pro feature gate helper.

The gate helper is the single entry point for CLI-layer Pro/Enterprise
feature checks.  A future contributor adding a new Pro flag should call
``gate()`` instead of repeating the upsell panel inline.
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from rich.console import Console

from mcp_audit._gate import gate


def _make_console() -> tuple[Console, StringIO]:
    """Return a Rich console that writes into a ``StringIO`` buffer."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, color_system=None, width=120)
    return console, buf


class TestGate:
    def test_gate_returns_true_when_licensed(self) -> None:
        """When the feature is available the helper must be silent."""
        console, buf = _make_console()
        with patch(
            "mcp_audit.cli.cached_is_pro_feature_available",
            return_value=True,
        ) as mock_gate:
            result = gate("sast", console)

        assert result is True
        assert buf.getvalue() == ""
        mock_gate.assert_called_once_with("sast")

    def test_gate_returns_false_when_unlicensed(self) -> None:
        """Unlicensed callers must see ``False`` plus the upsell panel."""
        console, buf = _make_console()
        with patch(
            "mcp_audit.cli.cached_is_pro_feature_available",
            return_value=False,
        ):
            result = gate("sast", console)

        output = buf.getvalue()
        assert result is False
        assert "Pro feature required" in output
        assert "Pro or Enterprise license" in output
        assert "mcp-audit activate" in output

    def test_gate_includes_custom_message(self) -> None:
        """The optional *message* argument is rendered below the panel body."""
        console, buf = _make_console()
        with patch(
            "mcp_audit.cli.cached_is_pro_feature_available",
            return_value=False,
        ):
            result = gate(
                "sast",
                console,
                message="--sast requires Pro",
            )

        output = buf.getvalue()
        assert result is False
        assert "--sast requires Pro" in output

    def test_gate_without_message_has_no_trailing_dim_line(self) -> None:
        """When *message* is absent, only the upsell body is rendered."""
        console, buf = _make_console()
        with patch(
            "mcp_audit.cli.cached_is_pro_feature_available",
            return_value=False,
        ):
            gate("sast", console)

        output = buf.getvalue()
        # The dim message separator only appears when message= is supplied.
        assert "--" not in output or "----" in output  # allow panel borders

    def test_gate_passes_feature_key_verbatim(self) -> None:
        """The *feature* argument must reach the cached helper unchanged."""
        console, _ = _make_console()
        with patch(
            "mcp_audit.cli.cached_is_pro_feature_available",
            return_value=True,
        ) as mock_gate:
            gate("custom_rules", console)

        mock_gate.assert_called_once_with("custom_rules")
