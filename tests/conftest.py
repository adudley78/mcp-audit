"""Shared pytest configuration and fixtures.

Provides a session-scoped autouse fixture that patches the Pro feature gate
in the output modules so existing formatter tests continue to work without
requiring a valid license file on the test machine.

Tests in test_licensing.py exercise the gate logic directly via monkeypatching
and are not affected by this fixture (they don't call the output formatters).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True, scope="session")
def _bypass_license_gate_in_output_modules() -> None:  # type: ignore[return]
    """Patch is_pro_feature_available to True in output modules for all tests.

    This keeps formatter tests independent of the license system.
    Tests that specifically exercise the gate (test_licensing.py) control
    _PUBLIC_KEY_BYTES directly and do not call the output formatters.
    """
    with (
        patch(
            "mcp_audit.output.dashboard.is_pro_feature_available",
            return_value=True,
        ),
        patch(
            "mcp_audit.output.nucleus.is_pro_feature_available",
            return_value=True,
        ),
    ):
        yield
