"""Shared pytest configuration and fixtures.

Opt-in license gate fixture
-----------------------------
``pro_enabled`` patches ``is_pro_feature_available`` to return ``True`` in
the output modules, so formatter tests can call Pro/Enterprise formatters
without needing a real license key on the test machine.

Design decision — keep it **opt-in** (no ``autouse``):

* Tests that do *not* request ``pro_enabled`` run against the real (unlicensed)
  gating logic, which enables negative gate tests in ``test_pro_gating.py``.
* If a contributor accidentally removes a Pro gate from an output module the
  negative tests will catch it — they can only do so if the default state of
  ``is_pro_feature_available`` is the real, unlicensed implementation.
* Session-scope is intentionally avoided: a session-scoped fixture would be
  shared once activated, making isolation between positive and negative tests
  impossible within the same run.

Usage
-----
Add ``pro_enabled`` as a parameter to any test or fixture that exercises a
Pro/Enterprise output formatter::

    def test_something(pro_enabled):
        html = generate_html(scan_result)
        assert html is not None

For test classes that have ``setup_method`` calling a gated formatter, add a
class-level autouse fixture so the patch is active before ``setup_method``::

    class TestMyClass:
        @pytest.fixture(autouse=True)
        def _pro(self, pro_enabled):
            pass
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture()
def pro_enabled() -> None:  # type: ignore[return]
    """Patch is_pro_feature_available to return True for all Pro/Enterprise keys.

    Opt-in only — do not make autouse. Tests that don't request this fixture
    run with real (unlicensed) gating behaviour, enabling negative gate tests.
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
