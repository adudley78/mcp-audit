"""Shared pytest configuration and fixtures.

Historical note
---------------
mcp-audit was previously sold in Community/Pro/Enterprise tiers.  The
``pro_enabled`` fixture was used to flip the Pro gate on in formatter tests.
Gating has been removed entirely (all features are available to all users);
``pro_enabled`` is retained as a no-op so test classes that already reference
it keep collecting cleanly.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def pro_enabled() -> None:  # type: ignore[return]
    """Historical no-op fixture — all features are available to all users."""
    yield  # type: ignore[misc]
