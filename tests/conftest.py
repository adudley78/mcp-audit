"""Shared pytest configuration and fixtures.

Historical note
---------------
mcp-audit was previously sold in Community/Pro/Enterprise tiers and a
``pro_enabled`` fixture was used to flip the Pro gate on in formatter tests.
As of the open-source conversion (Apache 2.0), gating has been removed and
every feature is available to every user.  ``pro_enabled`` is retained as a
no-op so test classes that already reference it keep collecting cleanly — it
does nothing and can be removed in a future cleanup.
"""

from __future__ import annotations

import pytest

from mcp_audit._license_cache import get_cached_license


@pytest.fixture(autouse=True)
def _clear_license_cache() -> None:
    """Clear the process-lifetime license cache before every test.

    Prevents lru_cache state from leaking between tests when
    ``mcp_audit.licensing.get_active_license`` is patched.
    """
    get_cached_license.cache_clear()
    yield  # type: ignore[misc]
    get_cached_license.cache_clear()


@pytest.fixture()
def pro_enabled() -> None:  # type: ignore[return]
    """Historical no-op fixture — all features are available to all users."""
    yield  # type: ignore[misc]
