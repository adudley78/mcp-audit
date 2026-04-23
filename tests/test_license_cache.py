"""Tests for the process-lifetime license cache shim.

After the open-source conversion (Apache 2.0), ``cached_is_pro_feature_available``
always returns ``True``.  The ``get_cached_license`` lru_cache is still live
because ``mcp-audit license`` / ``mcp-audit version`` read it to display
information about previously activated keys.
"""

from __future__ import annotations

from datetime import date
from unittest.mock import patch

from mcp_audit.licensing import LicenseInfo


def _make_license(tier: str = "pro") -> LicenseInfo:
    today = date.today()
    return LicenseInfo(
        tier=tier,  # type: ignore[arg-type]
        email="test@example.com",
        issued=today,
        expires=date(today.year + 1, today.month, today.day),
        is_valid=True,
    )


class TestGetCachedLicense:
    def test_get_cached_license_called_once(self) -> None:
        """get_active_license() must be invoked exactly once across multiple calls."""
        import mcp_audit._license_cache as cache_mod

        with patch(
            "mcp_audit.licensing.get_active_license",
            return_value=_make_license(),
        ) as mock_get:
            result1 = cache_mod.get_cached_license()
            result2 = cache_mod.get_cached_license()
            result3 = cache_mod.get_cached_license()

        assert mock_get.call_count == 1
        assert result1 is result2 is result3

    def test_returns_none_when_no_license(self) -> None:
        import mcp_audit._license_cache as cache_mod

        with patch(
            "mcp_audit.licensing.get_active_license",
            return_value=None,
        ):
            result = cache_mod.get_cached_license()

        assert result is None


class TestCachedIsProFeatureAvailable:
    """After the open-source conversion the helper always returns ``True``."""

    def test_returns_true_when_no_license(self) -> None:
        import mcp_audit._license_cache as cache_mod

        with patch("mcp_audit.licensing.get_active_license", return_value=None):
            assert cache_mod.cached_is_pro_feature_available("dashboard") is True
            assert cache_mod.cached_is_pro_feature_available("custom_rules") is True

    def test_returns_true_for_unknown_feature(self) -> None:
        import mcp_audit._license_cache as cache_mod

        assert cache_mod.cached_is_pro_feature_available("nonexistent_feature") is True

    def test_returns_true_for_expired_license(self) -> None:
        """Even expired keys no longer gate anything."""
        import mcp_audit._license_cache as cache_mod

        expired = LicenseInfo(
            tier="pro",
            email="test@example.com",
            issued=date(2020, 1, 1),
            expires=date(2020, 12, 31),
            is_valid=False,
        )

        with patch("mcp_audit.licensing.get_active_license", return_value=expired):
            assert cache_mod.cached_is_pro_feature_available("dashboard") is True
