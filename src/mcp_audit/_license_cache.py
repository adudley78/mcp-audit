"""Thin process-lifetime cache for get_active_license().

licensing.py is marked do-not-modify.  This shim wraps get_active_license()
with functools.lru_cache so the license file is read and Ed25519-verified at
most once per process, regardless of how many times is_pro_feature_available()
is called.
"""

from __future__ import annotations

import functools

import mcp_audit.licensing as _licensing_mod
from mcp_audit.licensing import _FEATURE_TIERS, LicenseInfo


@functools.lru_cache(maxsize=1)
def get_cached_license() -> LicenseInfo | None:
    """Return the active license, reading and verifying it at most once per process.

    Calls through the module attribute so that tests can patch
    ``mcp_audit.licensing.get_active_license`` without bypassing the cache.
    """
    return _licensing_mod.get_active_license()


def cached_is_pro_feature_available(feature_name: str) -> bool:
    """Return True if the cached active license includes *feature_name*.

    Mirrors the logic of licensing.is_pro_feature_available() but uses the
    cached result of get_active_license() instead of re-reading the file.

    Args:
        feature_name: A feature key from ``_FEATURE_TIERS``.

    Returns:
        ``True`` when the active, unexpired license tier includes the feature.
        ``False`` for an unrecognised feature, no license, or expired license.
    """
    required_tiers = _FEATURE_TIERS.get(feature_name)
    if required_tiers is None:
        return False

    info = get_cached_license()
    if info is None or not info.is_valid:
        return False

    return info.tier in required_tiers
