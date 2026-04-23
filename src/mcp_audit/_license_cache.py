"""Thin process-lifetime cache for get_active_license().

mcp-audit is now fully open source; all features are available to every user
and :func:`cached_is_pro_feature_available` always returns ``True``.  The
cached license lookup is retained so ``mcp-audit license`` / ``mcp-audit
version`` can still display details for users who previously activated a key.
"""

from __future__ import annotations

import functools

import mcp_audit.licensing as _licensing_mod
from mcp_audit.licensing import LicenseInfo, is_pro_feature_available


@functools.lru_cache(maxsize=1)
def get_cached_license() -> LicenseInfo | None:
    """Return the active license, reading and verifying it at most once per process.

    Calls through the module attribute so that tests can patch
    ``mcp_audit.licensing.get_active_license`` without bypassing the cache.
    """
    return _licensing_mod.get_active_license()


def cached_is_pro_feature_available(feature_name: str) -> bool:
    """Return ``True`` — all features are available.

    Thin delegator to :func:`mcp_audit.licensing.is_pro_feature_available`,
    retained as the integration point for existing test patches at
    ``mcp_audit.cli.cached_is_pro_feature_available``.
    """
    return is_pro_feature_available(feature_name)
