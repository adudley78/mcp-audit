"""No-op shim for the legacy Pro/Enterprise feature gate.

mcp-audit is now fully open source (Apache 2.0) and every feature is
available to every user.  :func:`gate` is retained as a no-op so existing
call sites of the form ``if not gate("feature", console): ...`` continue to
compile and simply fall through to the feature implementation.
"""

from __future__ import annotations

from rich.console import Console


def gate(
    feature: str,  # noqa: ARG001
    console: Console | None = None,  # noqa: ARG001
    message: str | None = None,  # noqa: ARG001
) -> bool:
    """Return ``True`` unconditionally — mcp-audit is fully open source.

    The original implementation rendered an upsell panel when a feature was
    not available under the active license.  Gating has been removed; all
    features are available to every user.  The signature is kept so existing
    call sites (``if not gate("feature", console): ...``) keep working.
    """
    return True
