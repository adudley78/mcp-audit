"""Choose the version ``affected --fix`` pins a server to (STORY-0127).

The advisory supplies the fix, so no network call is needed.  The rule is
deliberately cautious: pick the lowest fixed version above the one the server
runs; when that cannot be decided, say why and change nothing.  A pin is never
written unless the advisory's own rules then say the server is clear.
"""

from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from mcp_audit.analyzers.supply_chain import _schemes_differ


@dataclass(frozen=True)
class Pin:
    """One server to pin, or the reason it is skipped."""

    subject: str
    config_path: str
    server_name: str
    package: str
    current: str | None
    target: str | None = None
    skipped: str | None = None


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def crosses_major(current: str | None, target: str) -> bool:
    """Does pinning to *target* move to a different major version?"""
    a, b = (_version(current) if current else None), _version(target)
    return a is not None and b is not None and a.major != b.major


def candidates(current: str | None, fixes: tuple[str, ...]) -> tuple[list[str], str]:
    """Fixed versions to try, lowest first, or ``([], reason)``.

    Fixed releases above *current* (pre-releases only when no release exists).
    With no known current version only a single fix is unambiguous.
    """
    if not fixes:
        return [], "the advisory records no fixed version"
    usable = [(raw, v) for raw in fixes if (v := _version(raw)) is not None]
    if not usable:
        return [], "none of the advisory's fixed versions can be ordered"
    releases = [(r, v) for r, v in usable if not v.is_prerelease] or usable
    if current is None:
        if len(releases) == 1:
            return [releases[0][0]], ""
        return [], "no version is known and the advisory lists several fixes"
    here = _version(current)
    if here is None:
        return [], f"{current} cannot be ordered against the fixed versions"
    if any(_schemes_differ(current, raw) for raw, _ in releases):
        return [], (
            "the fixed version uses a different numbering scheme (calendar versus "
            "semantic), so it cannot be ordered offline"
        )
    above = sorted((v, raw) for raw, v in releases if v > here)
    if not above:
        return [], f"no fixed version is above {current}"
    return [raw for _v, raw in above], ""


def choose(current: str | None, fixes: tuple[str, ...]) -> tuple[str | None, str]:
    """``(version, "")`` to pin to (the lowest candidate), or ``(None, reason)``."""
    found, why = candidates(current, fixes)
    return (found[0], "") if found else (None, why)
