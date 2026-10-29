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


def choose(current: str | None, fixes: tuple[str, ...]) -> tuple[str | None, str]:
    """``(version, "")`` to pin to, or ``(None, reason)``.

    The lowest fixed version above *current* (a release, not a pre-release),
    so a backport on the server's own line wins over a newer major.  With no
    known current version only a single fix is unambiguous.
    """
    if not fixes:
        return None, "the advisory records no fixed version"
    parsed = [(v, _version(v)) for v in fixes]
    usable = [(raw, ver) for raw, ver in parsed if ver is not None]
    if not usable:
        return None, "none of the advisory's fixed versions can be ordered"
    releases = [(r, v) for r, v in usable if not v.is_prerelease] or usable
    if current is None:
        if len(releases) == 1:
            return releases[0][0], ""
        return None, "no version is known and the advisory lists several fixes"
    here = _version(current)
    if here is None:
        return None, f"{current} cannot be ordered against the fixed versions"
    if any(_schemes_differ(current, raw) for raw, _ in releases):
        return None, (
            "the fixed version uses a different numbering scheme (calendar versus "
            "semantic), so it cannot be ordered offline"
        )
    above = sorted((v, raw) for raw, v in releases if v > here)
    if not above:
        return None, f"no fixed version is above {current}"
    return above[0][1], ""
