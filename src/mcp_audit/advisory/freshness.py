"""Feed freshness: TUF timestamp+snapshot collapsed into ``index.json``.

``snapshot_version`` and ``expires`` live only on the signed index. Advisory
records stay stock OSV 1.6.0. See ``docs/advisory-feed.md``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from platformdirs import user_config_dir

__all__ = [
    "DEFAULT_TTL_DAYS",
    "SNAPSHOT_VERSION_MAX",
    "Freshness",
    "FreshnessError",
    "age_days",
    "check_expiry",
    "check_rollback",
    "default_seen_path",
    "expires_from_ttl",
    "identity_key",
    "load_seen",
    "parse_freshness",
    "parse_utc",
    "record_seen",
    "resolve_snapshot_version",
    "save_seen",
]

DEFAULT_TTL_DAYS = 14
SNAPSHOT_VERSION_MAX = 2**31 - 1
_TS = "%Y-%m-%dT%H:%M:%SZ"


class FreshnessError(ValueError):
    """Feed failed a freshness check. The message is user-facing."""


@dataclass(frozen=True)
class Freshness:
    """Parsed ``index.json`` freshness fields."""

    snapshot_version: int
    published_at: str
    expires: str


def parse_utc(value: object, *, field: str) -> datetime:
    """Parse an RFC 3339 UTC timestamp (``YYYY-MM-DDTHH:MM:SSZ``)."""
    if not isinstance(value, str) or not value:
        raise FreshnessError(f"index.json {field} is missing or unparseable")
    try:
        parsed = datetime.strptime(value, _TS)
    except ValueError as exc:
        raise FreshnessError(f"index.json {field} is missing or unparseable") from exc
    return parsed.replace(tzinfo=UTC)


def parse_freshness(index: object) -> Freshness:
    """Read freshness fields. Missing or garbage is a refusal, not a pass."""
    if not isinstance(index, dict):
        raise FreshnessError("index.json is missing snapshot_version")
    if "snapshot_version" not in index:
        raise FreshnessError("index.json is missing snapshot_version")
    if "expires" not in index:
        raise FreshnessError("index.json is missing expires")
    if "published_at" not in index:
        raise FreshnessError("index.json is missing published_at")

    raw_version = index["snapshot_version"]
    if isinstance(raw_version, bool) or not isinstance(raw_version, int):
        raise FreshnessError("index.json snapshot_version is missing or unparseable")
    if raw_version < 1 or raw_version > SNAPSHOT_VERSION_MAX:
        raise FreshnessError("index.json snapshot_version is missing or unparseable")

    published_at = index["published_at"]
    expires = index["expires"]
    parse_utc(published_at, field="published_at")
    parse_utc(expires, field="expires")
    if not isinstance(published_at, str) or not isinstance(expires, str):
        raise FreshnessError("index.json published_at is missing or unparseable")
    return Freshness(
        snapshot_version=raw_version,
        published_at=published_at,
        expires=expires,
    )


def expires_from_ttl(published_at: str, ttl_days: int = DEFAULT_TTL_DAYS) -> str:
    """Return ``published_at + ttl_days`` as an RFC 3339 UTC timestamp."""
    start = parse_utc(published_at, field="published_at")
    return (start + timedelta(days=ttl_days)).strftime(_TS)


def age_days(published_at: str, now: datetime) -> int:
    """Whole days between publish and *now*, floored, never negative."""
    published = parse_utc(published_at, field="published_at")
    delta = now - published
    return max(0, delta.days)


def identity_key(index: dict) -> str:
    """Stable client-state key: Sigstore workflow identity + OIDC issuer.

    Rotation of that identity resets rollback protection for every client —
    that is a consequence of rotation, not a fingerprint of an ephemeral cert.
    Key-mode feeds (no identity) share a backend-scoped bucket.
    """
    signing = index.get("signing")
    if not isinstance(signing, dict):
        signing = {}
    identity = signing.get("identity") or ""
    issuer = signing.get("oidc_issuer") or ""
    if identity or issuer:
        return f"{identity}\n{issuer}"
    backend = signing.get("backend") or "unknown"
    return f"key-mode\n{backend}"


def default_seen_path() -> Path:
    """``<user-config-dir>/mcp-audit/feed/seen.json``."""
    return Path(user_config_dir("mcp-audit")) / "feed" / "seen.json"


def load_seen(path: Path) -> dict[str, int]:
    """Load the highest ``snapshot_version`` seen per identity. Missing file is {}."""
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    versions = payload.get("versions") if isinstance(payload, dict) else None
    if not isinstance(versions, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in versions.items():
        if (
            isinstance(key, str)
            and isinstance(value, int)
            and not isinstance(value, bool)
        ):
            out[key] = value
    return out


def save_seen(path: Path, versions: dict[str, int]) -> None:
    """Write seen versions at 0o700 dir / 0o600 file."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps({"versions": versions}, indent=2, sort_keys=True) + "\n"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(payload)


def check_expiry(freshness: Freshness, now: datetime) -> None:
    """Refuse a feed at or past ``expires``. Message includes the client clock."""
    expires = parse_utc(freshness.expires, field="expires")
    if now >= expires:
        raise FreshnessError(
            f"this feed expired on {freshness.expires}; "
            f"current time is {now.strftime(_TS)}"
        )


def check_rollback(freshness: Freshness, seen: dict[str, int], key: str) -> None:
    """Refuse ``snapshot_version`` lower than one already recorded for *key*."""
    previous = seen.get(key)
    if previous is None:
        return
    if freshness.snapshot_version < previous:
        raise FreshnessError("this feed is older than one you have already seen")


def record_seen(path: Path, key: str, snapshot_version: int) -> None:
    """Record *snapshot_version* as the highest seen for *key*."""
    seen = load_seen(path)
    seen[key] = max(seen.get(key, 0), snapshot_version)
    save_seen(path, seen)


def resolve_snapshot_version(
    *,
    explicit: int | None,
    previous_index: Path | None,
    require_explicit: bool,
) -> int:
    """Pick the next ``snapshot_version``. Signed publish must not silently use 1."""
    previous: int | None = None
    if previous_index is not None:
        try:
            payload = json.loads(previous_index.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FreshnessError(
                f"previous index {previous_index} is not valid JSON"
            ) from exc
        previous = parse_freshness(payload).snapshot_version

    if explicit is not None:
        if explicit < 1 or explicit > SNAPSHOT_VERSION_MAX:
            raise FreshnessError("snapshot_version is out of range")
        if previous is not None and explicit <= previous:
            raise FreshnessError(
                f"snapshot_version {explicit} does not exceed previous {previous}"
            )
        return explicit
    if previous is not None:
        nxt = previous + 1
        if nxt > SNAPSHOT_VERSION_MAX:
            raise FreshnessError("snapshot_version overflow")
        return nxt
    if require_explicit:
        raise FreshnessError(
            "signed publish requires --snapshot-version or --previous-index; "
            "refusing to default to 1"
        )
    return 1
