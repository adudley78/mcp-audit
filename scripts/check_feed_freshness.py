#!/usr/bin/env python3
"""Canary: fail loudly if the live published advisory feed is near expiry.

R31: ``.github/workflows/advisory-feed-publish.yml`` now refreshes
``expires`` on every scheduled run, whether or not advisory content
changed — see that workflow's header comment. But "the code refreshes it
every run" and "the run actually happens" are different claims. GitHub
disables scheduled workflows after enough repository inactivity, a broken
step can silently no-op, and nothing inside that workflow can detect its
own failure to fire. This script is the outside check: read the live
published feed and assert its expiry still has a full publish interval of
headroom. If it does not, the publisher has stopped running.

Deliberately independent of ``advisory-feed-publish.yml``: this must be
wired into its own separately-scheduled workflow
(``advisory-feed-freshness-canary.yml``) so it keeps checking even if the
publish workflow itself is the thing that broke. Read-only (a single HTTPS
GET) and cheap by design — this is a canary, not a rebuild.

Usage::

    python scripts/check_feed_freshness.py
    python scripts/check_feed_freshness.py --url https://.../index.json --margin-days 7
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError

DEFAULT_URL = "https://raw.githubusercontent.com/adudley78/mcp-audit/feed/index.json"

# advisory-feed-publish.yml runs weekly (cron "0 14 * * 0"). A live feed
# with less than one full interval of headroom before `expires` means at
# least one scheduled publish was missed -- normal weekly jitter never
# eats into a margin this wide, so this does not need a grace factor.
PUBLISH_INTERVAL_DAYS = 7

# Must match mcp_audit.advisory.freshness._TS. Duplicated rather than
# imported: every other script/ tool here is a standalone process with no
# dependency on the installed package, and this canary should not need
# `pip install -e .` to run.
_TS = "%Y-%m-%dT%H:%M:%SZ"


def _now() -> datetime:
    """Current UTC instant. A seam so tests can pin `main()`'s clock."""
    return datetime.now(UTC)


def fetch_index(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310  # nosec B310 -- URL is validated (https://raw.githubusercontent.com/) before this call
        payload = response.read()
    return json.loads(payload)


def check(index: dict, *, now: datetime, margin_days: int) -> str | None:
    """Return a human-readable failure message, or ``None`` if fresh enough."""
    expires_raw = index.get("expires")
    if not isinstance(expires_raw, str) or not expires_raw:
        return "published index.json has no expires field"
    try:
        expires = datetime.strptime(expires_raw, _TS).replace(tzinfo=UTC)
    except ValueError:
        return f"published index.json expires={expires_raw!r} is not RFC 3339 UTC"

    margin = expires - now
    if margin < timedelta(days=margin_days):
        return (
            f"published feed expires {expires_raw}, only {margin} away -- less "
            f"than the {margin_days}-day publish interval. The publisher has "
            "likely stopped running; check the last successful run of "
            "advisory-feed-publish.yml."
        )
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Published index.json to check (default: {DEFAULT_URL}).",
    )
    parser.add_argument(
        "--margin-days",
        type=int,
        default=PUBLISH_INTERVAL_DAYS,
        help=f"Minimum acceptable headroom before expires, in days "
        f"(default: {PUBLISH_INTERVAL_DAYS}, one publish interval).",
    )
    args = parser.parse_args(argv)

    if not args.url.startswith("https://raw.githubusercontent.com/"):
        print(
            f"ERROR: refusing a non-raw.githubusercontent.com URL: {args.url}",
            file=sys.stderr,
        )
        return 2

    try:
        index = fetch_index(args.url)
    except (HTTPError, URLError, TimeoutError) as exc:
        print(f"ERROR: could not fetch {args.url}: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: {args.url} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    failure = check(index, now=_now(), margin_days=args.margin_days)
    if failure is not None:
        print(f"FRESHNESS CANARY FAILED: {failure}", file=sys.stderr)
        return 1

    print(
        f"OK: published feed expires {index.get('expires')} "
        f"(snapshot_version={index.get('snapshot_version')}, "
        f"count={index.get('count')}).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
