#!/usr/bin/env python3
"""Open Credenzo Team subscriptions: record the Stripe payment link.

One command writes the three places that hold the link:

- ``team/offer.json`` (the checkout link, the payment link ID and the date
  the 90 days start),
- the "Subscribe" block of ``docs/team.md``.

The licence workflow copies the link from ``team/offer.json`` to the public
licence list, and the Team action reads it there, so a workflow that pins an
earlier release of the action shows the link too.

Usage::

    python3 scripts/team_go_live.py \\
        --checkout-url https://buy.stripe.com/abc123 \\
        --payment-link-id plink_1AbCdEf \\
        --portal-url https://billing.stripe.com/p/login/xyz

``--check`` changes nothing and fails when ``docs/team.md`` and
``team/offer.json`` do not agree (the test suite runs the same comparison).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OFFER_PATH = ROOT / "team" / "offer.json"
DOC_PATH = ROOT / "docs" / "team.md"
START = "<!-- team-checkout:start -->"
END = "<!-- team-checkout:end -->"

_CHECKOUT = re.compile(r"https://buy\.stripe\.com/[A-Za-z0-9_]+")
_PORTAL = re.compile(r"https://billing\.stripe\.com/p/login/[A-Za-z0-9_]+")
_LINK_ID = re.compile(r"plink_[A-Za-z0-9]+")


def block(offer: dict[str, Any]) -> str:
    """Return the "Subscribe" block of ``docs/team.md`` for *offer*."""
    if not offer.get("live_since"):
        return (
            "Subscriptions are not open yet. Until they open, the action sends"
            " alerts for every repository."
        )
    lines = [
        f"**[Subscribe to {offer['name']}]({offer['checkout_url']})**:"
        f" ${offer['price_usd_per_month']} a month for up to {offer['seats']} seats."
    ]
    if offer.get("portal_url"):
        lines.append(
            f"\n[Change the card, get an invoice or cancel]({offer['portal_url']})."
        )
    return "\n".join(lines)


def with_block(text: str, offer: dict[str, Any]) -> str:
    """Return *text* with the block between the two markers replaced."""
    head, _, rest = text.partition(START)
    _, found, tail = rest.partition(END)
    if not found:
        raise ValueError(f"{DOC_PATH.name} has no {START} ... {END} block")
    return f"{head}{START}\n{block(offer)}\n{END}{tail}"


def main(argv: list[str] | None = None) -> int:
    """Record the link, or check the files. Return the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--checkout-url")
    parser.add_argument("--payment-link-id")
    parser.add_argument("--portal-url")
    parser.add_argument("--live-since", default=date.today().isoformat())
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    offer = json.loads(OFFER_PATH.read_text(encoding="utf-8"))
    doc = DOC_PATH.read_text(encoding="utf-8")
    if args.check:
        if with_block(doc, offer) != doc:
            print("docs/team.md and team/offer.json do not agree.")
            return 1
        return 0

    problems = []
    if not _CHECKOUT.fullmatch(args.checkout_url or ""):
        problems.append("--checkout-url must be a https://buy.stripe.com/... link")
    elif "/test_" in args.checkout_url:
        problems.append("--checkout-url is a Stripe test-mode link; use the live one")
    if not _LINK_ID.fullmatch(args.payment_link_id or ""):
        problems.append("--payment-link-id must be a plink_... ID")
    if args.portal_url and not _PORTAL.fullmatch(args.portal_url):
        problems.append(
            "--portal-url must be a https://billing.stripe.com/p/login/... link"
        )
    try:
        date.fromisoformat(args.live_since)
    except ValueError:
        problems.append("--live-since must be a date, YYYY-MM-DD")
    if problems:
        print("\n".join(problems))
        return 2

    offer.update(
        live_since=args.live_since,
        checkout_url=args.checkout_url,
        payment_link_id=args.payment_link_id,
        portal_url=args.portal_url,
    )
    OFFER_PATH.write_text(json.dumps(offer, indent=2) + "\n", encoding="utf-8")
    DOC_PATH.write_text(with_block(doc, offer), encoding="utf-8")
    print(f"Subscriptions open from {args.live_since}. Commit the two files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
