#!/usr/bin/env python3
"""Build the public Credenzo Team licence list from Stripe.

``.github/workflows/team-licenses.yml`` runs this on a schedule. It reads the
completed checkouts of the Team payment link and the state of each
subscription, and writes ``index.json``. The Team action (``team/``) reads
that file from the ``team-licenses`` branch to decide whether an
organization gets drift alerts.

What the list holds
-------------------
- ``offer``: whether subscriptions are open, and the checkout link. Both come
  from ``team/offer.json``.
- ``owners``: SHA-256 digests. A digest is of a GitHub owner name that a
  subscriber typed at checkout, or it is a filler. The list always has a
  multiple of 64 entries, so its length does not show how many subscribers
  there are. Fillers come from a secret (``TEAM_INDEX_SALT``) and do not
  change between runs. Each new subscriber takes the place of one filler, so
  someone who keeps the copies of the list over time can count the entries
  that are new.

The list holds no name, no email address, no Stripe ID and no amount. This
script prints no count of subscribers: the log of a public repository is
public.

A failed Stripe request stops the run with a non-zero exit code and writes
nothing, so a list is never published with subscribers missing.

The owner name is on the Checkout Session, not on the subscription, so the
list depends on Stripe keeping completed Checkout Sessions in the list call.

Usage::

    STRIPE_API_KEY=rk_live_... TEAM_INDEX_SALT=... \\
        python3 scripts/team_licenses.py --out out/
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OFFER_PATH = ROOT / "team" / "offer.json"
STRIPE_API = "https://api.stripe.com"

#: Must equal ``DIGEST_PREFIX`` in ``team/credenzo_team.py`` (pinned by a test).
DIGEST_PREFIX = "credenzo-team:"
#: The key of the custom field on the Stripe payment link.
OWNER_FIELD = "githubowner"
#: A subscription in one of these states keeps its alerts. ``past_due`` is in
#: the list on purpose: a failed card must not stop a customer's alerts while
#: Stripe tries the card again.
ENTITLED = frozenset({"active", "trialing", "past_due"})
BLOCK = 64
MAX_OWNERS_PER_CHECKOUT = 3
MAX_PAGES = 500
MIN_SALT_CHARS = 16
HTTP_TIMEOUT_SECONDS = 30

_OWNER = re.compile(r"[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}")

Get = Callable[[str], Any]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse each redirect: the Stripe key goes to the first URL only."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class StripeError(RuntimeError):
    """A Stripe request did not return the expected document."""


def stripe_get(key: str) -> Get:
    """Return a function that GETs a Stripe API path and decodes the JSON."""

    def get(path: str) -> Any:
        request = urllib.request.Request(  # noqa: S310 - constant https host
            STRIPE_API + path, headers={"Authorization": f"Bearer {key}"}
        )
        try:
            # nosec B310 - constant https host; redirects are refused
            with _OPENER.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # The body can repeat request details. Give the status only.
            raise StripeError(
                f"Stripe answered {exc.code} for {path.split('?')[0]}"
            ) from None
        except (OSError, ValueError) as exc:
            raise StripeError(
                f"Stripe request failed for {path.split('?')[0]}: {type(exc).__name__}"
            ) from None

    return get


def stripe_list(get: Get, path: str, params: dict[str, str]) -> list[dict[str, Any]]:
    """Return every object of a Stripe list, following its pages."""
    items: list[dict[str, Any]] = []
    after: str | None = None
    for _ in range(MAX_PAGES):
        query = {**params, "limit": "100"}
        if after:
            query["starting_after"] = after
        page = get(f"{path}?{urllib.parse.urlencode(query)}")
        data = page.get("data") if isinstance(page, dict) else None
        if not isinstance(data, list) or not all(isinstance(i, dict) for i in data):
            raise StripeError(f"Stripe list {path} is not a list")
        items += data
        if not page.get("has_more") or not data:
            return items
        after = data[-1].get("id")
        if not isinstance(after, str):
            raise StripeError(f"Stripe list {path} has an object with no id")
    raise StripeError(f"Stripe list {path} has more than {MAX_PAGES} pages")


def owner_digest(owner: str) -> str:
    """Return the digest under which *owner* is listed."""
    return hashlib.sha256((DIGEST_PREFIX + owner.strip().lower()).encode()).hexdigest()


def owner_names(text: object) -> tuple[list[str], bool]:
    """Read the GitHub owner names a subscriber typed.

    Accepts one to three names, split by commas or spaces, each as ``acme``,
    ``@acme`` or ``https://github.com/acme``.

    Returns:
        The names in lower case, and ``True`` when any part of the text is
        not a GitHub owner name.
    """
    if not isinstance(text, str):
        return [], True
    names: list[str] = []
    bad = False
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        name = re.sub(r"^(?:https?://)?(?:www\.)?github\.com/", "", part.lower())
        name = name.lstrip("@").split("/")[0]
        if _OWNER.fullmatch(name):
            names.append(name)
        else:
            bad = True
    unique = sorted(set(names))
    if len(unique) > MAX_OWNERS_PER_CHECKOUT:
        return unique[:MAX_OWNERS_PER_CHECKOUT], True
    return unique, bad or not unique


def subscribed_owners(
    sessions: list[dict[str, Any]], subscriptions: list[dict[str, Any]]
) -> tuple[set[str], bool]:
    """Return the owner names with a subscription that is in force.

    Returns:
        The names, and ``True`` when a checkout with a subscription in force
        holds text that is not a usable owner name.
    """
    state = {s.get("id"): s.get("status") for s in subscriptions}
    owners: set[str] = set()
    unusable = False
    for session in sessions:
        subscription = session.get("subscription")
        if isinstance(subscription, dict):
            subscription = subscription.get("id")
        if state.get(subscription) not in ENTITLED:
            continue
        typed: object = None
        fields = session.get("custom_fields")
        for field in fields if isinstance(fields, list) else []:
            if isinstance(field, dict) and field.get("key") == OWNER_FIELD:
                text = field.get("text")
                typed = text.get("value") if isinstance(text, dict) else None
        names, bad = owner_names(typed)
        owners.update(names)
        unusable = unusable or bad
    return owners, unusable


def padded(digests: set[str], salt: str) -> list[str]:
    """Return *digests* plus fillers, sorted, as a multiple of ``BLOCK`` entries."""
    total = max(BLOCK, -(-len(digests) // BLOCK) * BLOCK)
    fillers = [
        hmac.new(salt.encode(), f"filler:{i}".encode(), hashlib.sha256).hexdigest()
        for i in range(total - len(digests))
    ]
    return sorted(digests | set(fillers))


def build_index(offer: dict[str, Any], owners: set[str], salt: str) -> dict[str, Any]:
    """Return the document that the Team action reads."""
    live = bool(offer.get("live_since")) and bool(offer.get("checkout_url"))
    return {
        "schema_version": 1,
        "offer": {
            "live": live,
            "checkout_url": offer.get("checkout_url") if live else None,
            "price_usd_per_month": offer.get("price_usd_per_month"),
            "seats": offer.get("seats"),
        },
        "owners": padded({owner_digest(o) for o in owners}, salt),
    }


def run(
    offer: dict[str, Any], get: Get | None, salt: str
) -> tuple[dict[str, Any], bool]:
    """Build the list. Stripe is read only when the offer names a payment link."""
    link = offer.get("payment_link_id")
    if not link or get is None:
        return build_index(offer, set(), salt), False
    sessions = stripe_list(
        get, "/v1/checkout/sessions", {"payment_link": str(link), "status": "complete"}
    )
    subscriptions = stripe_list(get, "/v1/subscriptions", {"status": "all"})
    owners, unusable = subscribed_owners(sessions, subscriptions)
    return build_index(offer, owners, salt), unusable


def main(argv: list[str] | None = None) -> int:
    """Write ``index.json``. Return the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="directory to write")
    args = parser.parse_args(argv)

    salt = os.environ.get("TEAM_INDEX_SALT", "")
    if len(salt) < MIN_SALT_CHARS:
        print(f"TEAM_INDEX_SALT must have {MIN_SALT_CHARS} characters or more.")
        return 2
    offer = json.loads(OFFER_PATH.read_text(encoding="utf-8"))
    key = os.environ.get("STRIPE_API_KEY", "")
    if offer.get("payment_link_id") and not key:
        print("team/offer.json names a payment link and STRIPE_API_KEY is not set.")
        return 2
    try:
        index, unusable = run(offer, stripe_get(key) if key else None, salt)
    except StripeError as exc:
        print(f"::error title=Team licence list::{exc}. Nothing was written.")
        return 1
    if unusable:
        print(
            "::warning title=Team licence list::A checkout with a subscription"
            " in force holds text that is not a GitHub owner name. Read the"
            f" `{OWNER_FIELD}` field of the recent checkouts in Stripe."
        )
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Licence list written: {len(index['owners'])} entries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
