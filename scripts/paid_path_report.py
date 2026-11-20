#!/usr/bin/env python3
"""Weekly numbers for the Credenzo Team experiment, and the decision.

The experiment has one rule, set before it started:

- Continue when there are 10 paying customers or $1,000 of monthly revenue.
- Stop when, 90 days after subscriptions opened, there are fewer than 3
  paying customers or less than $300 of monthly revenue. At $99 a month,
  3 customers are $297, so the stop line needs 4 customers.

This script reads the numbers that are public (GitHub, PyPI) through the
``gh`` command and applies the rule to the two numbers that are not: paying
customers and monthly revenue. Give those with ``--customers`` and ``--mrr``
(read them from the Stripe dashboard). They are not read from Stripe here and
are not written anywhere, so a run of this script in a public log shows
nothing private unless you pass them.

Not measured, on purpose: guard blocks, and locks or checks in private
repositories. Credenzo sends no telemetry (docs/telemetry.md), so the only
usage numbers are the public ones below.

Usage::

    python3 scripts/paid_path_report.py --customers 0 --mrr 0
    python3 scripts/paid_path_report.py --json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OFFER_PATH = ROOT / "team" / "offer.json"
REPO = "adudley78/credenzo"

SUCCESS_CUSTOMERS = 10
SUCCESS_MRR_USD = 1000
STOP_CUSTOMERS = 3
STOP_MRR_USD = 300
WINDOW_DAYS = 90

#: Public code searches. Each counts repositories other than this one.
SEARCHES = {
    "public_repos_with_a_credenzo_lock": [
        '"generated_by" "mcp-audit" filename:mcp-lock.json'
    ],
    "public_repos_that_run_the_action": [
        "adudley78/credenzo path:.github/workflows",
        "adudley78/mcp-audit path:.github/workflows",
    ],
    "public_repos_that_run_the_team_action": [
        "adudley78/credenzo/team path:.github/workflows"
    ],
}
SEARCH_PAUSE_SECONDS = 7  # The code search API allows 10 requests a minute.

Api = Callable[[str, dict[str, str]], Any]


def decide(
    live_since: str | None, today: date, customers: int | None, mrr: float | None
) -> dict[str, Any]:
    """Apply the rule. Return the state, the day count and one sentence."""
    if not live_since:
        return {
            "state": "NOT LIVE",
            "day": None,
            "text": "Subscriptions are not open. The 90 days have not started.",
        }
    day = (today - date.fromisoformat(live_since)).days
    if customers is None or mrr is None:
        return {
            "state": "UNKNOWN",
            "day": day,
            "text": f"Day {day} of {WINDOW_DAYS}. Give --customers and --mrr.",
        }
    if customers >= SUCCESS_CUSTOMERS or mrr >= SUCCESS_MRR_USD:
        return {
            "state": "CONTINUE",
            "day": day,
            "text": f"Day {day}. The success line is met. Continue Priority 1.",
        }
    if day >= WINDOW_DAYS and (customers < STOP_CUSTOMERS or mrr < STOP_MRR_USD):
        return {
            "state": "STOP",
            "day": day,
            "text": f"Day {day}. Below the stop line after {WINDOW_DAYS} days."
            " Stop work on the lock offer and start Priority 2.",
        }
    if day >= WINDOW_DAYS:
        return {
            "state": "CONTINUE",
            "day": day,
            "text": f"Day {day}. Above the stop line and below the success line.",
        }
    return {
        "state": "RUNNING",
        "day": day,
        "text": f"Day {day} of {WINDOW_DAYS}. No decision before day {WINDOW_DAYS}"
        " unless the success line is met.",
    }


def gh_api(path: str, fields: dict[str, str]) -> Any:
    """GET a GitHub REST path with the ``gh`` command. ``None`` on failure."""
    args = ["gh", "api", "-X", "GET", path]
    for key, value in fields.items():
        args += ["-f", f"{key}={value}"]
    try:
        done = subprocess.run(  # noqa: S603
            args, capture_output=True, text=True, check=False, timeout=60
        )
        return json.loads(done.stdout) if done.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def pypi_last_month(package: str = "mcp-audit-scanner") -> int | None:
    """Return last month's PyPI downloads from pypistats.org, when reachable."""
    url = f"https://pypistats.org/api/packages/{package}/recent"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310
            return int(json.loads(response.read())["data"]["last_month"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _get(data: Any, *keys: str) -> Any:
    for key in keys:
        data = data.get(key) if isinstance(data, dict) else None
    return data


def public_numbers(
    api: Api = gh_api,
    pause: Callable[[float], None] = time.sleep,
    pypi: Callable[[], int | None] = pypi_last_month,
) -> dict[str, Any]:
    """Collect the public numbers. A number that cannot be read is ``None``."""
    repo = api(f"repos/{REPO}", {})
    release = api(f"repos/{REPO}/releases/latest", {})
    assets = _get(release, "assets")
    numbers: dict[str, Any] = {
        "stars": _get(repo, "stargazers_count"),
        "forks": _get(repo, "forks_count"),
        "visitors_14_days": _get(api(f"repos/{REPO}/traffic/views", {}), "uniques"),
        "cloners_14_days": _get(api(f"repos/{REPO}/traffic/clones", {}), "uniques"),
        "latest_release": _get(release, "tag_name"),
        "latest_release_downloads": sum(
            a.get("download_count", 0) for a in assets if isinstance(a, dict)
        )
        if isinstance(assets, list)
        else None,
        "pypi_downloads_last_month": pypi(),
    }
    for name, queries in SEARCHES.items():
        repos: set[str] | None = set()
        for query in queries:
            pause(SEARCH_PAUSE_SECONDS)
            found = api("search/code", {"q": query, "per_page": "100"})
            items = _get(found, "items")
            if not isinstance(items, list):
                repos = None
                break
            repos |= {
                str(_get(item, "repository", "full_name"))
                for item in items
                if isinstance(item, dict)
            }
        numbers[name] = None if repos is None else sorted(repos - {REPO})
    return numbers


def render(numbers: dict[str, Any], decision: dict[str, Any]) -> str:
    """Return the report as Markdown."""
    lines = [
        f"**{decision['state']}** - {decision['text']}",
        "",
        "| Public number | Value |",
        "|---|---|",
    ]
    for name, value in numbers.items():
        label = name.replace("_", " ")
        if isinstance(value, list):
            shown = f"{len(value)}" + (f" ({', '.join(value)})" if value else "")
        else:
            shown = "not read" if value is None else str(value)
        lines.append(f"| {label} | {shown} |")
    lines += [
        "",
        "Not measured: guard blocks, and locks or checks in private"
        " repositories. Credenzo sends no telemetry.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Print the report. Return the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--customers", type=int, help="paying customers (Stripe)")
    parser.add_argument("--mrr", type=float, help="monthly revenue in USD (Stripe)")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)

    offer = json.loads(OFFER_PATH.read_text(encoding="utf-8"))
    decision = decide(offer.get("live_since"), date.today(), args.customers, args.mrr)
    numbers = public_numbers()
    if args.json:
        print(json.dumps({"decision": decision, "public": numbers}, indent=2))
    else:
        print(render(numbers, decision))
    return 0


if __name__ == "__main__":
    sys.exit(main())
