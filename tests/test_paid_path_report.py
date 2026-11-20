"""`scripts/paid_path_report.py`: the continue/stop rule and the public numbers."""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "paid_path_report", ROOT / "scripts" / "paid_path_report.py"
)
report = importlib.util.module_from_spec(_spec)
sys.modules["paid_path_report"] = report
_spec.loader.exec_module(report)

LIVE = "2026-12-01"


def _state(day: int, customers: int | None, mrr: float | None) -> str:
    today = date.fromordinal(date.fromisoformat(LIVE).toordinal() + day)
    return report.decide(LIVE, today, customers, mrr)["state"]


def test_nothing_is_decided_before_subscriptions_open() -> None:
    got = report.decide(None, date(2026, 12, 1), 50, 5000.0)
    assert (got["state"], got["day"]) == ("NOT LIVE", None)


def test_the_paid_numbers_are_needed_for_a_decision() -> None:
    assert _state(10, None, None) == "UNKNOWN"
    assert _state(10, 3, None) == "UNKNOWN"


@pytest.mark.parametrize(
    ("day", "customers", "mrr", "state"),
    [
        (5, 0, 0.0, "RUNNING"),
        (89, 0, 0.0, "RUNNING"),
        (5, 10, 990.0, "CONTINUE"),  # 10 customers
        (5, 4, 1000.0, "CONTINUE"),  # $1,000 with fewer customers
        (90, 0, 0.0, "STOP"),
        (90, 2, 500.0, "STOP"),  # fewer than 3 customers
        (90, 3, 297.0, "STOP"),  # 3 customers at $99 are under $300
        (90, 4, 396.0, "CONTINUE"),
        (200, 9, 891.0, "CONTINUE"),
        (200, 10, 990.0, "CONTINUE"),
    ],
)
def test_the_rule(day: int, customers: int, mrr: float, state: str) -> None:
    assert _state(day, customers, mrr) == state


def test_the_thresholds_are_the_ones_that_were_set() -> None:
    assert (report.SUCCESS_CUSTOMERS, report.SUCCESS_MRR_USD) == (10, 1000)
    assert (report.STOP_CUSTOMERS, report.STOP_MRR_USD) == (3, 300)
    assert report.WINDOW_DAYS == 90


def _api(overrides: dict[str, Any] | None = None) -> Any:
    answers: dict[str, Any] = {
        "repos/adudley78/credenzo": {"stargazers_count": 6, "forks_count": 4},
        "repos/adudley78/credenzo/releases/latest": {
            "tag_name": "v0.34.0",
            "assets": [{"download_count": 12}, {"download_count": 8}, "junk"],
        },
        "repos/adudley78/credenzo/traffic/views": {"uniques": 83},
        "repos/adudley78/credenzo/traffic/clones": {"uniques": 879},
        "search/code": {
            "items": [
                {"repository": {"full_name": "adudley78/credenzo"}},
                {"repository": {"full_name": "someone/app"}},
                {"repository": {"full_name": "someone/app"}},
            ]
        },
        **(overrides or {}),
    }
    return lambda path, _fields: answers.get(path)


def test_public_numbers_count_other_repositories_once() -> None:
    pauses: list[float] = []
    numbers = report.public_numbers(_api(), pauses.append, lambda: 1234)
    assert numbers["stars"] == 6 and numbers["forks"] == 4
    assert numbers["visitors_14_days"] == 83 and numbers["cloners_14_days"] == 879
    assert numbers["latest_release_downloads"] == 20
    assert numbers["pypi_downloads_last_month"] == 1234
    assert numbers["public_repos_with_a_credenzo_lock"] == ["someone/app"]
    assert len(pauses) == sum(len(q) for q in report.SEARCHES.values())


def test_a_number_that_cannot_be_read_is_none_and_not_zero() -> None:
    api = _api(
        {
            "search/code": None,
            "repos/adudley78/credenzo/traffic/views": None,
            "repos/adudley78/credenzo/releases/latest": None,
        }
    )
    numbers = report.public_numbers(api, lambda _s: None, lambda: None)
    assert numbers["visitors_14_days"] is None
    assert numbers["latest_release_downloads"] is None
    assert numbers["public_repos_that_run_the_action"] is None
    text = report.render(numbers, report.decide(None, date(2026, 12, 1), None, None))
    assert "| visitors 14 days | not read |" in text
    assert "| public repos that run the action | not read |" in text


def test_the_report_says_what_is_not_measured() -> None:
    numbers = report.public_numbers(_api(), lambda _s: None, lambda: None)
    text = report.render(numbers, report.decide(LIVE, date(2027, 3, 1), 0, 0.0))
    assert text.startswith("**STOP** - Day 90.")
    assert "| public repos with a credenzo lock | 1 (someone/app) |" in text
    assert "Not measured: guard blocks" in text
