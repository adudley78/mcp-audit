"""Dates in tool text that move with the calendar (STORY-0179, STORY-0180).

Some servers write the date of today into a tool description or a schema
default. Such a tool has a new ``definition`` digest each day although its
author changed nothing. This module holds the one rule that tells that case
from a change:

- :func:`without_dates` cuts the ISO dates (``YYYY-MM-DD``) out of a value
  and returns the dates that it found.
- :func:`moved_with_calendar` compares the dates of two records made on two
  known days.
- :func:`followed_calendar` is the same test for the lock, where the clock
  of the server can differ from the clock of the reader by one day.

The rule is strict on purpose. A date counts as moved with the calendar only
when it moved by the days (or, for a first day of a month, the months)
between the two records. A date that an author moved, a new date and a
removed date are changes. Text that is not a real date is never a date.

Standard library only: ``credenzo run`` imports this module on its launch
path. ``scripts/drift_snapshot.py`` and ``scripts/drift_compare.py`` use the
same functions for the drift index.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

_ISO_DATE = re.compile(r"(?<![0-9])([0-9]{4})-([0-9]{2})-([0-9]{2})(?![0-9])")
_ISO_DATE_ONLY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

#: A tool with more dates than this gets no calendar record.
MAX_DATES = 200

#: The date of the server can be one day before or after the date of the
#: reader (time zones), at the lock and again at the check.
_CLOCK_OFFSETS = (0, -1, 1)


def today() -> str:
    """Return the date of today (UTC) as ``YYYY-MM-DD``."""
    return dt.datetime.now(dt.UTC).date().isoformat()


def parse_day(text: object) -> dt.date | None:
    """Return *text* as a date when it is exactly a real ``YYYY-MM-DD``."""
    if not isinstance(text, str) or not _ISO_DATE_ONLY.fullmatch(text):
        return None
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        return None


def without_dates(value: Any, found: list[str]) -> Any:
    """Return *value* with the ISO dates cut out of its strings.

    Each string becomes the list of its pieces between the dates, so a string
    with no date becomes a list of one piece. Each date that is cut out is
    added to *found*, in a fixed order (keys sorted). The result of two
    values is the same only when they are the same value apart from their
    dates: no text can stand for a date, because a date leaves a gap between
    two pieces and nothing else does. Text that is not a real date
    (``1111-22-33``, month 13) stays in its piece. Keys are not changed.
    """
    if isinstance(value, str):
        pieces: list[str] = []
        start = 0
        for match in _ISO_DATE.finditer(value):
            try:
                dt.date(int(match[1]), int(match[2]), int(match[3]))
            except ValueError:
                continue
            pieces.append(value[start : match.start()])
            found.append(match[0])
            start = match.end()
        pieces.append(value[start:])
        return pieces
    if isinstance(value, list):
        return [without_dates(item, found) for item in value]
    if isinstance(value, dict):
        return {key: without_dates(value[key], found) for key in sorted(value)}
    return value


def moved_with_calendar(
    old: dict[str, Any], new: dict[str, Any], day_old: dt.date, day_new: dt.date
) -> bool:
    """Whether a tool's only difference is that its dates followed the calendar.

    *old* and *new* are the tool's records made on *day_old* and *day_new*.
    True needs the same ``undated`` digest and, for each pair of dates in
    order, one of: the same date; a move by the days between the records;
    two first days of a month, moved by the months between them.
    """
    undated = old.get("undated")
    if not isinstance(undated, str) or not undated or undated != new.get("undated"):
        return False
    dates_old, dates_new = old.get("dates"), new.get("dates")
    if not isinstance(dates_old, list) or not isinstance(dates_new, list):
        return False
    if not dates_old or len(dates_old) != len(dates_new):
        return False
    days = (day_new - day_old).days
    months = (day_new.year - day_old.year) * 12 + day_new.month - day_old.month
    for text_old, text_new in zip(dates_old, dates_new, strict=True):
        a, b = parse_day(text_old), parse_day(text_new)
        if a is None or b is None:
            return False
        if a == b or (b - a).days == days:
            continue
        if a.day == b.day == 1 and (b.year - a.year) * 12 + b.month - a.month == months:
            continue
        return False
    return True


def followed_calendar(was: object, now: object) -> bool:
    """Whether two calendar records of one tool differ only by the calendar.

    *was* is the record in the lock and *now* is the record of the live tool.
    Each is ``{"day", "dates", "undated"}``. The test is
    :func:`moved_with_calendar` with the two ``day`` values. The server reads
    its own clock, which can be one day from the clock that wrote ``day``, so
    each day is also tried one day earlier and one day later. One choice must
    explain every date of the tool.

    The bound that follows: a date can be two days from the exact count, and
    a first day of a month can be one month from the exact count for each of
    the two days that is the first or the last day of a month.
    """
    if not isinstance(was, dict) or not isinstance(now, dict):
        return False
    day_old, day_new = parse_day(was.get("day")), parse_day(now.get("day"))
    if day_old is None or day_new is None:
        return False
    one = dt.timedelta(days=1)
    for a in _CLOCK_OFFSETS:
        for b in _CLOCK_OFFSETS:
            try:
                first, second = day_old + a * one, day_new + b * one
            except OverflowError:
                continue
            if moved_with_calendar(was, now, first, second):
                return True
    return False


def calendar_record(definition: dict[str, Any], day: str) -> dict[str, Any] | None:
    """Return the dates of one tool definition, or ``None`` when it has none.

    The result is ``{"day": day, "dates": [...], "undated": <value>}``, where
    ``undated`` is the definition with each date cut out (the caller digests
    it). The tool's name is never cut: a name is an identity, not text.
    """
    found: list[str] = []
    rest = {key: value for key, value in definition.items() if key != "name"}
    plain = {**without_dates(rest, found), "name": definition.get("name")}
    if not found or len(found) > MAX_DATES:
        return None
    return {"day": day, "dates": found, "undated": plain}
