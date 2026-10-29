"""What ``affected`` was asked: an advisory ID, or a ``pkg@range``.

A range is a PEP 440 specifier set (``==1.107.0``, ``<2025.7.1``,
``>=1,<2``), which ``packaging`` already evaluates; this module resolves no
semver ranges and picks no "highest satisfying" version.  npm's ``^`` and
``~`` shorthands are refused with a message rather than guessed at.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet

MAX_QUERY_CHARS = 256
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:\-]*")
_NPM_SHORTHAND_RE = re.compile(r"^[\^~](?!=)")
_BARE_VERSION_RE = re.compile(r"^\d")


class QueryError(ValueError):
    """The query could not be understood; the message is shown to the user."""


@dataclass(frozen=True)
class Query:
    """A parsed ``affected`` argument.

    Attributes:
        kind: ``"advisory"`` for an ID, ``"range"`` for ``pkg@range``.
        text: The argument as given.
        advisory_id: The ID, for ``kind == "advisory"``.
        package: The package name, for ``kind == "range"``.
        specifier: The PEP 440 set, for ``kind == "range"``.
    """

    kind: Literal["advisory", "range"]
    text: str
    advisory_id: str | None = None
    package: str | None = None
    specifier: SpecifierSet | None = None

    @property
    def label(self) -> str:
        """The name used for this query in output (the SARIF rule ID)."""
        return self.advisory_id or self.text


def _split_package_range(text: str) -> tuple[str, str] | None:
    """Split ``name@spec`` (scoped names keep their leading ``@``)."""
    start = 1 if text.startswith("@") else 0
    idx = text.find("@", start)
    if idx < 0:
        return None
    return text[:idx], text[idx + 1 :]


def parse_query(text: str) -> Query:
    """Parse the CLI argument.

    Args:
        text: An advisory ID (``CVE-2025-53109``, ``GHSA-…``, ``MAL-…``,
            ``x_MCPRS-…``) or ``package@specifier``.

    Returns:
        The parsed :class:`Query`.

    Raises:
        QueryError: Empty, over-long, or not an ID or a valid ``pkg@range``.
    """
    text = text.strip()
    if not text:
        raise QueryError("give an advisory ID or a package@range")
    if len(text) > MAX_QUERY_CHARS:
        raise QueryError(f"query is over {MAX_QUERY_CHARS} characters")
    parts = _split_package_range(text)
    if parts is None:
        if not _ID_RE.fullmatch(text):
            raise QueryError(f"{text!r} is not an advisory ID or a package@range")
        return Query(kind="advisory", text=text, advisory_id=text)
    package, spec = parts
    if not package or package == "@":
        raise QueryError("the package name before '@' is empty")
    spec = spec.strip()
    if not spec:
        raise QueryError(f"{text!r} has no version range after '@'")
    if _NPM_SHORTHAND_RE.match(spec):
        raise QueryError(
            "'^' and '~' ranges are not evaluated; write the bounds, e.g. "
            "'>=1.2.0,<2' (comma means and)"
        )
    if _BARE_VERSION_RE.match(spec):
        spec = f"=={spec}"
    try:
        specifier = SpecifierSet(spec)
    except InvalidSpecifier as exc:
        raise QueryError(
            f"{spec!r} is not a version range (use PEP 440 comparators such as "
            "'==1.2.3', '<2025.7.1', '>=1,<2')"
        ) from exc
    if not list(specifier):
        raise QueryError(f"{spec!r} names no version bound")
    return Query(kind="range", text=text, package=package, specifier=specifier)
