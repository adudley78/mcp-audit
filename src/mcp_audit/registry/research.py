"""Research records: agent-stack findings that have no CVE or GHSA (STORY-0122).

Much of what hits coding agents and MCP clients is published as a research
write-up (a named attack, a bypass, a campaign) long before, or instead of, a
CVE.  ``src/mcp_audit/data/research-records.json`` holds those findings as
OSV-shaped records, credited to the people who found them, so a later command
(``mcp-audit affected``, EPIC-0008) can answer for them like any other
advisory.  Nothing reads this file yet.

A record is **not** a finding.  It says what was reported, by whom, which
products were affected and where they were fixed, and which mcp-audit checks
test the underlying condition (``checks``).  Nothing here is inferred: a field
the write-up does not state is ``None`` here, never guessed.  In particular a
record carries *product names* as the write-up gives them, not package names
mcp-audit would have to invent; ``affected`` will therefore report a harness
version it cannot read as "could not check" (planned behaviour).

IDs are ``x_MCPRS-<12 hex>``: the first 12 hex digits of
``sha256("research\\0" + source_url + "\\0" + "|".join(sorted(products)))``,
so the same finding gets the same ID on every host and a reworded summary does
not fork it (compare ``x_MCPSA`` in ``docs/advisory-feed.md``).  ``x_`` is
OSV's experimental namespace.

The file (``mcp_audit/data/research-records.json``) is package data, so it is in
the wheel and all four binaries and is read offline.  The
loader is tolerant, like :mod:`mcp_audit.registry.malicious`: a missing or
malformed file yields an empty index with ``load_error`` set, and one bad
entry is skipped and reported, never fatal.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

__all__ = [
    "MAX_ENTRIES",
    "MAX_FILE_BYTES",
    "AffectedProduct",
    "Credit",
    "ResearchIndex",
    "ResearchRecord",
    "load_research_records",
    "research_id",
]

ProductStatus = Literal["fixed", "unfixed", "wontfix"]

_STATUSES: Final[tuple[str, ...]] = ("fixed", "unfixed", "wontfix")
_ID_PREFIX: Final = "x_MCPRS-"
_ID_RE: Final = re.compile(r"x_MCPRS-[0-9a-f]{12}")

# The shipped file is a few KB.  These caps only matter for a corrupt or
# substituted file, and hitting one is reported in ``load_error``.
MAX_FILE_BYTES: Final = 4 * 1024 * 1024
MAX_ENTRIES: Final = 5_000


def research_id(source_url: str, products: list[str] | tuple[str, ...]) -> str:
    """Return the stable record ID for a finding.

    Args:
        source_url: The primary write-up's URL, exactly as the record cites it.
        products: The product names the record lists (order does not matter).

    Returns:
        ``x_MCPRS-`` plus 12 hex digits.
    """
    basis = "research\0" + source_url + "\0" + "|".join(sorted(products))
    return _ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]


def _resolve_bundled_path() -> Path:
    """Locate ``research-records.json``: package data, so every wheel and binary has it.

    It lives in ``mcp_audit/data/`` (not ``registry/``) because that directory
    is already bundled by the wheel and all four PyInstaller specs, which keeps
    this data out of the packaging files (``pyproject.toml``, the specs).
    """
    from mcp_audit._paths import data_dir  # noqa: PLC0415

    return data_dir() / "research-records.json"


@dataclass(frozen=True)
class Credit:
    """One credited finder (OSV ``credits`` item)."""

    name: str
    type: str = "FINDER"


@dataclass(frozen=True)
class AffectedProduct:
    """One product a write-up says is affected, as the write-up names it.

    Attributes:
        product: The product name, e.g. ``"Claude Code"``.
        vendor: The vendor, e.g. ``"Anthropic"``.
        status: ``fixed`` (``fixed_in`` is set), ``unfixed`` (no fix yet), or
            ``wontfix`` (the vendor said none will ship).
        fixed_in: The first fixed version, only when ``status`` is ``fixed``.
        note: Who said so, in a sentence.
    """

    product: str
    vendor: str
    status: ProductStatus
    fixed_in: str | None = None
    note: str = ""


@dataclass(frozen=True)
class ResearchRecord:
    """One credited research finding.

    Attributes:
        id: ``x_MCPRS-<12 hex>``.
        summary: One line.
        details: What was reported and what mcp-audit can and cannot tell.
        published: When the research was published (ISO 8601).
        modified: When mcp-audit last changed the record.
        aliases: Other IDs (CVE, GHSA) once one exists.
        credits: Who found it.
        references: ``(type, url)`` pairs; the first is the primary write-up.
        products: Affected products with their fixed versions.
        checks: mcp-audit finding IDs that test the underlying condition.
    """

    id: str
    summary: str
    details: str
    published: str | None
    modified: str | None
    aliases: tuple[str, ...] = ()
    credits: tuple[Credit, ...] = ()
    references: tuple[tuple[str, str], ...] = ()
    products: tuple[AffectedProduct, ...] = ()
    checks: tuple[str, ...] = ()

    @property
    def source_url(self) -> str | None:
        """The primary write-up (the first reference), if any."""
        return self.references[0][1] if self.references else None

    @property
    def credit_line(self) -> str:
        """``"Name (Org), Name (Org)"`` for output, or an empty string."""
        return ", ".join(c.name for c in self.credits)


@dataclass
class ResearchIndex:
    """All usable records, keyed by ID and by alias.

    ``load_error`` is set when the file could not be read at all; ``skipped``
    lists entries that were dropped and why; ``withdrawn`` maps a withdrawn
    record's ID to its withdrawal timestamp, so a lookup of a withdrawn ID can
    be told apart from an unknown one.  Both are surfaced to the user by
    the caller, never swallowed.
    """

    records: dict[str, ResearchRecord] = field(default_factory=dict)
    load_error: str | None = None
    skipped: list[str] = field(default_factory=list)
    withdrawn: dict[str, str] = field(default_factory=dict)
    _aliases: dict[str, str] = field(default_factory=dict, repr=False)

    def __len__(self) -> int:
        return len(self.records)

    def lookup(self, advisory_id: str) -> ResearchRecord | None:
        """Find a record by its ID or by an alias (case-insensitive for CVE/GHSA)."""
        if advisory_id in self.records:
            return self.records[advisory_id]
        canonical = self._aliases.get(advisory_id.upper())
        return self.records.get(canonical) if canonical else None


def _as_list(raw: Any) -> list[Any] | None:
    """Return ``raw`` if it is a list (or absent), else ``None``."""
    if raw is None:
        return []
    return raw if isinstance(raw, list) else None


def _parse_products(raw: Any) -> tuple[AffectedProduct, ...] | None:
    items = _as_list(raw)
    if items is None:
        return None
    out: list[AffectedProduct] = []
    for item in items:
        if not isinstance(item, dict):
            return None
        name, vendor, status = (
            item.get("product"),
            item.get("vendor"),
            item.get("status"),
        )
        if not isinstance(name, str) or not isinstance(vendor, str):
            return None
        if status not in _STATUSES:
            return None
        fixed_in = item.get("fixed_in")
        if status == "fixed" and not isinstance(fixed_in, str):
            return None
        if status != "fixed" and fixed_in is not None:
            return None
        out.append(
            AffectedProduct(
                product=name,
                vendor=vendor,
                status=status,
                fixed_in=fixed_in if isinstance(fixed_in, str) else None,
                note=str(item.get("note") or ""),
            )
        )
    return tuple(out)


def _parse_record(raw: Any) -> tuple[ResearchRecord | None, str | None]:
    """Build a record from one ``entries`` item; return ``(record, reason)``.

    Never raises on a wrongly typed field: every shape problem is a ``reason``.
    """
    if not isinstance(raw, dict):
        return None, "entry is not an object"
    rid = raw.get("id")
    if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
        return None, "entry has a missing or malformed id"
    if raw.get("withdrawn"):
        return None, "withdrawn"
    db = raw.get("database_specific")
    meta = db.get("mcp_audit") if isinstance(db, dict) else None
    if not isinstance(meta, dict) or meta.get("kind") != "research":
        return None, f"{rid}: not a research record"
    products = _parse_products(meta.get("products"))
    credits_raw = _as_list(raw.get("credits"))
    refs_raw = _as_list(raw.get("references"))
    aliases_raw = _as_list(raw.get("aliases"))
    checks_raw = _as_list(meta.get("checks"))
    if (
        products is None
        or credits_raw is None
        or refs_raw is None
        or aliases_raw is None
        or checks_raw is None
    ):
        return None, f"{rid}: a list field has the wrong type or a malformed row"
    credit_items = tuple(
        Credit(name=c["name"], type=str(c.get("type") or "FINDER"))
        for c in credits_raw
        if isinstance(c, dict) and isinstance(c.get("name"), str)
    )
    references = tuple(
        (str(r.get("type") or "WEB"), r["url"])
        for r in refs_raw
        if isinstance(r, dict) and isinstance(r.get("url"), str)
    )
    return (
        ResearchRecord(
            id=rid,
            summary=str(raw.get("summary") or ""),
            details=str(raw.get("details") or ""),
            published=raw["published"]
            if isinstance(raw.get("published"), str)
            else None,
            modified=raw["modified"] if isinstance(raw.get("modified"), str) else None,
            aliases=tuple(a for a in aliases_raw if isinstance(a, str)),
            credits=credit_items,
            references=references,
            products=products,
            checks=tuple(c for c in checks_raw if isinstance(c, str)),
        ),
        None,
    )


def load_research_records(path: Path | None = None) -> ResearchIndex:
    """Load the research records.

    Args:
        path: A file to read instead of the bundled one.

    Returns:
        A :class:`ResearchIndex`.  Never raises: a missing, oversized,
        unparseable or wrongly shaped file gives an empty index with
        ``load_error`` explaining why.
    """
    from mcp_audit import bundle  # noqa: PLC0415

    if path is None:
        path = bundle.override("research-records.json")
    target = path if path is not None else _resolve_bundled_path()
    index = ResearchIndex()
    try:
        # Bounded read: never trust st_size (a symlink to /dev/zero reports 0).
        with target.open("rb") as handle:
            blob = handle.read(MAX_FILE_BYTES + 1)
        if len(blob) > MAX_FILE_BYTES:
            index.load_error = f"research records file is over {MAX_FILE_BYTES} bytes"
            return index
        data = json.loads(blob.decode("utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        index.load_error = f"research records could not be read: {type(exc).__name__}"
        return index
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        index.load_error = "research records file has no 'entries' list"
        return index
    if len(entries) > MAX_ENTRIES:
        index.load_error = (
            f"research records file has {len(entries)} entries (limit {MAX_ENTRIES})"
        )
        return index
    for raw in entries:
        try:
            record, reason = _parse_record(raw)
        except (AttributeError, TypeError, ValueError, KeyError) as exc:
            record, reason = None, f"entry could not be parsed: {type(exc).__name__}"
        if record is None:
            if reason == "withdrawn" and isinstance(raw, dict):
                index.withdrawn[str(raw["id"])] = str(raw.get("withdrawn"))
            elif reason:
                index.skipped.append(reason)
            continue
        if record.id in index.records:
            index.skipped.append(f"{record.id}: duplicate id (first one kept)")
            continue
        index.records[record.id] = record
        for alias in record.aliases:
            key = alias.upper()
            if key in index._aliases and index._aliases[key] != record.id:
                index.skipped.append(
                    f"{record.id}: alias {alias} already used by {index._aliases[key]}"
                )
                continue
            index._aliases[key] = record.id
    return index
