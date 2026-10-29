"""OpenVEX output for ``affected`` and ``scan`` (STORY-0125).

An OpenVEX document says, per product and advisory, whether the product is
``affected``, ``not_affected``, ``fixed`` or ``under_investigation``.  Products
are the npm or PyPI package a server launches, as a package URL (purl), with
the version when mcp-audit knows it.

Only rows where a server really runs the advisory's package become
statements.  A server on some other package, or with no readable package,
says nothing about this advisory and is left out.  No config paths, server
names or environment values are written.

Status mapping:

* AFFECTED → ``affected``, with the fix (or its absence) as the action.
* NOT AFFECTED because the version is at or above the fix → ``fixed``.
* NOT AFFECTED because a verified tag shows the advisory is in transport code
  the server does not run → ``not_affected`` with
  ``vulnerable_code_not_in_execute_path``.
* COULDN'T CHECK → ``under_investigation``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import quote

from mcp_audit import __version__
from mcp_audit.affected.match import (
    NOT_REACHABLE,
    RAN_THE_PACKAGE,
    VERSION_OUTSIDE,
    LockIndex,
    RegistryRule,
    Row,
    RuleSet,
    Status,
    decide_servers,
    rules_for_advisory,
)
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import KnownServerRegistry
from mcp_audit.registry.malicious import load_known_malicious
from mcp_audit.registry.reachability import JUSTIFICATION
from mcp_audit.registry.research import load_research_records

CONTEXT = "https://openvex.dev/ns/v0.2.0"
_CAUTION = {"affected": 3, "under_investigation": 2, "not_affected": 1, "fixed": 0}


def purl(package: str, version: str | None) -> str | None:
    """``pkg:npm/...`` or ``pkg:pypi/...`` for a ``npm:name`` / ``pypi:name`` id."""
    ecosystem, _, name = package.partition(":")
    if ecosystem == "npm":
        # purl: the namespace's "@" is percent-encoded.
        base = "pkg:npm/" + quote(name, safe="/")
    elif ecosystem == "pypi":
        base = "pkg:pypi/" + name.lower().replace("_", "-")
    else:
        return None
    return f"{base}@{quote(version, safe='')}" if version else base


def statement(advisory: str, row: Row) -> dict | None:
    """The OpenVEX statement for one row, or ``None`` when it says nothing."""
    if row.package is None or row.reason not in RAN_THE_PACKAGE:
        return None
    product = purl(row.package, row.version)
    if product is None:
        return None
    out: dict = {
        "vulnerability": {"name": advisory},
        "products": [{"@id": product}],
    }
    if row.status is Status.AFFECTED:
        out["status"] = "affected"
        out["action_statement"] = (
            f"Upgrade to {row.fixed_in} or later."
            if row.fixed_in
            else "No fixed version is recorded; remove the server or watch it."
        )
    elif (
        row.status is Status.NOT_AFFECTED
        and row.reason == NOT_REACHABLE
        and row.version
    ):
        # Only for a known version: a versionless purl would claim every
        # release, and this is one machine's launch, not the product.
        out["status"] = "not_affected"
        out["justification"] = JUSTIFICATION
        out["impact_statement"] = row.evidence
    elif row.status is Status.NOT_AFFECTED and row.reason == VERSION_OUTSIDE:
        out["status"] = "fixed"
    elif row.status is Status.COULDNT_CHECK or row.reason == NOT_REACHABLE:
        out["status"] = "under_investigation"
        out["status_notes"] = row.evidence
        if row.reason == NOT_REACHABLE:
            out["status_notes"] += " (no version is known, so no claim is made)"
    else:
        return None
    return out


def build(
    pairs: Iterable[tuple[str, Row]], *, timestamp: datetime | None = None
) -> dict:
    """An OpenVEX document from ``(advisory, row)`` pairs; duplicates collapse."""
    # One product can be launched by several servers (one stdio, one HTTP) and
    # a VEX statement is per product, so the most cautious status wins.
    best: dict[tuple[str, str], dict] = {}
    for advisory, row in pairs:
        item = statement(advisory, row)
        if item is None:
            continue
        key = (advisory, item["products"][0]["@id"])
        held = best.get(key)
        if held is None or _CAUTION[item["status"]] > _CAUTION[held["status"]]:
            best[key] = item
    statements = list(best.values())
    statements.sort(
        key=lambda s: (s["vulnerability"]["name"], s["products"][0]["@id"], s["status"])
    )
    stamp = (timestamp or datetime.now(UTC)).replace(microsecond=0)
    body = json.dumps(statements, sort_keys=True)
    return {
        "@context": CONTEXT,
        "@id": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, body)),
        "author": "mcp-audit",
        "timestamp": stamp.isoformat().replace("+00:00", "Z"),
        "version": 1,
        "tooling": f"mcp-audit {__version__}",
        "statements": statements,
    }


def render(document: dict) -> str:
    """The document as JSON text."""
    return json.dumps(document, indent=2) + "\n"


def pairs_for_servers(
    servers: list[ServerConfig],
    registry: KnownServerRegistry,
    locks: LockIndex,
) -> list[tuple[str, Row]]:
    """Every registry advisory, decided against each server that runs its package.

    Used by ``scan --vex``: the machine's whole answer, not one advisory's.
    """
    malicious = load_known_malicious()
    research = load_research_records()
    found: set[str] = set()
    for e in registry.entries:
        found.update(str(c) for c in e.known_vulnerabilities or [] if c)
        found.update(
            str(r["cve"])
            for r in e.known_vulns or []
            if isinstance(r, dict) and r.get("cve")
        )
    ids = sorted(found)
    pairs: list[tuple[str, Row]] = []
    for advisory in ids:
        rules = [
            r
            for r in rules_for_advisory(advisory, registry, malicious, research).rules
            if isinstance(r, RegistryRule)
        ]
        if not rules:
            continue
        rows = decide_servers(
            servers, RuleSet(rules=list(rules)), registry, locks, advisory
        )
        pairs.extend((advisory, row) for row in rows)
    return pairs
