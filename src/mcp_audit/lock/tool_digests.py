"""Tool-definition digests: the ``tools`` section of ``mcp-lock.json``.

STORY-0086, ADR-0005 amendment "mcp-audit owns ``tools``". ``mcp-audit lock
--connect`` asks each server for its tool list and records, per tool, two
SHA-256 digests of the RFC 8785 canonical JSON of what the server sent:

- ``definition`` — name, title, description, inputSchema, outputSchema and
  annotations. (``icons``, ``_meta`` and ``execution`` are not digested.)
- ``contract`` — the same minus the free text (title and description).

Comparing both tells ``lock --verify --connect`` which kind of change it is
looking at: a different ``contract`` means the schema or annotations moved
(LOCK-007); the same ``contract`` with a different ``definition`` means only
the text changed (LOCK-008). Only names and digests are written, never the
tool text.

The section declares its producer and carries its own checksum::

    "tools": {
      "_producer": "mcp-audit",
      "_schema_version": 1,
      "servers": {
        "<client>/<name>": {
          "tools": {"<tool>": {"contract": "sha256:...", "definition": "sha256:..."}}
        }
      },
      "_checksum": "sha256:<hex>"
    }

The top-level ``checksum`` keeps its ADR-0005 §10 scope. Folding ``tools``
into it would make every mcp-audit up to 0.20 report LOCK-005 ("tampered")
on a lock written with ``--connect``; a section-local checksum lets those
versions see a populated section they cannot verify instead, which they
already report honestly (R56).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from mcp_audit.advisory.canonical import canonicalize
from mcp_audit.models import ServerConfig, ToolInfo

TOOLS_KEY = "tools"
TOOLS_PRODUCER = "mcp-audit"
TOOLS_SCHEMA_VERSION = 1

#: Free text a model or person reads; no effect on what the tool accepts,
#: returns, or declares about itself.
TEXT_FIELDS: tuple[str, ...] = ("title", "description")


def digest(value: object) -> str:
    """Return ``"sha256:<hex>"`` of *value*'s RFC 8785 canonical JSON."""
    return "sha256:" + hashlib.sha256(canonicalize(value)).hexdigest()


def tool_definition(tool: ToolInfo) -> dict:
    """Return the wire-format definition of *tool* that gets digested.

    Fields the server did not send are left out rather than written as
    ``null``, so "absent" and "explicitly null" digest the same.
    """
    definition = {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
        "annotations": tool.annotations,
    }
    return {key: value for key, value in definition.items() if value is not None}


def _contract(definition: dict) -> dict:
    return {k: v for k, v in definition.items() if k not in TEXT_FIELDS}


def tool_digests(tools: list[ToolInfo]) -> dict[str, dict[str, str]]:
    """Return ``{tool name: {"contract": ..., "definition": ...}}`` for *tools*.

    A server that lists two tools under one name (a collision, never valid)
    gets one entry digesting all of them in a fixed order, so any change to
    any of them still shows.
    """
    grouped: dict[str, list[dict]] = {}
    for tool in tools:
        grouped.setdefault(tool.name, []).append(tool_definition(tool))

    records: dict[str, dict[str, str]] = {}
    for name, definitions in grouped.items():
        contracts = [_contract(d) for d in definitions]
        if len(definitions) == 1:
            records[name] = {
                "contract": digest(contracts[0]),
                "definition": digest(definitions[0]),
            }
        else:
            records[name] = {
                "contract": digest(sorted(contracts, key=canonicalize)),
                "definition": digest(sorted(definitions, key=canonicalize)),
            }
    return records


def server_record(tools: list[ToolInfo]) -> dict:
    """Return one server's record for the ``tools`` section."""
    return {"tools": tool_digests(tools)}


def is_owned(section: object) -> bool:
    """Whether *section* is a ``tools`` section this version of mcp-audit wrote.

    Ownership is declared, not positional (ADR-0005 §1). A section from any
    other producer, or from a newer mcp-audit schema this version cannot
    read, is foreign: preserved untouched and never overwritten.
    """
    return (
        isinstance(section, dict)
        and section.get("_producer") == TOOLS_PRODUCER
        and section.get("_schema_version") == TOOLS_SCHEMA_VERSION
    )


def section_checksum(section: dict) -> str:
    """Return the checksum of *section*, excluding its own ``_checksum``."""
    return digest({k: v for k, v in section.items() if k != "_checksum"})


def checksum_ok(section: dict) -> bool:
    """Whether *section*'s ``_checksum`` matches its content and shape."""
    servers = section.get("servers")
    if not isinstance(servers, dict):
        return False
    return section.get("_checksum") == section_checksum(section)


def build_section(servers: dict[str, dict]) -> dict | None:
    """Return a complete owned ``tools`` section, or ``None`` when empty."""
    if not servers:
        return None
    section: dict = {
        "_producer": TOOLS_PRODUCER,
        "_schema_version": TOOLS_SCHEMA_VERSION,
        "servers": {key: servers[key] for key in sorted(servers)},
    }
    section["_checksum"] = section_checksum(section)
    return section


def merge_section(
    existing: object,
    new_records: dict[str, dict],
    keep_keys: set[str],
) -> dict | None:
    """Return the ``tools`` section for a rewritten lock.

    Starts from the existing owned section (if any), replaces the records for
    servers enumerated this run, and drops records for servers no longer in
    the lock. A server whose enumeration failed this run keeps its previous
    record: a transient failure never erases an approval.

    Records are only carried forward from a section that passes
    :func:`checksum_ok`; the caller decides what to do about one that does
    not (``lock/writer.py::regenerate`` refuses, or with ``--connect``
    starts over), so a hand-edited record is never re-checksummed into a
    valid one here.

    Args:
        existing: The current ``tools`` value (owned or ``None``).
        new_records: ``{lock key: server_record(...)}`` from this run.
        keep_keys: The lock keys present in the rewritten ``servers``.
    """
    servers: dict[str, dict] = {}
    if is_owned(existing) and checksum_ok(existing):  # type: ignore[arg-type]
        servers.update(existing["servers"])  # type: ignore[index]
    servers.update(new_records)
    return build_section({k: v for k, v in servers.items() if k in keep_keys})


def enumeration_key(server: ServerConfig) -> tuple[str, str]:
    """Key a live enumeration to the discovered server it came from."""
    return (str(server.config_path), server.name)


@dataclass
class ToolDiff:
    """How a server's current tools differ from its locked record."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    contract_changed: list[str] = field(default_factory=list)
    text_changed: list[str] = field(default_factory=list)


def compare(locked: dict, current: dict[str, dict[str, str]]) -> ToolDiff:
    """Compare a locked server record with freshly computed digests.

    Args:
        locked: The server's record from the lock (``{"tools": {...}}``).
        current: :func:`tool_digests` of what the server lists now.
    """
    locked_tools = locked.get("tools") if isinstance(locked, dict) else None
    if not isinstance(locked_tools, dict):
        locked_tools = {}
    diff = ToolDiff(
        added=sorted(set(current) - set(locked_tools)),
        removed=sorted(set(locked_tools) - set(current)),
    )
    for name in sorted(set(current) & set(locked_tools)):
        was, now = locked_tools[name], current[name]
        if not isinstance(was, dict) or was.get("contract") != now["contract"]:
            diff.contract_changed.append(name)
        elif was.get("definition") != now["definition"]:
            diff.text_changed.append(name)
    return diff
