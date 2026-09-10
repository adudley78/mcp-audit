"""Write and regenerate ``mcp-lock.json`` (ADR-0005).

:func:`regenerate` builds the new full document as a plain ``dict`` (never a
serialised ``LockFile`` model instance) so that foreign top-level sections —
``trees``, ``tools``, anything unrecognised — pass through completely
untouched as the exact Python values :func:`json.loads` produced when the
existing file was read.  :func:`serialize` then renders the *whole* document,
including those foreign sections, through
:func:`mcp_audit.advisory.canonical.canonicalize` — the format-level
requirement ADR-0005 §2 places on ``mcp-lock.json`` so that two independent,
possibly cross-language producers (mcp-audit and the #88 tree generator)
always agree on the bytes for a value neither one has changed.

mcp-audit's own ``checksum`` covers only the sub-document it owns
(:func:`mcp_audit.lock.model.owned_subdocument`) — see ADR-0005 §10.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.advisory.canonical import CanonicalError, canonicalize
from mcp_audit.analyzers.rug_pull import compute_hashes, server_key
from mcp_audit.lock.identity import build_identity
from mcp_audit.lock.model import (
    LOCK_VERSION,
    RESERVED_FOREIGN_KEYS,
    STRUCTURAL_KEYS,
    compute_checksum,
)
from mcp_audit.lock.resolve import resolve_package
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import KnownServerRegistry


class LockWriteError(Exception):
    """The document cannot be safely serialised.

    Raised instead of letting :class:`~mcp_audit.advisory.canonical.CanonicalError`
    propagate as a traceback — ADR-0005 §2 rule 3 / §10's checkpoint-review
    fix: a clean message naming the oversized section, never a bare
    traceback and never a silently truncated write.
    """


def load_existing(path: Path) -> dict | None:
    """Load an existing lock document, or ``None`` if absent/unreadable.

    Args:
        path: Path to ``mcp-lock.json``.

    Returns:
        The parsed document, or ``None`` when the file does not exist or is
        not valid JSON (treated the same as "no lock yet" for *writing* —
        ``lock --verify`` is the command that reports a genuinely corrupt
        file as a finding, not this loader).
    """
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _relative_config_path(config_path: Path, root: Path) -> str:
    """Return *config_path* as a repo-relative or ``~``-relative string.

    Never an absolute, machine-specific path — ADR-0005's "never contains an
    absolute path" invariant.

    Args:
        config_path: The absolute path to a discovered config file.
        root: The project root ``lock`` was run against.

    Returns:
        A POSIX-style relative path (project-relative when under *root*,
        ``~/...`` when under ``$HOME``, otherwise just the file name as a
        last resort).
    """
    resolved = config_path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        pass
    try:
        home = Path.home()
        return f"~/{resolved.relative_to(home).as_posix()}"
    except (ValueError, RuntimeError):
        return resolved.name


def build_entry(
    server: ServerConfig,
    root: Path,
    *,
    offline: bool,
    registry: KnownServerRegistry | None,
    existing: dict | None,
    now: str,
) -> dict:
    """Build one server's lock entry.

    Args:
        server: A parsed MCP server configuration.
        root: The project root ``lock`` was run against.
        offline: Suppress all network resolution when ``True``.
        registry: The known-server registry (for ``known_hashes`` and
            ``capabilities``).
        existing: The previous entry for this server key, if any — used to
            preserve ``first_locked`` and (via
            :func:`mcp_audit.lock.resolve.resolve_package`) implement
            write-on-change for ``resolved_at``.
        now: ISO-8601 timestamp for this run, used only for a genuinely new
            server's ``first_locked``.

    Returns:
        A dict matching :class:`~mcp_audit.lock.model.LockEntry`'s shape.
    """
    package = resolve_package(
        server,
        offline=offline,
        registry=registry,
        existing=(existing or {}).get("package"),
    )
    capabilities: list[str] | None = None
    if package is not None and registry is not None:
        registry_entry = registry.get(package["name"])
        if registry_entry is not None:
            capabilities = registry_entry.capabilities

    return {
        "client": server.client,
        "name": server.name,
        "config": _relative_config_path(server.config_path, root),
        "identity": build_identity(server),
        "package": package,
        "env_keys": sorted(server.env.keys()),
        "header_keys": sorted(server.headers.keys()),
        "capabilities": capabilities,
        "first_locked": (existing or {}).get("first_locked", now),
        "hashes": compute_hashes(server),
    }


def regenerate(
    existing_doc: dict | None,
    servers: list[ServerConfig],
    root: Path,
    *,
    offline: bool,
    registry: KnownServerRegistry | None,
) -> dict:
    """Build the new full lock document from the current server list.

    Foreign top-level sections in *existing_doc* (``trees``, ``tools``, and
    anything unrecognised) are copied through verbatim as the exact parsed
    Python values — never re-derived, never touched.  Used by both
    ``mcp-audit lock`` and ``mcp-audit lock --accept``: the two commands
    perform the same regeneration; ``--accept`` exists as the explicit,
    named step in the "review the drift, then re-lock" workflow.

    Args:
        existing_doc: The previously loaded document, or ``None`` for a
            first-time lock.
        servers: All servers this run of ``lock`` discovered.
        root: The project root ``lock`` was run against.
        offline: Suppress all network resolution when ``True``.
        registry: The known-server registry.

    Returns:
        The new full document, including a freshly computed ``checksum``
        (ADR-0005 §10 — scoped to ``{lock_version, generated_by, servers}``
        only).
    """
    existing_servers: dict = (existing_doc or {}).get("servers", {})
    now = datetime.now(UTC).isoformat()

    new_servers: dict[str, dict] = {}
    for server in servers:
        key = server_key(server)
        new_servers[key] = build_entry(
            server,
            root,
            offline=offline,
            registry=registry,
            existing=existing_servers.get(key),
            now=now,
        )

    doc: dict = {}
    if existing_doc:
        for key, value in existing_doc.items():
            if key not in STRUCTURAL_KEYS and key != "servers":
                doc[key] = value
    for key in RESERVED_FOREIGN_KEYS:
        doc.setdefault(key, {} if key == "trees" else None)

    doc["lock_version"] = LOCK_VERSION
    doc["generated_by"] = f"mcp-audit/{__version__}"
    doc["generated_at"] = now
    doc["servers"] = new_servers
    doc["checksum"] = compute_checksum(doc)
    return doc


def _find_oversized_key(doc: dict) -> str:
    """Identify which top-level key overflows the canonicalization bound.

    Used only on the (rare) error path — :func:`serialize` has already
    established that canonicalizing the whole document fails.
    """
    for key, value in doc.items():
        try:
            canonicalize({key: value})
        except CanonicalError:
            return key
    return "<unknown>"


def serialize(doc: dict) -> bytes:
    """Render the full document to its on-disk bytes.

    The on-disk format *is* the RFC 8785 canonical encoding — ADR-0005 §2
    rule 2 — so that a section neither producer has touched reproduces
    identical bytes on every write, regardless of which implementation
    (or language) wrote it.

    Args:
        doc: The full lock document (owned sections + any foreign ones).

    Returns:
        Canonical UTF-8 bytes ready to write to disk.

    Raises:
        LockWriteError: A top-level section is too large to canonicalize
            safely.  The message names the offending section — ADR-0005
            §2 rule 3 / §10: never a bare traceback, never a partial write.
    """
    try:
        return canonicalize(doc)
    except CanonicalError:
        offending = _find_oversized_key(doc)
        raise LockWriteError(
            f"{offending!r} section is too large for mcp-audit to process "
            "safely (exceeds an internal canonicalization size bound). "
            "This is a limitation of mcp-audit's own processing, not a "
            "problem with your lock file — see docs/lock.md."
        ) from None


def write_atomic(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically (``.tmp`` + rename), like ``fix --apply``.

    Args:
        path: Destination file path.
        data: Bytes to write.
    """
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(data)
    tmp_path.replace(path)


def write_lock(path: Path, doc: dict) -> None:
    """Serialize *doc* and write it atomically to *path*.

    Args:
        path: Destination ``mcp-lock.json`` path.
        doc: The full lock document, as built by :func:`regenerate`.

    Raises:
        LockWriteError: See :func:`serialize`.
    """
    write_atomic(path, serialize(doc))
