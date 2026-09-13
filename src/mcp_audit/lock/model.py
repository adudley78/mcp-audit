"""Pydantic models for ``mcp-lock.json`` and the ownership-scoped checksum.

See ``docs/decisions/ADR-0005-mcp-audit-lock.md`` for the full rationale.
This module implements the ADR's ownership boundary: mcp-audit owns
``lock_version``, ``generated_by``, ``generated_at``, and ``servers``.  Every
other top-level key (``trees``, ``tools``, and anything unrecognised) is
foreign — mcp-audit preserves it, reports it, and never includes it in its
own ``checksum`` or claims to have verified it (ADR §1, §3, §10).
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, Field

from mcp_audit.advisory.canonical import canonicalize

LOCK_VERSION = 1
LOCK_FILENAME = "mcp-lock.json"

#: Top-level keys mcp-audit itself produces and checksums.  ``generated_at``
#: is deliberately excluded from the checksummed body — ADR-0005 §5 (a
#: no-op re-lock must not churn the checksum).
OWNED_CHECKSUM_KEYS: frozenset[str] = frozenset(
    {"lock_version", "generated_by", "servers"}
)

#: The envelope around the checksummed body: present on every lock file,
#: neither "owned content" (checksummed) nor "foreign" (unverified).
STRUCTURAL_KEYS: frozenset[str] = frozenset(
    {"lock_version", "generated_by", "generated_at", "checksum"}
)

#: Reserved-but-foreign sections: mcp-audit declares them in the schema but
#: never populates or verifies their contents (ADR-0005 §1, §4, §11).
RESERVED_FOREIGN_KEYS: frozenset[str] = frozenset({"trees", "tools"})

#: The exact default stub value ``lock/writer.py::regenerate()`` writes for
#: each reserved-but-foreign key when no other producer has populated it yet
#: (``trees: {}``, ``tools: null``).  A key present with exactly this value is
#: mcp-audit's own placeholder, not evidence any other producer touched the
#: file — see :func:`foreign_sections_with_content`.
RESERVED_FOREIGN_DEFAULTS: dict[str, object] = {"trees": {}, "tools": None}


class LockResolution(BaseModel):
    """How and when a package's version was resolved (ADR-0005 §7)."""

    method: Literal["dist-tag:latest", "exact-pin", "known_hashes", "unresolved"]
    resolved_at: str | None = None


class LockPackage(BaseModel):
    """The resolved package identity for one locked server (ADR-0005 shape)."""

    ecosystem: Literal["npm", "pypi"]
    name: str
    spec_as_written: str
    range_spec: bool = False
    resolved_version: str | None = None
    resolution: LockResolution
    integrity: str | None = None
    source: Literal["registry", "known_hashes", "unresolved"]
    #: The package registry's own deprecation notice for `resolved_version`,
    #: or `None` when not deprecated. Populated only via the network-fetch
    #: path (`resolution.method == "dist-tag:latest"`) — an exact pin never
    #: makes the network call this is read from (STORY-0073/R58). Owned by
    #: mcp-audit and covered by the checksum like every other field here;
    #: `lock_version` stays 1 (additive field, not a schema break).
    deprecated: str | None = None


class LockIdentity(BaseModel):
    """Launch identity used for drift comparison (ADR-0005 §9).

    Exactly one of (``command`` + ``args``) or ``url`` is populated,
    mirroring the platform allowlist matchers (``serverCommand`` /
    ``serverUrl``) so STORY-0071 can export without translation.
    """

    command: str | None = None
    args: list[str] | None = None
    url: str | None = None


class LockEntry(BaseModel):
    """One locked server, keyed ``{client}/{name}`` in ``LockFile.servers``."""

    client: str
    name: str
    config: str
    identity: LockIdentity
    package: LockPackage | None = None
    env_keys: list[str] = Field(default_factory=list)
    header_keys: list[str] = Field(default_factory=list)
    capabilities: list[str] | None = None
    first_locked: str
    hashes: dict[str, str] = Field(default_factory=dict)


class LockFile(BaseModel):
    """mcp-audit's owned view of ``mcp-lock.json``.

    Foreign sections (``trees``, ``tools``, anything unrecognised) are not
    modelled here — they are opaque values handled by
    :mod:`mcp_audit.lock.writer` / :mod:`mcp_audit.lock.verifier`, which
    operate on the full on-disk document, not on this model alone.
    """

    lock_version: int = LOCK_VERSION
    generated_by: str
    generated_at: str
    servers: dict[str, LockEntry] = Field(default_factory=dict)
    checksum: str


def owned_subdocument(doc: dict) -> dict:
    """Return the sub-document mcp-audit's ``checksum`` actually covers.

    ADR-0005 §10: ``{lock_version, generated_by, servers}`` only — never
    ``generated_at``, ``checksum`` itself, or any foreign section (``trees``,
    ``tools``, anything unrecognised).  Scoping the checksum this way means a
    legitimate rewrite of ``trees`` by an independent producer never
    invalidates it (the checkpoint-review fix that keeps LOCK-005 meaning one
    thing: mcp-audit's own record was tampered).

    Args:
        doc: The full on-disk lock document as a plain dict.

    Returns:
        A new dict containing only the owned keys present in *doc*.
    """
    return {k: doc[k] for k in ("lock_version", "generated_by", "servers") if k in doc}


def compute_checksum(doc: dict) -> str:
    """Compute mcp-audit's owned-section checksum for *doc* (ADR-0005 §10).

    Args:
        doc: The full on-disk lock document as a plain dict.

    Returns:
        ``"sha256:<hex>"``.
    """
    body = owned_subdocument(doc)
    digest = hashlib.sha256(canonicalize(body)).hexdigest()
    return f"sha256:{digest}"


def unverified_sections(doc: dict) -> list[str]:
    """Return top-level keys present in *doc* that mcp-audit does not verify.

    Drives the generic (not ``trees``-specific) ``lock --verify`` summary
    line — ADR-0005 §3's checkpoint-review fix: a future foreign section is
    named automatically instead of the summary silently reading as fully
    verified.

    Args:
        doc: The full on-disk lock document as a plain dict.

    Returns:
        Sorted list of top-level keys outside mcp-audit's owned/structural
        set (e.g. ``["trees"]``).
    """
    owned_and_structural = OWNED_CHECKSUM_KEYS | STRUCTURAL_KEYS
    return sorted(k for k in doc if k not in owned_and_structural)


def foreign_sections_with_content(doc: dict) -> list[str]:
    """Return unverified top-level sections that carry real foreign content.

    Strict subset of :func:`unverified_sections` (R56, prompted by issue #88 —
    `humans/...` correspondence, and ADR-0005 §3's "honest partial
    verification" MUST applied to ``lock --verify``'s *exit code*, not just
    its printed summary line).

    ``lock`` itself always writes the ``trees: {}`` / ``tools: null`` default
    stubs (``writer.py::regenerate()``, ``RESERVED_FOREIGN_DEFAULTS`` above) —
    their mere presence is mcp-audit's own placeholder, not evidence that any
    other producer touched the file. Per ADR-0005 §4's MUST ("never a reason
    to fail `lock` or `--verify`"), that default-stub case must **not** flip
    the exit code, or every single lock file mcp-audit has ever written would
    fail `--verify` unconditionally.

    A key present with a value *other than* its declared default (Prachet
    Poddar's tree generator has actually populated ``trees``; a future
    ``--connect``-derived ``tools`` payload; a wholly unrecognised key
    mcp-audit never writes at all, e.g. a synthetic ``resolutions`` sidecar)
    means a section mcp-audit did not write and structurally cannot check is
    genuinely present. That is the gap this function exists to catch:
    distinct from, and narrower than, the always-present empty-stub case
    already covered by :func:`unverified_sections`.

    Args:
        doc: The full on-disk lock document as a plain dict.

    Returns:
        Sorted list of top-level keys mcp-audit did not write and cannot
        verify, excluding its own untouched default stubs.
    """
    return [
        key
        for key in unverified_sections(doc)
        if key not in RESERVED_FOREIGN_DEFAULTS
        or doc.get(key) != RESERVED_FOREIGN_DEFAULTS[key]
    ]
