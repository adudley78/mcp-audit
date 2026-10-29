"""Signed data bundle for air-gapped use (STORY-0129).

A bundle is a directory carrying the published advisory feed (``index.json`` and
``advisories/``) plus the four data files ``scan`` and ``affected`` read:

    bundle/
      index.json, index.json.sig, advisories/...   the feed, as published
      data/known-servers.json                      the registry
      data/known-malicious.json                    the malicious-package mirror
      data/research-records.json                   credited research records
      data/exploit-signals.json                    KEV / EPSS / PoC
      bundle.json, bundle.json.sig                 manifest, signed like the feed

``bundle.json`` records the SHA-256 of each data file and of the feed index's
canonical bytes, and is signed with the same key as the feed.  Verification is
the feed's own (:func:`~mcp_audit.advisory.sign.verify_feed`: signatures, digests,
expiry, rollback; there is no way to accept an expired feed) followed by the
manifest's signature, the index digest, and every data file's digest.  An
unsigned feed or manifest is refused: a bundle is carried across a trust
boundary, so "integrity only" is not enough.

Nothing here touches the network.  After :func:`activate`, the bundled loaders
(known-malicious, research records, exploit signals) read the bundle's files;
the registry path is returned by :meth:`Bundle.path` for call sites to pass.
"""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit.advisory.sign import (
    SigningConfig,
    SigningError,
    canonical_bytes_for,
    verify_feed,
    verify_path,
)

MANIFEST = "bundle.json"
KIND = "mcp-audit-data-bundle"
SCHEMA_VERSION = 1
DATA_DIR = "data"
DATA_FILES = (
    "known-servers.json",
    "known-malicious.json",
    "research-records.json",
    "exploit-signals.json",
)
MAX_DATA_BYTES = 64 * 1024 * 1024


class BundleError(RuntimeError):
    """A bundle could not be verified; ``failures`` lists every reason."""

    def __init__(self, failures: list[str]) -> None:
        super().__init__("; ".join(failures))
        self.failures = failures


@dataclass(frozen=True)
class Bundle:
    """A verified bundle."""

    root: Path
    published_at: str
    expires: str | None
    snapshot_version: int | None
    age_days: int | None
    created_at: str | None
    files: dict[str, Path] = field(default_factory=dict)

    def path(self, name: str) -> Path:
        """The verified data file called *name* (``known-servers.json``...)."""
        return self.files[name]

    @property
    def date(self) -> str:
        """The bundle's date: the feed's ``published_at``, day only."""
        return self.published_at[:10]

    def line(self) -> str:
        """One line for every run's output."""
        age = f", {self.age_days} days old" if self.age_days is not None else ""
        snap = (
            f", feed snapshot {self.snapshot_version}"
            if self.snapshot_version is not None
            else ""
        )
        return f"Signed bundle {self.date}{age}{snap} (verified, no network)"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_inside(root: Path, rel: str) -> Path | None:
    """*rel* under *root* when it is a regular file that stays inside it."""
    candidate = root / rel
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
        if not stat.S_ISREG(resolved.stat().st_mode):
            return None
    except (OSError, ValueError):
        return None
    return resolved


def verify_bundle(
    root: Path,
    config: SigningConfig,
    *,
    now: datetime | None = None,
    state_path: Path | None = None,
) -> Bundle:
    """Verify the bundle at *root* and return it.

    Raises:
        BundleError: with every failure found.  Unsigned, expired, rolled back,
            tampered, or missing a data file all fail.
    """
    root = Path(root)
    if not root.is_dir():
        raise BundleError([f"bundle directory not found: {root}"])
    now = now or datetime.now(UTC)

    report = verify_feed(root, config, now=now, state_path=state_path)
    failures = list(report.failures)
    if report.ok and not report.signed:
        failures.append(
            "the feed in this bundle is unsigned; a bundle must be signed "
            "(an unsigned feed is integrity-checked only)"
        )
    if failures:
        raise BundleError(failures)

    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        raise BundleError([f"{MANIFEST} not found in {root}"])
    try:
        verify_path(manifest_path, config)
    except SigningError as exc:
        raise BundleError([f"{MANIFEST}: {exc}"]) from None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise BundleError([f"{MANIFEST} is not readable JSON: {exc}"]) from None
    if (
        not isinstance(manifest, dict)
        or manifest.get("kind") != KIND
        or manifest.get("schema_version") != SCHEMA_VERSION
        or not isinstance(manifest.get("files"), dict)
    ):
        raise BundleError([f"{MANIFEST} is not a v{SCHEMA_VERSION} bundle manifest"])

    try:
        index_digest = hashlib.sha256(
            canonical_bytes_for(root / "index.json")
        ).hexdigest()
    except SigningError as exc:
        raise BundleError([str(exc)]) from None
    if manifest.get("feed_index_sha256") != index_digest:
        failures.append(
            f"{MANIFEST} was made for a different feed index than the one here"
        )

    listed = manifest["files"]
    files: dict[str, Path] = {}
    for name in DATA_FILES:
        rel = f"{DATA_DIR}/{name}"
        entry = listed.get(rel)
        if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
            failures.append(f"{rel}: not listed in {MANIFEST}")
            continue
        found = _regular_inside(root, rel)
        if found is None:
            failures.append(f"{rel}: missing, or not a regular file inside the bundle")
            continue
        if found.stat().st_size > MAX_DATA_BYTES:
            failures.append(f"{rel}: larger than {MAX_DATA_BYTES} bytes")
            continue
        if _sha256(found) != entry["sha256"]:
            failures.append(f"{rel}: content does not match the digest in {MANIFEST}")
            continue
        files[name] = found
    for rel in sorted(set(listed) - {f"{DATA_DIR}/{n}" for n in DATA_FILES}):
        failures.append(
            f"{rel}: listed in {MANIFEST} but not a file this version reads"
        )
    data_dir = root / DATA_DIR
    if data_dir.is_dir():
        for child in sorted(data_dir.iterdir()):
            if child.name not in DATA_FILES:
                failures.append(
                    f"{DATA_DIR}/{child.name}: present but not in {MANIFEST}"
                )
    if failures:
        raise BundleError(failures)

    return Bundle(
        root=root,
        published_at=report.published_at or "",
        expires=report.expires,
        snapshot_version=report.snapshot_version,
        age_days=report.age_days,
        created_at=manifest.get("created_at"),
        files=files,
    )


# ── Activation ──────────────────────────────────────────────────────────────

_active: Bundle | None = None


def activate(bundle: Bundle | None) -> None:
    """Make the loaders read *bundle*'s files (``None`` goes back to bundled)."""
    global _active  # noqa: PLW0603
    _active = bundle
    from mcp_audit.exploit import signals  # noqa: PLC0415

    signals.reset_cache()


def active() -> Bundle | None:
    """The activated bundle, if any."""
    return _active


def override(name: str) -> Path | None:
    """The activated bundle's path for data file *name*, else ``None``."""
    return _active.files.get(name) if _active is not None else None
