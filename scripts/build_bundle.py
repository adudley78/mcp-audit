#!/usr/bin/env python3
"""Assemble, sign or verify an air-gapped data bundle (STORY-0129, Q-058).

A bundle is the published advisory feed plus the four data files ``scan`` and
``affected`` read, with a manifest ``bundle.json`` signed like the feed.  See
``src/mcp_audit/bundle.py`` for the layout and ``docs/air-gapped.md`` for how
to carry one across.

    # Copy a signed feed and add the data files and a signed manifest:
    python scripts/build_bundle.py --feed ./feed --out ./bundle \\
        --private-key minisign.key --public-key minisign.pub

    # Add them to the feed directory itself (the weekly publish does this, so
    # the `feed` branch is a bundle):
    python scripts/build_bundle.py --feed ./feed --in-place \\
        --private-key KEY --public-key keys/mcp-audit-feed.pub \\
        --exploit-signals fresh-signals.json

    # Verify one (exit 0 verified, 1 not):
    python scripts/build_bundle.py --verify ./bundle --public-key KEY.pub

Without ``--private-key`` the manifest is written unsigned, which
``--bundle`` refuses; that is for assembling a bundle another party signs.
The feed directory must already be signed and unexpired: this script does not
re-sign it.

``--exploit-signals FILE`` takes a freshly fetched KEV/EPSS file instead of
the committed one, but only when it looks complete: it parses, its KEV
catalog date is not older than the committed file's, and it lists at least as
many KEV entries.  Otherwise the committed file is used and a warning printed,
so a source outage never ships thinner data or stops the publish.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from mcp_audit import bundle as bundle_mod  # noqa: E402
from mcp_audit.advisory.sign import (  # noqa: E402
    BACKEND_MINISIGN,
    SigningConfig,
    canonical_bytes_for,
    sign_path,
)

SOURCES = {
    "known-servers.json": REPO / "registry" / "known-servers.json",
    "known-malicious.json": REPO / "registry" / "known-malicious.json",
    "research-records.json": REPO
    / "src"
    / "mcp_audit"
    / "data"
    / "research-records.json",
    "exploit-signals.json": REPO
    / "src"
    / "mcp_audit"
    / "data"
    / "exploit-signals.json",
}


def _kev(path: Path) -> tuple[str, int]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    kev = doc["kev"]
    return str(kev.get("date_released") or ""), len(kev["entries"])


def choose_signals(fresh: Path | None, committed: Path) -> Path:
    """*fresh* if it is at least as complete as *committed*, else *committed*."""
    if fresh is None:
        return committed
    try:
        fresh_date, fresh_count = _kev(fresh)
        old_date, old_count = _kev(committed)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(
            f"warning: fresh exploit signals unreadable ({exc}); "
            "using the committed file"
        )
        return committed
    if not fresh_date or fresh_date < old_date or fresh_count < old_count:
        print(
            f"warning: fresh exploit signals look incomplete (KEV {fresh_date}, "
            f"{fresh_count} entries vs committed {old_date}, {old_count}); "
            "using the committed file"
        )
        return committed
    return fresh


def build(
    feed: Path,
    out: Path | None,
    config: SigningConfig | None,
    *,
    signals: Path | None = None,
) -> Path:
    """Write the bundle and return its directory.

    With *out*, the feed is copied there first (*out* must not exist); with
    ``out=None`` the data files and manifest are added to *feed* itself.
    """
    if not (feed / "index.json").is_file():
        raise SystemExit(f"{feed}/index.json not found")
    if out is None:
        out = feed
        for name in (
            bundle_mod.DATA_DIR,
            bundle_mod.MANIFEST,
            bundle_mod.MANIFEST + ".sig",
        ):
            if (out / name).exists():
                raise SystemExit(f"{out / name} already exists")
    else:
        if out.exists():
            raise SystemExit(f"{out} already exists; choose a new directory")
        out.mkdir(parents=True)
        for name in ("index.json", "index.json.sig"):
            if (feed / name).is_file():
                shutil.copy2(feed / name, out / name)
        if (feed / "advisories").is_dir():
            shutil.copytree(feed / "advisories", out / "advisories")
    sources = dict(SOURCES)
    sources["exploit-signals.json"] = choose_signals(
        signals, SOURCES["exploit-signals.json"]
    )
    (out / bundle_mod.DATA_DIR).mkdir()
    files: dict[str, dict[str, object]] = {}
    for name, source in sources.items():
        target = out / bundle_mod.DATA_DIR / name
        shutil.copy2(source, target)
        files[f"{bundle_mod.DATA_DIR}/{name}"] = {
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "bytes": target.stat().st_size,
        }
    manifest = {
        "kind": bundle_mod.KIND,
        "schema_version": bundle_mod.SCHEMA_VERSION,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feed_index_sha256": hashlib.sha256(
            canonical_bytes_for(out / "index.json")
        ).hexdigest(),
        "files": files,
    }
    path = out / bundle_mod.MANIFEST
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if config is not None:
        sign_path(path, config)
    return out


def verify(directory: Path, public_key: Path) -> int:
    """Verify *directory* as a bundle; print the result; 0 when it verifies."""
    config = SigningConfig.from_env(backend=BACKEND_MINISIGN, public_key=public_key)
    with tempfile.TemporaryDirectory() as tmp:
        try:
            opened = bundle_mod.verify_bundle(
                directory, config, state_path=Path(tmp) / "seen.json"
            )
        except bundle_mod.BundleError as exc:
            for failure in exc.failures:
                print(f"FAILED  {failure}")
            return 1
    print(opened.line())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--feed", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--in-place", action="store_true")
    parser.add_argument("--verify", type=Path, metavar="DIR")
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--exploit-signals", type=Path)
    args = parser.parse_args(argv)
    if args.verify is not None:
        if args.public_key is None:
            parser.error("--verify needs --public-key")
        return verify(args.verify, args.public_key)
    if args.feed is None or (args.out is None) == (not args.in_place):
        parser.error("give --feed and exactly one of --out or --in-place")
    config = (
        SigningConfig.from_env(
            backend=BACKEND_MINISIGN,
            private_key=args.private_key,
            public_key=args.public_key,
        )
        if args.private_key
        else None
    )
    out = build(
        args.feed,
        None if args.in_place else args.out,
        config,
        signals=args.exploit_signals,
    )
    state = "signed" if config else "UNSIGNED (--bundle will refuse it)"
    print(f"Wrote {state} bundle to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
