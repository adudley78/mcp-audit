#!/usr/bin/env python3
"""Assemble (and sign) an air-gapped data bundle (STORY-0129).

A bundle is the published advisory feed plus the four data files ``scan`` and
``affected`` read, with a manifest ``bundle.json`` signed like the feed.  See
``src/mcp_audit/bundle.py`` for the layout and ``docs/air-gapped.md`` for how
to carry one across.

    # Verified, signed feed (for example a checkout of the `feed` branch):
    python scripts/build_bundle.py --feed ./feed --out ./bundle \\
        --private-key minisign.key --public-key minisign.pub

Without ``--private-key`` the manifest is written unsigned, which
``--bundle`` refuses; that is for assembling a bundle another party signs.
The feed directory must already be signed and unexpired: this script copies it
and does not re-sign it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
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


def build(feed: Path, out: Path, config: SigningConfig | None) -> Path:
    """Write the bundle to *out* (which must not exist) and return its path."""
    if out.exists():
        raise SystemExit(f"{out} already exists; choose a new directory")
    if not (feed / "index.json").is_file():
        raise SystemExit(f"{feed}/index.json not found")
    out.mkdir(parents=True)
    for name in ("index.json", "index.json.sig"):
        if (feed / name).is_file():
            shutil.copy2(feed / name, out / name)
    if (feed / "advisories").is_dir():
        shutil.copytree(feed / "advisories", out / "advisories")
    (out / bundle_mod.DATA_DIR).mkdir()
    files: dict[str, dict[str, object]] = {}
    for name, source in SOURCES.items():
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--feed", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--public-key", type=Path)
    args = parser.parse_args(argv)
    config = (
        SigningConfig.from_env(
            backend=BACKEND_MINISIGN,
            private_key=args.private_key,
            public_key=args.public_key,
        )
        if args.private_key
        else None
    )
    out = build(args.feed, args.out, config)
    state = "signed" if config else "UNSIGNED (--bundle will refuse it)"
    print(f"Wrote {state} bundle to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
