"""Shared ``--bundle`` handling for ``scan`` and ``affected`` (STORY-0129)."""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console

from mcp_audit import bundle as bundle_mod
from mcp_audit.advisory.sign import (
    BACKEND_MINISIGN,
    ENV_PUBLIC_KEY,
    SigningConfig,
    SigningError,
    bundled_public_key_path,
)


def open_bundle(path: Path, public_key: Path | None, con: Console) -> bundle_mod.Bundle:
    """Verify *path*, activate it for the loaders, print its date, and return it.

    Verification is the feed's own, with minisign and mcp-audit's bundled project
    key unless ``--bundle-key`` or ``$MCP_AUDIT_SIGNING_PUBKEY`` names another.
    Any failure prints every reason and exits 2; nothing falls back to the
    bundled data, because a half-trusted bundle is worse than none.
    """
    key = public_key
    if key is None and not os.environ.get(ENV_PUBLIC_KEY):
        key = bundled_public_key_path()
    try:
        config = SigningConfig.from_env(backend=BACKEND_MINISIGN, public_key=key)
        opened = bundle_mod.verify_bundle(path, config)
    except SigningError as exc:
        con.print(f"[red]Error:[/red] --bundle: {exc}")
        raise typer.Exit(2) from None
    except bundle_mod.BundleError as exc:
        con.print(f"[red]Error:[/red] --bundle {path} did not verify:")
        for failure in exc.failures:
            con.print(f"  [red]-[/red] {failure}")
        raise typer.Exit(2) from None
    bundle_mod.activate(opened)
    con.print(f"[dim]{opened.line()}[/dim]")
    return opened
