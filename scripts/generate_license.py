# ruff: noqa: E501
"""Generate mcp-audit Pro/Enterprise license keys.

This script is for internal use only — it is NOT shipped in the package.
Run it locally to issue license keys for customers.

Usage:
    # Generate a new Ed25519 keypair (run once; paste public key into licensing.py)
    python scripts/generate_license.py --generate-keypair --key-file ~/.mcp-audit-signing-key.pem

    # Issue a Pro key valid for 365 days
    python scripts/generate_license.py \\
        --tier pro \\
        --email user@example.com \\
        --days 365 \\
        --key-file ~/.mcp-audit-signing-key.pem

    # Issue an Enterprise key valid for 1 year
    python scripts/generate_license.py \\
        --tier enterprise \\
        --email enterprise@example.com \\
        --days 365 \\
        --key-file ~/.mcp-audit-signing-key.pem
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _generate_keypair(key_file: Path) -> None:
    """Generate a new Ed25519 keypair and save the private key to *key_file*.

    Prints the raw public key bytes (as a Python bytes literal) to stdout
    so it can be pasted into ``src/mcp_audit/licensing.py``.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    if key_file.exists():
        answer = input(f"Key file {key_file} already exists. Overwrite? [y/N] ")
        if answer.strip().lower() != "y":
            print("Aborted.")
            sys.exit(0)

    private_key = Ed25519PrivateKey.generate()
    pem_bytes = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )

    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(pem_bytes)
    key_file.chmod(0o600)

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(f"\n✓ Private key saved to: {key_file}")
    print("\nPaste the following line into src/mcp_audit/licensing.py")
    print("replacing the _PUBLIC_KEY_BYTES placeholder:\n")
    print(f"_PUBLIC_KEY_BYTES: bytes = {pub_bytes!r}")
    print(f"\n  # ({len(pub_bytes)} bytes, Ed25519 raw public key)")


def _issue_key(tier: str, email: str, days: int, key_file: Path) -> None:
    """Generate and print a signed license key."""
    if not key_file.exists():
        print(f"Error: key file not found: {key_file}", file=sys.stderr)
        print("Run with --generate-keypair first.", file=sys.stderr)
        sys.exit(1)

    # Import from the package if available; otherwise fall back to a local import.
    try:
        from mcp_audit.licensing import generate_license_key
    except ImportError:
        # Allow running the script directly from the repo root without installing.
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from mcp_audit.licensing import generate_license_key  # type: ignore[no-redef]

    key = generate_license_key(
        tier=tier,
        email=email,
        duration_days=days,
        private_key_path=key_file,
    )

    from datetime import date, timedelta
    expires = date.today() + timedelta(days=days)

    print("\n✓ License key issued")
    print(f"  Tier:    {tier}")
    print(f"  Email:   {email}")
    print(f"  Expires: {expires.isoformat()}  ({days} days)")
    print(f"\nKey:\n{key}\n")


def main() -> None:
    """Entry point for the license key generation script."""
    parser = argparse.ArgumentParser(
        description="Generate mcp-audit Pro/Enterprise license keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--generate-keypair",
        action="store_true",
        help="Generate a new Ed25519 keypair and print the public key bytes.",
    )
    parser.add_argument(
        "--tier",
        choices=["pro", "enterprise"],
        help="License tier to issue.",
    )
    parser.add_argument(
        "--email",
        help="Purchaser email address.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="License validity in days from today (default: 365).",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=Path.home() / ".mcp-audit-signing-key.pem",
        help="Path to the Ed25519 private key PEM file.",
    )

    args = parser.parse_args()

    if args.generate_keypair:
        _generate_keypair(args.key_file)
        return

    if not args.tier or not args.email:
        parser.error("--tier and --email are required when issuing a key.")

    _issue_key(
        tier=args.tier,
        email=args.email,
        days=args.days,
        key_file=args.key_file,
    )


if __name__ == "__main__":
    main()
