# ruff: noqa: E501
"""Generate mcp-audit Pro/Enterprise license keys.

This script is for internal use only — it is NOT shipped in the package.
Run it locally to issue license keys for customers.

Usage:
    # Generate a new Ed25519 keypair (run once; paste public key into licensing.py)
    python scripts/generate_license.py --generate-keypair --key-file ~/.mcp-audit-signing-key.pem

    # Issue a Pro key valid for 90 days (default)
    python scripts/generate_license.py \\
        --tier pro \\
        --email user@example.com \\
        --key-file ~/.mcp-audit-signing-key.pem

    # Issue an Enterprise key with an explicit Lemon Squeezy order ID
    python scripts/generate_license.py \\
        --tier enterprise \\
        --email enterprise@example.com \\
        --sub ls_order_9f8e7d \\
        --key-file ~/.mcp-audit-signing-key.pem

    # Sign and emit a revocation list (commit the output to the repo)
    python scripts/generate_license.py sign-revocation-list \\
        --kids a1b2c3d4,deadbeef \\
        --key-file ~/.mcp-audit-signing-key.pem \\
        --out src/mcp_audit/data/revoked.json
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
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


def _append_audit_log(row: dict) -> None:
    """Append one JSONL row to the operator-side issuance audit log (0o600)."""
    log_path = Path.home() / ".mcp-audit-issued-keys.jsonl"
    fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except Exception as exc:  # noqa: BLE001
        print(f"Warning: could not write audit log: {exc}", file=sys.stderr)


def _issue_key(
    tier: str,
    email: str,
    days: int,
    key_file: Path,
    kid: str | None = None,
    sub: str | None = None,
) -> None:
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

    # Auto-generate kid if not supplied.
    resolved_kid = kid if kid is not None else secrets.token_hex(4)

    key = generate_license_key(
        tier=tier,
        email=email,
        duration_days=days,
        private_key_path=key_file,
        kid=resolved_kid,
        sub=sub,
    )

    from datetime import date, timedelta

    expires = date.today() + timedelta(days=days)

    print("\n✓ License key issued")
    print(f"  Tier:    {tier}")
    print(f"  Email:   {email}")
    print(f"  Kid:     {resolved_kid}")
    if sub:
        print(f"  Sub:     {sub}")
    print(f"  Expires: {expires.isoformat()}  ({days} days)")
    print(f"\nKey:\n{key}\n")

    _append_audit_log(
        {
            "kid": resolved_kid,
            "email": email,
            "sub": sub,
            "issued": date.today().isoformat(),
            "expires": expires.isoformat(),
            "revoked": False,
        }
    )


def _sign_revocation_list(
    kids: list[str],
    key_file: Path,
    out_path: Path,
) -> None:
    """Emit a signed revoked.json ready to commit to the repo.

    The canonical payload (version, issued, revoked — no signature field) is
    serialised with sorted keys and no whitespace, then signed with the Ed25519
    private key.  The signature is base64-encoded and written back into the JSON
    object under the ``"signature"`` key.
    """
    import base64
    from datetime import datetime, timezone

    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if not key_file.exists():
        print(f"Error: key file not found: {key_file}", file=sys.stderr)
        sys.exit(1)

    private_key = load_pem_private_key(key_file.read_bytes(), password=None)
    payload: dict = {
        "version": 1,
        "issued": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),  # noqa: UP017
        "revoked": sorted(kids),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = private_key.sign(payload_bytes)  # type: ignore[union-attr]
    payload["signature"] = base64.b64encode(sig).decode()

    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"✓ Written {out_path} ({len(kids)} revoked kid(s))")


def _main_sign_revocation_list(argv: list[str]) -> None:
    """Entry point for the sign-revocation-list sub-command."""
    parser = argparse.ArgumentParser(
        prog="generate_license.py sign-revocation-list",
        description="Sign and emit a revocation list for bundling in the next release.",
    )
    parser.add_argument(
        "--kids",
        required=True,
        help="Comma-separated list of kid values to revoke (e.g. a1b2c3d4,deadbeef).",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=Path.home() / ".mcp-audit-signing-key.pem",
        help="Path to the Ed25519 private key PEM file.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("src/mcp_audit/data/revoked.json"),
        help="Output path for revoked.json (default: src/mcp_audit/data/revoked.json).",
    )
    args = parser.parse_args(argv)
    kids = [k.strip() for k in args.kids.split(",") if k.strip()]
    _sign_revocation_list(kids=kids, key_file=args.key_file, out_path=args.out)


def main() -> None:
    """Entry point for the license key generation script."""
    # Dispatch sign-revocation-list as a sub-command before the main argparse
    # so it gets its own --help and clean argument namespace.
    if len(sys.argv) > 1 and sys.argv[1] == "sign-revocation-list":
        _main_sign_revocation_list(sys.argv[2:])
        return

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
        default=90,
        help="License validity in days from today (default: 90).",
    )
    parser.add_argument(
        "--kid",
        default=None,
        help="8-char hex key ID (auto-generated if omitted).",
    )
    parser.add_argument(
        "--sub",
        default=None,
        help="Lemon Squeezy order/subscription ID (optional).",
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
        kid=args.kid,
        sub=args.sub,
    )


if __name__ == "__main__":
    main()
