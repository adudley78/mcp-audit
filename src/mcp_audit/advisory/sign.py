"""Detached signing and verification of the advisory feed.

What gets signed is *not* the file on disk. Advisory files are pretty-printed so a
human can read a diff, but two publishers who serialise the same record with different
indentation would then produce different bytes and incompatible signatures. So the
signed payload is always the RFC 8785 (JCS) canonicalization of the *parsed* document,
which :func:`verify_path` re-derives from scratch at verification time. Reformatting a
file is therefore harmless; changing any value is not.

Signing uses a **static project key**, not Sigstore's keyless flow. That is a
deliberate departure from ``snapshot --sign``, and the difference is the threat model,
not taste. A snapshot is a one-off forensic artifact where keyless is ideal: the human
identity *is* the evidence, verified online at investigation time. A feed is a
distributed data product that CI gates, gateways, and the PyInstaller binary consume —
mostly offline, reproducibly, against a stable *project* identity rather than whoever
happened to run the build. Keyless provides none of those: it binds each signature to
an individual's OIDC account, cannot be produced by a reproducible build, and needs a
Rekor round-trip to verify. A static key restores all four.

Two backends, selected with ``--key-alt``:

``cosign`` (default)
    Signs with the key at ``--key`` / ``$MCP_AUDIT_SIGNING_KEY``. Emits a Sigstore
    bundle at ``<file>.sigstore.json`` plus the raw detached signature at
    ``<file>.sig``. Key mode skips Rekor by design, so both signing and verification
    work fully offline.

``minisign``
    A single small binary with no transparency log and no PKI, for environments where
    installing the Sigstore toolchain is not practical. Emits ``<file>.sig`` only.

Keyless cosign remains reachable via ``SigningConfig(keyless=True)`` (``--keyless`` on
the CLI) for one-off attestations where a human identity is the point. It is never the
default for a feed, and verification then requires an expected identity and issuer,
because a valid signature by *someone* proves nothing at all.

Neither CLI is a hard dependency. When the chosen backend is not on PATH the error
names the install step and the ``--no-sign`` escape hatch, mirroring how
``sast/runner.py`` treats a missing semgrep: the crypto stays out of the 16.6 MB binary
(the same reason the ``sigstore`` stack is excluded from the PyInstaller specs) while
offline ``feed verify`` still works wherever cosign is installed.

Key passphrases are read by the signing CLIs themselves from their own environment
variables (``COSIGN_PASSWORD`` for cosign, ``MINISIGN_PASSWORD`` for minisign) and are
never handled, logged, or passed on the command line by this module.

No private key is committed to this repository. ``examples/feed/`` therefore ships
unsigned — still schema-valid and still digest-bound by its index — and the signing
path is proven instead by ``tests/test_advisory_sign.py``, which mints an ephemeral
key pair, signs a feed, verifies it, and asserts that a mutated record fails.
See ``docs/advisory-feed.md`` for the key-custody and rotation story.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 — invoking the cosign/minisign CLIs is the whole point
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .canonical import canonicalize

__all__ = [
    "BACKENDS",
    "SIGNING_TIMEOUT_SECONDS",
    "SigningConfig",
    "SigningError",
    "VerifyReport",
    "advisory_json_paths",
    "canonical_bytes_for",
    "feed_is_signed",
    "sign_feed",
    "sign_path",
    "signature_artifacts",
    "verify_feed",
    "verify_path",
]

BACKEND_COSIGN = "cosign"
BACKEND_MINISIGN = "minisign"
BACKENDS = (BACKEND_COSIGN, BACKEND_MINISIGN)

# Security: a hung signing subprocess must not hang the publish pipeline forever.
# Keyless cosign contacts Fulcio and Rekor, so this is generous rather than tight.
SIGNING_TIMEOUT_SECONDS: int = 120

# Environment overrides so CI can supply a key without putting a path on the command
# line (where it would land in shell history and process listings).
ENV_PRIVATE_KEY = "MCP_AUDIT_SIGNING_KEY"
ENV_PUBLIC_KEY = "MCP_AUDIT_SIGNING_PUBKEY"
ENV_IDENTITY = "MCP_AUDIT_SIGNING_IDENTITY"
ENV_OIDC_ISSUER = "MCP_AUDIT_SIGNING_OIDC_ISSUER"


class SigningError(RuntimeError):
    """Signing or verification could not be completed."""


@dataclass(frozen=True)
class SigningConfig:
    """How to sign and verify a feed.

    A feed is signed with a static project key by default. ``keyless`` must be opted
    into explicitly — it is the right model for a one-off forensic artifact, not for a
    data product consumed offline against a stable project identity.

    Attributes:
        backend: ``"cosign"`` or ``"minisign"``.
        private_key: Private key path. Required for signing unless ``keyless``.
        public_key: Public key path used for verification. Defaults to
            ``private_key`` with a ``.pub`` suffix when a private key is given.
        keyless: Opt in to cosign's ambient-OIDC flow instead of a key.
        identity: Expected certificate-identity regex for cosign keyless verify.
        oidc_issuer: Expected OIDC-issuer regex for cosign keyless verify.
    """

    backend: str = BACKEND_COSIGN
    private_key: Path | None = None
    public_key: Path | None = None
    keyless: bool = False
    identity: str | None = None
    oidc_issuer: str | None = None

    def __post_init__(self) -> None:
        if self.backend not in BACKENDS:
            raise SigningError(
                f"Unknown signing backend {self.backend!r}; expected one of "
                f"{', '.join(BACKENDS)}"
            )
        if self.keyless and self.backend != BACKEND_COSIGN:
            raise SigningError(
                f"{self.backend} has no keyless mode — supply a key with --key "
                f"or ${ENV_PRIVATE_KEY}"
            )
        if self.keyless and self.private_key is not None:
            raise SigningError(
                "--keyless and --key are mutually exclusive: a keyless signature is "
                "bound to an OIDC identity, not to a key."
            )
        # A config with only a public key is legitimate: that is verify-only.
        if (
            not self.keyless
            and self.private_key is None
            and self.public_key is None
            and self.backend == BACKEND_MINISIGN
        ):
            raise SigningError(
                "minisign has no keyless mode — supply a key with --key "
                f"or ${ENV_PRIVATE_KEY}"
            )

    def require_signing_key(self) -> Path:
        """Return the private key to sign with, or explain what is missing.

        Called before any signing run so a misconfigured publish fails immediately with
        an actionable message rather than part-way through a feed.

        Raises:
            SigningError: No private key is configured and ``keyless`` was not
                requested.
        """
        if self.private_key is None:
            raise SigningError(
                "Signing a feed needs a project key. Pass --key PATH or set "
                f"${ENV_PRIVATE_KEY}.\n"
                "Create one with: cosign generate-key-pair\n"
                "Use --no-sign to write an unsigned feed, or --keyless for a "
                "one-off OIDC-bound signature (not recommended for a published feed)."
            )
        return self.private_key

    @classmethod
    def from_env(
        cls,
        backend: str = BACKEND_COSIGN,
        private_key: Path | None = None,
        public_key: Path | None = None,
        keyless: bool = False,
        identity: str | None = None,
        oidc_issuer: str | None = None,
    ) -> SigningConfig:
        """Build a config, falling back to environment variables for unset values."""
        private_key = private_key or _env_path(ENV_PRIVATE_KEY)
        public_key = public_key or _env_path(ENV_PUBLIC_KEY)
        if public_key is None and private_key is not None:
            candidate = private_key.with_suffix(private_key.suffix + ".pub")
            legacy = private_key.with_suffix(".pub")
            public_key = candidate if candidate.exists() else legacy
        return cls(
            backend=backend,
            private_key=private_key,
            public_key=public_key,
            keyless=keyless,
            identity=identity or os.environ.get(ENV_IDENTITY) or None,
            oidc_issuer=oidc_issuer or os.environ.get(ENV_OIDC_ISSUER) or None,
        )

    def as_metadata(self) -> dict:
        """Signing parameters recorded in ``index.json`` for verifiers to reproduce.

        Only the *mode* and expected identity are recorded — never a key path, which
        is local to the publisher and useless (at best) to a downstream consumer.
        """
        return {
            "backend": self.backend,
            "mode": "keyless" if self.keyless else "key",
            "identity": self.identity,
            "oidc_issuer": self.oidc_issuer,
        }


def _env_path(name: str) -> Path | None:
    raw = os.environ.get(name)
    return Path(raw).expanduser() if raw else None


# ── Canonicalization ──────────────────────────────────────────────────────────


def canonical_bytes_for(path: Path) -> bytes:
    """Return the RFC 8785 canonical bytes of the JSON document at *path*.

    Raises:
        SigningError: The file is missing or is not valid JSON.
    """
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SigningError(f"No such file to canonicalize: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SigningError(f"{path} is not valid JSON: {exc}") from exc
    return canonicalize(document)


# ── Subprocess plumbing ───────────────────────────────────────────────────────


def _resolve_tool(name: str) -> str:
    """Return the absolute path to a signing CLI, or raise a actionable error.

    Security: resolved through ``shutil.which`` (PATH lookup only), never from a
    user-supplied argument, so the executable cannot be redirected by CLI input.
    """
    path = shutil.which(name)
    if path is None:
        raise SigningError(
            f"{name} is not installed or not on PATH. Install it, choose the other "
            f"backend with --key-alt, or pass --no-sign to write an unsigned feed."
        )
    return path


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a signing CLI with a bounded timeout and captured output."""
    try:
        return subprocess.run(  # noqa: S603 — list form, shell=False, argv0 from which()
            cmd,
            capture_output=True,
            text=True,
            timeout=SIGNING_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SigningError(
            f"{Path(cmd[0]).name} timed out after {SIGNING_TIMEOUT_SECONDS} seconds"
        ) from exc
    except OSError as exc:
        raise SigningError(f"Could not run {Path(cmd[0]).name}: {exc}") from exc


@lru_cache(maxsize=1)
def _cosign_signing_flags() -> tuple[str, ...]:
    """Return the extra ``sign-blob`` flags this cosign build needs for offline keys.

    cosign 3.x resolves service URLs from a TUF-provided signing config and rejects
    ``--tlog-upload=false`` unless that resolution is turned off; cosign 2.x has no such
    flag and errors on it. Probing ``--help`` once keeps a single code path working
    against both, instead of parsing a version string whose format is not a contract.
    """
    cosign = _resolve_tool("cosign")
    proc = _run([cosign, "sign-blob", "--help"])
    help_text = f"{proc.stdout}{proc.stderr}"
    if "--use-signing-config" in help_text:
        return ("--use-signing-config=false", "--tlog-upload=false")
    return ("--tlog-upload=false",)


# Suffixes of files this module writes next to an advisory. They must never be
# mistaken for advisories themselves — .sigstore.json in particular is valid JSON
# sitting in the advisories/ directory.
_SIGNATURE_SUFFIXES = (".sig", ".sigstore.json")


def signature_artifacts(path: Path, backend: str) -> list[Path]:
    """Return the signature files a backend writes alongside *path*."""
    path = Path(path)
    sig = path.with_suffix(path.suffix + ".sig")
    if backend == BACKEND_COSIGN:
        return [sig, path.with_suffix(path.suffix + ".sigstore.json")]
    return [sig]


def advisory_json_paths(advisories_dir: Path) -> list[Path]:
    """Return the advisory records in a directory, excluding signature artifacts."""
    return sorted(
        path
        for path in Path(advisories_dir).glob("*.json")
        if not path.name.endswith(_SIGNATURE_SUFFIXES)
    )


# ── Signing ───────────────────────────────────────────────────────────────────


def sign_path(path: Path, config: SigningConfig) -> list[Path]:
    """Sign the canonical form of the JSON document at *path*.

    Writes ``<path>.sig`` (raw detached signature) and, for cosign, the Sigstore
    bundle at ``<path>.sigstore.json`` carrying the certificate and log proof.

    Returns:
        The signature artifacts written, in a stable order.
    """
    path = Path(path)
    payload = canonical_bytes_for(path)
    sig_path = path.with_suffix(path.suffix + ".sig")

    with tempfile.TemporaryDirectory(prefix="mcp-audit-sign-") as tmp:
        blob = Path(tmp) / "payload.jcs.json"
        blob.write_bytes(payload)
        if config.backend == BACKEND_COSIGN:
            return _cosign_sign(blob, path, sig_path, config)
        return _minisign_sign(blob, sig_path, config)


def _cosign_sign(
    blob: Path, target: Path, sig_path: Path, config: SigningConfig
) -> list[Path]:
    cosign = _resolve_tool("cosign")
    bundle_path = target.with_suffix(target.suffix + ".sigstore.json")

    cmd = [cosign, "sign-blob", "--yes", "--bundle", str(bundle_path)]
    if config.private_key is not None:
        # Key mode is the offline path: no Fulcio certificate to fetch and no Rekor
        # entry to upload, so a feed can be rebuilt in an air-gapped CI runner.
        cmd += ["--key", str(config.private_key), *_cosign_signing_flags()]
    cmd.append(str(blob))

    proc = _run(cmd)
    if proc.returncode != 0:
        raise SigningError(f"cosign sign-blob failed for {target.name}: {_tail(proc)}")

    sig_path.write_text(_signature_from_bundle(bundle_path) + "\n", encoding="utf-8")
    return [sig_path, bundle_path]


def _signature_from_bundle(bundle_path: Path) -> str:
    """Extract the base64 signature from a Sigstore bundle.

    cosign 3.x no longer writes a standalone signature file, but plenty of tooling
    still wants the raw detached signature, so it is lifted out of the bundle rather
    than lost. The bundle remains the artifact verification actually uses.
    """
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SigningError(f"cosign did not write a readable bundle: {exc}") from exc

    signature = bundle.get("messageSignature", {}).get("signature")
    if not signature:
        # DSSE-enveloped bundles carry the signature one level deeper.
        signatures = bundle.get("dsseEnvelope", {}).get("signatures") or []
        signature = signatures[0].get("sig") if signatures else None
    if not signature:
        raise SigningError(f"No signature found in bundle {bundle_path.name}")
    return str(signature)


def _minisign_sign(blob: Path, sig_path: Path, config: SigningConfig) -> list[Path]:
    minisign = _resolve_tool("minisign")
    if config.private_key is None:
        raise SigningError("minisign requires a private key; none was configured")

    proc = _run(
        [
            minisign,
            "-S",
            "-s",
            str(config.private_key),
            "-m",
            str(blob),
            "-x",
            str(sig_path),
        ]
    )
    if proc.returncode != 0:
        raise SigningError(f"minisign signing failed: {_tail(proc)}")
    return [sig_path]


def sign_feed(out_dir: Path, config: SigningConfig) -> list[Path]:
    """Sign every advisory in a feed directory and then the index.

    The index is signed last, after the signing parameters are recorded inside it, so
    the signature covers both the advisory digests and the configuration a verifier
    must reproduce.

    Returns:
        Every signature artifact written, ordered by the file it covers.
    """
    out_dir = Path(out_dir)
    index_path = out_dir / "index.json"
    if not index_path.is_file():
        raise SigningError(f"No index.json in {out_dir}; run write_feed() first")
    # Fail before writing a single signature rather than part-way through a feed.
    if not config.keyless:
        config.require_signing_key()

    written: list[Path] = []
    for advisory_path in advisory_json_paths(out_dir / "advisories"):
        written.extend(sign_path(advisory_path, config))

    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["signing"] = config.as_metadata()
    index_path.write_text(
        json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    written.extend(sign_path(index_path, config))
    return written


# ── Verification ──────────────────────────────────────────────────────────────


@dataclass
class VerifyReport:
    """Result of verifying a feed.

    Attributes:
        checked: How many artifacts were examined.
        verified: Relative paths that passed every applicable check.
        failures: Human-readable descriptions of what failed.
        signed: False when the feed carries no signatures at all, in which case
            :attr:`verified` reflects integrity only — every record still matches the
            digest its index records, but nothing attests to *who* produced it.
    """

    checked: int = 0
    verified: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    signed: bool = True

    @property
    def ok(self) -> bool:
        return not self.failures


def feed_is_signed(out_dir: Path, backend: str = BACKEND_COSIGN) -> bool:
    """Return True when a feed directory carries signature artifacts for its index.

    An unsigned feed is a legitimate artifact — ``examples/feed/`` ships that way,
    because committing a private key to sign it would be worse than not signing it —
    so verification distinguishes "unsigned" from "signature missing or bad".
    """
    index_path = Path(out_dir) / "index.json"
    return any(
        artifact.is_file() for artifact in signature_artifacts(index_path, backend)
    )


def verify_path(path: Path, config: SigningConfig) -> None:
    """Verify the detached signature over the canonical form of *path*.

    Raises:
        SigningError: The signature is missing, malformed, or does not verify.
    """
    path = Path(path)
    required = signature_artifacts(path, config.backend)[-1]
    if not required.is_file():
        raise SigningError(f"Missing signature artifact {required.name}")

    payload = canonical_bytes_for(path)
    with tempfile.TemporaryDirectory(prefix="mcp-audit-verify-") as tmp:
        blob = Path(tmp) / "payload.jcs.json"
        blob.write_bytes(payload)
        if config.backend == BACKEND_COSIGN:
            _cosign_verify(blob, required, config)
        else:
            _minisign_verify(blob, required, config)


def _cosign_verify(blob: Path, bundle_path: Path, config: SigningConfig) -> None:
    cosign = _resolve_tool("cosign")
    cmd = [cosign, "verify-blob", "--bundle", str(bundle_path)]

    if config.public_key is not None:
        # Key-signed feeds have no Rekor entry by construction, so tlog verification
        # is skipped here — and only here. Keyless feeds below always check it.
        cmd += ["--key", str(config.public_key), "--insecure-ignore-tlog"]
    elif not config.identity or not config.oidc_issuer:
        # A keyless signature only proves *someone* with an OIDC identity signed
        # this. Without pinning who, verification is theatre.
        raise SigningError(
            "Keyless verification requires --identity and --oidc-issuer so the "
            "signer is pinned; any Sigstore user can otherwise produce a valid "
            "signature over these bytes. Use --public-key for a key-signed feed."
        )
    else:
        cmd += [
            "--certificate-identity-regexp",
            config.identity,
            "--certificate-oidc-issuer-regexp",
            config.oidc_issuer,
        ]
    cmd.append(str(blob))

    proc = _run(cmd)
    if proc.returncode != 0:
        raise SigningError(f"signature does not verify: {_tail(proc)}")


def _minisign_verify(blob: Path, sig_path: Path, config: SigningConfig) -> None:
    minisign = _resolve_tool("minisign")
    if config.public_key is None:
        raise SigningError(
            f"minisign verification requires a public key (--public-key or "
            f"${ENV_PUBLIC_KEY})"
        )
    proc = _run(
        [
            minisign,
            "-V",
            "-p",
            str(config.public_key),
            "-m",
            str(blob),
            "-x",
            str(sig_path),
        ]
    )
    if proc.returncode != 0:
        raise SigningError(f"signature does not verify: {_tail(proc)}")


def verify_feed(out_dir: Path, config: SigningConfig) -> VerifyReport:
    """Re-canonicalize and verify every advisory and the index in a feed directory.

    Four things are checked, because a signature alone does not make a feed sound:

    1. The index signature verifies over the index's canonical bytes.
    2. Every advisory the index lists exists and its own signature verifies.
    3. Each advisory's recomputed canonical digest matches the one in the index, which
       is what stops an attacker swapping in a validly-signed record of their own.
    4. No advisory file is present that the index does not list.

    A feed with no signatures at all is checked for integrity only — steps 3 and 4 —
    and :attr:`VerifyReport.signed` is False. That is not a silent downgrade: an
    unsigned feed is an explicit publishing choice (see ``examples/feed/``), and the
    caller is told which guarantee it is getting. A feed that *claims* to be signed but
    has a missing or bad signature still fails.

    Returns:
        A :class:`VerifyReport`; check :attr:`VerifyReport.ok` for the verdict.
    """
    out_dir = Path(out_dir)
    report = VerifyReport()

    index_path = out_dir / "index.json"
    if not index_path.is_file():
        report.failures.append(f"index.json not found in {out_dir}")
        return report

    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.failures.append(f"index.json is not valid JSON: {exc}")
        return report

    # An index that records signing parameters asserts it was signed, so a missing
    # artifact from here on is a failure rather than an unsigned feed.
    report.signed = feed_is_signed(out_dir, config.backend) or "signing" in index

    report.checked += 1
    if not report.signed:
        report.verified.append("index.json")
    else:
        try:
            verify_path(index_path, config)
        except SigningError as exc:
            report.failures.append(f"index.json: {exc}")
        else:
            report.verified.append("index.json")

    listed: set[Path] = set()
    for entry in index.get("advisories", []):
        rel = entry.get("path") or f"advisories/{entry.get('id')}.json"
        advisory_path = out_dir / rel
        listed.add(advisory_path)
        report.checked += 1

        if not advisory_path.is_file():
            report.failures.append(f"{rel}: listed in index but missing on disk")
            continue

        expected = entry.get("canonical_sha256")
        try:
            actual = hashlib.sha256(canonical_bytes_for(advisory_path)).hexdigest()
        except SigningError as exc:
            report.failures.append(f"{rel}: {exc}")
            continue

        if expected and actual != expected:
            report.failures.append(
                f"{rel}: content does not match the digest recorded in index.json"
            )
            continue

        if not report.signed:
            report.verified.append(rel)
            continue

        try:
            verify_path(advisory_path, config)
        except SigningError as exc:
            report.failures.append(f"{rel}: {exc}")
        else:
            report.verified.append(rel)

    advisories_dir = out_dir / "advisories"
    if advisories_dir.is_dir():
        for path in advisory_json_paths(advisories_dir):
            if path not in listed:
                report.failures.append(
                    f"advisories/{path.name}: present on disk but absent from "
                    f"index.json"
                )

    return report


def _tail(proc: subprocess.CompletedProcess[str], limit: int = 400) -> str:
    """Return the most useful trailing slice of a failed CLI's output."""
    text = (proc.stderr or proc.stdout or "").strip()
    return text[-limit:] if text else f"exit code {proc.returncode}"
