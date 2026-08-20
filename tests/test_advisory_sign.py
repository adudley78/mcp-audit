"""Tests for feed signing and verification.

These exercise the real ``cosign`` and ``minisign`` binaries rather than mocking the
subprocess boundary. A signing test that never runs the signer proves nothing about
whether the feed we publish can actually be verified; the tests skip cleanly on hosts
where the tool is not installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_audit.advisory.feed import build_advisories, write_feed
from mcp_audit.advisory.sign import (
    ENV_PRIVATE_KEY,
    ENV_PUBLIC_KEY,
    SigningConfig,
    SigningError,
    advisory_json_paths,
    canonical_bytes_for,
    feed_is_signed,
    sign_feed,
    sign_path,
    signature_artifacts,
    verify_feed,
    verify_path,
)
from tests.test_advisory_feed import FIXED_NOW, _scan_result

HAS_COSIGN = shutil.which("cosign") is not None
HAS_MINISIGN = shutil.which("minisign") is not None

needs_cosign = pytest.mark.skipif(not HAS_COSIGN, reason="cosign is not installed")
needs_minisign = pytest.mark.skipif(
    not HAS_MINISIGN, reason="minisign is not installed"
)


# ── Key material ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def cosign_keys(tmp_path_factory) -> tuple[Path, Path]:
    """Generate a throwaway, passwordless cosign key pair."""
    directory = tmp_path_factory.mktemp("cosign-keys")
    subprocess.run(  # noqa: S603
        [shutil.which("cosign"), "generate-key-pair"],
        cwd=directory,
        env={**os.environ, "COSIGN_PASSWORD": ""},
        capture_output=True,
        check=True,
        timeout=120,
    )
    return directory / "cosign.key", directory / "cosign.pub"


@pytest.fixture(scope="module")
def minisign_keys(tmp_path_factory) -> tuple[Path, Path]:
    """Generate a throwaway, unencrypted minisign key pair."""
    directory = tmp_path_factory.mktemp("minisign-keys")
    private, public = directory / "ms.key", directory / "ms.pub"
    subprocess.run(  # noqa: S603
        [shutil.which("minisign"), "-G", "-W", "-p", str(public), "-s", str(private)],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return private, public


@pytest.fixture
def cosign_config(cosign_keys, monkeypatch: pytest.MonkeyPatch) -> SigningConfig:
    private, public = cosign_keys
    # cosign reads the private-key passphrase from the environment; without it the
    # CLI tries to prompt and fails on a non-tty.
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    return SigningConfig(backend="cosign", private_key=private, public_key=public)


@pytest.fixture
def minisign_config(minisign_keys) -> SigningConfig:
    private, public = minisign_keys
    return SigningConfig(backend="minisign", private_key=private, public_key=public)


@pytest.fixture(scope="module")
def rotated_minisign_keys(tmp_path_factory) -> tuple[Path, Path]:
    """A second, unrelated key pair — the key a rotation moves the feed onto."""
    directory = tmp_path_factory.mktemp("minisign-rotated")
    private, public = directory / "next.key", directory / "next.pub"
    subprocess.run(  # noqa: S603
        [shutil.which("minisign"), "-G", "-W", "-p", str(public), "-s", str(private)],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return private, public


@pytest.fixture
def feed_dir(tmp_path: Path) -> Path:
    """An unsigned feed built from the shared scan fixture."""
    advisories = build_advisories(_scan_result(), now=FIXED_NOW).advisories
    write_feed(advisories, tmp_path / "feed")
    return tmp_path / "feed"


# ── Configuration ─────────────────────────────────────────────────────────────


class TestSigningConfig:
    def test_rejects_an_unknown_backend(self) -> None:
        with pytest.raises(SigningError, match="Unknown signing backend"):
            SigningConfig(backend="pgp")

    def test_cosign_does_not_default_to_keyless(self) -> None:
        """A feed is signed with a stable project key, not whoever ran the build."""
        assert not SigningConfig().keyless

    def test_signing_without_a_key_fails_with_an_actionable_message(self) -> None:
        with pytest.raises(SigningError, match="needs a project key"):
            SigningConfig().require_signing_key()

    def test_require_signing_key_returns_the_configured_key(
        self, tmp_path: Path
    ) -> None:
        assert SigningConfig(private_key=tmp_path / "k").require_signing_key() == (
            tmp_path / "k"
        )

    def test_keyless_is_opt_in(self) -> None:
        assert SigningConfig(keyless=True).keyless

    def test_keyless_and_key_are_mutually_exclusive(self, tmp_path: Path) -> None:
        with pytest.raises(SigningError, match="mutually exclusive"):
            SigningConfig(keyless=True, private_key=tmp_path / "k")

    def test_minisign_has_no_keyless_mode(self) -> None:
        with pytest.raises(SigningError, match="no keyless mode"):
            SigningConfig(backend="minisign")

    def test_minisign_cannot_opt_into_keyless(self, tmp_path: Path) -> None:
        with pytest.raises(SigningError, match="no keyless mode"):
            SigningConfig(backend="minisign", keyless=True)

    def test_minisign_verify_only_needs_just_a_public_key(self, tmp_path: Path) -> None:
        assert SigningConfig(backend="minisign", public_key=tmp_path / "p")

    def test_keys_are_read_from_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_PRIVATE_KEY, str(tmp_path / "k"))
        monkeypatch.setenv(ENV_PUBLIC_KEY, str(tmp_path / "k.pub"))
        config = SigningConfig.from_env()
        assert config.private_key == tmp_path / "k"
        assert config.public_key == tmp_path / "k.pub"

    def test_explicit_arguments_beat_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_PRIVATE_KEY, str(tmp_path / "from-env"))
        config = SigningConfig.from_env(private_key=tmp_path / "explicit")
        assert config.private_key == tmp_path / "explicit"

    def test_metadata_records_the_mode_but_never_a_key_path(
        self, tmp_path: Path
    ) -> None:
        metadata = SigningConfig(private_key=tmp_path / "secret.key").as_metadata()
        assert metadata["mode"] == "key"
        assert "secret.key" not in json.dumps(metadata)


def _assert_no_signature_material(feed_dir: Path) -> None:
    """Fail if any advisory record embeds something signature- or certificate-shaped."""
    for path in advisory_json_paths(feed_dir / "advisories"):
        record = json.loads(path.read_text(encoding="utf-8"))
        embedded = [
            key for key in record if "sig" in key.lower() or "cert" in key.lower()
        ]
        assert not embedded, (
            f"{path.name} embeds {embedded}; signatures must stay detached or every "
            f"key rotation rewrites every record"
        )


class TestRotationLeavesRecordsUntouched:
    """Rotating the signing key must not churn a single advisory record.

    This is the property that makes key rotation invisible to anything consuming
    records rather than signatures, and it is what `docs/advisory-feed.md` promises
    downstream: publish the new public key, re-sign, and no advisory ID, digest, or
    byte changes. Consumers that mirror the feed see no diff.

    Two separate properties hold it up, and it is worth being precise about which does
    what, so a future change is weighed against the right one:

    **Detachment** is what keeps the record bytes fixed. Inline a signature or a
    certificate into the record and every rotation rewrites every record. Nothing else
    in this file would catch that, which is why these tests exist.

    **Canonical bytes** are what keep a rotated signature verifiable against a mirror
    that re-serialised the record with different formatting — covered by
    `test_reformatting_an_advisory_still_verifies`. Signing raw on-disk bytes would
    leave the no-rewrite property intact but freeze the feed into one exact byte
    layout, so any mirror that pretty-printed it would fail verification.

    Rotation is invisible only when both hold.
    """

    @needs_minisign
    def test_re_signing_with_a_new_key_leaves_record_bytes_identical(
        self,
        feed_dir: Path,
        minisign_config: SigningConfig,
        rotated_minisign_keys: tuple[Path, Path],
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        before = {
            path.name: path.read_bytes()
            for path in advisory_json_paths(feed_dir / "advisories")
        }
        signatures_before = {
            path.name: path.read_bytes() for path in feed_dir.rglob("*.sig")
        }

        private, public = rotated_minisign_keys
        rotated = SigningConfig(
            backend="minisign", private_key=private, public_key=public
        )
        sign_feed(feed_dir, rotated)

        after = {
            path.name: path.read_bytes()
            for path in advisory_json_paths(feed_dir / "advisories")
        }
        assert after == before, "rotation rewrote advisory records"

        signatures_after = {
            path.name: path.read_bytes() for path in feed_dir.rglob("*.sig")
        }
        assert signatures_after.keys() == signatures_before.keys()
        assert signatures_after != signatures_before, (
            "signatures are unchanged, so this test would pass even if sign_feed "
            "had done nothing"
        )

        report = verify_feed(feed_dir, rotated)
        assert report.ok, report.failures

    @needs_minisign
    def test_the_old_key_no_longer_verifies_after_rotation(
        self,
        feed_dir: Path,
        minisign_config: SigningConfig,
        rotated_minisign_keys: tuple[Path, Path],
    ) -> None:
        """Rotation must actually move trust, not merely add a second signature."""
        sign_feed(feed_dir, minisign_config)
        private, public = rotated_minisign_keys
        sign_feed(
            feed_dir,
            SigningConfig(backend="minisign", private_key=private, public_key=public),
        )

        assert not verify_feed(feed_dir, minisign_config).ok

    def test_a_built_record_carries_no_signature_material(self, feed_dir: Path) -> None:
        """Detachment at build time, asserted on the record not on the signer."""
        _assert_no_signature_material(feed_dir)

    @needs_minisign
    def test_signing_does_not_add_signature_material_to_a_record(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        """The case that matters: signing must write beside a record, never into it.

        Asserting this only on an unsigned feed would prove nothing about the signer,
        which is where an inlined signature would actually be introduced.
        """
        sign_feed(feed_dir, minisign_config)
        _assert_no_signature_material(feed_dir)


class TestUnsignedFeed:
    """An unsigned feed is a supported artifact, not a broken one.

    `examples/feed/` ships unsigned because committing the private key needed to sign
    it reproducibly would be worse than not signing it. Verification must therefore
    distinguish "no signatures" from "signature missing or bad", and must still catch
    tampering through the digests the index records.
    """

    def test_a_fresh_feed_is_reported_as_unsigned(self, feed_dir: Path) -> None:
        assert not feed_is_signed(feed_dir)

    def test_integrity_verifies_without_any_signatures(self, feed_dir: Path) -> None:
        report = verify_feed(feed_dir, SigningConfig())
        assert report.ok
        assert not report.signed
        assert report.checked > 1

    def test_a_mutated_record_still_fails_when_unsigned(self, feed_dir: Path) -> None:
        """Do not weaken this test on the assumption a signature also covers this.

        Until the project signing key is minted, `canonical_sha256` in `index.json` is
        the *only* integrity guarantee anyone consuming the in-repo `examples/feed/`
        gets. There is no signature covering that case today, so this assertion is
        load-bearing rather than redundant with the signed-feed tests below. It stays
        meaningful after the key exists, too: an unsigned feed remains a supported
        artifact, so the digest binding must keep working on its own.
        """
        target = next(iter(advisory_json_paths(feed_dir / "advisories")))
        record = json.loads(target.read_text(encoding="utf-8"))
        record["summary"] = "tampered"
        target.write_text(
            json.dumps(record, indent=2, sort_keys=True), encoding="utf-8"
        )

        report = verify_feed(feed_dir, SigningConfig())
        assert not report.ok
        assert any("does not match the digest" in f for f in report.failures)

    def test_an_extra_unlisted_record_still_fails_when_unsigned(
        self, feed_dir: Path
    ) -> None:
        (feed_dir / "advisories" / "x_MCPSA-2026-deadbeefcafe.json").write_text(
            "{}", encoding="utf-8"
        )
        report = verify_feed(feed_dir, SigningConfig())
        assert not report.ok
        assert any("absent from" in f for f in report.failures)

    @needs_minisign
    def test_a_feed_that_claims_signing_is_not_treated_as_unsigned(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        """Deleting signatures from a signed feed must fail, not silently downgrade."""
        sign_feed(feed_dir, minisign_config)
        assert feed_is_signed(feed_dir, "minisign")
        for artifact in feed_dir.rglob("*.sig"):
            artifact.unlink()

        report = verify_feed(feed_dir, minisign_config)
        assert report.signed, "index.json still records signing parameters"
        assert not report.ok
        assert any("Missing signature artifact" in f for f in report.failures)


# ── Canonicalization at the signing boundary ──────────────────────────────────


class TestCanonicalBytes:
    def test_reformatting_does_not_change_the_signed_bytes(
        self, tmp_path: Path
    ) -> None:
        """This is why advisories can be pretty-printed and still verify."""
        document = {"b": 2, "a": {"d": None, "c": [1, 2]}}
        compact = tmp_path / "compact.json"
        pretty = tmp_path / "pretty.json"
        compact.write_text(json.dumps(document, separators=(",", ":")))
        pretty.write_text(json.dumps(document, indent=4, sort_keys=True))
        assert canonical_bytes_for(compact) == canonical_bytes_for(pretty)

    def test_changing_a_value_changes_the_signed_bytes(self, tmp_path: Path) -> None:
        original = tmp_path / "a.json"
        mutated = tmp_path / "b.json"
        original.write_text(json.dumps({"summary": "one"}))
        mutated.write_text(json.dumps({"summary": "two"}))
        assert canonical_bytes_for(original) != canonical_bytes_for(mutated)

    def test_missing_file_raises_a_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(SigningError, match="No such file"):
            canonical_bytes_for(tmp_path / "absent.json")

    def test_invalid_json_raises_a_clear_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(SigningError, match="not valid JSON"):
            canonical_bytes_for(path)


class TestArtifactNaming:
    def test_cosign_emits_a_signature_and_a_bundle(self, tmp_path: Path) -> None:
        artifacts = signature_artifacts(tmp_path / "a.json", "cosign")
        assert [p.name for p in artifacts] == ["a.json.sig", "a.json.sigstore.json"]

    def test_minisign_emits_only_a_signature(self, tmp_path: Path) -> None:
        artifacts = signature_artifacts(tmp_path / "a.json", "minisign")
        assert [p.name for p in artifacts] == ["a.json.sig"]

    def test_signature_files_are_not_mistaken_for_advisories(
        self, tmp_path: Path
    ) -> None:
        """.sigstore.json is valid JSON sitting in the advisories/ directory."""
        (tmp_path / "x.json").write_text("{}")
        (tmp_path / "x.json.sigstore.json").write_text("{}")
        (tmp_path / "x.json.sig").write_text("sig")
        assert [p.name for p in advisory_json_paths(tmp_path)] == ["x.json"]


# ── Round trips ───────────────────────────────────────────────────────────────


@needs_minisign
class TestMinisignRoundTrip:
    def test_sign_then_verify_a_single_file(
        self, tmp_path: Path, minisign_config: SigningConfig
    ) -> None:
        path = tmp_path / "advisory.json"
        path.write_text(json.dumps({"id": "x_MCPSA-2026-000000000000"}))
        written = sign_path(path, minisign_config)
        assert written == [tmp_path / "advisory.json.sig"]
        verify_path(path, minisign_config)

    def test_sign_feed_then_verify_feed_passes(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        report = verify_feed(feed_dir, minisign_config)
        assert report.ok, report.failures
        assert report.checked == len(report.verified)

    def test_signing_records_its_parameters_in_the_index(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        index = json.loads((feed_dir / "index.json").read_text(encoding="utf-8"))
        assert index["signing"] == {
            "backend": "minisign",
            "mode": "key",
            "identity": None,
            "oidc_issuer": None,
        }

    def test_mutating_an_advisory_fails_verification(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        target = advisory_json_paths(feed_dir / "advisories")[0]
        record = json.loads(target.read_text(encoding="utf-8"))
        record["summary"] = "nothing to see here"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

        report = verify_feed(feed_dir, minisign_config)
        assert not report.ok
        assert any(target.name in failure for failure in report.failures)

    def test_reformatting_an_advisory_still_verifies(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        """Signatures cover values, not whitespace."""
        sign_feed(feed_dir, minisign_config)
        target = advisory_json_paths(feed_dir / "advisories")[0]
        record = json.loads(target.read_text(encoding="utf-8"))
        target.write_text(json.dumps(record, indent=8))

        report = verify_feed(feed_dir, minisign_config)
        assert report.ok, report.failures

    def test_deleting_an_advisory_fails_verification(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        advisory_json_paths(feed_dir / "advisories")[0].unlink()
        report = verify_feed(feed_dir, minisign_config)
        assert any("missing on disk" in failure for failure in report.failures)

    def test_injecting_an_unlisted_advisory_fails_verification(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        """A validly-signed record the index never listed must still be rejected."""
        sign_feed(feed_dir, minisign_config)
        smuggled = feed_dir / "advisories" / "x_MCPSA-2026-ffffffffffff.json"
        smuggled.write_text(json.dumps({"id": "x_MCPSA-2026-ffffffffffff"}, indent=2))
        sign_path(smuggled, minisign_config)

        report = verify_feed(feed_dir, minisign_config)
        assert any("absent from index.json" in failure for failure in report.failures)

    def test_swapping_an_advisory_for_a_resigned_forgery_fails(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        """The digest in the signed index is what makes re-signing insufficient."""
        sign_feed(feed_dir, minisign_config)
        target = advisory_json_paths(feed_dir / "advisories")[0]
        record = json.loads(target.read_text(encoding="utf-8"))
        record["summary"] = "downgraded"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        sign_path(target, minisign_config)  # attacker re-signs with the same key

        report = verify_feed(feed_dir, minisign_config)
        assert any(
            "does not match the digest" in failure for failure in report.failures
        )

    def test_mutating_the_index_fails_verification(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        index_path = feed_dir / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["count"] = 0
        index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")

        report = verify_feed(feed_dir, minisign_config)
        assert any(failure.startswith("index.json") for failure in report.failures)

    def test_removing_a_signature_fails_verification(
        self, feed_dir: Path, minisign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        target = advisory_json_paths(feed_dir / "advisories")[0]
        target.with_suffix(target.suffix + ".sig").unlink()
        report = verify_feed(feed_dir, minisign_config)
        assert any("Missing signature" in failure for failure in report.failures)

    def test_a_wrong_public_key_fails_verification(
        self, feed_dir: Path, minisign_config: SigningConfig, tmp_path: Path
    ) -> None:
        sign_feed(feed_dir, minisign_config)
        other_pub = tmp_path / "other.pub"
        subprocess.run(  # noqa: S603
            [
                shutil.which("minisign"),
                "-G",
                "-W",
                "-p",
                str(other_pub),
                "-s",
                str(tmp_path / "other.key"),
            ],
            capture_output=True,
            check=True,
            timeout=120,
        )
        wrong = SigningConfig(backend="minisign", public_key=other_pub)
        assert not verify_feed(feed_dir, wrong).ok


@needs_cosign
class TestCosignRoundTrip:
    def test_sign_emits_a_signature_and_a_sigstore_bundle(
        self, tmp_path: Path, cosign_config: SigningConfig
    ) -> None:
        path = tmp_path / "advisory.json"
        path.write_text(json.dumps({"id": "x_MCPSA-2026-000000000000"}))
        written = sign_path(path, cosign_config)
        assert [p.name for p in written] == [
            "advisory.json.sig",
            "advisory.json.sigstore.json",
        ]
        bundle = json.loads(written[1].read_text(encoding="utf-8"))
        assert "messageSignature" in bundle

    def test_sign_feed_then_verify_feed_passes(
        self, feed_dir: Path, cosign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, cosign_config)
        report = verify_feed(feed_dir, cosign_config)
        assert report.ok, report.failures

    def test_mutating_an_advisory_fails_verification(
        self, feed_dir: Path, cosign_config: SigningConfig
    ) -> None:
        sign_feed(feed_dir, cosign_config)
        target = advisory_json_paths(feed_dir / "advisories")[0]
        record = json.loads(target.read_text(encoding="utf-8"))
        record["details"] = "tampered"
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        assert not verify_feed(feed_dir, cosign_config).ok

    def test_keyless_verification_demands_a_pinned_identity(
        self, feed_dir: Path, cosign_config: SigningConfig
    ) -> None:
        """A keyless signature by *someone* proves nothing without pinning who."""
        sign_feed(feed_dir, cosign_config)
        unpinned = SigningConfig(backend="cosign")
        report = verify_feed(feed_dir, unpinned)
        assert any("--identity" in failure for failure in report.failures)


# ── Failure handling ──────────────────────────────────────────────────────────


class TestFeedLevelErrors:
    def test_signing_without_an_index_is_rejected(self, tmp_path: Path) -> None:
        config = SigningConfig(backend="minisign", private_key=tmp_path / "k")
        with pytest.raises(SigningError, match="No index.json"):
            sign_feed(tmp_path, config)

    def test_verifying_a_directory_without_an_index_reports_it(
        self, tmp_path: Path
    ) -> None:
        config = SigningConfig(backend="minisign", public_key=tmp_path / "p")
        report = verify_feed(tmp_path, config)
        assert not report.ok
        assert "index.json not found" in report.failures[0]

    def test_verifying_a_corrupt_index_reports_it(self, tmp_path: Path) -> None:
        (tmp_path / "index.json").write_text("{not json")
        config = SigningConfig(backend="minisign", public_key=tmp_path / "p")
        report = verify_feed(tmp_path, config)
        assert not report.ok
        assert "not valid JSON" in report.failures[0]

    def test_unsigned_feed_verifies_integrity_and_says_it_is_unsigned(
        self, feed_dir: Path
    ) -> None:
        """The verdict must never imply authenticity a feed does not carry."""
        config = SigningConfig(backend="minisign", public_key=feed_dir / "nope.pub")
        report = verify_feed(feed_dir, config)
        assert report.ok
        assert not report.signed

    def test_signing_a_feed_without_a_key_fails_before_writing_anything(
        self, feed_dir: Path
    ) -> None:
        with pytest.raises(SigningError, match="needs a project key"):
            sign_feed(feed_dir, SigningConfig())
        assert not list(feed_dir.rglob("*.sig"))

    def test_missing_tool_produces_an_actionable_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        path = tmp_path / "a.json"
        path.write_text("{}")
        config = SigningConfig(backend="minisign", private_key=tmp_path / "k")
        with pytest.raises(SigningError, match="not installed or not on PATH"):
            sign_path(path, config)
