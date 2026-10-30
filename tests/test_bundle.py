"""STORY-0129: scan and affected from a signed, air-gapped bundle."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit import bundle as bundle_mod
from mcp_audit.advisory.sign import SigningConfig, SigningError, VerifyReport
from mcp_audit.cli import app

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import build_bundle  # noqa: E402

runner = CliRunner()
FAKE_MAL = {
    "id": "MAL-2099-0001",
    "ecosystem": "PyPI",
    "name": "bundle-only-pkg",
    "aliases": [],
    "summary": "Malicious code in bundle-only-pkg (PyPI)",
    "published": "2099-01-01T00:00:00Z",
    "versions": ["1.0.0"],
    "ranges": [],
}
CONFIG = {"mcpServers": {"s": {"command": "uvx", "args": ["bundle-only-pkg==1.0.0"]}}}


@pytest.fixture(autouse=True)
def _reset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Hermetic: never touch the real rollback record.
    monkeypatch.setattr(
        bundle_mod, "default_seen_path", lambda: tmp_path / "seen-default.json"
    )
    yield
    bundle_mod.activate(None)


def _report(**over: object) -> VerifyReport:
    base: dict[str, object] = {
        "checked": 1,
        "signed": True,
        "published_at": "2026-10-29T00:00:00Z",
        "expires": "2026-11-12T00:00:00Z",
        "snapshot_version": 3,
        "age_days": 2,
    }
    base.update(over)
    return VerifyReport(**base)  # type: ignore[arg-type]


@pytest.fixture
def trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for the signature tool (the real one is in the minisign test)."""
    monkeypatch.setattr(bundle_mod, "verify_feed", lambda *a, **k: _report())
    monkeypatch.setattr(bundle_mod, "verify_path", lambda *a, **k: None)


@pytest.fixture
def made(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A bundle whose malicious list also names ``bundle-only-pkg``."""
    mal = json.loads((REPO / "registry" / "known-malicious.json").read_text())
    mal["entries"].append(FAKE_MAL)
    patched = tmp_path / "known-malicious.json"
    patched.write_text(json.dumps(mal))
    monkeypatch.setitem(build_bundle.SOURCES, "known-malicious.json", patched)
    return build_bundle.build(REPO / "examples" / "feed", tmp_path / "bundle", None)


def _config() -> SigningConfig:
    return SigningConfig(backend="minisign", public_key=Path("unused.pub"))


class TestVerify:
    def test_verified_bundle_reports_its_date(self, trusted: None, made: Path) -> None:
        b = bundle_mod.verify_bundle(made, _config())
        assert b.date == "2026-10-29"
        assert "2026-10-29" in b.line() and "no network" in b.line()
        assert set(b.files) == set(bundle_mod.DATA_FILES)

    def test_unsigned_feed_is_refused(self, monkeypatch, made: Path) -> None:
        monkeypatch.setattr(
            bundle_mod, "verify_feed", lambda *a, **k: _report(signed=False)
        )
        with pytest.raises(bundle_mod.BundleError, match="unsigned"):
            bundle_mod.verify_bundle(made, _config())

    def test_expired_or_rolled_back_feed_fails_as_feed_verify_does(
        self, monkeypatch, made: Path
    ) -> None:
        bad = _report(failures=["feed expired on 2026-11-12"])
        monkeypatch.setattr(bundle_mod, "verify_feed", lambda *a, **k: bad)
        with pytest.raises(bundle_mod.BundleError, match="expired"):
            bundle_mod.verify_bundle(made, _config())

    def test_bad_manifest_signature_fails(self, monkeypatch, made: Path) -> None:
        monkeypatch.setattr(bundle_mod, "verify_feed", lambda *a, **k: _report())

        def boom(*a: object, **k: object) -> None:
            raise SigningError("signature does not verify")

        monkeypatch.setattr(bundle_mod, "verify_path", boom)
        with pytest.raises(bundle_mod.BundleError, match="bundle.json"):
            bundle_mod.verify_bundle(made, _config())

    def test_altered_data_file_fails(self, trusted: None, made: Path) -> None:
        target = made / "data" / "known-malicious.json"
        target.write_text(target.read_text().replace("bundle-only-pkg", "other-pkg"))
        with pytest.raises(bundle_mod.BundleError, match="does not match the digest"):
            bundle_mod.verify_bundle(made, _config())

    def test_manifest_for_a_different_feed_fails(
        self, trusted: None, made: Path
    ) -> None:
        index = json.loads((made / "index.json").read_text())
        index["snapshot_version"] = 99
        (made / "index.json").write_text(json.dumps(index))
        with pytest.raises(bundle_mod.BundleError, match="different feed index"):
            bundle_mod.verify_bundle(made, _config())

    def test_missing_extra_and_symlinked_files_fail(
        self, trusted: None, made: Path, tmp_path: Path
    ) -> None:
        (made / "data" / "known-servers.json").unlink()
        (made / "data" / "extra.json").write_text("{}")
        outside = tmp_path / "outside.json"
        outside.write_text("{}")
        link = made / "data" / "exploit-signals.json"
        link.unlink()
        link.symlink_to(outside)
        with pytest.raises(bundle_mod.BundleError) as err:
            bundle_mod.verify_bundle(made, _config())
        text = " ".join(err.value.failures)
        assert "known-servers.json: missing" in text
        assert "exploit-signals.json: missing, or not a regular file" in text
        assert "extra.json: present but not in" in text

    def test_files_are_read_from_a_private_copy(
        self, trusted: None, made: Path
    ) -> None:
        b = bundle_mod.verify_bundle(made, _config())
        assert made not in b.path("known-malicious.json").parents
        (made / "data" / "known-malicious.json").write_text("{}")  # after the check
        assert "bundle-only-pkg" in b.path("known-malicious.json").read_text()

    def test_failed_bundle_does_not_advance_the_rollback_record(
        self, monkeypatch, made: Path, tmp_path: Path
    ) -> None:
        def feed_ok(root, config, *, now, state_path):
            state_path.write_text('{"seen": 9}')  # what verify_feed records on success
            return _report()

        monkeypatch.setattr(bundle_mod, "verify_feed", feed_ok)
        monkeypatch.setattr(bundle_mod, "verify_path", lambda *a, **k: None)
        (made / "data" / "known-servers.json").write_text("{}")  # breaks a digest
        state = tmp_path / "seen.json"
        with pytest.raises(bundle_mod.BundleError):
            bundle_mod.verify_bundle(made, _config(), state_path=state)
        assert not state.exists()
        (made / "data" / "known-servers.json").write_bytes(
            (REPO / "registry" / "known-servers.json").read_bytes()
        )
        bundle_mod.verify_bundle(made, _config(), state_path=state)
        assert state.exists()

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
    def test_rollback_record_is_written_private(
        self, monkeypatch, made: Path, tmp_path: Path
    ) -> None:
        def feed_ok(root, config, *, now, state_path):
            state_path.write_text('{"versions": {"key-mode\\nminisign": 9}}')
            return _report()

        monkeypatch.setattr(bundle_mod, "verify_feed", feed_ok)
        monkeypatch.setattr(bundle_mod, "verify_path", lambda *a, **k: None)
        state = tmp_path / "state-dir" / "seen.json"
        bundle_mod.verify_bundle(made, _config(), state_path=state)
        assert stat.S_IMODE(state.stat().st_mode) == 0o600
        assert stat.S_IMODE(state.parent.stat().st_mode) == 0o700
        assert json.loads(state.read_text()) == {"versions": {"key-mode\nminisign": 9}}

    def test_missing_directory(self, tmp_path: Path) -> None:
        with pytest.raises(bundle_mod.BundleError, match="not found"):
            bundle_mod.verify_bundle(tmp_path / "nope", _config())


class TestCli:
    def test_affected_reads_the_bundles_malicious_list(
        self, trusted: None, made: Path, tmp_path: Path
    ) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps(CONFIG))
        args = ["affected", "MAL-2099-0001", "-p", str(cfg), "-f", "json"]
        without = runner.invoke(app, args)
        assert without.exit_code == 2  # not in the installed data
        bundle_mod.activate(None)
        result = runner.invoke(app, [*args, "--bundle", str(made)])
        assert result.exit_code == 1, result.output
        assert "Signed bundle 2026-10-29" in result.output
        doc = json.loads(result.output[result.output.index("{") :])
        assert doc["results"][0]["status"] == "AFFECTED"
        assert any("Signed bundle 2026-10-29" in s for s in doc["sources"])

    def test_scan_with_bundle_prints_date_and_flags_malicious_package(
        self, trusted: None, made: Path, tmp_path: Path
    ) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps(CONFIG))
        result = runner.invoke(app, ["scan", str(cfg), "--bundle", str(made)])
        assert "Signed bundle 2026-10-29" in result.output
        assert "MAL-2099-0001" in result.output

    def test_scan_with_bundle_keeps_the_config_hygiene_checks(
        self, trusted: None, made: Path
    ) -> None:
        demo = str(REPO / "demo" / "configs")
        online = runner.invoke(app, ["scan", demo, "-f", "json"])
        bundled = runner.invoke(
            app, ["scan", demo, "-f", "json", "--bundle", str(made)]
        )

        def analyzers(out: str) -> set[str]:
            doc = json.loads(out[out.index("{") :])
            return {f.get("analyzer") for f in doc["findings"]}

        assert "config_hygiene" in analyzers(online.output)
        assert "config_hygiene" in analyzers(bundled.output)

    def test_failed_bundle_stops_the_run(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["affected", "CVE-2026-59822", "--bundle", str(tmp_path)]
        )
        assert result.exit_code == 2
        assert "did not verify" in result.output

    def test_bundle_refuses_network_flags_and_registry(
        self, trusted: None, made: Path
    ) -> None:
        live = runner.invoke(
            app, ["affected", "CVE-2026-59822", "--live", "--bundle", str(made)]
        )
        assert live.exit_code == 2 and "no network" in live.output
        reg = runner.invoke(
            app,
            [
                "scan",
                "--bundle",
                str(made),
                "--registry",
                str(REPO / "registry" / "known-servers.json"),
            ],
        )
        assert reg.exit_code == 2 and "--registry" in reg.output
        net = runner.invoke(app, ["scan", "--bundle", str(made), "--check-vulns"])
        assert net.exit_code == 2 and "no network" in net.output


@pytest.mark.skipif(
    shutil.which("minisign") is None, reason="minisign is not installed"
)
def test_real_minisign_round_trip(tmp_path: Path) -> None:
    """Sign a feed and a bundle with minisign; verify; then break each piece."""
    import subprocess

    from mcp_audit.advisory.sign import sign_feed

    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    subprocess.run(  # noqa: S603
        [shutil.which("minisign"), "-G", "-W", "-p", str(pub), "-s", str(priv)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    config = SigningConfig(backend="minisign", private_key=priv, public_key=pub)
    feed = tmp_path / "feed"
    shutil.copytree(REPO / "examples" / "feed", feed)
    sign_feed(feed, config)
    out = build_bundle.build(feed, tmp_path / "bundle", config)
    state = tmp_path / "seen.json"
    b = bundle_mod.verify_bundle(out, config, state_path=state)
    assert b.published_at
    (out / "data" / "known-malicious.json").write_text("{}")
    with pytest.raises(bundle_mod.BundleError, match="does not match the digest"):
        bundle_mod.verify_bundle(out, config, state_path=state)
    out2 = build_bundle.build(feed, tmp_path / "bundle2", config)
    manifest = json.loads((out2 / "bundle.json").read_text())
    manifest["created_at"] = "2000-01-01T00:00:00Z"
    (out2 / "bundle.json").write_text(json.dumps(manifest))
    with pytest.raises(bundle_mod.BundleError, match="bundle.json"):
        bundle_mod.verify_bundle(out2, config, state_path=state)


class TestBuilder:
    def _signals(self, tmp_path: Path, date: str, count: int) -> Path:
        committed = json.loads(build_bundle.SOURCES["exploit-signals.json"].read_text())
        committed["kev"]["date_released"] = date
        entries = dict(list(committed["kev"]["entries"].items())[:count])
        committed["kev"]["entries"] = entries
        path = tmp_path / f"signals-{date}-{count}.json"
        path.write_text(json.dumps(committed))
        return path

    def test_fresh_signals_are_used_only_when_at_least_as_complete(
        self, tmp_path: Path
    ) -> None:
        committed = build_bundle.SOURCES["exploit-signals.json"]
        old_date, old_count, _, _ = build_bundle._shape(committed)
        good = self._signals(tmp_path, "2099-01-01", old_count)
        thin = self._signals(tmp_path, "2099-01-01", old_count - 1)
        stale = self._signals(tmp_path, "2000-01-01", old_count)
        broken = tmp_path / "broken.json"
        broken.write_text("{")
        assert build_bundle.choose_signals(good, committed) == good
        assert build_bundle.choose_signals(thin, committed) == committed
        assert build_bundle.choose_signals(stale, committed) == committed
        assert build_bundle.choose_signals(broken, committed) == committed
        assert build_bundle.choose_signals(None, committed) == committed
        epss_thin = json.loads(good.read_text())
        epss_thin["epss"]["entries"] = dict(
            list(epss_thin["epss"]["entries"].items())[:5]
        )
        thin_epss = tmp_path / "thin-epss.json"
        thin_epss.write_text(json.dumps(epss_thin))
        assert build_bundle.choose_signals(thin_epss, committed) == committed

    def test_in_place_adds_data_and_manifest_to_the_feed(self, tmp_path: Path) -> None:
        feed = tmp_path / "feed"
        shutil.copytree(REPO / "examples" / "feed", feed)
        build_bundle.build(feed, None, None)
        assert (feed / "bundle.json").is_file()
        assert {p.name for p in (feed / "data").iterdir()} == set(bundle_mod.DATA_FILES)
        with pytest.raises(SystemExit):
            build_bundle.build(feed, None, None)  # never overwrites


@pytest.mark.skipif(
    shutil.which("minisign") is None, reason="minisign is not installed"
)
def test_in_place_signed_feed_verifies_as_a_bundle(tmp_path: Path) -> None:
    """The weekly publish path: sign a feed, add the bundle in place, verify."""
    import subprocess

    from mcp_audit.advisory.sign import sign_feed

    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    subprocess.run(  # noqa: S603
        [shutil.which("minisign"), "-G", "-W", "-p", str(pub), "-s", str(priv)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    config = SigningConfig(backend="minisign", private_key=priv, public_key=pub)
    feed = tmp_path / "feed"
    shutil.copytree(REPO / "examples" / "feed", feed)
    sign_feed(feed, config)
    build_bundle.build(feed, None, config)
    assert build_bundle.main(["--verify", str(feed), "--public-key", str(pub)]) == 0
    (feed / "bundle.json.sig").unlink()
    assert build_bundle.main(["--verify", str(feed), "--public-key", str(pub)]) == 1
