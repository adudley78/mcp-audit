"""``lock --verify`` — compare ``mcp-lock.json`` against the current MCP configs.

Implements ADR-0005 §8's table: default ``verify()`` is fully offline and
only ever produces LOCK-001/002/003 (config drift); ``resolve=True`` adds
LOCK-004 (registry drift) via a real network call per unresolved/floating
entry. LOCK-005 (mcp-audit's own owned-section checksum mismatch) always
short-circuits every other check — nothing else is evaluated once it fires.

This module never claims to validate `trees` or any other foreign section
(ADR-0005 §3) — :data:`VerifyResult.unverified_sections` names them instead
of ``verify()`` staying silent about the scope of what it checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcp_audit.analyzers.rug_pull import server_key
from mcp_audit.analyzers.supply_chain import build_deprecated_package_finding
from mcp_audit.lock.identity import build_identity
from mcp_audit.lock.model import (
    compute_checksum,
    foreign_sections_with_content,
    unverified_sections,
)
from mcp_audit.lock.resolve import resolve_package
from mcp_audit.lock.writer import load_existing
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import KnownServerRegistry

_OWASP = ["MCP04"]


@dataclass
class UnverifiedItem:
    """One thing this run could not check, with a human-readable why (R56).

    ``lock --verify``'s exit code now reflects these (see :func:`verify`),
    so the waiver flag (``--allow-unverified``) has something concrete to
    name in its output — "the waiver must name every unverified
    section/entry" (R56 Part 1, STEP 3) — rather than a bare count.
    """

    kind: Literal["entry", "section"]
    name: str
    reason: str


@dataclass
class VerifyResult:
    """Outcome of one ``lock --verify`` run."""

    findings: list[Finding] = field(default_factory=list)
    #: Top-level sections present in the lock that this run did not verify
    #: (e.g. ``["trees"]``) — ADR-0005 §3's generic, not-`trees`-specific rule.
    #: Includes mcp-audit's own default ``trees``/``tools`` stubs (informational
    #: only — see :attr:`unverified` for the exit-code-affecting subset).
    unverified_sections: list[str] = field(default_factory=list)
    #: Locked server keys whose ``package.source == "unresolved"`` — never
    #: silently presented as verified (ADR-0005 §8's "plausible answer
    #: instead of a complaint" guard).
    unresolved_entries: list[str] = field(default_factory=list)
    #: Per-item detail behind the exit code (R56): one entry per unresolved
    #: package plus one per foreign section that is genuinely populated
    #: (excludes mcp-audit's own untouched default stubs — ADR-0005 §4's
    #: "never a reason to fail" MUST still holds for those). Empty when
    #: everything this run could check was fully verified.
    unverified: list[UnverifiedItem] = field(default_factory=list)
    #: ``True`` when :attr:`unverified` was non-empty *and* the caller passed
    #: ``allow_unverified=True`` to :func:`verify`, restoring exit 0 for that
    #: reason. Never ``True`` when the exit code is 1 because of an actual
    #: LOCK-001/002/004 drift finding — the waiver does not hide real drift.
    waived: bool = False
    checked_servers: int = 0
    exit_code: int = 0
    lock_missing: bool = False
    tampered: bool = False


def verify(
    lock_path: Path,
    servers: list[ServerConfig],
    *,
    resolve: bool = False,
    registry: KnownServerRegistry | None = None,
    allow_unverified: bool = False,
) -> VerifyResult:
    """Compare *servers* against the lock file at *lock_path*.

    Args:
        lock_path: Path to ``mcp-lock.json``.
        servers: Currently discovered and parsed servers.
        resolve: Also re-resolve floating specs against the registry
            (network; produces LOCK-004). Offline by default — ADR-0005 §8.
        registry: Known-server registry, consulted only when *resolve* is
            ``True``.
        allow_unverified: Waive unresolved entries and populated foreign
            sections from the exit code (``--allow-unverified``, R56 Part 1
            STEP 3). Never waives an actual LOCK-001/002/004 drift finding —
            see :attr:`VerifyResult.waived`.

    Returns:
        A :class:`VerifyResult`. ``exit_code`` is ``2`` when the lock is
        missing or tampered (LOCK-005); otherwise ``1`` when any
        LOCK-001/002/004 finding exists, **or** (R56, unless waived) when
        :attr:`VerifyResult.unverified` is non-empty — an unresolved package
        version or a genuinely populated foreign section (not mcp-audit's own
        default ``trees: {}``/``tools: null`` stub — ADR-0005 §4's "never a
        reason to fail" MUST still holds for that default case) was present
        and this run could not check it. ``0`` otherwise — LOCK-003 alone (a
        server was removed) never fails the exit code, and neither does an
        unresolved/foreign condition that was explicitly waived.
    """
    doc = load_existing(lock_path)
    if doc is None:
        return VerifyResult(lock_missing=True, exit_code=2)

    # ── LOCK-005 short-circuits everything else (ADR-0005 §10) ─────────────
    expected_checksum = compute_checksum(doc)
    actual_checksum = doc.get("checksum")
    if actual_checksum != expected_checksum:
        finding = Finding(
            id="LOCK-005",
            severity=Severity.CRITICAL,
            analyzer="lock",
            client="",
            server="",
            title="Lock file tampered or hand-edited",
            description=(
                "mcp-lock.json's checksum does not match its own owned "
                "content (lock_version, generated_by, servers). This check "
                "covers mcp-audit's own record only — it never fires on an "
                "edit inside a foreign section such as `trees`, which is "
                "that section's own producer's responsibility to verify."
            ),
            evidence=f"expected {expected_checksum}, found {actual_checksum!r}",
            remediation=(
                "Inspect the change (`git diff mcp-lock.json`). If it was "
                "intentional, run `mcp-audit lock --accept` to regenerate a "
                "valid lock rather than hand-editing the file."
            ),
            finding_path=str(lock_path),
            owasp_mcp_top_10=_OWASP,
        )
        return VerifyResult(findings=[finding], exit_code=2, tampered=True)

    locked_servers: dict = doc.get("servers", {})
    current: dict[str, ServerConfig] = {server_key(s): s for s in servers}
    findings: list[Finding] = []

    unresolved_entries = [
        key
        for key, entry in locked_servers.items()
        if (entry.get("package") or {}).get("source") == "unresolved"
    ]

    for key, server in current.items():
        if key not in locked_servers:
            findings.append(_lock_002(key, server))
            continue

        locked_entry = locked_servers[key]
        drift_finding = _check_drift(key, server, locked_entry)
        if drift_finding is not None:
            findings.append(drift_finding)
            continue

        if resolve:
            package = locked_entry.get("package")
            fresh = (
                resolve_package(server, offline=False, registry=registry, existing=None)
                if package
                else None
            )
            resolution_finding = _check_resolution(package, fresh, server)
            if resolution_finding is not None:
                findings.append(resolution_finding)
            deprecation_finding = _check_deprecation(server, fresh)
            if deprecation_finding is not None:
                findings.append(deprecation_finding)

    for key, entry in locked_servers.items():
        if key not in current:
            findings.append(_lock_003(key, entry))

    ids_present = {f.id for f in findings}
    has_drift = bool(ids_present & {"LOCK-001", "LOCK-002", "LOCK-004"})

    unverified_items: list[UnverifiedItem] = [
        UnverifiedItem(
            kind="entry",
            name=key,
            reason="locked with an unresolved version (offline at lock time) "
            "— never confirmed against the registry",
        )
        for key in unresolved_entries
    ] + [
        UnverifiedItem(
            kind="section",
            name=section,
            reason="foreign section mcp-audit did not write and cannot "
            "verify the contents of — see docs/lock.md#trees",
        )
        for section in foreign_sections_with_content(doc)
    ]

    if has_drift or (unverified_items and not allow_unverified):
        exit_code = 1
        waived = False
    else:
        exit_code = 0
        waived = bool(unverified_items) and allow_unverified

    return VerifyResult(
        findings=findings,
        unverified_sections=unverified_sections(doc),
        unresolved_entries=unresolved_entries,
        unverified=unverified_items,
        waived=waived,
        checked_servers=len(locked_servers),
        exit_code=exit_code,
    )


def _lock_002(key: str, server: ServerConfig) -> Finding:
    return Finding(
        id="LOCK-002",
        severity=Severity.HIGH,
        analyzer="lock",
        client=server.client,
        server=server.name,
        title=f"Server not in lock: {server.name!r}",
        description=(
            f"{key!r} is configured but was never approved through `mcp-audit lock`."
        ),
        evidence=f"config: {server.config_path}",
        remediation=(
            "If intentional, run `mcp-audit lock --accept` to add it to the "
            "lock. If not, remove it from the configuration."
        ),
        finding_path=str(server.config_path),
        owasp_mcp_top_10=_OWASP,
    )


def _lock_003(key: str, entry: dict) -> Finding:
    client, _, name = key.partition("/")
    return Finding(
        id="LOCK-003",
        severity=Severity.MEDIUM,
        analyzer="lock",
        client=client,
        server=name,
        title=f"Locked server missing: {name!r}",
        description=(
            f"{key!r} was approved through `mcp-audit lock` but is no longer "
            "configured."
        ),
        evidence=f"first_locked: {entry.get('first_locked', 'unknown')}",
        remediation=(
            "If intentionally removed, no action needed. If unexpected, "
            "verify your MCP configuration was not tampered with."
        ),
        finding_path=str(entry.get("config", "")),
        owasp_mcp_top_10=_OWASP,
    )


def _check_drift(key: str, server: ServerConfig, locked_entry: dict) -> Finding | None:
    """Return a LOCK-001 finding when identity/env/header names drifted."""
    current_identity = build_identity(server)
    current_env = sorted(server.env.keys())
    current_headers = sorted(server.headers.keys())
    locked_identity = locked_entry.get("identity", {})
    locked_env = locked_entry.get("env_keys", [])
    locked_headers = locked_entry.get("header_keys", [])

    diffs: list[str] = []
    if current_identity != locked_identity:
        diffs.append(f"identity: locked={locked_identity!r} now={current_identity!r}")
    if current_env != locked_env:
        diffs.append(f"env_keys: locked={locked_env!r} now={current_env!r}")
    if current_headers != locked_headers:
        diffs.append(f"header_keys: locked={locked_headers!r} now={current_headers!r}")

    if not diffs:
        return None

    return Finding(
        id="LOCK-001",
        severity=Severity.HIGH,
        analyzer="lock",
        client=server.client,
        server=server.name,
        title=f"Server drifted from lock: {server.name!r}",
        description=(
            f"{key!r}'s launch identity, environment variable names, or "
            "header names changed since it was locked."
        ),
        evidence="; ".join(diffs),
        remediation=(
            "Review the change. If approved, run `mcp-audit lock --accept`; "
            "otherwise revert the configuration."
        ),
        finding_path=str(server.config_path),
        owasp_mcp_top_10=_OWASP,
    )


def _check_resolution(
    package: dict | None,
    fresh: dict | None,
    server: ServerConfig,
) -> Finding | None:
    """Return a LOCK-004 finding under ``--resolve`` when resolution drifted.

    Args:
        package: The currently-locked ``package`` sub-object, or ``None``.
        fresh: A freshly re-resolved ``package`` dict for *server* (already
            computed once by the caller — see :func:`verify` — so this and
            :func:`_check_deprecation` never each make their own network
            call for the same server).
        server: The server being verified.
    """
    if not package:
        return None
    if fresh is None or fresh.get("resolved_version") is None:
        return None

    locked_version = package.get("resolved_version")
    fresh_version = fresh["resolved_version"]

    if fresh_version != locked_version:
        return Finding(
            id="LOCK-004",
            severity=Severity.HIGH,
            analyzer="lock",
            client=server.client,
            server=server.name,
            title=f"Resolution drifted: {server.name!r}",
            description=(
                f"{package.get('spec_as_written')!r} resolved to "
                f"{locked_version!r} on "
                f"{(package.get('resolution') or {}).get('resolved_at')}; it "
                f"now resolves to {fresh_version!r}."
            ),
            evidence=f"locked={locked_version!r} now={fresh_version!r}",
            remediation=(
                "Review the new version, then run `mcp-audit lock --accept`, "
                "or pin the config with `mcp-audit fix --fix-type pinning`."
            ),
            finding_path=str(server.config_path),
            owasp_mcp_top_10=_OWASP,
        )

    locked_integrity = package.get("integrity")
    fresh_integrity = fresh.get("integrity")
    if locked_integrity and fresh_integrity and locked_integrity != fresh_integrity:
        return Finding(
            id="LOCK-004",
            severity=Severity.CRITICAL,
            analyzer="lock",
            client=server.client,
            server=server.name,
            title=f"Same version, different hash: {server.name!r}",
            description=(
                f"{package.get('name')}@{locked_version} now hashes "
                "differently than when it was locked — a republished "
                "artifact."
            ),
            evidence=f"locked={locked_integrity!r} now={fresh_integrity!r}",
            remediation=(
                "Treat as a supply-chain incident: do not run this server "
                "until the republish is understood."
            ),
            finding_path=str(server.config_path),
            owasp_mcp_top_10=_OWASP,
            cwe="CWE-494",
        )

    return None


def _check_deprecation(server: ServerConfig, fresh: dict | None) -> Finding | None:
    """Return an SC-005 finding under ``--resolve`` when the fresh resolution
    is deprecated.

    Fires from the same freshly re-resolved ``package`` dict
    :func:`_check_resolution` uses (no second network call) — STORY-0073/R58,
    scope-cut to ``lock`` and ``lock --verify --resolve`` only; see
    :func:`mcp_audit.analyzers.supply_chain.build_deprecated_package_finding`.
    """
    if fresh is None:
        return None
    return build_deprecated_package_finding(
        client=server.client,
        server=server.name,
        config_path=str(server.config_path),
        package=fresh,
    )
