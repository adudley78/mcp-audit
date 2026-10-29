"""``lock --verify`` — compare ``mcp-lock.json`` against the current MCP configs.

Implements ADR-0005 §8's table: default ``verify()`` is fully offline and
only ever produces LOCK-001/002/003 (config drift); ``resolve=True`` adds
LOCK-004 (registry drift) via a real network call per unresolved/floating
entry. LOCK-005 (mcp-audit's own owned-section checksum mismatch) always
short-circuits every other check — nothing else is evaluated once it fires.

With ``tool_enumerations`` (``lock --verify --connect``, STORY-0086) it also
compares each server's live tool list with the digests in the lock's
``tools`` section: LOCK-006 (tool added), LOCK-007 (schema or annotations
changed), LOCK-008 (only the description or title changed), LOCK-009 (tool
removed). The ``tools`` section's own ``_checksum`` is checked on every run
and a mismatch is LOCK-005, like the top-level checksum.

This module never claims to validate `trees` or any other foreign section
(ADR-0005 §3) — :data:`VerifyResult.unverified_sections` names them instead
of ``verify()`` staying silent about the scope of what it checked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcp_audit.advisory.canonical import CanonicalError
from mcp_audit.analyzers.rug_pull import server_key
from mcp_audit.analyzers.supply_chain import (
    build_deprecated_package_finding,
    redact_text,
)
from mcp_audit.lock import section_digests, tool_digests
from mcp_audit.lock import tool_text as tool_text_mod
from mcp_audit.lock.identity import (
    MatchKey,
    build_identity,
    comparable_identity,
    launch_carries_secret,
    match_key,
    normalize_config_ref,
)
from mcp_audit.lock.model import (
    SECTION_DIGESTS_KEY,
    compute_checksum,
    foreign_sections_with_content,
    is_version_2,
    unsupported_version,
    unverified_sections,
)
from mcp_audit.lock.resolve import resolve_package
from mcp_audit.lock.writer import load_existing
from mcp_audit.models import Finding, ServerConfig, ServerEnumeration, Severity
from mcp_audit.registry.loader import KnownServerRegistry

_OWASP = ["MCP04"]

#: Findings that fail the exit code. LOCK-003 and LOCK-009 (something was
#: removed) never do on their own.
_DRIFT_IDS = frozenset(
    {
        "LOCK-001",
        "LOCK-002",
        "LOCK-004",
        "LOCK-006",
        "LOCK-007",
        "LOCK-008",
        "LOCK-011",
    }
)

#: ``resolution_context`` fields compared by LOCK-010. ``resolved_at`` is
#: not: it differs on every resolution by construction.
_CONTEXT_FIELDS = ("latest", "latest_deprecated", "npm_major", "node_version")

#: Longest context value quoted in a LOCK-010 message.
_MAX_CONTEXT_TEXT = 200

#: LOCK-011 findings listed per lock; the rest are counted in the last one.
_MAX_DIGEST_FINDINGS = 20

#: How many tool names a finding's evidence lists before summarising.
_MAX_NAMED_TOOLS = 20


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
    #: Config files this run saw that live outside the lock root (and outside
    #: ``$HOME``, the ``--include-user`` dotfiles shape). Such a file is not
    #: something this lock describes, so it produces no LOCK finding in either
    #: direction — just one warning line, so the skip is visible (R61).
    outside_root: list[str] = field(default_factory=list)
    #: Servers with a tool record in the lock's (mcp-audit-owned) ``tools``
    #: section — STORY-0086.
    tools_recorded: int = 0
    #: Servers whose live tool list was compared with its record this run;
    #: ``None`` when tools were not enumerated (no ``--connect``), so a green
    #: result never implies tool definitions were checked.
    tools_compared: int | None = None
    #: ``{lock key: [full per-tool diff]}`` when saved tool text was used
    #: (``lock --verify --connect`` with ``mcp-lock.tools.json``). Uncapped;
    #: the terminal shows a capped view.
    tool_diffs: dict[str, list[dict]] = field(default_factory=dict)
    #: Why saved tool text could not be used for a server (out of step with
    #: the lock, unreadable). Informational: it never changes the exit code.
    tool_text_notes: list[str] = field(default_factory=list)
    #: The lock's ``lock_version`` when it is newer than this mcp-audit can
    #: verify; nothing else was checked (exit 2).
    unsupported_version: int | None = None


def verify(
    lock_path: Path,
    servers: list[ServerConfig],
    *,
    root: Path | None = None,
    resolve: bool = False,
    registry: KnownServerRegistry | None = None,
    allow_unverified: bool = False,
    tool_enumerations: dict[tuple[str, str], ServerEnumeration] | None = None,
    tool_text: dict | None = None,
    tool_text_problem: str | None = None,
) -> VerifyResult:
    """Compare *servers* against the lock file at *lock_path*.

    A discovered server is matched to a lock entry by
    **(config path relative to** *root* **, server name)** —
    :func:`mcp_audit.lock.identity.match_key`, R61 — never by the
    ``<client>/<name>`` entry key, because the client label is assigned by
    whichever discovery pass found the file and differs between ``lock``,
    a bare ``scan``, and ``scan --path``. That key string is still the
    entry's id in the file and in every message.

    Args:
        lock_path: Path to ``mcp-lock.json``.
        servers: Currently discovered and parsed servers.
        root: The lock root — the directory the lock's relative ``config``
            paths are expressed against. Defaults to *lock_path*'s own
            parent, which is correct for every case except a lock written
            elsewhere via ``lock --output``; the CLI passes the real root
            explicitly for that.
        resolve: Also re-resolve floating specs against the registry
            (network; produces LOCK-004). Offline by default — ADR-0005 §8.
        registry: Known-server registry, consulted only when *resolve* is
            ``True``.
        allow_unverified: Waive unresolved entries and populated foreign
            sections from the exit code (``--allow-unverified``, R56 Part 1
            STEP 3). Never waives an actual LOCK-001/002/004 drift finding —
            see :attr:`VerifyResult.waived`.
        tool_enumerations: Live enumerations keyed by
            :func:`mcp_audit.lock.tool_digests.enumeration_key`
            (``lock --verify --connect``). ``None`` skips the tool
            comparison. A server with no tool record, or whose tools could
            not be listed, is reported as unverified rather than passed.
        tool_text: The loaded ``mcp-lock.tools.json`` document, if any
            (:mod:`mcp_audit.lock.tool_text`). Used only to show *what*
            changed in LOCK-006/007/008; it never decides a verdict, and a
            stored definition is shown only if it hashes to the digest the
            lock holds.
        tool_text_problem: Why the tool-text file could not be read, if it
            could not; reported once as a note.

    A ``lock_version`` 1 lock is verified exactly as mcp-audit 0.22 verified
    it. A version-2 lock also gets its ``section_digests`` checked (LOCK-011)
    and its bytes compared with their canonical form (LOCK-012), and under
    *resolve* each entry's ``resolution_context`` compared (LOCK-010). A
    version above 2 is not checked at all (:attr:`VerifyResult.unsupported_version`).

    Returns:
        A :class:`VerifyResult`. ``exit_code`` is ``2`` when the lock is
        missing, tampered (LOCK-005), or newer than this mcp-audit reads;
        otherwise ``1`` when any
        LOCK-001/002/004/006/007/008/011 finding exists, **or** (R56, unless
        waived) when :attr:`VerifyResult.unverified` is non-empty — an
        unresolved package version, a genuinely populated foreign section
        (not mcp-audit's own default ``trees: {}``/``tools: null`` stub —
        ADR-0005 §4's "never a reason to fail" MUST still holds for that
        default case), or, with *tool_enumerations*, a server whose tools
        could not be compared. ``0`` otherwise — LOCK-003 or LOCK-009 alone
        (something was removed) never fails the exit code, and neither does
        an unverified condition that was explicitly waived.
    """
    doc = load_existing(lock_path)
    if doc is None:
        return VerifyResult(lock_missing=True, exit_code=2)

    # A lock_version this mcp-audit does not know may mean anything; checking
    # it as an older format would claim more than was checked.
    newer = unsupported_version(doc)
    if newer is not None:
        return VerifyResult(unsupported_version=newer, exit_code=2)

    # ── LOCK-005 short-circuits everything else (ADR-0005 §10) ─────────────
    try:
        expected_checksum = compute_checksum(doc)
    except CanonicalError as exc:
        # mcp-audit never writes owned content it cannot encode (too large, or
        # a lone surrogate), so such content is an edit: tampered, not a crash.
        finding = _lock_005(
            lock_path,
            scope="its own owned content (lock_version, generated_by, servers)",
            evidence=f"owned content cannot be canonically encoded: {exc}",
        )
        return VerifyResult(findings=[finding], exit_code=2, tampered=True)
    actual_checksum = doc.get("checksum")
    if actual_checksum != expected_checksum:
        finding = _lock_005(
            lock_path,
            scope="its own owned content (lock_version, generated_by, servers)",
            evidence=f"expected {expected_checksum}, found {actual_checksum!r}",
        )
        return VerifyResult(findings=[finding], exit_code=2, tampered=True)

    tools_section = doc.get(tool_digests.TOOLS_KEY)
    owned_tools = tool_digests.is_owned(tools_section)
    if owned_tools and not _tools_checksum_ok(tools_section):
        finding = _lock_005(
            lock_path,
            scope="the content of its `tools` section (`tools._checksum`)",
            evidence=(
                f"tools._checksum: found {tools_section.get('_checksum')!r}, "
                "content does not match"
            ),
        )
        return VerifyResult(findings=[finding], exit_code=2, tampered=True)
    locked_tool_servers: dict = tools_section["servers"] if owned_tools else {}
    tool_items: list[UnverifiedItem] = []
    tools_compared = 0
    tool_diffs: dict[str, list[dict]] = {}
    tool_text_notes: list[str] = [tool_text_problem] if tool_text_problem else []

    lock_root = root if root is not None else lock_path.resolve().parent
    locked_servers: dict = doc.get("servers", {})
    locked_by_match = _index_locked_entries(locked_servers)
    current, outside_root = _index_current_servers(servers, lock_root)
    findings: list[Finding] = []

    unresolved_entries = [
        key
        for key, entry in locked_servers.items()
        if (entry.get("package") or {}).get("source") == "unresolved"
    ]

    # ── lock_version 2: per-section digests and canonical bytes ─────────────
    # A version-1 lock skips this entirely, so it verifies exactly as before.
    digest_items: list[UnverifiedItem] = []
    if is_version_2(doc):
        digest_findings, digest_items = _check_section_digests(lock_path, doc)
        findings.extend(digest_findings)

    for match, server in current.items():
        if match not in locked_by_match:
            findings.append(_lock_002(server_key(server), server))
            continue

        key, locked_entry = locked_by_match[match]
        if launch_carries_secret(server):
            findings.append(_lock_013(key, server))
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
            context_finding = _check_context(key, package, fresh, server)
            if context_finding is not None:
                findings.append(context_finding)
            deprecation_finding = _check_deprecation(server, fresh)
            if deprecation_finding is not None:
                findings.append(deprecation_finding)

        if tool_enumerations is not None:
            problem = _tool_problem(
                key,
                locked_tool_servers.get(key),
                tool_enumerations.get(tool_digests.enumeration_key(server)),
            )
            if problem is not None:
                tool_items.append(problem)
            else:
                enumeration = tool_enumerations[tool_digests.enumeration_key(server)]
                diff = tool_digests.compare(
                    locked_tool_servers[key],
                    tool_digests.tool_digests(enumeration.tools),
                )
                details = _tool_details(
                    key,
                    locked_tool_servers[key],
                    enumeration.tools,
                    diff,
                    tool_text,
                )
                if details.note:
                    tool_text_notes.append(details.note)
                if details.changes:
                    tool_diffs[key] = [c.to_json() for c in details.changes.values()]
                findings.extend(_tool_findings(key, server, diff, details))
                tools_compared += 1

    for match, (key, entry) in locked_by_match.items():
        if match not in current:
            findings.append(_lock_003(key, entry))

    ids_present = {f.id for f in findings}
    has_drift = bool(ids_present & _DRIFT_IDS)

    unverified_items: list[UnverifiedItem] = (
        [
            UnverifiedItem(
                kind="entry",
                name=key,
                reason="locked with an unresolved version (offline at lock time) "
                "— never confirmed against the registry",
            )
            for key in unresolved_entries
        ]
        + [
            UnverifiedItem(
                kind="section",
                name=section,
                reason="foreign section mcp-audit did not write and cannot "
                "verify the contents of — see docs/lock.md#trees",
            )
            for section in foreign_sections_with_content(doc)
        ]
        + digest_items
        + tool_items
    )

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
        outside_root=outside_root,
        tools_recorded=len(locked_tool_servers),
        tools_compared=tools_compared if tool_enumerations is not None else None,
        tool_diffs=tool_diffs,
        tool_text_notes=tool_text_notes,
    )


def servers_to_connect(
    lock_path: Path, servers: list[ServerConfig], *, root: Path | None = None
) -> list[ServerConfig]:
    """Return the servers ``lock --verify --connect`` needs to start.

    Only a server whose tools can actually be compared: it matches a locked
    entry, has not drifted (no LOCK-001), and has a tool record. Nothing is
    started for a lock that is missing or fails either checksum, for an
    unlocked server (LOCK-002), or for one whose launch line changed — that
    command was never approved, so it is reported, not run.

    Args:
        lock_path: Path to ``mcp-lock.json``.
        servers: Currently discovered and parsed servers.
        root: The lock root (see :func:`verify`).
    """
    doc = load_existing(lock_path)
    if doc is None:
        return []
    try:
        if doc.get("checksum") != compute_checksum(doc):
            return []
    except CanonicalError:
        return []
    section = doc.get(tool_digests.TOOLS_KEY)
    if not tool_digests.is_owned(section) or not _tools_checksum_ok(section):
        return []
    records = section["servers"]
    lock_root = root if root is not None else lock_path.resolve().parent
    locked_by_match = _index_locked_entries(doc.get("servers", {}))
    current, _ = _index_current_servers(servers, lock_root)
    eligible: list[ServerConfig] = []
    for match, server in current.items():
        if match not in locked_by_match:
            continue
        key, entry = locked_by_match[match]
        if key in records and _check_drift(key, server, entry) is None:
            eligible.append(server)
    return eligible


def _lock_005(lock_path: Path, *, scope: str, evidence: str) -> Finding:
    """Build the LOCK-005 finding for a checksum that no longer matches."""
    return Finding(
        id="LOCK-005",
        severity=Severity.CRITICAL,
        analyzer="lock",
        client="",
        server="",
        title="Lock file tampered or hand-edited",
        description=(
            f"mcp-lock.json's checksum does not match {scope}. This check "
            "covers mcp-audit's own record only — it never fires on an edit "
            "inside a foreign section such as `trees`, which is that "
            "section's own producer's responsibility to verify."
        ),
        evidence=evidence,
        remediation=(
            "Inspect the change (`git diff mcp-lock.json`). If it was "
            "intentional, run `mcp-audit lock --accept` to regenerate a "
            "valid lock rather than hand-editing the file."
        ),
        finding_path=str(lock_path),
        owasp_mcp_top_10=_OWASP,
    )


def _tools_checksum_ok(section: dict) -> bool:
    """``tools._checksum`` holds; content that cannot be encoded does not."""
    try:
        return tool_digests.checksum_ok(section)
    except CanonicalError:
        return False


def _short(text: str) -> str:
    """Redact and cap text taken from the lock file for a message."""
    text = redact_text(text)
    if len(text) > _MAX_CONTEXT_TEXT:
        text = text[:_MAX_CONTEXT_TEXT] + "…"
    return text


def _check_section_digests(
    lock_path: Path, doc: dict
) -> tuple[list[Finding], list[UnverifiedItem]]:
    """LOCK-011 / LOCK-012 for a version-2 lock (STORY-0116).

    LOCK-011: a ``section_digests`` entry does not hold — the section changed
    without its producer updating its digest, or the map itself was edited.
    LOCK-012: the file is not byte-identical to its canonical form, so some
    tool reformatted it (content intact; not a failure on its own). A section
    too large to digest is returned as unverified, never as passed.
    """
    findings: list[Finding] = []
    items: list[UnverifiedItem] = []
    outcome = section_digests.check(doc)
    shown = outcome.problems[:_MAX_DIGEST_FINDINGS]
    hidden = len(outcome.problems) - len(shown)
    for index, problem in enumerate(shown):
        section = _short(repr(problem.section))
        evidence = f"{SECTION_DIGESTS_KEY}[{section}]: {problem.reason}"
        if problem.recorded or problem.computed:
            evidence += (
                f"; recorded {_short(problem.recorded or 'nothing')}, "
                f"computed {problem.computed or 'nothing'}"
            )
        if hidden and index == len(shown) - 1:
            evidence += f"; and {hidden} more section_digests problem(s) not listed"
        findings.append(
            Finding(
                id="LOCK-011",
                severity=Severity.HIGH,
                analyzer="lock",
                client="",
                server="",
                title=f"Lock section digest does not hold: {section}",
                description=(
                    "mcp-lock.json (lock_version 2) records a digest per "
                    "section so that each producer can tell when a section it "
                    "wrote was changed by someone else. "
                    f"{section}: {problem.reason}. mcp-audit cannot "
                    "say who changed it; for a section another tool produces "
                    "(such as `trees`), that tool's own verifier is the "
                    "authority on its contents."
                ),
                evidence=evidence,
                remediation=(
                    "Inspect `git diff mcp-lock.json`. If mcp-audit's own "
                    "section changed, re-run `mcp-audit lock --accept`; if "
                    "another producer's section changed, re-run that producer "
                    "so it records a fresh digest."
                ),
                finding_path=str(lock_path),
                owasp_mcp_top_10=_OWASP,
            )
        )
    for name in outcome.not_digestible:
        items.append(
            UnverifiedItem(
                kind="section",
                name=_short(name),
                reason="too large for mcp-audit to digest, or holds text with no "
                "canonical encoding (a lone UTF-16 surrogate), so its recorded "
                "digest was not checked — see docs/lock.md",
            )
        )

    try:
        raw = lock_path.read_bytes()
    except OSError:
        return findings, items
    reformatted = section_digests.noncanonical_sections(raw, doc)
    if reformatted:
        findings.append(
            Finding(
                id="LOCK-012",
                severity=Severity.LOW,
                analyzer="lock",
                client="",
                server="",
                title="Lock file is not in canonical form",
                description=(
                    "mcp-lock.json is written in RFC 8785 canonical form so "
                    "that two producers never disagree on the bytes of a "
                    "section neither changed. This file differs from its "
                    "canonical form: something reformatted it. Its content "
                    "still matches its checksums; this does not fail "
                    "verification on its own."
                ),
                evidence="not canonical: "
                + ", ".join(_short(name) for name in reformatted),
                remediation=(
                    "Re-run `mcp-audit lock --accept` to rewrite the file "
                    "canonically, and keep editors and formatters off "
                    "mcp-lock.json (use a git textconv to read diffs — see "
                    "docs/lock.md)."
                ),
                finding_path=str(lock_path),
                owasp_mcp_top_10=_OWASP,
            )
        )
    elif reformatted is None:
        items.append(
            UnverifiedItem(
                kind="section",
                name="<file>",
                reason="too large for mcp-audit to re-encode, or holds text with "
                "no canonical encoding, so its canonical form was not checked — "
                "see docs/lock.md",
            )
        )
    return findings, items


def _tool_problem(
    key: str,
    record: dict | None,
    enumeration: ServerEnumeration | None,
) -> UnverifiedItem | None:
    """Say why *key*'s tools cannot be compared this run, or ``None`` if they can."""
    if record is None:
        reason = (
            "no tool record in the lock — run `mcp-audit lock --connect` to record one"
        )
    elif enumeration is None:
        reason = "tools were not listed this run"
    elif enumeration.error:
        reason = f"could not connect to list tools: {enumeration.error}"
    elif enumeration.tools_error:
        reason = f"could not list every tool: {enumeration.tools_error}"
    else:
        return None
    return UnverifiedItem(kind="entry", name=key, reason=reason)


def _name_list(names: list[str]) -> str:
    shown = ", ".join(repr(n) for n in names[:_MAX_NAMED_TOOLS])
    extra = len(names) - _MAX_NAMED_TOOLS
    return f"{shown} and {extra} more" if extra > 0 else shown


@dataclass
class _ToolDetails:
    """What saved tool text lets verify say about one server's changes."""

    #: ``{tool: change}`` for every changed tool the saved text can vouch for.
    changes: dict[str, tool_text_mod.ToolChange] = field(default_factory=dict)
    #: Current definitions of added tools (always known: they were just listed).
    added: dict[str, dict] = field(default_factory=dict)
    #: A note when the saved text could not be used for this server.
    note: str | None = None
    #: True when there is no saved text at all, so a hint is worth printing.
    hint: bool = False


_SAVE_HINT = (
    "No tool text is saved, so what changed is not shown; "
    "`mcp-audit lock --accept --connect --save-tool-text` would show it next time."
)


def _tool_details(
    key: str,
    locked_server: dict,
    tools: list,
    diff: tool_digests.ToolDiff,
    saved: dict | None,
) -> _ToolDetails:
    """Pair each change in *diff* with the saved text the lock vouches for."""
    details = _ToolDetails()
    current = {t.name: tool_digests.tool_definition(t) for t in tools}
    details.added = {n: current[n] for n in diff.added if n in current}
    changed = diff.contract_changed + diff.text_changed
    if saved is None or key not in saved.get("servers", {}):
        details.hint = bool(changed) and saved is None
        return details
    stale = tool_text_mod.out_of_step(saved, locked_server, key)
    if stale:
        details.note = (
            f"{tool_text_mod.TOOL_TEXT_FILENAME} is out of step with the lock for "
            f"{key!r} ({_name_list(stale)}); no diff shown. Re-run "
            "`mcp-audit lock --connect --save-tool-text` to refresh it."
        )
        return details
    for name in changed:
        before = tool_text_mod.trusted_definition(saved, locked_server, key, name)
        if before is not None and name in current:
            details.changes[name] = tool_text_mod.diff_tool(name, before, current[name])
    return details


def _evidence(head: str, lines: list[str], *, hint: bool = False) -> str:
    """Join the one-line summary with any per-tool detail lines."""
    out = [head, *lines]
    if hint:
        out.append(_SAVE_HINT)
    return "\n".join(out)


def _change_lines(names: list[str], details: _ToolDetails) -> list[str]:
    lines: list[str] = []
    for name in names[:_MAX_NAMED_TOOLS]:
        change = details.changes.get(name)
        if change is not None:
            lines.extend(tool_text_mod.describe(change))
    return lines


def _tool_findings(
    key: str,
    server: ServerConfig,
    diff: tool_digests.ToolDiff,
    details: _ToolDetails | None = None,
) -> list[Finding]:
    """Turn a :class:`~mcp_audit.lock.tool_digests.ToolDiff` into LOCK-006..009.

    One finding per kind of change per server, naming the tools, so a server
    that changed 124 tool descriptions produces one LOCK-008, not 124.
    """
    details = details or _ToolDetails()
    findings: list[Finding] = []
    accept = (
        "If approved, run `mcp-audit lock --accept --connect`; otherwise pin "
        "the server to the version you approved."
    )
    review = (
        "`mcp-audit scan --connect` runs the poisoning checks over the "
        "current tool text."
    )
    if diff.added:
        findings.append(
            Finding(
                id="LOCK-006",
                severity=Severity.HIGH,
                analyzer="lock",
                client=server.client,
                server=server.name,
                title=f"Tool added since lock: {server.name!r}",
                description=(
                    f"{key!r} now lists {len(diff.added)} tool(s) that were not "
                    "there when its tools were locked. A new tool is "
                    "capability the approval never covered."
                ),
                evidence=_evidence(
                    f"added: {_name_list(diff.added)}",
                    [
                        tool_text_mod.describe_added(n, d)
                        for n, d in details.added.items()
                    ][:_MAX_NAMED_TOOLS],
                ),
                remediation=f"Review the new tools; {review} {accept}",
                finding_path=str(server.config_path),
                owasp_mcp_top_10=["MCP02", "MCP04"],
            )
        )
    if diff.contract_changed:
        findings.append(
            Finding(
                id="LOCK-007",
                severity=Severity.HIGH,
                analyzer="lock",
                client=server.client,
                server=server.name,
                title=f"Tool contract changed since lock: {server.name!r}",
                description=(
                    f"{len(diff.contract_changed)} of {key!r}'s tools changed "
                    "their input schema, output schema, or annotations since "
                    "they were locked: what they accept, return, or declare "
                    "about themselves (for example read-only or destructive)."
                ),
                evidence=_evidence(
                    f"changed: {_name_list(diff.contract_changed)}",
                    _change_lines(diff.contract_changed, details),
                    hint=details.hint,
                ),
                remediation=f"Review the change; {review} {accept}",
                finding_path=str(server.config_path),
                owasp_mcp_top_10=["MCP03", "MCP04"],
            )
        )
    if diff.text_changed:
        findings.append(
            Finding(
                id="LOCK-008",
                severity=Severity.MEDIUM,
                analyzer="lock",
                client=server.client,
                server=server.name,
                title=f"Tool description changed since lock: {server.name!r}",
                description=(
                    f"{len(diff.text_changed)} of {key!r}'s tools changed only "
                    "their description or title; schemas and annotations are "
                    "unchanged. The description is what the model reads, and "
                    "it is where tool poisoning arrives, so this still needs "
                    "review."
                ),
                evidence=_evidence(
                    f"changed: {_name_list(diff.text_changed)}",
                    _change_lines(diff.text_changed, details),
                    hint=details.hint,
                ),
                remediation=f"Read the new descriptions; {review} {accept}",
                finding_path=str(server.config_path),
                owasp_mcp_top_10=["MCP03", "MCP04"],
            )
        )
    if diff.removed:
        findings.append(
            Finding(
                id="LOCK-009",
                severity=Severity.LOW,
                analyzer="lock",
                client=server.client,
                server=server.name,
                title=f"Tool removed since lock: {server.name!r}",
                description=(
                    f"{len(diff.removed)} tool(s) {key!r} listed when its tools "
                    "were locked are gone. Removing a tool does not fail "
                    "verification on its own."
                ),
                evidence=f"removed: {_name_list(diff.removed)}",
                remediation=(
                    "If the removal was expected, run "
                    "`mcp-audit lock --accept --connect`."
                ),
                finding_path=str(server.config_path),
                owasp_mcp_top_10=_OWASP,
            )
        )
    return findings


def _index_locked_entries(
    locked_servers: dict,
) -> dict[MatchKey, tuple[str, dict]]:
    """Index the lock's entries by their ``(config, name)`` match key (R61).

    Args:
        locked_servers: The lock's ``servers`` object.

    Returns:
        A mapping from match key to ``(entry_key, entry)``, where
        ``entry_key`` is the original ``<client>/<name>`` string — still the
        entry's id for every message and for the file's own shape. An entry
        missing either half of the pair keeps its key string as a fallback
        identity so a malformed lock degrades to the old behaviour for that
        one entry rather than silently dropping it.
    """
    indexed: dict[MatchKey, tuple[str, dict]] = {}
    for key, entry in locked_servers.items():
        config = entry.get("config")
        name = entry.get("name") or key.partition("/")[2]
        match: MatchKey = (
            (normalize_config_ref(config), name) if config else (key, name)
        )
        indexed[match] = (key, entry)
    return indexed


def _index_current_servers(
    servers: list[ServerConfig], root: Path
) -> tuple[dict[MatchKey, ServerConfig], list[str]]:
    """Index discovered *servers* by match key, separating out-of-scope ones.

    Args:
        servers: Currently discovered and parsed servers.
        root: The lock root.

    Returns:
        ``(by_match, outside_root)`` — the second element names the config
        files that are under neither *root* nor ``$HOME`` and so are not
        described by this lock at all. Those produce no LOCK finding in
        either direction; see :attr:`VerifyResult.outside_root`.
    """
    by_match: dict[MatchKey, ServerConfig] = {}
    outside: list[str] = []
    for server in servers:
        match = match_key(server.config_path, root, server.name)
        if match is None:
            path = str(server.config_path)
            if path not in outside:
                outside.append(path)
            continue
        by_match[match] = server
    return by_match, outside


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
            "Run `mcp-audit lock` to approve it (or `lock --accept` after review)."
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
        remediation=("If the removal was intended, run `mcp-audit lock --accept`."),
        finding_path=str(entry.get("config", "")),
        owasp_mcp_top_10=_OWASP,
    )


def _lock_013(key: str, server: ServerConfig) -> Finding:
    """LOW: the launch line carries a credential the lock keeps out (STORY-0118)."""
    return Finding(
        id="LOCK-013",
        severity=Severity.LOW,
        analyzer="lock",
        client=server.client,
        server=server.name,
        title=f"Launch arguments carry a credential: {server.name!r}",
        description=(
            f"{key!r} passes a credential on its command line. `mcp-audit lock` "
            "records the launch with that value replaced by [REDACTED], so it "
            "never reaches the committed lock file, and the lock cannot tell "
            "when only the credential's value changes."
        ),
        evidence="credential in command or arguments (value not shown)",
        remediation=(
            "Move the credential to an environment variable the server reads "
            "(`env` in the config, a `${VAR}` reference) so the launch line "
            "carries no secret."
        ),
        finding_path=str(server.config_path),
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
    # Both sides in redacted form (STORY-0118): an older lock holding a
    # credential verbatim still matches, and evidence never quotes one.
    current_identity = comparable_identity(current_identity)
    locked_identity = comparable_identity(locked_identity)
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


def _context_text(value: object) -> str:
    """Render one context value for a message: redacted and length-capped."""
    text = redact_text(repr(value))
    if len(text) > _MAX_CONTEXT_TEXT:
        text = text[:_MAX_CONTEXT_TEXT] + "…"
    return text


def _check_context(
    key: str, package: dict | None, fresh: dict | None, server: ServerConfig
) -> Finding | None:
    """Return LOCK-010 under ``--resolve`` when the resolution context changed.

    Compares the locked ``resolution.resolution_context`` (lock_version 2)
    with a fresh one: what ``latest`` pointed at, its deprecation notice,
    and the npm major / Node version of the resolver. Reported on its own,
    never folded into LOCK-004: the context explains why two locks differ;
    only resolved versions and integrity hashes can regenerate one. An entry
    without a recorded context (a version-1 entry, an exact pin, an
    unresolved entry) has nothing to compare and is skipped.
    """
    if not package:
        return None
    locked = (package.get("resolution") or {}).get("resolution_context")
    now = ((fresh or {}).get("resolution") or {}).get("resolution_context")
    if not isinstance(locked, dict) or not isinstance(now, dict):
        return None
    changed = [f for f in _CONTEXT_FIELDS if locked.get(f) != now.get(f)]
    if not changed:
        return None
    parts = [
        f"{field}: locked={_context_text(locked.get(field))} "
        f"now={_context_text(now.get(field))}"
        for field in changed
    ]
    return Finding(
        id="LOCK-010",
        severity=Severity.INFO,
        analyzer="lock",
        client=server.client,
        server=server.name,
        title=f"Resolution context changed: {server.name!r}",
        description=(
            f"What the registry said when {key!r} was resolved "
            f"({_context_text(locked.get('resolved_at'))}) differs from what it "
            "says now. The context explains why two locks differ; it cannot "
            "regenerate one. Any change to the resolved version or its hash "
            "is reported separately as LOCK-004."
        ),
        evidence="; ".join(parts),
        remediation=(
            "No action needed on its own. Re-lock with `mcp-audit lock "
            "--accept` to record the current context."
        ),
        finding_path=str(server.config_path),
        owasp_mcp_top_10=_OWASP,
    )


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


def _fence(text: str) -> str:
    """Wrap *text* in a code fence longer than any backtick run inside it."""
    longest = max((len(r) for r in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}\n{text}\n{ticks}"


def _code(text: str) -> str:
    """Inline code span for *text*, on one line, safe whatever it contains."""
    flat = " ".join(str(text).split())
    longest = max((len(r) for r in re.findall(r"`+", flat)), default=0)
    ticks = "`" * (longest + 1)
    return f"{ticks} {flat} {ticks}"


def _shown(text: str, limit: int | None = None) -> str:
    """Server-supplied text for a fence: credentials redacted, length capped."""
    clean = tool_text_mod.redact(text)
    cap = limit or tool_text_mod.MAX_COMMENT_TEXT
    return clean if len(clean) <= cap else clean[: cap - 1] + "…"


_COMMENT_LIMIT = 60_000


def render_pr_comment(result: VerifyResult) -> str:
    """Render *result* as GitHub-flavored Markdown for a pull-request comment.

    Tool changes with saved text show before and after; without it they show
    the finding's evidence. Everything a server or a config can influence (a
    server or tool name, a schema path, a description, a note) goes in a code
    fence or an inline code span longer than any backtick run it contains, so
    it cannot render as Markdown, mention anyone, or break out. Credentials in
    tool text are redacted and long text is capped; the comment as a whole
    stays under GitHub's limit.
    """
    if result.tampered or result.unsupported_version is not None:
        detail = (
            result.findings[0].evidence
            if result.tampered
            else f"lock_version {result.unsupported_version} is newer than this "
            "mcp-audit can verify; nothing was checked."
        )
        return f"## mcp-audit lock\n\n{_fence(_shown(detail))}\n"
    lines = ["## mcp-audit lock"]
    if not result.findings and not result.unverified:
        lines.append(f"\n{result.checked_servers} server(s) verified.")
        return "\n".join(lines) + "\n"
    for finding in result.findings:
        lines.append(f"\n### {finding.id} · {finding.severity.value}")
        lines.append(_fence(_shown(f"{finding.title}\n{finding.description}")))
        head = finding.evidence.split("\n", 1)[0]
        lines.append(_fence(_shown(head)))
    for key, changes in sorted(result.tool_diffs.items()):
        for change in changes:
            lines.append(f"\n#### {_code(key)} · tool {_code(change['tool'])}")
            for fc in change["fields"][: tool_text_mod.MAX_CHANGES_PER_TOOL]:
                lines.append(f"\n{_code(fc['path'])}")
                lines.append(_fence(_shown(f"- {fc['old']}\n+ {fc['new']}", 1000)))
            for text_field in change["words"]:
                before = (change["before"] or {}).get(text_field) or ""
                after = (change["after"] or {}).get(text_field) or ""
                lines.append(f"\n**{text_field}, before**\n{_fence(_shown(before))}")
                lines.append(f"**{text_field}, after**\n{_fence(_shown(after))}")
            if change["poison"]:
                lines.append("\nThe added text matches: " + ", ".join(change["poison"]))
    for item in result.unverified:
        lines.append(f"\n- not verified: {item.kind} {_code(item.name)}")
        lines.append(_fence(_shown(item.reason, 500)))
    for note in result.tool_text_notes:
        lines.append("\n" + _fence(_shown(note, 500)))
    out = "\n".join(lines) + "\n"
    if len(out) > _COMMENT_LIMIT:
        out = (
            out[:_COMMENT_LIMIT]
            + "\n\n(comment truncated; use --format json for the rest)\n"
        )
    return out
