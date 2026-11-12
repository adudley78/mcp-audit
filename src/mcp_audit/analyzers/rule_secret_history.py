"""Secrets in permission rules that git history still holds (CRED-005, STORY-0153).

CRED-004 reads ``.claude/settings.json`` and ``.claude/settings.local.json`` as
they are on disk.  A rule holding a secret that was committed and later deleted
is gone from the file but not from the repository: every clone carries the old
version.  Apiiro (Shmulik Cohen and Matan Giladi, via The Hacker News,
2026-11-07) found a secret in 1,122 of 104,185 public ``settings.local.json``
copies, 215 of which neither gitleaks nor TruffleHog flagged, so a general
history scanner is not a substitute for reading these rules the way CRED-004
does.

This module walks every commit reachable from the repository's refs and
``HEAD``, reads the two settings files at the root of each commit's tree, and
runs CRED-004's own detector (:func:`rule_secret_hits`) over every distinct
version.  A rule that holds a secret in history but not in today's file is
reported once per file as CRED-005 (HIGH: anyone with a clone has it), quoted
with the secret replaced by ``[REDACTED]``.  A rule still in today's file is
left to CRED-004.

It never runs git (the repository may be someone else's; running git in it is
the attack TRUST-006/007 describe).  :mod:`mcp_audit._gitobjects` reads git's
own files under the budgets below; a repository using SHA-256 object names, a
missing object (shallow or partial clone) or a budget that runs out is
reported in the scan's errors, never as a crash.  Only the settings files at a
commit's root are read: a nested project's ``.claude`` folder and other files
are not, and general secret scanning of history stays with tools built for it.
"""

from __future__ import annotations

import json
import os
import stat as stat_module
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit._gitobjects import (
    BudgetExceededError,
    GitObjectError,
    ObjectStore,
    ReadBudget,
    parse_commit,
    parse_tag_target,
    tree_entries,
)
from mcp_audit.analyzers.rule_secrets import (
    CWE,
    OWASP,
    RuleSecretHit,
    rule_secret_hits,
)
from mcp_audit.models import Finding, Severity

FINDING_ID = "CRED-005"
TITLE = "Secret in a permission rule in git history"

#: The settings files read, at the root of each commit's tree.
SETTINGS_NAMES = ("settings.json", "settings.local.json")
#: Commits walked per repository.
MAX_COMMITS = 50_000
#: Distinct settings-file versions read per repository.
MAX_VERSIONS = 5_000
#: Largest settings-file version read (the config parser's own cap).
MAX_SETTINGS_BYTES = 4 * 1024 * 1024
#: Bytes inflated per repository, across every object read.
INFLATE_BUDGET = 2 * 1024 * 1024 * 1024
#: Rules quoted per finding.
_LIST_CAP = 20
_QUOTE_CHARS = 160
_BLOB_MODES = (b"100644", b"100755")
_TREE_MODE = b"40000"


@dataclass
class _FileHistory:
    """What the walk found for one settings file name."""

    rules: dict[str, str] = field(default_factory=dict)  # redacted → location
    commits: set[str] = field(default_factory=set)


@dataclass
class HistoryScan:
    """Result of walking one repository's history."""

    files: dict[str, _FileHistory] = field(default_factory=dict)
    commits_read: int = 0
    versions_read: int = 0
    errors: list[str] = field(default_factory=list)


def _label(worktree: Path) -> str:
    return worktree.name or "repository"


def _object_format(common_dir: Path) -> str:
    """``extensions.objectFormat`` from the repository config (``sha1`` if unset)."""
    from mcp_audit.analyzers.git_exec import parse_git_config  # noqa: PLC0415

    path = common_dir / "config"
    try:
        st = os.stat(path, follow_symlinks=False)
        if not stat_module.S_ISREG(st.st_mode) or st.st_size > 1024 * 1024:
            return "sha1"
        text = path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return "sha1"
    value = "sha1"
    for entry in parse_git_config(text, path).entries:
        if entry.var == "extensions.objectformat" and entry.value:
            value = entry.value.strip().lower()
    return value


def _settings_blobs(store: ObjectStore, tree_id: str) -> dict[str, str]:
    """``{settings file name: blob id}`` under ``.claude/`` in a root tree."""
    found = store.read(tree_id)
    if found is None or found[0] != "tree":
        return {}
    claude = next(
        (
            oid
            for mode, name, oid in tree_entries(found[1])
            if name == b".claude" and mode == _TREE_MODE
        ),
        None,
    )
    if claude is None:
        return {}
    sub = store.read(claude)
    if sub is None or sub[0] != "tree":
        return {}
    wanted = {name.encode(): name for name in SETTINGS_NAMES}
    return {
        wanted[name]: oid
        for mode, name, oid in tree_entries(sub[1])
        if name in wanted and mode in _BLOB_MODES
    }


def _hits_of(store: ObjectStore, blob_id: str) -> list[RuleSecretHit]:
    found = store.read(blob_id)
    if found is None or found[0] != "blob" or len(found[1]) > MAX_SETTINGS_BYTES:
        return []
    try:
        raw = json.loads(found[1].decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return []
    return rule_secret_hits(raw).hits


def walk_history(store: ObjectStore, label: str) -> HistoryScan:
    """Read every reachable version of the two settings files.

    Args:
        store: The repository's object store.
        label: Repository name for error text (never an absolute path).
    """
    scan = HistoryScan()
    queue: deque[str] = deque()
    seen: set[str] = set()
    for tip in store.ref_tips():
        target: str | None = tip
        for _ in range(10):  # annotated tags may point at tags
            if target is None:
                break
            found = store.read(target)
            if found is None or found[0] != "tag":
                break
            target = parse_tag_target(found[1])
        if target is not None and target not in seen:
            seen.add(target)
            queue.append(target)
    blob_hits: dict[str, list[RuleSecretHit]] = {}
    tree_cache: dict[str, dict[str, str]] = {}
    while queue:
        if scan.commits_read >= MAX_COMMITS:
            scan.errors.append(
                f"git history of '{label}': only the first {MAX_COMMITS} commits"
                " were read for CRED-005"
            )
            break
        commit_id = queue.popleft()
        found = store.read(commit_id)
        if found is None or found[0] != "commit":
            continue
        scan.commits_read += 1
        tree_id, parents = parse_commit(found[1])
        for parent in parents:
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)
        blobs = tree_cache.get(tree_id)
        if blobs is None:
            blobs = _settings_blobs(store, tree_id)
            tree_cache[tree_id] = blobs
        for name, blob_id in blobs.items():
            hits = blob_hits.get(blob_id)
            if hits is None:
                if scan.versions_read >= MAX_VERSIONS:
                    continue
                scan.versions_read += 1
                hits = _hits_of(store, blob_id)
                blob_hits[blob_id] = hits
            if not hits:
                continue
            history = scan.files.setdefault(name, _FileHistory())
            history.commits.add(commit_id)
            for hit in hits:
                history.rules.setdefault(hit.redacted, hit.location)
    if scan.versions_read >= MAX_VERSIONS:
        scan.errors.append(
            f"git history of '{label}': only the first {MAX_VERSIONS} versions of"
            " the settings files were read for CRED-005"
        )
    return scan


def _current_rules(worktree: Path, name: str) -> set[str]:
    """Redacted secret-holding rules in today's file (CRED-004 reports these)."""
    path = worktree / ".claude" / name
    try:
        st = os.stat(path, follow_symlinks=False)
        if not stat_module.S_ISREG(st.st_mode) or st.st_size > MAX_SETTINGS_BYTES:
            return set()
        raw = json.loads(path.read_bytes().decode("utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError):
        return set()
    return {hit.redacted for hit in rule_secret_hits(raw).hits}


def _quote(text: str) -> str:
    if len(text) > _QUOTE_CHARS:
        text = text[:_QUOTE_CHARS] + "…"
    return repr(text)


def _finding(
    worktree: Path, name: str, rules: list[tuple[str, str]], commits: set[str]
) -> Finding:
    path = worktree / ".claude" / name
    ordered = sorted(commits)
    quoted = [f"{location}: {_quote(rule)}" for rule, location in rules[:_LIST_CAP]]
    if len(rules) > _LIST_CAP:
        quoted.append(f"(+{len(rules) - _LIST_CAP} more)")
    return Finding(
        id=FINDING_ID,
        severity=Severity.HIGH,
        analyzer="sandbox",
        client="claude-code",
        server="(config-level)",
        title=TITLE,
        description=(
            f"Git history holds {len(rules)} permission rule(s) in"
            f" '.claude/{name}' that contain a credential (a token, key, password"
            f" or connection string) and are not in the file today. They are in"
            f" {len(ordered)} commit(s), so anyone with a clone of '{_label(worktree)}'"
            " can read them: deleting a rule, or the file, does not remove it from"
            " history. Claude Code saves a rule when you choose \"Yes, and don't"
            ' ask again", and the rule is the approved command word for word.'
            " Apiiro (Shmulik Cohen and Matan Giladi, via The Hacker News,"
            " 2026-11-07) found a secret in 1,122 of 104,185 public"
            " settings.local.json copies, 215 of which neither gitleaks nor"
            " TruffleHog flagged."
        ),
        evidence=(
            f"{path} in commit {ordered[0][:12]}"
            + (f" and {len(ordered) - 1} other(s)" if len(ordered) > 1 else "")
            + ": "
            + "; ".join(quoted)
        ),
        remediation=(
            "Rotate each credential now: a pushed commit has been copied by every"
            " clone and fork, and rewriting history does not reach those copies."
            " Then, if the repository is private and every copy is under your"
            " control, you can remove the file from history (git filter-repo"
            " --invert-paths --path .claude/settings.local.json) and force-push."
            " Keep .claude/settings.local.json in .gitignore, and approve commands"
            " with secrets read from environment variables."
        ),
        cwe=CWE,
        owasp_mcp_top_10=list(OWASP),
        finding_path=str(path),
    )


def history_rule_secret_findings(
    worktree: Path, git_dir: Path, common_dir: Path, errors: list[str]
) -> list[Finding]:
    """CRED-005 for one repository; never raises.

    Args:
        worktree: The repository's working tree (where ``.claude/`` lives).
        git_dir: Its git directory.
        common_dir: Where its objects and refs live.
        errors: The scan's error list; problems are appended (no absolute paths).
    """
    label = _label(worktree)
    try:
        object_format = _object_format(common_dir)
        if object_format != "sha1":
            errors.append(
                f"git history of '{label}' was not read for CRED-005: it uses"
                f" {object_format} object names"
            )
            return []
        store = ObjectStore(git_dir, common_dir, ReadBudget(limit=INFLATE_BUDGET))
        with store:
            try:
                scan = walk_history(store, label)
            except BudgetExceededError:
                errors.append(
                    f"git history of '{label}' was only partly read for CRED-005:"
                    " the read budget ran out"
                )
                return []
            errors.extend(scan.errors)
            errors.extend(f"git history of '{label}': {e}" for e in store.errors)
            if (common_dir / "shallow").exists():
                errors.append(
                    f"'{label}' is a shallow clone, so CRED-005 read only the git"
                    " history it has (fetch the full history, e.g. fetch-depth: 0,"
                    " to check all of it)"
                )
            elif store.missing:
                errors.append(
                    f"git history of '{label}': {store.missing} object(s) are not in"
                    " this clone (a partial clone or an alternate object store), so"
                    " that history was not read for CRED-005"
                )
    except GitObjectError as exc:
        errors.append(f"git history of '{label}' was not read for CRED-005: {exc}")
        return []
    except Exception as exc:  # noqa: BLE001 — reported, never fatal
        errors.append(
            f"git history check error for '{label}': {type(exc).__name__}: {exc}"
        )
        return []
    findings: list[Finding] = []
    for name in SETTINGS_NAMES:
        history = scan.files.get(name)
        if history is None:
            continue
        current = _current_rules(worktree, name)
        rules = sorted(
            (rule, location)
            for rule, location in history.rules.items()
            if rule not in current
        )
        if rules:
            findings.append(_finding(worktree, name, rules, history.commits))
    return findings


def find_repository(start: Path) -> tuple[Path, Path, Path] | None:
    """``(worktree, git_dir, common_dir)`` of the repository git would use.

    Searches upward from *start* as git does (and as
    :func:`mcp_audit.analyzers.git_exec.scan_cwd_repository` does): a valid
    ``.git`` directory or ``gitdir:`` file wins, an invalid ``.git`` directory
    is skipped, a malformed ``.git`` file stops the search.  A bare repository
    has no working tree and gives ``None``.
    """
    from mcp_audit.analyzers.git_exec import (  # noqa: PLC0415
        _common_dir,
        _resolve_dot_git,
    )

    try:
        current = start.resolve()
    except OSError:
        return None
    for candidate in (current, *current.parents):
        dot_git = candidate / ".git"
        try:
            if not os.path.lexists(dot_git):
                continue
            resolved = _resolve_dot_git(dot_git)
            if resolved is not None:
                git_dir, worktree = resolved
                return worktree, git_dir, _common_dir(git_dir)
            if not dot_git.is_dir():
                return None
        except OSError:
            return None
    return None


def scan_repository_history(start: Path, errors: list[str]) -> list[Finding]:
    """CRED-005 for the repository containing *start*; ``[]`` outside one."""
    found = find_repository(start)
    if found is None:
        return []
    worktree, git_dir, common_dir = found
    return history_rule_secret_findings(worktree, git_dir, common_dir, errors)
