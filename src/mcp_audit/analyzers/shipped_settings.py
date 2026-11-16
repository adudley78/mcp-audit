"""Claude Code settings files an image or npm package ships (CRED-006, STORY-0157).

CRED-004, CRED-005 and SANDBOX-005 ask whether a ``.claude/settings.json`` or
``.claude/settings.local.json`` reaches git.  Git is not the only way out of a
working copy.  Docker does not read ``.gitignore``: ``COPY . .`` copies the
working tree, so a git-ignored ``.claude/settings.local.json`` goes into the
image unless ``.dockerignore`` excludes it.  GitGuardian (Guillaume Valadon,
2026-11-09) found 613 distinct secrets from Claude Code settings files in
public Docker Hub images (99 valid at detection; one valid Cloudflare token in
559 tags of one image).  npm has the same gap: when a package has a
``.npmignore``, npm does not read ``.gitignore``, and npm never reads git's
global excludes file or ``.git/info/exclude`` (where Claude Code writes
``**/.claude/settings.local.json``).  Reported by Tich Kadandara (2026-11-15).

What is reported, one finding per Dockerfile (with its build context) or
``package.json``:

* **HIGH** when a shipped settings file holds a credential in a permission
  rule (CRED-004's detector, :func:`mcp_audit.analyzers.rule_secrets.rule_secret_hits`).
* **LOW** when a shipped ``settings.local.json`` holds no secret this check
  recognises: it still ships the user's own approvals and home paths.
* A shared ``settings.json`` with no recognised secret is not reported: it is
  committed with the repository anyway.

Container builds.  Every ``Dockerfile``, ``Containerfile``, ``*.Dockerfile``,
``*.Containerfile``, ``Dockerfile.*`` and ``Containerfile.*`` under the root
(the project walk's skip list, depth cap and symlink rule) is read with its own
directory as the build context, unless a Compose file's ``build`` names it,
in which case that context (and ``target``) is used.  The ignore file is
``<Dockerfile name>.dockerignore`` next to the Dockerfile when it exists
(BuildKit), else ``.dockerignore`` at the context root, matched with Docker's
rules: every pattern is anchored at the context root, a pattern that matches a
parent directory matches the file, ``!`` re-includes, the last match wins, and
``COPY --exclude`` patterns are applied too.  Only stages that end up in the
image count: the final stage (or the Compose ``target``), the stages it is
built ``FROM``, and files a final-chain ``COPY --from=<stage>`` takes from a
stage that copied the context (traced by image path through ``WORKDIR``).

npm packages.  Every ``package.json`` with a ``name`` that is not
``"private": true``.  With a ``files`` list, a settings file ships when an
entry includes it.  Without one, npm reads ``.npmignore`` in each folder, or
``.gitignore`` where a folder has no ``.npmignore``.

Read-only: never runs ``docker``, ``npm`` or ``git``, uses no network, and
never raises (problems go to ``errors`` with the ``CRED-006:`` prefix).
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit._gitignore import (
    _GLOBSTAR,
    IgnoreSource,
    MatchBudgetExceededError,
    MatchMeter,
    _match_segments,
    _parse_segments,
    _Segment,
    _tokenize,
    is_ignored,
    parse_ignore_text,
)
from mcp_audit.analyzers.rule_secrets import RuleSecretHit, rule_secret_hits
from mcp_audit.models import Finding, Severity

FINDING_ID = "CRED-006"
TITLE = "Claude Code settings file copied into a container image or npm package"
CWE = "CWE-538"
OWASP = ("MCP01",)
ERROR_PREFIX = "CRED-006: "

SETTINGS_NAMES = ("settings.json", "settings.local.json")
#: Directory names the walk does not enter (same list as ``scan --project``).
SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".tox",
        "venv",
        ".venv",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".claude",
    }
)
MAX_DEPTH = 8
#: Directories one walk visits before it stops and says so.
MAX_DIRS = 20_000
#: Largest Dockerfile, Compose, package.json or ignore file read.
MAX_FILE_BYTES = 1024 * 1024
#: Largest settings file read for secrets.
MAX_SETTINGS_BYTES = 4 * 1024 * 1024
#: Dockerfiles and package.json files examined per walk.
MAX_BUILD_FILES = 500
_LIST_CAP = 10
_QUOTE_CHARS = 120

_COMPOSE_NAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
)
_DOCKERFILE_RE = re.compile(
    r"\A(?:(?:docker|container)file(?:\.[^/]+)?|[^/]+\.(?:docker|container)file)\Z",
    re.IGNORECASE,
)
_HEREDOC_RE = re.compile(r"<<(-?)([\"']?)([A-Za-z_][A-Za-z0-9_]*)\2")
_DIRECTIVE_RE = re.compile(r"\A#\s*([A-Za-z]+)\s*=\s*(\S+)\s*\Z")


# ── Settings files ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SettingsFile:
    """A Claude Code settings file found under the root.

    Attributes:
        path: Absolute path.
        rel: Path parts relative to the walk root.
        local: ``True`` for ``settings.local.json``.
        hits: Permission rules holding a credential (CRED-004's detector).
    """

    path: Path
    rel: tuple[str, ...]
    local: bool
    hits: tuple[RuleSecretHit, ...] = ()

    @property
    def reportable(self) -> bool:
        """Shipping it matters: it holds a secret, or it is the user's own file."""
        return bool(self.hits) or self.local


def _read_text(path: Path, limit: int, errors: list[str], label: str) -> str | None:
    """Read a regular, non-symlink file of at most *limit* bytes; else ``None``."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > limit:
            errors.append(
                f"{ERROR_PREFIX}'{label}' is larger than {limit} bytes and was not read"
            )
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(
            f"{ERROR_PREFIX}'{label}' could not be read: {type(exc).__name__}"
        )
        return None


def _load_settings(path: Path, rel: tuple[str, ...], errors: list[str]) -> SettingsFile:
    text = _read_text(path, MAX_SETTINGS_BYTES, errors, "/".join(rel))
    hits: tuple[RuleSecretHit, ...] = ()
    if text is not None:
        try:
            hits = tuple(rule_secret_hits(json.loads(text)).hits)
        except ValueError:
            hits = ()
    return SettingsFile(path, rel, path.name == "settings.local.json", hits)


# ── Walk ──────────────────────────────────────────────────────────────────────


@dataclass
class _Tree:
    root: Path
    settings: list[SettingsFile] = field(default_factory=list)
    dockerfiles: list[Path] = field(default_factory=list)
    composes: list[Path] = field(default_factory=list)
    packages: list[Path] = field(default_factory=list)


def _is_regular(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_file()
    except OSError:
        return False


def _walk(root: Path, errors: list[str]) -> _Tree:
    tree = _Tree(root)
    visited = 0
    stack: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while stack:
        dirpath, rel = stack.pop()
        visited += 1
        if visited > MAX_DIRS:
            errors.append(
                f"{ERROR_PREFIX}stopped after {MAX_DIRS} folders; build files and"
                " settings files further down were not checked"
            )
            break
        claude = dirpath / ".claude"
        try:
            claude_ok = not claude.is_symlink() and claude.is_dir()
        except OSError:
            claude_ok = False
        if claude_ok:
            for name in SETTINGS_NAMES:
                candidate = claude / name
                if _is_regular(candidate):
                    tree.settings.append(
                        _load_settings(candidate, (*rel, ".claude", name), errors)
                    )
        try:
            children = sorted(dirpath.iterdir())
        except OSError:
            continue
        subdirs: list[tuple[Path, tuple[str, ...]]] = []
        for child in children:
            name = child.name
            try:
                if child.is_symlink():
                    continue
                if child.is_dir():
                    if name not in SKIP_DIRS and len(rel) < MAX_DEPTH:
                        subdirs.append((child, (*rel, name)))
                    continue
                if not child.is_file():
                    continue
            except OSError:
                continue
            lower = name.lower()
            if lower.endswith(".dockerignore"):
                continue
            if _DOCKERFILE_RE.match(name):
                tree.dockerfiles.append(child)
            elif lower in _COMPOSE_NAMES:
                tree.composes.append(child)
            elif name == "package.json":
                tree.packages.append(child)
        stack.extend(reversed(subdirs))
    return tree


# ── Docker ignore rules ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class DockerPattern:
    """One ``.dockerignore`` line (or ``COPY --exclude`` value), parsed.

    Attributes:
        text: The pattern as written.
        negated: The line started with ``!``.
        segments: One token tuple per path segment, a globstar marker for a
            whole ``**`` segment.
    """

    text: str
    negated: bool
    segments: tuple[_Segment, ...]


def _docker_segments(body: str) -> tuple[_Segment, ...] | None:
    """Segments of a cleaned Docker pattern; ``None`` when it matches nothing."""
    segments: list[_Segment] = []
    for raw in body.split("/"):
        if not raw:
            return None
        if len(raw) >= 2 and set(raw) == {"*"}:
            if not (segments and segments[-1] is _GLOBSTAR):
                segments.append(_GLOBSTAR)
            continue
        tokens = _tokenize(raw)
        if tokens is None:
            return None
        segments.append(tokens)
    return tuple(segments) or None


def _clean_pattern(pattern: str) -> str:
    """Docker's preprocessing: ``filepath.Clean``, then drop one leading ``/``."""
    cleaned = posixpath.normpath(pattern)
    if len(cleaned) > 1 and cleaned.startswith("/"):
        cleaned = cleaned.lstrip("/")
    return cleaned


def parse_docker_pattern(line: str) -> DockerPattern | None:
    """Parse one Docker ignore pattern, or ``None`` for a blank or no-op line."""
    pattern = line.strip()
    if not pattern:
        return None
    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:].strip()
    if not pattern:
        return None
    cleaned = _clean_pattern(pattern)
    if cleaned in (".", "/") or cleaned.startswith("../"):
        return None
    segments = _docker_segments(cleaned)
    if segments is None:
        return None
    return DockerPattern(("!" if negated else "") + cleaned, negated, segments)


def parse_dockerignore(text: str) -> list[DockerPattern]:
    """Parse a ``.dockerignore`` file with Docker's (BuildKit's) rules.

    A line whose first character is ``#`` is a comment; other lines are
    trimmed, ``!`` marks an exception, and each pattern is cleaned as Go's
    ``filepath.Clean`` would (so ``.claude/`` and ``./.claude`` are
    ``.claude``) with one leading ``/`` removed.
    """
    if text.startswith("﻿"):
        text = text[1:]
    patterns: list[DockerPattern] = []
    for raw in text.splitlines():
        if raw.startswith("#"):
            continue
        parsed = parse_docker_pattern(raw)
        if parsed is not None:
            patterns.append(parsed)
    return patterns


def _matches_or_parent(
    segments: tuple[_Segment, ...], parts: Sequence[str], meter: MatchMeter
) -> bool:
    """True when *segments* match *parts* or one of its parent directories."""
    return any(
        _match_segments(segments, parts[:k], meter) for k in range(len(parts), 0, -1)
    )


def docker_excluded(
    parts: Sequence[str], patterns: Sequence[DockerPattern], meter: MatchMeter
) -> DockerPattern | None:
    """The pattern that excludes *parts* (context-relative), or ``None``.

    Docker checks every pattern in order against the path and each parent
    directory; the last pattern that matches decides, and an exception
    (``!``) re-includes even inside an excluded directory.
    """
    decided: DockerPattern | None = None
    for pattern in patterns:
        if _matches_or_parent(pattern.segments, parts, meter):
            decided = None if pattern.negated else pattern
    return decided


# ── Dockerfile parsing ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Instruction:
    """One Dockerfile instruction: its first line, keyword and argument text."""

    line: int
    keyword: str
    rest: str


def parse_dockerfile(text: str) -> list[Instruction]:
    """Split a Dockerfile into instructions.

    Handles the ``# escape=`` parser directive, line continuations, comment
    lines inside a continued instruction, and heredoc bodies (skipped).
    """
    lines = text.splitlines()
    escape = "\\"
    index = 0
    # Parser directives come before anything else.
    while index < len(lines):
        match = _DIRECTIVE_RE.match(lines[index].strip())
        if not match:
            break
        if match.group(1).lower() == "escape" and match.group(2) in ("\\", "`"):
            escape = match.group(2)
        index += 1
    instructions: list[Instruction] = []
    while index < len(lines):
        start = index
        raw = lines[index]
        index += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = [stripped]
        while parts[-1].endswith(escape) and index < len(lines):
            parts[-1] = parts[-1][: -len(escape)]
            nxt = lines[index].strip()
            index += 1
            while (not nxt or nxt.startswith("#")) and index < len(lines):
                nxt = lines[index].strip()
                index += 1
            parts.append(nxt)
        if parts[-1].endswith(escape):
            parts[-1] = parts[-1][: -len(escape)]
        logical = " ".join(p for p in parts if p)
        keyword, _, rest = logical.partition(" ")
        # Heredocs: skip each body up to its terminator.
        for heredoc in _HEREDOC_RE.finditer(rest):
            marker = heredoc.group(3)
            while index < len(lines):
                body = lines[index]
                index += 1
                if (body.lstrip("\t") if heredoc.group(1) else body) == marker:
                    break
        instructions.append(Instruction(start + 1, keyword.upper(), rest.strip()))
    return instructions


@dataclass
class CopyStep:
    """A ``COPY`` or ``ADD`` in one stage."""

    line: int
    text: str
    sources: list[str]
    dest: str | None  # absolute image path; ``None`` when unknown
    dest_is_dir: bool
    from_ref: str | None
    excludes: list[DockerPattern]


@dataclass
class Stage:
    """One ``FROM`` block."""

    index: int
    name: str | None
    base: str
    parent: int | None = None
    workdir: str | None = "/"
    copies: list[CopyStep] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.name or str(self.index)


def _copy_args(rest: str) -> list[str]:
    stripped = rest.strip()
    if stripped.startswith("["):
        try:
            value = json.loads(stripped)
        except ValueError:
            value = None
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return list(value)
    return stripped.split()


def _resolve(base: str | None, path: str) -> str | None:
    """*path* as an absolute image path, or ``None`` when it can't be known."""
    if not path or "$" in path:
        return None
    if path.startswith("/"):
        return posixpath.normpath(path) if path != "/" else "/"
    if base is None:
        return None
    return posixpath.normpath(posixpath.join(base, path))


def build_stages(instructions: Sequence[Instruction]) -> list[Stage]:
    """Stages with their context and ``--from`` copies and ``WORKDIR`` state."""
    stages: list[Stage] = []
    by_name: dict[str, int] = {}
    for instr in instructions:
        if instr.keyword == "FROM":
            words = [w for w in instr.rest.split() if not w.startswith("--")]
            base = words[0] if words else ""
            name = (
                words[2].lower()
                if len(words) >= 3 and words[1].lower() == "as"
                else None
            )
            stage = Stage(len(stages), name, base)
            parent = by_name.get(base.lower())
            if parent is not None:
                stage.parent = parent
                stage.workdir = stages[parent].workdir
            stages.append(stage)
            if name:
                by_name[name] = stage.index
            continue
        if not stages:
            continue
        stage = stages[-1]
        if instr.keyword == "WORKDIR":
            target = instr.rest.strip().strip("'\"")
            stage.workdir = _resolve(stage.workdir, target)
            continue
        if instr.keyword not in ("COPY", "ADD"):
            continue
        args = _copy_args(instr.rest)
        from_ref: str | None = None
        excludes: list[DockerPattern] = []
        positional: list[str] = []
        for arg in args:
            if not positional and arg.startswith("--"):
                flag, _, value = arg.partition("=")
                if flag == "--from":
                    from_ref = value.lower()
                elif flag == "--exclude":
                    parsed = parse_docker_pattern(value)
                    if parsed is not None:
                        excludes.append(parsed)
                continue
            positional.append(arg)
        if len(positional) < 2:
            continue
        sources, dest = positional[:-1], positional[-1]
        dest_is_dir = (
            dest.endswith("/")
            or len(sources) > 1
            or any(ch in src for src in sources for ch in "*?[")
        )
        stage.copies.append(
            CopyStep(
                line=instr.line,
                text=f"{instr.keyword} {instr.rest}"[:160],
                sources=sources,
                dest=_resolve(stage.workdir, dest),
                dest_is_dir=dest_is_dir,
                from_ref=from_ref,
                excludes=excludes,
            )
        )
    return stages


# ── What the image holds ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class Landing:
    """Where a settings file ends up in a stage, and the steps that put it there."""

    path: str | None
    steps: tuple[str, ...]


def _source_segments(src: str) -> tuple[_Segment, ...] | None:
    cleaned = _clean_pattern(src)
    if cleaned in (".", "/", ""):
        return ()
    if cleaned.startswith("../") or cleaned == "..":
        return None
    return _docker_segments(cleaned)


def _anchor(
    segments: tuple[_Segment, ...], parts: tuple[str, ...], meter: MatchMeter
) -> tuple[str, ...] | None:
    """The shallowest of *parts* and its parents that *segments* match."""
    if not segments:
        return ()
    for k in range(1, len(parts) + 1):
        if _match_segments(segments, parts[:k], meter):
            return parts[:k]
    return None


def _landing_path(
    step: CopyStep, parts: tuple[str, ...], anchor: tuple[str, ...]
) -> str | None:
    if step.dest is None:
        return None
    if anchor == parts:  # the file itself was named
        if step.dest_is_dir:
            return posixpath.join(step.dest, parts[-1])
        return step.dest
    return posixpath.join(step.dest, *parts[len(anchor) :])


def _excluded_by_flag(
    step: CopyStep, parts: tuple[str, ...], anchor: tuple[str, ...], meter: MatchMeter
) -> bool:
    if not step.excludes:
        return False
    below = parts[len(anchor) :] if anchor != parts else parts[-1:]
    return any(
        _matches_or_parent(p.segments, parts, meter)
        or (below and _matches_or_parent(p.segments, below, meter))
        for p in step.excludes
    )


@dataclass
class _ImageModel:
    stages: list[Stage]
    ignore: list[DockerPattern]
    files: list[tuple[str, ...]]  # context-relative settings files
    meter: MatchMeter
    memo: dict[int, dict[tuple[str, ...], list[Landing]]] = field(default_factory=dict)

    def _stage_for(self, ref: str, before: int) -> int | None:
        for stage in self.stages[:before]:
            if stage.name == ref:
                return stage.index
        if ref.isdigit() and int(ref) < before:
            return int(ref)
        return None

    def landings(self, index: int) -> dict[tuple[str, ...], list[Landing]]:
        if index in self.memo:
            return self.memo[index]
        self.memo[index] = {}  # guards a malformed cycle
        stage = self.stages[index]
        out: dict[tuple[str, ...], list[Landing]] = {}
        if stage.parent is not None:
            for key, value in self.landings(stage.parent).items():
                out.setdefault(key, []).extend(value)
        for step in stage.copies:
            if step.from_ref is None:
                self._from_context(step, out)
            else:
                source = self._stage_for(step.from_ref, index)
                if source is not None:
                    self._from_stage(step, self.stages[source], out)
        self.memo[index] = out
        return out

    def _from_context(
        self, step: CopyStep, out: dict[tuple[str, ...], list[Landing]]
    ) -> None:
        for parts in self.files:
            if docker_excluded(parts, self.ignore, self.meter) is not None:
                continue
            for src in step.sources:
                if "$" in src or "://" in src or src.startswith("git@"):
                    continue
                segments = _source_segments(src)
                if segments is None:
                    continue
                anchor = _anchor(segments, parts, self.meter)
                if anchor is None or _excluded_by_flag(step, parts, anchor, self.meter):
                    continue
                out.setdefault(parts, []).append(
                    Landing(
                        _landing_path(step, parts, anchor),
                        (f"line {step.line}: {step.text}",),
                    )
                )
                break

    def _from_stage(
        self,
        step: CopyStep,
        source: Stage,
        out: dict[tuple[str, ...], list[Landing]],
    ) -> None:
        for parts, landings in self.landings(source.index).items():
            for landing in landings:
                if landing.path is None:
                    continue
                image_parts = tuple(p for p in landing.path.split("/") if p)
                for src in step.sources:
                    if "$" in src:
                        continue
                    candidates = [src] if src.startswith("/") else ["/" + src]
                    if not src.startswith("/") and source.workdir:
                        candidates.append(posixpath.join(source.workdir, src))
                    anchor = None
                    for candidate in candidates:
                        segments = _source_segments(candidate)
                        if segments is None:
                            continue
                        anchor = _anchor(segments, image_parts, self.meter)
                        if anchor is not None:
                            break
                    if anchor is None:
                        continue
                    out.setdefault(parts, []).append(
                        Landing(
                            _landing_path(step, image_parts, anchor),
                            (
                                *landing.steps,
                                f"line {step.line}: {step.text}"
                                f" (from stage {source.label})",
                            ),
                        )
                    )
                    break


# ── Findings ──────────────────────────────────────────────────────────────────


def _quote(text: str) -> str:
    if len(text) > _QUOTE_CHARS:
        text = text[:_QUOTE_CHARS] + "…"
    return repr(text)


def _describe_file(settings: SettingsFile, rel: str) -> str:
    if not settings.hits:
        return f"{rel} (no secret recognised; it holds your own approvals)"
    quoted = "; ".join(
        f"{hit.location}: {_quote(hit.redacted)}" for hit in settings.hits[:3]
    )
    more = f" (+{len(settings.hits) - 3} more)" if len(settings.hits) > 3 else ""
    return f"{rel} ({len(settings.hits)} rule(s) with a credential: {quoted}{more})"


_GG_LINE = (
    " GitGuardian (Guillaume Valadon, 2026-11-09) found 613 distinct secrets from"
    " Claude Code settings files in public Docker Hub images, 99 still valid; one"
    " valid Cloudflare token was in 559 tags of one image."
)


def _finding(
    *,
    vehicle: Path,
    kind: str,
    shipped: list[tuple[SettingsFile, str, str]],
    how: str,
    remediation: str,
) -> Finding:
    secret = any(s.hits for s, _, _ in shipped)
    severity = Severity.HIGH if secret else Severity.LOW
    names = ", ".join(rel for _, rel, _ in shipped[:_LIST_CAP])
    if len(shipped) > _LIST_CAP:
        names += f" (+{len(shipped) - _LIST_CAP} more)"
    target = "container image" if kind == "docker" else "npm package"
    article = "a" if kind == "docker" else "an"
    them = "them" if len(shipped) > 1 else "it"
    reader = "pull the image" if kind == "docker" else "install the package"
    lead = (
        f"{'One or more of them hold' if len(shipped) > 1 else 'It holds'} a"
        f" credential in a permission rule, so anyone who can {reader} can read it."
        if secret
        else f"No secret this check recognises is in {them}, but"
        f" {'they hold' if len(shipped) > 1 else 'it holds'} your own"
        ' "don\'t ask again" approvals and can hold home-directory paths.'
    )
    evidence = "; ".join(
        f"{_describe_file(s, rel)} via {via}" for s, rel, via in shipped[:_LIST_CAP]
    )
    return Finding(
        id=FINDING_ID,
        severity=severity,
        analyzer="sandbox",
        client="claude-code",
        server="(config-level)",
        title=TITLE,
        description=(
            f"'{vehicle.parent.name}/{vehicle.name}' builds {article} {target} that"
            f" includes {names}. {how.format(them=them)} {lead} Claude Code saves a"
            " rule when you"
            ' choose "Yes, and don\'t ask again", and the rule is the approved'
            " command word for word, secret included. Deleting the file from the"
            f" repository later does not change {article} {target} already published."
            + (_GG_LINE if kind == "docker" else "")
        ),
        evidence=f"{vehicle}: {evidence}",
        remediation=remediation,
        cwe=CWE,
        owasp_mcp_top_10=list(OWASP),
        finding_path=str(vehicle),
    )


_DOCKER_FIX = (
    "Rotate each credential first: every image built from this folder has a"
    " copy. Add the line **/.claude/ to {ignore} (a pattern .claude matches only"
    " the folder at the context root, not a nested one). Then rebuild and push"
    " every tag, and delete or overwrite the old tags: a later RUN rm, or"
    " deleting the file from the repository, does not remove it from layers"
    " already pushed."
)
_NPM_FIX = (
    "Rotate each credential first: every published version that carried the"
    " file has a copy. Add .claude/ to .npmignore, or list only your build output"
    ' in the package.json "files" field, and run npm pack --dry-run to check the'
    " file list. Then publish a new version and deprecate the versions that"
    " carried the file."
)


def _rel_label(parts: Sequence[str]) -> str:
    return "/".join(parts)


def _docker_findings(
    tree: _Tree,
    dockerfile: Path,
    context: Path,
    target: str | None,
    errors: list[str],
    meter: MatchMeter,
) -> list[Finding]:
    try:
        context_rel = context.relative_to(tree.root).parts
    except ValueError:
        return []
    files = {
        s.rel[len(context_rel) :]: s
        for s in tree.settings
        if s.reportable and s.rel[: len(context_rel)] == context_rel
    }
    if not files:
        return []
    root_label = _rel_label(dockerfile.relative_to(tree.root).parts)
    text = _read_text(dockerfile, MAX_FILE_BYTES, errors, root_label)
    if text is None:
        return []
    stages = build_stages(parse_dockerfile(text))
    if not stages:
        return []
    final = len(stages) - 1
    if target:
        named = [s.index for s in stages if s.name == target.lower()]
        if named:
            final = named[0]
    specific = dockerfile.parent / f"{dockerfile.name}.dockerignore"
    ignore_path = specific if _is_regular(specific) else context / ".dockerignore"
    ignore_label = (
        _rel_label(ignore_path.relative_to(tree.root).parts)
        if _is_regular(ignore_path)
        else None
    )
    ignore_text = (
        _read_text(ignore_path, MAX_FILE_BYTES, errors, ignore_label)
        if ignore_label
        else None
    )
    if ignore_label and ignore_text is None:
        return []  # unreadable: the answer is unknown, reported in errors
    ignore = parse_dockerignore(ignore_text or "")
    model = _ImageModel(stages, ignore, sorted(files), meter)
    shipped: list[tuple[SettingsFile, str, str]] = []
    for parts, landings in sorted(model.landings(final).items()):
        settings = files[parts]
        steps = landings[0].steps
        shipped.append((settings, _rel_label(settings.rel), " → ".join(steps)))
    if not shipped:
        return []
    context_label = _rel_label(context_rel) or "."
    if ignore_label is None:
        how = (
            f"The build context is '{context_label}' and it has no .dockerignore,"
            " so COPY and ADD copy every file in it; Docker does not read"
            " .gitignore."
        )
        ignore_name = f"a .dockerignore in '{context_label}'"
    else:
        nested_only = any(
            any(
                _matches_or_parent(p.segments, (".claude", "x"), meter)
                for p in ignore
                if not p.negated
            )
            and len(s.rel) - len(context_rel) > 2
            for s, _, _ in shipped
        )
        how = f"'{ignore_label}' does not exclude" + (
            " {them}: a .claude pattern there matches only the folder at the"
            " context root, not a nested one."
            if nested_only
            else " {them}, and Docker does not read .gitignore."
        )
        ignore_name = f"'{ignore_label}'"
    return [
        _finding(
            vehicle=dockerfile,
            kind="docker",
            shipped=shipped,
            how=how,
            remediation=_DOCKER_FIX.format(ignore=ignore_name),
        )
    ]


def _compose_builds(
    tree: _Tree, errors: list[str]
) -> list[tuple[Path, Path, str | None]]:
    """``(dockerfile, context, target)`` for each local Compose ``build``."""
    import yaml  # noqa: PLC0415 — only when a Compose file exists

    builds: list[tuple[Path, Path, str | None]] = []
    for compose in tree.composes:
        label = _rel_label(compose.relative_to(tree.root).parts)
        text = _read_text(compose, MAX_FILE_BYTES, errors, label)
        if text is None:
            continue
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            errors.append(f"{ERROR_PREFIX}'{label}' is not valid YAML and was skipped")
            continue
        services = data.get("services") if isinstance(data, dict) else None
        if not isinstance(services, dict):
            continue
        for service in services.values():
            build = service.get("build") if isinstance(service, dict) else None
            if isinstance(build, str):
                context_value, dockerfile_value, target = build, "Dockerfile", None
            elif isinstance(build, dict):
                context_value = build.get("context", ".")
                dockerfile_value = build.get("dockerfile", "Dockerfile")
                target = build.get("target")
                if "dockerfile_inline" in build:
                    continue
            else:
                continue
            if not isinstance(context_value, str) or not isinstance(
                dockerfile_value, str
            ):
                continue
            if (
                "://" in context_value
                or context_value.startswith("git@")
                or "$" in context_value
                or "$" in dockerfile_value
            ):
                continue
            context = Path(os.path.normpath(compose.parent / context_value))
            dockerfile = Path(os.path.normpath(context / dockerfile_value))
            try:
                context.relative_to(tree.root)
                dockerfile.relative_to(tree.root)
            except ValueError:
                continue
            if _is_regular(dockerfile):
                builds.append(
                    (dockerfile, context, target if isinstance(target, str) else None)
                )
    return builds


# ── npm ───────────────────────────────────────────────────────────────────────


def _files_includes(
    entries: list[str], parts: tuple[str, ...], meter: MatchMeter
) -> bool:
    """True when the package.json ``files`` list includes *parts*."""
    included = False
    for entry in entries:
        negated = entry.startswith("!")
        body = entry[1:] if negated else entry
        body = posixpath.normpath(body.strip()).lstrip("/")
        if body.startswith("./"):
            body = body[2:]
        if body in ("", "."):
            hit = True
        else:
            segments = _parse_segments(body.rstrip("/"))
            if segments is None:
                continue
            hit = _matches_or_parent(segments, parts, meter)
        if hit:
            included = not negated
    return included


def _npm_sources(
    package_dir: Path, rel: tuple[str, ...], errors: list[str], root: Path
) -> tuple[list[IgnoreSource], str]:
    """Ignore files npm reads for *rel*: per folder, .npmignore else .gitignore."""
    sources: list[IgnoreSource] = []
    used: list[str] = []
    for depth in range(len(rel)):
        folder = package_dir.joinpath(*rel[:depth])
        for name in (".npmignore", ".gitignore"):
            candidate = folder / name
            if _is_regular(candidate):
                label = _rel_label(candidate.relative_to(root).parts)
                text = _read_text(candidate, MAX_FILE_BYTES, errors, label)
                if text is not None:
                    sources.append(
                        IgnoreSource(rel[:depth], tuple(parse_ignore_text(text)), label)
                    )
                    used.append(label)
                break
    return sources, ", ".join(used)


def _npm_findings(
    tree: _Tree, package_json: Path, errors: list[str], meter: MatchMeter
) -> list[Finding]:
    package_dir = package_json.parent
    package_rel = package_dir.relative_to(tree.root).parts
    files = [
        s
        for s in tree.settings
        if s.reportable and s.rel[: len(package_rel)] == package_rel
    ]
    if not files:
        return []
    label = _rel_label(package_json.relative_to(tree.root).parts)
    text = _read_text(package_json, MAX_FILE_BYTES, errors, label)
    if text is None:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict) or data.get("private") is True:
        return []
    if not isinstance(data.get("name"), str):
        return []
    entries = data.get("files")
    shipped: list[tuple[SettingsFile, str, str]] = []
    if isinstance(entries, list) and all(isinstance(e, str) for e in entries):
        for settings in files:
            rel = settings.rel[len(package_rel) :]
            # The root ignore file does not override "files"; ones in
            # subfolders still apply (npm docs, package.json "files").
            nested, _ = _npm_sources(package_dir, rel, errors, tree.root)
            nested = [source for source in nested if source.base]
            if _files_includes(entries, rel, meter) and not is_ignored(
                rel, nested, meter
            ):
                shipped.append(
                    (settings, _rel_label(settings.rel), 'the "files" field')
                )
        how = 'The package.json "files" field includes {them}.'
    else:
        used_any = False
        for settings in files:
            rel = settings.rel[len(package_rel) :]
            sources, used = _npm_sources(package_dir, rel, errors, tree.root)
            used_any = used_any or bool(used)
            if not is_ignored(rel, sources, meter):
                via = f"no rule in {used}" if used else "no .npmignore or .gitignore"
                shipped.append((settings, _rel_label(settings.rel), via))
        how = (
            'The package has no "files" field, and the .npmignore or .gitignore'
            " files in the package folder do not exclude {them}. npm does not read"
            " git's global excludes file or .git/info/exclude, where Claude Code"
            " records settings.local.json."
            if used_any
            else 'The package has no "files" field and no .npmignore or .gitignore'
            " in its folder, so npm packs every file. npm does not read git's"
            " global excludes file or .git/info/exclude, where Claude Code records"
            " settings.local.json."
        )
    if not shipped:
        return []
    return [
        _finding(
            vehicle=package_json,
            kind="npm",
            shipped=shipped,
            how=how,
            remediation=_NPM_FIX,
        )
    ]


# ── Entry points ──────────────────────────────────────────────────────────────


def scan_tree(root: Path, errors: list[str]) -> list[Finding]:
    """CRED-006 for every Dockerfile and package.json under *root*; never raises."""
    try:
        root = root.resolve()
        tree = _walk(root, errors)
        if not any(s.reportable for s in tree.settings):
            return []
        meter = MatchMeter()
        findings: list[Finding] = []
        builds: list[tuple[Path, Path, str | None]] = (
            _compose_builds(tree, errors) if tree.composes else []
        )
        named = {dockerfile for dockerfile, _, _ in builds}
        builds += [(d, d.parent, None) for d in tree.dockerfiles if d not in named]
        if len(builds) + len(tree.packages) > MAX_BUILD_FILES:
            errors.append(
                f"{ERROR_PREFIX}more than {MAX_BUILD_FILES} Dockerfiles and"
                " package.json files; only the first were checked"
            )
        budget = MAX_BUILD_FILES
        seen: set[tuple[Path, Path, str | None]] = set()
        for build in builds:
            if build in seen or budget <= 0:
                continue
            seen.add(build)
            budget -= 1
            findings.extend(_docker_findings(tree, *build, errors, meter))
        for package_json in tree.packages:
            if budget <= 0:
                break
            budget -= 1
            findings.extend(_npm_findings(tree, package_json, errors, meter))
        return findings
    except MatchBudgetExceededError:
        errors.append(
            f"{ERROR_PREFIX}ignore-pattern matching ran out of budget; some build"
            " files were not checked"
        )
        return []
    except Exception as exc:  # noqa: BLE001 — never fail the scan
        errors.append(f"{ERROR_PREFIX}check failed: {type(exc).__name__}: {exc}")
        return []


def scan_cwd_repository(cwd: Path, errors: list[str]) -> list[Finding]:
    """CRED-006 for the work tree containing *cwd*; ``[]`` outside one.

    A work tree that is the home directory, or contains it, is not walked.
    """
    from mcp_audit.analyzers.rule_secret_history import (  # noqa: PLC0415
        find_repository,
    )

    try:
        found = find_repository(cwd)
        if found is None:
            return []
        worktree = found[0].resolve()
        home = Path.home().resolve()
        if worktree == home or home.is_relative_to(worktree):
            return []
    except (OSError, RuntimeError):
        return []
    return scan_tree(worktree, errors)
