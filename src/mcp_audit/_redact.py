"""Shared local-filesystem-path redaction for output sinks that leave this host.

``Finding.finding_path`` and ``ServerConfig.config_path`` are always this
scanning host's own absolute path — under the operator's ``$HOME`` in the
overwhelming common case, which means they embed the operator's OS username.
That is correct and useful in terminal output and the HTML dashboard, where
the reader is looking at their own machine. It is a defect in any output
sink designed to be published, uploaded, or ingested somewhere else: the
advisory feed (``mcp-audit advise``), SARIF (``scan --format sarif``),
Nucleus FlexConnect (``push-nucleus`` / ``scan --format nucleus``), and the
forensic snapshot export (``mcp-audit snapshot``) all copy ``Finding`` text
and paths verbatim into a document meant to leave the machine.

:func:`redact_local_paths` is the one shared implementation every one of
those sinks calls at serialisation time — never by mutating the ``Finding``
or ``ServerConfig`` objects themselves, so that two sinks formatting the same
scan in one process never see each other's edits.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Below this length a path string is too generic to redact safely — "/" itself is
#: one character, and blindly `str.replace("/", ...)` would rewrite every path
#: separator in the whole document, not just the scanned config's own path.
_MIN_SAFE_PATH_LENGTH = 3


def redact_local_paths(text: str, config_path: Path) -> str:
    """Rewrite *config_path* and its ancestors in *text* to a cwd-relative form.

    ``config_hygiene.py`` (CFHYG-001/002/005) legitimately embeds the real, absolute
    scanned path in a finding's evidence/remediation — you need the actual path to
    run the ``chmod`` it suggests. Other analyzers (SAST, extensions, agent-files)
    likewise set ``Finding.finding_path`` to a real absolute path on this host. But
    every sink in this module's docstring copies that text verbatim into a document
    meant to be published, uploaded, or ingested somewhere else, and an absolute path
    there is the same defect class as the RFC 8785 float bug in a different shape:
    two hosts scanning the *same relative target* resolve it to two different
    absolute paths, so the same finding canonicalizes (and, for the advisory feed,
    signs) differently depending on where the scanning machine happens to keep its
    checkout — on top of leaking the operator's home-directory username, which
    contradicts mcp-audit's own privacy-first premise in the components designed to
    leave the machine.

    *config_path*, and each of its ancestors up to (but not including) ``$HOME``,
    is replaced by its path relative to the current working directory — not just
    the bare filename, which would make two same-named config files in different
    directories indistinguishable. Climbing stops at ``$HOME`` (or does not start
    at all when *config_path* is not under it) rather than continuing to the
    filesystem root: an ancestor that short — ``/`` is one character — would match,
    and get rewritten, everywhere a path separator appears in the rest of the text,
    not just in the scanned config's own path. ``$HOME`` itself becomes the
    conventional ``~``, since the directories above it carry no information a reader
    needs and only encode the local username.

    Cwd-relative is only safe when the working directory is itself under ``$HOME``:
    then the climb from cwd up to any shared ancestor never needs to go above
    ``$HOME``, so ``$HOME``'s own name is always climbed *past* (as an anonymous
    ``..``) and never descended back *through*. When the working directory has
    escaped ``$HOME`` entirely (e.g. a container mounting the repo outside the home
    volume), that guarantee doesn't hold — reaching a config file under ``$HOME``
    would require descending through ``$HOME``'s own directory entry from a shared
    ancestor above it, putting the username literally in the output. Ancestors
    under ``$HOME`` are rendered relative to ``$HOME`` (``~/...``) instead in that
    case: never a leak, at the cost of exact reproducibility across two hosts whose
    container mounts disagree — the same caveat any tool's relative-path output
    would carry there.

    Scope: this protects *this* invocation's own operator (``$HOME``), which is
    what "mcp-audit leaks the local username" means for the overwhelmingly common
    case of scanning your own client configs. It does not scrub an unrelated
    username that happens to appear in a *different* user's directory named in an
    explicitly-scanned path outside ``$HOME`` (e.g. ``--project`` pointed at
    another account's shared project on a multi-user host) — recognising an
    arbitrary OS username anywhere in a string is a different, open-ended problem
    from redacting the one home directory this process can name authoritatively.
    See ``docs/privacy.md`` for this documented as a stated boundary.
    """
    try:
        home: Path | None = Path.home()
    except RuntimeError:
        home = None
    under_home = home is not None and config_path.is_relative_to(home)
    cwd = Path.cwd()
    cwd_escaped_home = home is not None and not cwd.is_relative_to(home)

    ancestors: list[Path] = [config_path]
    if under_home:
        current = config_path
        while current != home:
            parent = current.parent
            if parent == home:
                break
            ancestors.append(parent)
            current = parent

    replacements: list[tuple[str, str]] = []
    for ancestor in ancestors:
        raw = str(ancestor)
        if len(raw) < _MIN_SAFE_PATH_LENGTH:
            continue
        if under_home and cwd_escaped_home:
            # cwd can't reach `ancestor` without passing through $HOME itself —
            # relpath would spell out $HOME's name. Anchor on $HOME instead.
            relative = f"~/{ancestor.relative_to(home)}" if ancestor != home else "~"
        else:
            try:
                relative = os.path.relpath(ancestor, cwd)
            except ValueError:
                relative = ancestor.name
        replacements.append((raw, relative))
    if home is not None and len(str(home)) >= _MIN_SAFE_PATH_LENGTH:
        replacements.append((str(home), "~"))

    # Longest string first: config_path's full string must be replaced before any
    # of its own ancestor directories, or a shorter ancestor's occurrence inside the
    # still-unreplaced longer string would be replaced first, leaving a malformed
    # hybrid path (part original, part rewritten) behind.
    by_length_desc = sorted(replacements, key=lambda pair: len(pair[0]), reverse=True)
    for raw, relative in by_length_desc:
        text = text.replace(raw, relative)
    return text


def redact_finding_path(text: str, finding_path: str | None) -> str:
    """Redact *finding_path* (and its ``$HOME``-bounded ancestors) inside *text*.

    Convenience wrapper around :func:`redact_local_paths` for the common call
    shape at every sink: every analyzer sets ``Finding.finding_path`` to the one
    absolute local path it was operating on (a scanned MCP config, a SAST source
    file, an extension manifest, an agent-instruction file), and that is exactly
    the anchor ``redact_local_paths`` needs to scrub occurrences of it out of the
    finding's own title/description/evidence/remediation text. Returns *text*
    unchanged when *finding_path* is ``None`` or empty — there is nothing to
    anchor a redaction on.
    """
    if not finding_path:
        return text
    return redact_local_paths(text, Path(finding_path))
