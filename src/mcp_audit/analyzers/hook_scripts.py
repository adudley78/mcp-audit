"""Does a hook command run a file the repository ships? (HOOK-003, STORY-0138)

Pure text analysis of one shell command string; no I/O, nothing is run.  The
command is split into simple commands (``;``, ``&&``, ``||``, ``|``, ``&``,
newlines, ``(``, ``)`` and backticks outside quotes), each is tokenised in one
linear pass (quotes removed, backslashes kept literally so Windows paths
survive) and read the way a shell would start it:

* leading ``VAR=value`` assignments and wrappers (``env``, ``exec``, ``nohup``,
  ``time``, ``sudo``, ...) are skipped;
* package-runner launchers (``npx``, ``bunx``, ``pnpm exec``, ``uv run``,
  ``poetry run``, ...) are skipped and the command they run is read instead;
* a head that is itself a project path (``./x.sh``, ``scripts/x.sh``,
  ``$CLAUDE_PROJECT_DIR/.claude/hooks/a.sh``) is a hit;
* a head that is an interpreter (``node``, ``python3``, ``bash``, ...) hits when
  its first non-option argument is a project path, or a bare file name with a
  script extension; the files an interpreter preloads (``node -r ./x.js``) and
  the string given to ``sh -c`` (two levels deep) are read too.

A "project path" is relative to the working directory (``./x``, ``.github/x``,
``scripts/x.sh``) or rooted at ``$CLAUDE_PROJECT_DIR`` / ``${CLAUDE_PROJECT_DIR}``
(also the ``%...%`` and ``$env:`` spellings).  Absolute paths, ``~``, other
variables, URLs and ``../`` paths are not.  Every pass is linear in the length
of the command: no regex has nested quantifiers and nothing is truncated, so
padding cannot push a hit out of view.
"""

from __future__ import annotations

import re

#: Interpreter names (after stripping a directory, ``.exe`` and a version).
_INTERPRETERS = frozenset(
    {
        "node",
        "nodejs",
        "bun",
        "deno",
        "python",
        "python3",
        "pypy",
        "pypy3",
        "ruby",
        "perl",
        "php",
        "lua",
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "pwsh",
        "powershell",
        "tsx",
        "ts-node",
        "ts-node-esm",
        "esno",
        "jiti",
        "zx",
        "babel-node",
        "source",
        ".",
    }
)
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})
_POWERSHELLS = frozenset({"pwsh", "powershell"})
_WRAPPERS = frozenset(
    {"env", "exec", "nohup", "time", "command", "builtin", "sudo", "nice", "stdbuf"}
)
#: Launchers with no subcommand: ``npx [options] <command> ...``.
_BARE_LAUNCHERS = frozenset({"npx", "bunx", "pnpx"})
#: Launchers with a subcommand: ``uv run <command> ...``.
_SUB_LAUNCHERS: dict[str, frozenset[str]] = {
    "uv": frozenset({"run"}),
    "poetry": frozenset({"run"}),
    "pipenv": frozenset({"run"}),
    "pnpm": frozenset({"exec", "dlx"}),
    "yarn": frozenset({"exec", "dlx"}),
    "npm": frozenset({"exec"}),
    "bun": frozenset({"x"}),
}
#: Options of the bare launchers that take a value.
_LAUNCHER_VALUE_OPTS = frozenset({"-p", "--package", "-c", "--call"})
#: Interpreter options whose value is code or a module name, not a file.
_INLINE_OPTS = frozenset(
    {"-e", "-p", "-r", "--eval", "--print", "-m", "-c", "-command", "-encodedcommand"}
)
#: Interpreters whose ``-r`` / ``--require`` / ``--import`` preloads a file.
_PRELOADERS = frozenset(
    {"node", "nodejs", "bun", "deno", "tsx", "ts-node", "ts-node-esm"}
)
#: Node-style options that load and run a file before the main script.
_PRELOAD_OPTS = frozenset(
    {"-r", "--require", "--import", "--loader", "--experimental-loader", "--preload"}
)
_PRELOAD_EQ_RE = re.compile(
    r"^(?:--require|--import|--loader|--experimental-loader|--preload)=(.+)$"
)
#: Options that take a separate value we must step over.
_VALUE_OPTS = frozenset(
    {
        "-executionpolicy",
        "-ep",
        "-windowstyle",
        "-workingdirectory",
        "--check-hash-based-pycs",
    }
)
#: Python's ``-W`` / ``-X`` take a value (case matters: bash ``-x`` does not).
_CASE_VALUE_OPTS = frozenset({"-W", "-X"})
_POWERSHELL_FILE_OPTS = frozenset({"-file", "-f"})
_SUBCOMMANDS = frozenset({"run", "exec", "x"})
_SHELL_C_RE = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VERSION_RE = re.compile(r"^([a-z][a-z-]*?)[0-9.]*$")
_SCRIPT_EXTS = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".cts",
        ".py",
        ".sh",
        ".bash",
        ".zsh",
        ".rb",
        ".pl",
        ".php",
        ".lua",
        ".ps1",
        ".bat",
        ".cmd",
    }
)
_PROJECT_DIR_RE = re.compile(
    r"^(?:\$\{CLAUDE_PROJECT_DIR\}|\$CLAUDE_PROJECT_DIR|%CLAUDE_PROJECT_DIR%"
    r"|\$env:CLAUDE_PROJECT_DIR)[/\\]",
    re.IGNORECASE,
)
_REDIRECT_RE = re.compile(r"^[0-9]*[<>]")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_MAX_DEPTH = 2
_SEPARATORS = frozenset(";|&\n\r()`")


def split_simple_commands(command: str) -> list[list[str]]:
    """Split *command* into simple commands, each a list of unquoted tokens.

    One pass over the text.  Single and double quotes group (and are removed);
    a backslash is kept literally; the separators ``; | & ( ) ` `` and newline
    end a simple command when outside quotes.  An unclosed quote runs to the
    end of the text.
    """
    commands: list[list[str]] = []
    tokens: list[str] = []
    buf: list[str] = []
    in_token = False
    quote = ""
    for ch in command:
        if quote:
            if ch == quote:
                quote = ""
            else:
                buf.append(ch)
            continue
        if ch in "'\"":
            quote = ch
            in_token = True
        elif ch in _SEPARATORS or ch in " \t":
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            if ch in _SEPARATORS and tokens:
                commands.append(tokens)
                tokens = []
        else:
            buf.append(ch)
            in_token = True
    if in_token:
        tokens.append("".join(buf))
    if tokens:
        commands.append(tokens)
    return commands


def _base(token: str) -> str:
    """Lower-case program name of *token*: no directory, ``.exe`` or version."""
    name = re.split(r"[/\\]", token)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    match = _VERSION_RE.match(name)
    if match and match.group(1) in _INTERPRETERS:
        return match.group(1)
    return name


def is_project_path(token: str, *, bare_script_ok: bool = False) -> bool:
    """True when *token* names a file inside the project directory.

    Args:
        token: One unquoted shell word.
        bare_script_ok: Also accept a name with no directory part but a script
            extension (``init.js``), valid only as an interpreter's argument.
    """
    if not token:
        return False
    if _PROJECT_DIR_RE.match(token):
        return True
    if token.startswith(("./", ".\\")):
        return len(token) > 2
    first = token[0]
    # Glob and case patterns (`*rg\ *)`) and operators are not file names.
    if first in "/\\~$%-@*?[!=+<>#" or token.startswith("..") or token[-1] == "\\":
        return False
    if _REDIRECT_RE.match(token):  # `2>/dev/null`, `>out`: a redirection
        return False
    if _SCHEME_RE.match(token):  # URL scheme or a Windows drive (C:\...)
        return False
    if "/" in token or "\\" in token:
        return True
    if bare_script_ok:
        dot = token.rfind(".")
        return dot > 0 and token[dot:].lower() in _SCRIPT_EXTS
    return False


def _skip_wrappers(tokens: list[str]) -> int:
    """Index of the first token that is not an assignment, wrapper or its option."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if _ASSIGN_RE.match(tok):
            i += 1
        elif _base(tok) in _WRAPPERS:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
        else:
            break
    return i


def _scan_interpreter(base: str, rest: list[str], depth: int) -> str | None:
    """The project file an interpreter invocation runs, if any."""
    j = 0
    if base in {"source", "."}:
        return rest[0] if rest and is_project_path(rest[0]) else None
    while j < len(rest):
        tok = rest[j]
        low = tok.lower()
        if base in _SHELLS and _SHELL_C_RE.match(tok):
            if j + 1 < len(rest) and depth < _MAX_DEPTH:
                return find_project_script(rest[j + 1], depth + 1)
            return None
        if (
            base not in _SHELLS
            and low in _INLINE_OPTS
            and not (low == "-r" and base in _PRELOADERS)
        ):
            return None
        if low in _PRELOAD_OPTS and base in _PRELOADERS:
            if j + 1 < len(rest) and is_project_path(rest[j + 1]):
                return rest[j + 1]
            j += 2
            continue
        eq = _PRELOAD_EQ_RE.match(tok) if base in _PRELOADERS else None
        if eq:
            if is_project_path(eq.group(1)):
                return eq.group(1)
            j += 1
            continue
        if base in _POWERSHELLS and low in _POWERSHELL_FILE_OPTS:
            ok = j + 1 < len(rest) and is_project_path(rest[j + 1], bare_script_ok=True)
            return rest[j + 1] if ok else None
        if low in _VALUE_OPTS or tok in _CASE_VALUE_OPTS:
            j += 2
            continue
        if tok.startswith("-"):
            j += 1
            continue
        if j == 0 and tok in _SUBCOMMANDS and base in {"bun", "deno"}:
            j += 1
            continue
        return tok if is_project_path(tok, bare_script_ok=True) else None
    return None


def _scan_command(tokens: list[str], depth: int) -> str | None:
    """The project file one simple command runs, if any."""
    start = _skip_wrappers(tokens)
    if start >= len(tokens):
        return None
    head = tokens[start]
    rest = tokens[start + 1 :]
    base = _base(head)
    if base in _BARE_LAUNCHERS:
        k = 0
        while k < len(rest) and rest[k].startswith("-"):
            k += 2 if rest[k] in _LAUNCHER_VALUE_OPTS else 1
        return _scan_command(rest[k:], depth)
    if base in _SUB_LAUNCHERS and rest and rest[0] in _SUB_LAUNCHERS[base]:
        k = 1
        while k < len(rest) and rest[k].startswith("-"):
            k += 1
        return _scan_command(rest[k:], depth)
    if is_project_path(head):
        return head
    if base in _INTERPRETERS:
        return _scan_interpreter(base, rest, depth)
    return None


def find_project_script(command: str, depth: int = 0) -> str | None:
    """Return the project-relative file *command* runs, or ``None``.

    Args:
        command: A hook command string (shell syntax).
        depth: Nesting level of ``sh -c`` strings already entered.

    Returns:
        The path token as written (for example ``.github/init.js`` or
        ``$CLAUDE_PROJECT_DIR/.claude/hooks/a.py``), the first one found.
    """
    for tokens in split_simple_commands(command):
        hit = _scan_command(tokens, depth)
        if hit is not None:
            return hit
    return None
