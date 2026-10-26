"""Pure text and byte checks behind the skill-package findings (STORY-0095).

Nothing here touches the filesystem; :mod:`mcp_audit.agent_files.skill_package`
walks the skill directory and calls these on what it read.

* :func:`install_step_hits` — SKILL-005 shapes in one text file.
* :func:`text_shape_hits` — SKILL-006 shapes in prose: telling the agent to
  switch permission prompts off, or pointing a model-API base URL at a host
  that is not the vendor's.
* :func:`blob_in_text`, :func:`identify`, :func:`decode_text`,
  :func:`entropy` — SKILL-007 inputs.
* :func:`redact` and :func:`parse_url` — shared helpers.

Every pattern is original and cites its source in PROVENANCE.md.  All
quantifiers are bounded and every logical line is clipped to
``LINE_CAP`` characters, so no input is quadratic.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.analyzers.poisoning import normalize_for_detection
from mcp_audit.models import Severity

LINE_CAP = 16 * 1024  # characters of one logical line the patterns see
_MAX_CONTINUATIONS = 20
_MAX_REASONS = 8  # reasons kept per hit line
BLOB_RUN = 4096  # base64 characters in one run that make a blob
BLOB_LINES = 64  # consecutive wrapped base64 lines that make a blob
HEX_RUN = 8192

_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def rank(severity: Severity) -> int:
    """Return *severity*'s position, INFO lowest."""
    return _SEVERITY_ORDER.index(severity)


# ── Redaction ─────────────────────────────────────────────────────────────────

_REDACTED = "[REDACTED]"
_URL_USERINFO_RE = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]{0,20}://)[^/\s@'\"`]{1,256}@")
_AUTH_HEADER_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token)"
    r"(\s{0,3}[:=]\s{0,3})(?:(?:bearer|basic|token)\s{1,3})?[^\s'\"`]{1,512}"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s{1,3}[A-Za-z0-9._~+/=-]{8,512}")
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|key|api_key|apikey|access_token|secret|password|sig|auth)=)"
    r"[^&\s'\"`#]{1,512}"
)


def redact(text: str) -> str:
    """Strip credentials from *text* before it lands in a finding.

    Applies ``SECRET_PATTERNS`` (the table ``advisory/feed.py::redact`` uses)
    plus the shapes a command line carries credentials in: URL userinfo,
    auth headers, ``Bearer``/``Basic`` values and credential query parameters.
    """
    cleaned = text
    for _label, pattern, _provider in SECRET_PATTERNS:
        cleaned = pattern.sub(_REDACTED, cleaned)
    cleaned = _URL_USERINFO_RE.sub(lambda m: f"{m.group(1)}{_REDACTED}@", cleaned)
    cleaned = _AUTH_HEADER_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", cleaned
    )
    cleaned = _BEARER_RE.sub(lambda m: f"{m.group(1)} {_REDACTED}", cleaned)
    return _QUERY_SECRET_RE.sub(lambda m: f"{m.group(1)}{_REDACTED}", cleaned)


def snippet(text: str, limit: int = 160) -> str:
    """One-line, redacted, length-capped copy of *text* for evidence."""
    one = " ".join(text.split())
    if len(one) > limit:
        one = one[: limit - 1] + "…"
    return redact(one)


# ── URLs and hosts (strict reading) ───────────────────────────────────────────

URL_RE = re.compile(r"(?i)\b(?:https?|ftps?|wss?)://[^\s'\"`<>(){}|;,]{1,2048}")
_AUTHORITY_RE = re.compile(r"(?i)^([a-z][a-z0-9+.-]{0,20})://([^/?#]{0,512})")
_IPV4_PART_RE = re.compile(r"(?i)^(?:0x[0-9a-f]{1,8}|[0-9]{1,10})$")


@dataclass(frozen=True)
class Url:
    """A URL as the strict reader sees it.

    ``host`` is ``None`` when the authority is not plain enough to trust.
    """

    scheme: str
    host: str | None
    path: str


def parse_url(url: str) -> Url:
    """Parse *url*, refusing authorities the real consumers read differently.

    Node's WHATWG parser, curl and Python's ``urlsplit`` disagree about a
    backslash, ``@`` or percent-encoding in the authority: for
    ``https://evil.example\\@api.anthropic.com`` Python reports the host
    ``api.anthropic.com`` while Node connects to ``evil.example``.  Any of
    those characters, whitespace or a control character makes the host
    unknown, which every caller treats as "not first-party, not a known
    vendor".
    """
    m = _AUTHORITY_RE.match(url)
    if m is None:
        return Url("", None, "")
    scheme, authority = m.group(1).lower(), m.group(2)
    path = url[m.end() :]
    if (
        not authority
        or any(c in authority for c in "@\\%")
        or any(c.isspace() or ord(c) < 0x20 for c in authority)
    ):
        return Url(scheme, None, path)
    if authority.startswith("["):
        end = authority.find("]")
        host: str | None = authority[1:end] if end > 0 else None
    else:
        host = authority.rsplit(":", 1)[0] if ":" in authority else authority
    if host is not None:
        host = host.lower().rstrip(".")
    return Url(scheme, host or None, path)


_IPV4_LIMITS = {
    1: (2**32,),
    2: (256, 2**24),
    3: (256, 256, 2**16),
    4: (256, 256, 256, 256),
}


def ip_of(host: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the address *host* names, reading IPv4 the way ``inet_aton`` does.

    curl and browsers accept ``127.1``, ``0x7f.0.0.1`` and ``2130706433``;
    Python's :mod:`ipaddress` rejects them, so they are decoded here.
    """
    if not host:
        return None
    if ":" in host:
        try:
            return ipaddress.IPv6Address(host.split("%", 1)[0])
        except ValueError:
            return None
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_IPV4_PART_RE.match(p) for p in parts):
        return None
    nums: list[int] = []
    for part in parts:
        if part.lower().startswith("0x"):
            nums.append(int(part, 16))
        elif len(part) > 1 and part.startswith("0"):
            if any(c in "89" for c in part):
                return None
            nums.append(int(part, 8))
        else:
            nums.append(int(part))
    limits = _IPV4_LIMITS[len(parts)]
    if any(n >= lim for n, lim in zip(nums, limits, strict=True)):
        return None
    value = 0
    for n, lim in zip(nums, limits, strict=True):
        value = value * lim + n
    return ipaddress.IPv4Address(value)


def is_loopback(host: str | None) -> bool:
    """True for ``localhost`` names and loopback/unspecified addresses."""
    if host is None:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    ip = ip_of(host)
    return ip is not None and (ip.is_loopback or ip.is_unspecified)


def is_public_ip(host: str | None) -> bool:
    """True when *host* is a literal, globally routable IP address."""
    ip = ip_of(host)
    return ip is not None and ip.is_global


#: Documented one-line installers on the vendor's own host.  A ``| sh`` from
#: one of these is INFO (still listed), not LOW.  Exact host, https only,
#: path prefix; a URL that does not parse plainly never matches.
VENDOR_INSTALLERS: tuple[tuple[str, str], ...] = (
    ("astral.sh", "/uv/"),
    ("astral.sh", "/ruff/"),
    ("sh.rustup.rs", "/"),
    ("win.rustup.rs", "/"),
    ("hf.co", "/cli/install"),
    ("huggingface.co", "/cli/install"),
    ("claude.ai", "/install."),
    ("bun.sh", "/install"),
    ("bun.com", "/install"),
    ("deno.land", "/install"),
    ("deno.land", "/x/install/"),
    ("get.docker.com", "/"),
    ("raw.githubusercontent.com", "/nvm-sh/nvm/"),
    ("raw.githubusercontent.com", "/homebrew/install/"),
    ("fnm.vercel.app", "/install"),
    ("get.pnpm.io", "/install"),
    ("install.python-poetry.org", "/"),
    ("ollama.com", "/install.sh"),
    ("sdk.cloud.google.com", "/"),
    ("pyenv.run", "/"),
    ("mise.run", "/"),
    ("get.volta.sh", "/"),
    ("starship.rs", "/install.sh"),
    ("install.determinate.systems", "/nix"),
    ("dot.net", "/v1/dotnet-install"),
)


def is_vendor_installer(url: Url) -> bool:
    """True for an https URL on :data:`VENDOR_INSTALLERS`."""
    if url.scheme != "https" or url.host is None:
        return False
    path = "/" + url.path.lstrip("/").lower()
    return any(
        url.host == host and path.startswith(prefix)
        for host, prefix in VENDOR_INSTALLERS
    )


# ── Logical lines ─────────────────────────────────────────────────────────────


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Split *text* into ``(1-based first line, logical line)`` pairs.

    A trailing backslash continues a shell line (at most
    ``_MAX_CONTINUATIONS`` times).  A logical line longer than ``LINE_CAP``
    is cut into overlapping windows, so no pattern sees unbounded text.
    """
    raw = text.split("\n")
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(raw):
        start = i
        parts = [raw[i].rstrip("\r")]
        while (
            parts[-1].endswith("\\")
            and i + 1 < len(raw)
            and len(parts) <= _MAX_CONTINUATIONS
        ):
            parts[-1] = parts[-1][:-1]
            i += 1
            parts.append(raw[i].rstrip("\r"))
        line = " ".join(parts)
        if len(line) <= LINE_CAP:
            out.append((start + 1, line))
        else:
            step = LINE_CAP - 512
            out.extend(
                (start + 1, line[offset : offset + LINE_CAP])
                for offset in range(0, len(line), step)
            )
        i += 1
    return out


# ── SKILL-005: install-step shapes ────────────────────────────────────────────

#: Shells read a script from stdin unless given ``-c`` or a script file.
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
#: Interpreters read a program from stdin unless given inline code or a file.
_INTERPRETERS = frozenset(
    {"node", "nodejs", "deno", "bun", "perl", "ruby", "php", "pwsh", "powershell"}
)
_PYTHON_RE = re.compile(r"^python[0-9.]{0,5}$|^py$")
#: Flags that make an interpreter run inline code, leaving stdin as data.
_INLINE_CODE_FLAGS = frozenset(
    {"-c", "-e", "-m", "-p", "-E", "-r", "--eval", "--print", "-command", "-Command"}
)
_WRAPPERS = frozenset({"sudo", "env", "nohup", "exec", "time", "command"})
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}=")
_SINK_WORDS = r"sh|bash|zsh|dash|ksh|fish|node|deno|bun|python[0-9.]{0,5}|perl|ruby"
_SUBST_SINK_RE = re.compile(
    r"(?:^|[\s`'\"(;&|])(?:(?:ba|z|da|k)?sh|eval|source|python[0-9.]{0,5}|node"
    r"|perl|ruby)(?:\s{1,5}-[a-z]{1,10}){0,4}\s{0,5}[\"']?(?:\$\(|<\()\s{0,5}$"
    r"|(?i:\b(?:iex|invoke-expression))\s{0,5}\(?\s{0,5}$"
)
_FETCH_RE = re.compile(
    r"(?i)(?<![\w./-])(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)"
    r"(?:\.exe)?(?![\w-])|\.download(?:string|file|data)\s{0,3}\("
)
_CURL_RE = re.compile(r"(?i)(?<![\w./-])curl(?:\.exe)?(?![\w-])")
_CURL_INSECURE_RE = re.compile(
    r"(?:^|\s)(?:-[a-zA-Z]{0,15}k[a-zA-Z]{0,15}|--insecure|--proxy-insecure)(?=\s|$)"
)
_OTHER_INSECURE_RE = re.compile(r"(?i)--no-check-certificate\b|-skipcertificatecheck\b")
_DECODE_CMD_RE = re.compile(
    r"(?i)\bbase64(?:\.exe)?\s{1,5}(?:-[a-ce-z]{0,3}d[a-z]{0,3}|-D|--decode)\b"
    r"|\bxxd\s{1,5}(?:-[a-z]{1,4}\s{1,5}){0,3}-r\b"
    r"|\bopenssl\s{1,5}(?:enc\s{1,5})?(?:-d\s{1,5})?-?base64\s{1,5}-d\b"
    r"|\bcertutil(?:\.exe)?\s{1,5}-decode\b"
)
_EVAL_DECODE_RE = re.compile(
    r"(?i)(?:\beval\b|\b(?:ba|z|da)?sh\s{1,5}-c\b)[^\n]{0,400}?\bbase64\s{1,5}"
    r"(?:-[a-ce-z]{0,3}d[a-z]{0,3}|-D|--decode)\b"
)
_PS_ENCODED_RE = re.compile(
    r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,200}?\s-(?:e|ec|en|enc|enco"
    r"|encodedcommand)\s{1,5}[A-Za-z0-9+/=]{20,}"
)
_PS_B64_RE = re.compile(r"(?i)frombase64string")
_PS_IEX_RE = re.compile(r"(?i)\b(?:iex|invoke-expression)\b")
_OUTPUT_TARGET_RE = re.compile(
    r"(?i)(?:\s-outfile\s{1,3}|\s-o(?![a-z])\s{0,3}|\s--output(?:=|\s{1,3})"
    r"|\s--output-document(?:=|\s{1,3})|(?<![0-9&])>{1,2}\s{0,3}"
    r"|\|\s{0,3}tee(?:\s{1,3}-a)?\s{1,3})[\"']?([^\s\"'|;&<>`)]{3,256})"
)
_MARSHAL_RE = re.compile(r"\bmarshal\.loads?\s{0,3}\(")
_ARCHIVE_PASSWORD_RE = re.compile(
    r"\bunzip(?:\.exe)?\b[^\n|;&]{0,200}?\s-P\s{0,3}\S"
    r"|\b7z[ar]?(?:\.exe)?\s{1,5}[xe]\b[^\n|;&]{0,200}?\s-p\S"
    r"|\bunrar(?:\.exe)?\s{1,5}[xe]\b[^\n|;&]{0,200}?\s-p\S"
    r"|\.setpassword\s{0,3}\("
    r"|\b(?:extractall|extract|open)\s{0,3}\([^)\n]{0,200}?\bpwd\s{0,3}="
)
_DNS_TXT_RE = re.compile(
    r"(?i)\bdig\b[^\n]{0,200}?\btxt\b"
    r"|\bnslookup\b[^\n]{0,200}?-(?:type|q|querytype)=txt\b"
    r"|\bhost\s{1,5}-t\s{0,3}txt\b"
    r"|\bresolve-dnsname\b[^\n]{0,200}?-type\s{1,5}txt\b"
    r"|resolver\.(?:resolve|query)\s{0,3}\([^)\n]{0,200}?['\"]txt['\"]"
)
_EXEC_SINK_RE = re.compile(
    r"(?i)\b(?:ba|z|da)?sh\s{1,5}-c\b|\beval\b|\|\s{0,3}(?:sudo\s{1,5})?(?:ba|z|da)?sh\b"
    r"|\biex\b|\binvoke-expression\b|\bbase64\s{1,5}(?:-d|--decode)\b"
    r"|(?<![\w.])exec\s{0,3}\(|\bos\.system\s{0,3}\(|\bsubprocess\.\w{1,20}\s{0,3}\("
)
_PY_DECODE_RE = re.compile(
    r"\b(?:b64decode|b32decode|b85decode|a85decode|urlsafe_b64decode|decodebytes"
    r"|a2b_base64|unhexlify)\s{0,3}\("
    r"|\b(?:zlib|lzma|bz2|gzip)\.decompress\s{0,3}\(|\bbytes\.fromhex\s{0,3}\("
    r"|\bcodecs\.decode\s{0,3}\([^)\n]{0,200}?['\"](?:rot.?13|hex|base64)['\"]"
)
_PY_EXEC_RE = re.compile(r"(?<![\w.])(?:exec|eval|compile)\s{0,3}\(")
_JS_DECODE_EXEC_RE = re.compile(
    r"(?<![\w.])eval\s{0,3}\(\s{0,3}(?:atob|Buffer\.from)\s{0,3}\("
    r"|\bnew\s{1,3}Function\s{0,3}\(\s{0,3}(?:atob|Buffer\.from)\s{0,3}\("
    r"|(?<![\w.])Function\s{0,3}\(\s{0,3}atob\s{0,3}\("
)
_PERSISTENCE_RE = re.compile(
    r"\|\s{0,3}(?:sudo\s{1,5})?crontab\s{1,5}-(?=\s|$|[`'\")])"
    r"|\bcrontab\s{1,5}(?!-)[\w./~$-]{1,200}"
    r"|(?:>{1,2}|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bln\b)[^\n|;&]{0,300}?"
    r"(?:/etc/cron(?:tab|\.d|\.daily|\.hourly|\.weekly|\.monthly)\b|/var/spool/cron\b"
    r"|Library/Launch(?:Agents|Daemons)/|/etc/systemd/(?:system|user)/"
    r"|\.config/systemd/user/|/lib/systemd/system/)"
    r"|\blaunchctl\s{1,5}(?:load|bootstrap|submit)\b"
    r"|(?i:\bschtasks(?:\.exe)?\s{1,5}/create\b|\bregister-scheduledtask\b)"
    r"|(?i:\breg(?:\.exe)?\s{1,5}add\s{1,5}[\"']?hk(?:cu|lm|ey_current_user"
    r"|ey_local_machine)\\software\\microsoft\\windows\\currentversion\\run)"
)
_REVERSE_SHELL_RE = re.compile(
    r"/dev/tcp/[A-Za-z0-9.\-]{1,253}/\d{1,5}"
    r"|\bnc(?:at)?\b[^\n|;&]{0,100}?\s-[a-zA-Z]{0,4}e\s{1,3}/bin/(?:ba|z)?sh\b"
    r"|\bbash\s{1,5}-i\s{0,3}>&"
    r"|\bsocat\b[^\n]{0,200}?\bexec:"
)
_NEGATION_RE = re.compile(
    r"(?i)\b(?:never|don'?t|do\s+not|avoid|must\s+not|should\s+not|shouldn'?t)\s+"
    r"(?:\w+\s+){0,3}?(?:use|run|pass|add|execute|pipe|call|enable|set|invoke|type"
    r"|start|launch)\b"
)
_COMMAND_START_RE = re.compile(r"(?i)`|\b(?:curl|wget|iwr|irm|base64|bash|sh)\b|\|")


@dataclass
class Hit:
    """One line's SKILL-005 evidence."""

    line: int
    severity: Severity
    reasons: list[str] = field(default_factory=list)
    text: str = ""


def negated(text_before: str) -> bool:
    """True when the sentence ending at *text_before* advises against an action."""
    window = text_before[-200:]
    cut = max(window.rfind(". "), window.rfind("! "), window.rfind("? "))
    if cut != -1:
        window = window[cut + 2 :]
    return bool(_NEGATION_RE.search(window))


def _split_segments(line: str) -> list[tuple[str, str]]:
    """Split a shell line into ``(separator before, segment)`` pairs."""
    pieces = re.split(r"(\|\||&&|\||;)", line)
    out: list[tuple[str, str]] = [("", pieces[0])]
    out.extend((pieces[i], pieces[i + 1]) for i in range(1, len(pieces) - 1, 2))
    return out


#: Pipeline stages after a fetch or decode that are examined.  Bounding this
#: (and ``_MAX_AFTER``) keeps a line of thousands of ``curl … |`` segments
#: linear: each segment costs a fixed amount of work, not the rest of the line.
_MAX_PIPELINE = 8
#: Later commands on the same and the next line searched for a run of a
#: downloaded or decoded file.
_MAX_AFTER = 32


def _command_tokens(segment: str) -> list[str]:
    """Whitespace tokens of *segment* after wrappers (``sudo``, ``env X=y`` …)."""
    # In Markdown the command ends where its inline-code span does.
    segment = segment.lstrip().lstrip("`").split("`", 1)[0]
    tokens = [t.strip("'\"()") for t in segment.split()[:64]]
    tokens = [t for t in tokens if t]
    i = 0
    while i < len(tokens):
        word = tokens[i]
        if word in _WRAPPERS or _ENV_ASSIGN_RE.match(word):
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            continue
        break
    return tokens[i:]


def _program(word: str) -> str:
    """``/usr/bin/bash`` and ``bash.exe`` → ``bash``."""
    name = word.replace("\\", "/").rsplit("/", 1)[-1]
    return name[:-4] if name.lower().endswith(".exe") else name


def runs_stdin(segment: str) -> bool:
    """True when *segment* executes what is piped into it.

    ``bash``, ``sudo -E bash``, ``bash -s -- --flag``, ``python3 -``, ``node``
    and PowerShell ``iex`` run their stdin.  ``bash -c '…'``, ``python3 -c
    '…'``, ``node -e '…'`` and ``python3 script.py`` run something else and
    read stdin as data, so a ``curl … | python3 -c 'parse json'`` is not an
    install step.
    """
    tokens = _command_tokens(segment)
    if not tokens:
        return False
    program = _program(tokens[0])
    if program.lower() in {"iex", "invoke-expression"}:
        return True
    if program == "source":
        return True
    is_shell = program in _SHELLS
    if not (is_shell or program in _INTERPRETERS or _PYTHON_RE.match(program)):
        return False
    for arg in tokens[1:]:
        if arg == "--":
            break
        if arg == "-":
            return True
        if arg in _INLINE_CODE_FLAGS:
            return False
        if arg.startswith("-"):
            short = arg[1:] if not arg.startswith("--") else ""
            if is_shell and "s" in short:
                return True
            if is_shell and "c" in short:
                return False
            continue
        return False  # a script file: stdin is its data
    return True


def _basename(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1]


def _files_run(segment: str) -> frozenset[str]:
    """Base names of the files *segment* runs or makes executable.

    ``./helper`` and ``/tmp/t.sh`` run themselves; ``bash t.sh`` and ``python3
    t.py`` run their first non-flag argument; ``chmod +x t.sh`` and PowerShell
    ``Start-Process``/``&`` name the file they act on.
    """
    tokens = _command_tokens(segment)
    if not tokens:
        return frozenset()
    head = tokens[0]
    out: set[str] = set()
    if "/" in head or "\\" in head:
        out.add(_basename(head))  # ./helper, /tmp/t.sh
    program = _program(head)
    if program == "&" and len(tokens) > 1:
        out.add(_basename(tokens[1]))
    elif program == "chmod" or program.lower() == "start-process":
        out.update(_basename(t) for t in tokens[1:])
    elif program in _SHELLS or program in _INTERPRETERS or _PYTHON_RE.match(program):
        for token in tokens[1:]:
            if not token.startswith("-"):
                out.add(_basename(token))
                break
    return frozenset(out)


#: Lower-case literals, at least one of which every match of each SKILL-005
#: pattern contains.  A file that holds none of a pattern's literals cannot
#: match it, so the pattern is not run on that file's lines: most files skip
#: every per-line pattern.  ``tests/test_install_steps.py`` runs every fixture
#: with and without these gates and requires identical results; update the
#: literals whenever a pattern changes.
_GATE_LITERALS: dict[str, tuple[str, ...]] = {
    "fetch": ("curl", "wget", "iwr", "irm", "invoke-", "download"),
    "decode": ("base64", "xxd", "certutil"),
    "ps_encoded": ("powershell", "pwsh"),
    "ps_b64": ("frombase64string",),
    "js": ("atob", "buffer.from"),
    "marshal": ("marshal",),
    "archive": ("unzip", "7z", "unrar", "setpassword", "pwd"),
    "persistence": (
        "cron",
        "launch",
        "systemd",
        "schtasks",
        "scheduledtask",
        "currentversion",
    ),
    "reverse": ("/dev/tcp", "/bin/", ">&", "socat"),
    "url": ("://",),
    "dns": ("txt",),
    "py_decode": ("decode", "unhexlify", "fromhex", "decompress", "a2b_"),
}
_ALL_GATES = frozenset(_GATE_LITERALS)
#: Gates used by the window rules rather than the per-line rules.
_WINDOW_GATES = frozenset({"dns", "py_decode"})
#: Off only in the parity test.
_GATING = True


def gates_for(text: str) -> frozenset[str]:
    """The SKILL-005 pattern groups that could match somewhere in *text*."""
    if not _GATING:
        return _ALL_GATES
    low = text.lower()
    return frozenset(
        name
        for name, literals in _GATE_LITERALS.items()
        if any(lit in low for lit in literals)
    )


class _Line:
    """One logical line split into shell segments, with per-segment caches.

    Every segment is tokenised at most twice (stdin check, files run), so a
    line of thousands of segments stays linear.
    """

    def __init__(self, line: str, next_line: str) -> None:
        self.text = line
        self.segments = _split_segments(line)
        self._next_line = next_line
        self._runs: dict[int, frozenset[str]] = {}
        self._stdin: dict[int, bool] = {}
        self._next_runs: list[frozenset[str]] | None = None

    def pipeline(self, idx: int) -> list[int]:
        """Indexes of the segments joined to *idx* by a single ``|`` (bounded)."""
        out: list[int] = []
        for j in range(idx + 1, min(idx + 1 + _MAX_PIPELINE, len(self.segments))):
            if self.segments[j][0] != "|":
                break
            out.append(j)
        return out

    def runs_stdin(self, j: int) -> bool:
        """Cached :func:`runs_stdin` of segment *j*."""
        if j not in self._stdin:
            self._stdin[j] = runs_stdin(self.segments[j][1])
        return self._stdin[j]

    def _files(self, j: int) -> frozenset[str]:
        if j not in self._runs:
            self._runs[j] = _files_run(self.segments[j][1])
        return self._runs[j]

    def after(self, start: int, *, next_line: bool) -> list[frozenset[str]]:
        """Run sets of up to ``_MAX_AFTER`` segments from *start*, plus next line."""
        end = min(start + _MAX_AFTER, len(self.segments))
        runs = [self._files(j) for j in range(start, end)]
        if next_line:
            if self._next_runs is None:
                self._next_runs = [
                    _files_run(seg)
                    for _sep, seg in _split_segments(self._next_line)[:_MAX_AFTER]
                ]
            runs += self._next_runs
        return runs

    def stage_runs_target(
        self, idx: int, pipeline: list[int], *, next_line: bool
    ) -> bool:
        """True when the stage at *idx* writes a file that a later command runs."""
        stage = " | ".join(self.segments[j][1] for j in [idx, *pipeline])
        targets = [t.group(1) for t in _OUTPUT_TARGET_RE.finditer(stage)]
        if not targets:
            return False
        start = (pipeline[-1] if pipeline else idx) + 1
        after = self.after(start, next_line=next_line)
        return any(_target_runs(t, after) for t in targets)


def _target_runs(target: str, runs: list[frozenset[str]]) -> bool:
    """True when one of the *runs* sets names the file *target* points at."""
    base = _basename(target)
    if len(base) < 3 or base in {"null", "tmp", "dev", "stdout", "stderr"}:
        return False
    return any(base in names for names in runs)


def _fetch_hits(ln: _Line, dockerfile: bool) -> list[tuple[Severity, str]]:
    """A remote fetch whose content is executed, and TLS-off fetches.

    Severity: HIGH when the fetch switches off TLS checks, decodes what it
    downloaded, uses plaintext or a raw IP host.  Otherwise LOW, or INFO for a
    known vendor installer or a Dockerfile ``RUN`` line (a container build).
    Piping a vendor's installer into a shell is common in ordinary skills, so a
    plain ``curl … | sh`` is not raised above LOW (measured; GAPS.md).
    """
    hits: list[tuple[Severity, str]] = []
    for idx, (_sep, seg) in enumerate(ln.segments):
        m = _FETCH_RE.search(seg)
        if m is None:
            continue
        first_url = URL_RE.search(seg)
        url = parse_url(first_url.group(0)) if first_url else None
        insecure = bool(
            _CURL_RE.search(seg) and _CURL_INSECURE_RE.search(seg[m.end() :])
        ) or bool(_OTHER_INSECURE_RE.search(seg))
        if insecure and url is not None and is_loopback(url.host):
            insecure = False

        pipeline = ln.pipeline(idx)
        how = ""
        if any(ln.runs_stdin(j) for j in pipeline):
            how = "piped into a shell or interpreter"
        elif _SUBST_SINK_RE.search(seg[max(0, m.start() - 120) : m.start()]):
            how = "executed through command substitution"
        elif ln.stage_runs_target(idx, pipeline, next_line=True):
            how = "downloaded to a file that is then run"

        if not how:
            if insecure:
                hits.append((Severity.HIGH, "TLS certificate checks switched off"))
            continue

        reasons = [f"remote content {how}"]
        severity = Severity.LOW
        if insecure:
            severity = Severity.HIGH
            reasons.append("TLS certificate checks switched off")
        if any(_DECODE_CMD_RE.search(ln.segments[j][1]) for j in pipeline):
            severity = Severity.HIGH
            reasons.append("the download is decoded before it runs")
        if url is not None and url.scheme in {"http", "ftp", "ws"}:
            severity = Severity.HIGH
            reasons.append("over plaintext")
        if url is not None and is_public_ip(url.host):
            severity = Severity.HIGH
            reasons.append("from a raw IP address")
        if severity == Severity.LOW:
            if url is not None and is_vendor_installer(url):
                severity = Severity.INFO
                reasons.append(f"from the vendor installer at {url.host}")
            elif dockerfile:
                severity = Severity.INFO
                reasons.append("in a container build (Dockerfile RUN)")
            elif url is not None and url.host:
                reasons.append(f"from {url.host}")
        hits.append((severity, "; ".join(reasons)))
    return hits


def _decode_exec_hits(
    ln: _Line, active: frozenset[str] = _ALL_GATES
) -> list[tuple[Severity, str]]:
    """Decode-then-execute chains on one logical line."""
    hits: list[tuple[Severity, str]] = []
    line = ln.text
    if "decode" in active and _DECODE_CMD_RE.search(line):
        hits.extend(_decode_pipeline_hits(ln))
    if not hits and "decode" in active and _EVAL_DECODE_RE.search(line):
        hits.append((Severity.HIGH, "base64-decoded text passed to eval or sh -c"))
    if "ps_encoded" in active and _PS_ENCODED_RE.search(line):
        hits.append((Severity.HIGH, "PowerShell runs an encoded command"))
    if "ps_b64" in active and _PS_B64_RE.search(line) and _PS_IEX_RE.search(line):
        hits.append((Severity.HIGH, "PowerShell decodes base64 and invokes it"))
    if "js" in active and _JS_DECODE_EXEC_RE.search(line):
        hits.append((Severity.HIGH, "decoded data passed to eval/Function"))
    return hits


def _decode_pipeline_hits(ln: _Line) -> list[tuple[Severity, str]]:
    """A decode command whose output is piped to a shell or saved and run."""
    hits: list[tuple[Severity, str]] = []
    for idx, (_sep, seg) in enumerate(ln.segments):
        if not _DECODE_CMD_RE.search(seg):
            continue
        pipeline = ln.pipeline(idx)
        if any(ln.runs_stdin(j) for j in pipeline):
            hits.append((Severity.HIGH, "decoded content piped into a shell"))
            break
        if ln.stage_runs_target(idx, pipeline, next_line=False):
            hits.append((Severity.HIGH, "decoded content written to a file and run"))
            break
    return hits


def _line_hits(
    line: str,
    next_line: str,
    dockerfile: bool,
    active: frozenset[str] = _ALL_GATES,
) -> list[tuple[Severity, str]]:
    hits: list[tuple[Severity, str]] = []
    ln = _Line(line, next_line)
    if "fetch" in active and _FETCH_RE.search(line):
        hits.extend(_fetch_hits(ln, dockerfile))
    hits.extend(_decode_exec_hits(ln, active))
    if "marshal" in active and _MARSHAL_RE.search(line):
        hits.append((Severity.HIGH, "marshal.loads loads Python bytecode"))
    if "archive" in active and _ARCHIVE_PASSWORD_RE.search(line):
        hits.append((Severity.HIGH, "an archive is opened with a password"))
    if "persistence" in active and _PERSISTENCE_RE.search(line):
        hits.append(
            (Severity.HIGH, "writes a scheduled job or login item (persistence)")
        )
    if "reverse" in active and _REVERSE_SHELL_RE.search(line):
        hits.append((Severity.HIGH, "reverse-shell shape"))
    if "url" in active:
        for raw in URL_RE.findall(line):
            url = parse_url(raw)
            if is_public_ip(url.host):
                hits.append(
                    (Severity.HIGH, f"endpoint is a raw IP address ({url.host})")
                )
                break
    return hits


def _window_hits(
    lines: list[tuple[int, str]],
    first: re.Pattern[str],
    second: re.Pattern[str],
    span: int,
) -> list[int]:
    """Line numbers where *first* matches and *second* matches within *span*."""
    marks = [bool(second.search(text)) for _num, text in lines]
    out: list[int] = []
    for i, (num, text) in enumerate(lines):
        if first.search(text) and any(marks[max(0, i - span) : i + span + 1]):
            out.append(num)
    return out


def install_step_hits(rel: str, text: str) -> list[Hit]:
    """Every SKILL-005 hit in one text file: one per line, highest first.

    Matching runs on a homoglyph-folded copy (``normalize_for_detection``);
    evidence keeps the original line.  A LOW shape in a sentence that advises
    against it ("never pipe … into bash") drops to INFO and says so; HIGH
    shapes are never softened.
    """
    # ASCII text has nothing to fold (no confusables, combining marks or
    # format characters), so skip the per-character pass.
    norm = text if text.isascii() else normalize_for_detection(text)
    original = text.split("\n")
    matched = norm if norm.count("\n") == text.count("\n") else text
    active = gates_for(matched)
    if not active:
        return []
    lines = logical_lines(matched)
    name = rel.rsplit("/", 1)[-1].lower()
    dockerfile = name.startswith(("dockerfile", "containerfile")) or name.endswith(
        ".dockerfile"
    )
    by_line: dict[int, Hit] = {}
    advised_against: dict[int, bool] = {}

    def is_negated(num: int, source: str) -> bool:
        # Once per line: a long line can produce many hits.
        if num not in advised_against:
            cut = _COMMAND_START_RE.search(source, 0, LINE_CAP)
            previous = original[num - 2][-400:] if num >= 2 else ""
            before = source[: cut.start() if cut else 0][-400:]
            advised_against[num] = negated(previous + "\n" + before)
        return advised_against[num]

    def add(num: int, severity: Severity, reason: str) -> None:
        source = original[num - 1] if 0 < num <= len(original) else ""
        if severity != Severity.HIGH and is_negated(num, source):
            severity = Severity.INFO
            reason += " (in a sentence that advises against it)"
        hit = by_line.setdefault(num, Hit(num, severity, [], source[:LINE_CAP]))
        raised = rank(severity) > rank(hit.severity)
        if raised:
            hit.severity = severity
        if reason not in hit.reasons:
            if len(hit.reasons) < _MAX_REASONS:
                hit.reasons.append(reason)
            elif raised:
                hit.reasons[-1] = reason  # keep the reason for the severity

    line_gates = active - _WINDOW_GATES
    for i, (num, line) in enumerate(lines):
        if not line_gates:
            break
        next_line = lines[i + 1][1] if i + 1 < len(lines) else ""
        for severity, reason in _line_hits(line, next_line, dockerfile, active):
            add(num, severity, reason)
    if "dns" in active:
        for num in _window_hits(lines, _DNS_TXT_RE, _EXEC_SINK_RE, 5):
            add(num, Severity.HIGH, "a DNS TXT record is fetched and executed")
    if "py_decode" in active:
        for num in _window_hits(lines, _PY_DECODE_RE, _PY_EXEC_RE, 3):
            add(num, Severity.HIGH, "decoded data passed to exec/eval/compile")
    return sorted(by_line.values(), key=lambda h: (-rank(h.severity), h.line))


# ── SKILL-006 text shapes ─────────────────────────────────────────────────────

#: A harness started with permission prompts off, or a settings value that
#: does it.  Command words are matched case-sensitively (the binaries are
#: lower-case; "Gemini CLI" in prose is not an invocation), and a flag named in
#: a table or a sentence without its command is not an instruction to run it.
_SKIP_PERMISSIONS_RE = re.compile(
    r"(?<![\w.-])(?:claude|claude-code)(?![\w-])[^\n|;&]{0,300}?\s"
    r"(?:--dangerously-skip-permissions\b|--permission-mode[= ]{1,3}[\"']?"
    r"bypassPermissions\b)"
    r"|(?<![\w.-])codex(?![\w-])[^\n|;&]{0,300}?\s"
    r"(?:--dangerously-bypass-approvals-and-sandbox|--yolo)\b"
    r"|(?<![\w.-])(?:gemini|qwen)(?![\w-])[^\n|;&]{0,300}?\s"
    r"(?:--yolo\b|--approval-mode[= ]{1,3}[\"']?yolo\b)"
    r"|[\"']defaultMode[\"']\s{0,5}[:=]\s{0,5}[\"']bypassPermissions[\"']"
    r"|\[\s{0,3}[\"']defaultMode[\"']\s{0,3}\]\s{0,3}=\s{0,3}[\"']bypassPermissions"
    r"|^[ \t]{0,40}defaultMode[ \t]{0,5}:[ \t]{0,5}[\"']?bypassPermissions\b"
    r"|[\"']?skipDangerousModePermissionPrompt[\"']?\s{0,5}[:=]\s{0,5}true\b",
    re.MULTILINE,
)
_BASE_URL_RE = re.compile(
    r"(?<![A-Za-z0-9_])(ANTHROPIC_[A-Z0-9_]{0,40}BASE_URL|OPENAI_BASE_URL"
    r"|GOOGLE_GEMINI_BASE_URL|GEMINI_BASE_URL|GOOGLE_VERTEX_BASE_URL)[\"']?"
    r"\s{0,5}[:=]\s{0,5}[\"']?((?:https?|wss?)://[^\s\"'`]{1,2048})"
)
_VERTEX_HOST_RE = re.compile(r"^(?:[a-z0-9-]{1,63}-)?aiplatform\.googleapis\.com$")
_FIRST_PARTY: dict[str, re.Pattern[str]] = {
    "ANTHROPIC_BASE_URL": re.compile(r"^api\.anthropic\.com$"),
    "ANTHROPIC_BEDROCK_BASE_URL": re.compile(
        r"^bedrock-runtime(?:-fips)?\.[a-z0-9-]{1,63}\.amazonaws\.com(?:\.cn)?$"
    ),
    "ANTHROPIC_VERTEX_BASE_URL": _VERTEX_HOST_RE,
    "ANTHROPIC_FOUNDRY_BASE_URL": re.compile(
        r"^[a-z0-9-]{1,63}\.services\.ai\.azure\.com$"
    ),
    "OPENAI_BASE_URL": re.compile(r"^api\.openai\.com$"),
    "GOOGLE_GEMINI_BASE_URL": re.compile(r"^generativelanguage\.googleapis\.com$"),
    "GEMINI_BASE_URL": re.compile(r"^generativelanguage\.googleapis\.com$"),
    "GOOGLE_VERTEX_BASE_URL": _VERTEX_HOST_RE,
}
_OTHER_ANTHROPIC_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.){0,5}anthropic\.com$")


def base_url_is_first_party(name: str, value: str) -> bool:
    """True when *value* is the vendor's endpoint for *name*, or loopback."""
    url = parse_url(value)
    if url.host is None:
        return False
    if is_loopback(url.host):
        return True
    if url.scheme != "https":
        return False
    return bool(_FIRST_PARTY.get(name, _OTHER_ANTHROPIC_RE).match(url.host))


@dataclass(frozen=True)
class TextShape:
    """A SKILL-006 shape found in prose."""

    line: int
    kind: str  # "permissions" | "base-url"
    variable: str
    source: str


def text_shape_hits(text: str, limit: int = 50) -> list[TextShape]:
    """SKILL-006 shapes: switching permission prompts off; API base-URL redirects.

    A permissions instruction in a sentence that advises against it
    ("do not use --dangerously-skip-permissions") is skipped.  At most *limit*
    lines of each kind are returned, one shape per line and kind.
    """
    lines = text.split("\n")
    out: list[TextShape] = []

    def line_numbers() -> Callable[[int], int]:
        # Matches arrive in order, so count newlines since the previous one
        # instead of from the start (which is quadratic on a match-dense file).
        state = [0, 1]

        def at(pos: int) -> int:
            state[1] += text.count("\n", state[0], pos)
            state[0] = pos
            return state[1]

        return at

    at = line_numbers()
    last = 0
    for m in _SKIP_PERMISSIONS_RE.finditer(text):
        if negated(text[max(0, m.start() - 200) : m.start()]):
            continue
        num = at(m.start())
        if num != last:
            last = num
            out.append(TextShape(num, "permissions", "", lines[num - 1][:LINE_CAP]))
            if len(out) >= limit:
                break
    found = len(out)
    at = line_numbers()
    last = 0
    for m in _BASE_URL_RE.finditer(text):
        name, value = m.group(1), m.group(2)
        if base_url_is_first_party(name, value):
            continue
        num = at(m.start())
        if num != last:
            last = num
            out.append(TextShape(num, "base-url", name, lines[num - 1][:LINE_CAP]))
            if len(out) - found >= limit:
                break
    return out


# ── SKILL-007 inputs: bytes and blobs ─────────────────────────────────────────

IMAGE_EXT = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff"}
)
FONT_EXT = frozenset({".ttf", ".otf", ".woff", ".woff2", ".ttc"})
MEDIA_EXT = frozenset(
    {".mp3", ".mp4", ".m4a", ".mov", ".wav", ".ogg", ".webm", ".flac", ".avi"}
)
DOCUMENT_EXT = frozenset(
    {".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub"}
)
ARCHIVE_EXT = frozenset(
    {
        ".zip",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".zst",
        ".tar",
        ".cab",
        ".jar",
        ".whl",
        ".egg",
        ".apk",
        ".vsix",
        ".xpi",
        ".crx",
        ".nupkg",
        ".mcpb",
        ".dxt",
    }
)
CLAIMED_EXT = IMAGE_EXT | FONT_EXT | MEDIA_EXT | DOCUMENT_EXT | ARCHIVE_EXT
_OFFICE_EXT = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub"})
#: Families whose content is ordinary in a skill and never reported.
BENIGN_FAMILIES = frozenset({"image", "font", "media", "document", "data"})


def expected_family(ext: str) -> str | None:
    """The family a file extension claims, if it claims one."""
    if ext in IMAGE_EXT:
        return "image"
    if ext in FONT_EXT:
        return "font"
    if ext in MEDIA_EXT:
        return "media"
    if ext in DOCUMENT_EXT:
        return "document"
    if ext in ARCHIVE_EXT:
        return "archive"
    return None


_SIMPLE_MAGIC: tuple[tuple[bytes, str, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image", "PNG image"),
    (b"\xff\xd8\xff", "image", "JPEG image"),
    (b"GIF87a", "image", "GIF image"),
    (b"GIF89a", "image", "GIF image"),
    (b"II*\x00", "image", "TIFF image"),
    (b"MM\x00*", "image", "TIFF image"),
    (b"%PDF-", "document", "PDF"),
    (b"\x00\x01\x00\x00", "font", "font"),
    (b"OTTO", "font", "font"),
    (b"true", "font", "font"),
    (b"ttcf", "font", "font"),
    (b"wOFF", "font", "font"),
    (b"wOF2", "font", "font"),
    (b"ID3", "media", "audio"),
    (b"OggS", "media", "audio"),
    (b"fLaC", "media", "audio"),
    (b"\x1aE\xdf\xa3", "media", "video"),
    (b"SQLite format 3\x00", "data", "SQLite database"),
    (b"\x93NUMPY", "data", "array data"),
    (b"PAR1", "data", "Parquet data"),
    (b"\x89HDF\r\n\x1a\n", "data", "HDF5 data"),
    (b"\x00\x00\x00\x01Bud1", "data", ".DS_Store"),
    (b"\xde\x12\x04\x95", "data", "gettext catalogue"),
    (b"\x95\x04\x12\xde", "data", "gettext catalogue"),
    (b"\x1f\x8b", "archive", "gzip archive"),
    (b"\xfd7zXZ\x00", "archive", "xz archive"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "7-Zip archive (encryption not checked)"),
    (b"Rar!\x1a\x07", "archive", "RAR archive (encryption not checked)"),
    (b"\x28\xb5\x2f\xfd", "archive", "zstd archive"),
    (b"MSCF", "archive", "CAB archive"),
    (b"\x7fELF", "compiled", "ELF executable or library"),
    (b"\xfe\xed\xfa\xce", "compiled", "Mach-O executable or library"),
    (b"\xfe\xed\xfa\xcf", "compiled", "Mach-O executable or library"),
    (b"\xce\xfa\xed\xfe", "compiled", "Mach-O executable or library"),
    (b"\xcf\xfa\xed\xfe", "compiled", "Mach-O executable or library"),
    (b"\xca\xfe\xba\xbe", "compiled", "Mach-O universal binary or Java class"),
    (b"\x00asm", "compiled", "WebAssembly module"),
    (b"MZ", "compiled", "Windows executable"),
)


def identify(head: bytes, ext: str) -> tuple[str, str]:
    """Return ``(family, label)`` for a non-text file's leading bytes.

    Families: image, font, media, document, data, archive,
    archive-encrypted, compiled, compiled-pyc, unknown.
    """
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        if ext in _OFFICE_EXT:
            return "document", "office document"
        if head.startswith(b"PK\x03\x04") and len(head) > 6 and head[6] & 0x01:
            return "archive-encrypted", "password-protected ZIP archive"
        return "archive", "ZIP archive"
    if head.startswith(b"RIFF") and head[8:12] in {b"WEBP", b"WAVE", b"AVI "}:
        return (
            ("image", "WebP image")
            if head[8:12] == b"WEBP"
            else ("media", "audio/video")
        )
    if head[4:8] == b"ftyp":
        return "media", "audio/video"
    if head.startswith(b"BM") and ext == ".bmp":
        return "image", "BMP image"
    if head.startswith(b"\x00\x00\x01\x00") and ext in {".ico", ".cur"}:
        return "image", "icon"
    if head[:2] in {b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"} and ext == ".mp3":
        return "media", "audio"
    if head.startswith(b"BZh") and ext in {".bz2", ".tbz", ".tbz2"}:
        return "archive", "bzip2 archive"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "archive", "tar archive"
    if ext == ".pyc" and head[2:4] == b"\r\n":
        return "compiled-pyc", "compiled Python"
    for magic, family, label in _SIMPLE_MAGIC:
        if head.startswith(magic):
            return family, label
    return "unknown", "unrecognised binary format"


def entropy(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def decode_text(data: bytes) -> str | None:
    """Return *data* as text, or ``None`` when it is binary."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:8192]:
        return None
    text = data.decode("utf-8", errors="replace")
    bad = text.count("\ufffd")
    if bad > 2 and bad > len(text) // 100:
        return None
    return text


_B64_RUN_RE = re.compile(rf"[A-Za-z0-9+/]{{{BLOB_RUN},}}")
_B64_LINE_RE = re.compile(r"^[A-Za-z0-9+/]{60,200}={0,2}$")
_HEX_RUN_RE = re.compile(rf"[0-9a-fA-F]{{{HEX_RUN},}}")


def _decoded_family(sample: str, hexa: bool) -> str:
    try:
        if hexa:
            head = bytes.fromhex(sample[:64])
        else:
            chunk = sample[:64]
            head = base64.b64decode(chunk + "=" * (-len(chunk) % 4))
    except (ValueError, binascii.Error):
        return "unknown"
    return identify(head, "")[0]


def blob_in_text(text: str) -> str | None:
    """Describe an encoded payload hidden in *text*, or return ``None``.

    A base64 run (or a block of wrapped base64 lines) or a hex run whose
    decoded bytes do not start with an image, font, media, document or data
    signature.  ``data:image/png;base64,…``, notebook outputs and embedded
    fonts decode to a known signature and are skipped; PEM blocks are skipped.
    """
    for m in _B64_RUN_RE.finditer(text):
        if _decoded_family(m.group(0), hexa=False) not in BENIGN_FAMILIES:
            return f"a {len(m.group(0)):,}-character base64 run"
    run, first, in_pem = 0, "", False
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("-----BEGIN "):
            in_pem, run = True, 0
            continue
        if stripped.startswith("-----END "):
            in_pem, run = False, 0
            continue
        if in_pem or not _B64_LINE_RE.match(stripped):
            run = 0
            continue
        if run == 0:
            first = stripped
        run += 1
        if (
            run == BLOB_LINES
            and _decoded_family(first, hexa=False) not in BENIGN_FAMILIES
        ):
            return f"{BLOB_LINES}+ consecutive lines of base64"
    for m in _HEX_RUN_RE.finditer(text):
        if _decoded_family(m.group(0), hexa=True) not in BENIGN_FAMILIES:
            return f"a {len(m.group(0)):,}-character hex run"
    return None
