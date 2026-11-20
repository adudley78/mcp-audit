"""Runtime tool-list check for ``credenzo run`` (EPIC-0009 Story 1.4).

The relay hands this module every JSON-RPC line in both directions. When the
server answers a ``tools/list`` request, the tools it lists are digested the
way ``credenzo lock --connect`` digests them and compared with the server's
record in ``mcp-lock.json``, raising the same findings ``lock --verify
--connect`` raises:

=========  ========  ===============================================
ID         Severity  Meaning
=========  ========  ===============================================
LOCK-006   HIGH      A tool that wasn't there when the tools were locked
LOCK-007   HIGH      A tool's schema or annotations changed
LOCK-008   MEDIUM    Only a tool's description or title changed
LOCK-009   LOW       A locked tool is gone
RUN-003    HIGH      The lock has no tool record for this server
POISON-*   policy    A tool's live text matches a poisoning pattern at or
                     above ``runtime.poison_threshold`` (default critical;
                     see :mod:`mcp_audit.runtime.poison`)
=========  ========  ===============================================

Monitor mode only reports (one stderr line per change). Enforce mode also
**withholds** added and changed tools: it removes them from the
``tools/list`` result the client sees and answers a ``tools/call`` for one
with a JSON-RPC error naming the finding, without forwarding the call. A
removed tool needs nothing withheld. With no tool record (RUN-003), enforce
mode has no approved tools, so it withholds every tool (EPIC-0009 decision
4: "return the locked tools only").

Enforce mode lets a ``tools/call`` through only for a tool that matched the
lock in a ``tools/list`` it has already checked, so a call made before the
client has listed the tools (real clients list first) is answered with an
error too.

A tool whose text holds a date that moved with the calendar since the lock
(``calendar`` in its lock record, :mod:`mcp_audit.lock.calendar_text`) is not
a change: it is approved and nothing is reported.

``notifications/tools/list_changed`` passes through; the client's next
``tools/list`` is compared afresh. A paginated list is compared as a whole:
added and changed tools are judged page by page, removed tools once the
last page (no ``nextCursor``) has arrived.

A tool that cannot be digested (its definition is past the limits of the
canonical form: 64 levels, 100,000 nodes) cannot equal a lock record, so it
is LOCK-006 when the lock does not hold its name and LOCK-007 when it does.
When a ``tools/list`` answer cannot be checked at all, enforce mode withholds
every tool in that answer and says so; it never forwards an answer that it
did not check.

Only lines that parse as JSON-RPC objects are inspected; anything else
passes untouched. Enforce mode rewrites a ``tools/list`` response only when
it withholds something (a tool, or an entry of the list that is not an
object), so an unchanged server's bytes are relayed exactly.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Callable

from mcp_audit.lock import calendar_text
from mcp_audit.lock.tool_digests import (
    compare,
    digests_of_definitions,
    wire_definition,
)

#: JSON-RPC "Invalid params", which MCP servers use for an unknown tool.
DENIED_TOOL_CODE = -32602

_WHY = {
    "LOCK-006": "added since the tools were locked",
    "LOCK-007": "schema or annotations changed since the tools were locked",
    "LOCK-008": "description or title changed since the tools were locked",
    "RUN-003": "mcp-lock.json has no tool record for this server",
}
_FIX = "review the change; if approved, run `credenzo lock --accept --connect`"
_FIX_NO_RECORD = "run `credenzo lock --connect` to record this server's tools"


def _say(message: str) -> None:
    try:
        sys.stderr.write(f"credenzo run: {message}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def _names(names: list[str], limit: int = 5) -> str:
    shown = ", ".join(repr(n) for n in names[:limit])
    extra = len(names) - limit
    return shown + (f" and {extra} more" if extra > 0 else "")


class ToolGuard:
    """Compares live tool lists with the lock and, in enforce mode, filters.

    Thread-safe: the relay calls :meth:`client_line` from the client-to-server
    thread and :meth:`server_line` from the server-to-client thread.

    Args:
        server_name: The server's name, for messages.
        tools_record: The server's record from the lock's ``tools`` section,
            or ``None`` when the lock has none.
        enforce: Withhold added and changed tools (``--mode enforce``).
        report: Where one-line reports go (stderr by default).
        poison: A :class:`~mcp_audit.runtime.poison.PoisonCheck` (duck-typed:
            ``threshold``, ``over_threshold(definitions)``), or ``None`` to
            skip the POISON-* check.
        today: Returns the date of today as ``YYYY-MM-DD`` (UTC by default),
            for tools whose text holds a date.
    """

    def __init__(
        self,
        server_name: str,
        tools_record: dict | None,
        *,
        enforce: bool,
        report: Callable[[str], None] = _say,
        poison: object | None = None,
        today: Callable[[], str] = calendar_text.today,
    ) -> None:
        self.server_name = server_name
        self._today = today
        self.poison = poison
        self._poison_severity: dict[str, str] = {}
        self.record = tools_record
        self.enforce = enforce
        self._report = report
        self._lock = threading.Lock()
        #: Request ids of ``tools/list`` calls awaiting an answer → whether
        #: the call started a new listing (no cursor).
        self._pending: dict[str, bool] = {}
        #: Tool names seen so far in the listing in progress.
        self._seen: set[str] = set()
        #: Tool name → finding ID for every tool being withheld.
        self.withheld: dict[str, str] = {}
        self._withheld_now: dict[str, str] = {}
        #: Tools that matched the lock in the latest checked listing.
        self.approved: set[str] = set()
        self._approved_now: set[str] = set()
        self._reported: set[tuple[str, tuple[str, ...]]] = set()

    # ── client → server ────────────────────────────────────────────────────

    def client_line(self, line: bytes) -> tuple[bytes | None, bytes | None]:
        """Inspect one client line.

        Never raises. In enforce mode a line that cannot be read as JSON, or
        that fails in this check, is not forwarded: the server's parser could
        read a ``tools/call`` in it that this check did not see. Monitor mode
        forwards every line as it is.

        Returns:
            ``(to_server, to_client)``: the line to forward (``None`` to drop
            it) and a reply to send the client instead (``None`` for none).
        """
        try:
            value = _read(line, strict=self.enforce)
            return self._client_message(value, line)
        except Exception as exc:  # noqa: BLE001 - fail closed, keep the session
            if not self.enforce:
                return line, None
            why = str(exc) if isinstance(exc, _UnreadableError) else type(exc).__name__
            self._report_once(
                ("client-unread",),
                f"withheld: server {self.server_name!r}: a line from the client "
                f"that could not be checked ({why}) was not forwarded",
            )
            return None, None

    def _client_message(
        self, value: object, line: bytes
    ) -> tuple[bytes | None, bytes | None]:
        if isinstance(value, list):
            return self._client_batch(value, line)
        if not isinstance(value, dict):
            return line, None
        msg = value
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "tools/list" and msg_id is not None:
            params = msg.get("params")
            new_listing = not (isinstance(params, dict) and params.get("cursor"))
            with self._lock:
                self._pending[_key(msg_id)] = new_listing
            return line, None
        if method == "tools/call" and self.enforce:
            denial = self._deny_call(msg)
            if denial is not None:
                if msg_id is not None:
                    return None, _encode(denial)
                # A call with no id gets no answer: it is not forwarded.
                self._silent_drop("a tools/call with no id to a withheld tool")
                return None, None
        return line, None

    def _deny_call(self, msg: dict) -> dict | None:
        """Return the error for one ``tools/call``, or ``None`` when it may go on."""
        params = msg.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        with self._lock:
            if isinstance(name, str) and name in self.approved:
                return None
            finding = self.withheld.get(name) if isinstance(name, str) else None
        return _denial(msg.get("id"), name, finding)

    def _client_batch(
        self, messages: list, raw: bytes
    ) -> tuple[bytes | None, bytes | None]:
        """Handle a JSON array from the client (a batch; none since 2025-06-18).

        In enforce mode a batch that holds a ``tools/call`` to a tool that is
        not approved is not forwarded. Each message of the batch that has an
        id gets an error, so the client does not wait for an answer.
        """
        if not self.enforce:
            return raw, None
        calls = [
            m
            for m in messages
            if isinstance(m, dict) and m.get("method") == "tools/call"
        ]
        denials = {id(m): d for m in calls if (d := self._deny_call(m)) is not None}
        # A list inside the batch is not JSON-RPC; it is not searched for calls.
        nested = any(isinstance(m, list) for m in messages)
        if not denials and not nested:
            return raw, None
        replies: list[dict] = []
        for message in messages:
            if not isinstance(message, dict) or message.get("id") is None:
                continue
            if "method" not in message:
                continue  # an answer of the client: no reply is due
            replies.append(
                denials.get(id(message))
                or {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": DENIED_TOOL_CODE,
                        "message": "Credenzo did not forward this batch: it holds "
                        "a call to a tool that is withheld, or a list",
                    },
                }
            )
        if replies:
            return None, _encode(replies)
        self._silent_drop("a batch with a call to a withheld tool, or with a list")
        return None, None

    def _silent_drop(self, what: str) -> None:
        """Say once on stderr that a client line got no answer and went nowhere."""
        self._report_once(
            ("client-drop", what),
            f"withheld: server {self.server_name!r}: {what} was not forwarded",
        )

    # ── server → client ────────────────────────────────────────────────────

    def server_line(self, line: bytes) -> bytes:
        """Inspect one server line; return what the client should receive.

        Never raises. In enforce mode the client gets only what was read and,
        for a tool list, checked:

        - a line that cannot be read as JSON (not JSON, nested too deep, a
          number too long, one key twice in an object) is not forwarded. The
          client's parser can read a line that this one cannot, so such a
          line could carry a tool list past the check;
        - every answer whose ``result`` holds a ``tools`` list is checked,
          also when no ``tools/list`` request with its id was seen;
        - an answer that cannot be checked reaches the client with no tools;
        - a batch (a JSON array) keeps its messages, but each tool list in it
          is emptied: MCP has no batch since protocol 2025-06-18.

        Monitor mode never changes a byte and reports what it can read.
        """
        try:
            value = _read(line, strict=self.enforce)
        except _UnreadableError as exc:
            if not self.enforce:
                return line
            self._report_once(
                ("unreadable",),
                f"withheld: server {self.server_name!r}: a line that could not be "
                f"read as JSON ({exc}) was not forwarded",
            )
            return b""
        try:
            return self._route(value, line)
        except Exception as exc:  # noqa: BLE001 - fail closed, keep the session
            if not self.enforce:
                return line
            self._report_once(
                ("unrouted",),
                f"withheld: server {self.server_name!r}: a message could not be "
                f"checked ({type(exc).__name__}) and was not forwarded",
            )
            return b""

    def _route(self, value: object, line: bytes) -> bytes:
        if isinstance(value, list):
            return self._batch(value, line)
        if not isinstance(value, dict) or "result" not in value:
            return line
        msg = value
        with self._lock:
            new_listing = self._pending.pop(_key(msg.get("id")), None)
        result = msg["result"]
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return line
        if new_listing is None:
            # An answer that nobody asked for is checked as its own listing.
            new_listing = True
        try:
            return self._check_page(
                msg, result, tools, new_listing=new_listing, raw=line
            )
        except Exception as exc:  # noqa: BLE001 - fail closed, keep the session
            return self._unchecked_page(msg, result, tools, exc, raw=line)

    def _batch(self, messages: list, raw: bytes) -> bytes:
        """Handle a JSON array from the server: empty each tool list in it."""
        if not self.enforce:
            return raw
        names: set[str] = set()
        out: list = []
        for item in messages:
            result = item.get("result") if isinstance(item, dict) else None
            tools = result.get("tools") if isinstance(result, dict) else None
            if isinstance(tools, list):
                names.update(
                    str(t.get("name", "")) for t in tools if isinstance(t, dict)
                )
                item = {**item, "result": {**result, "tools": []}}
            out.append(item)
        if out == messages:
            return raw
        with self._lock:
            self.approved.difference_update(names)
            self._approved_now.difference_update(names)
        self._report_once(
            ("batch",),
            f"withheld: server {self.server_name!r}: a tool list inside a batch "
            "is not checked; every tool in it is withheld",
        )
        return _encode(out)

    def _report_once(self, key: tuple[str, ...], message: str) -> None:
        with self._lock:
            if ("", key) in self._reported:
                return
            self._reported.add(("", key))
        self._report(message)

    def _unchecked_page(
        self, msg: dict, result: dict, tools: list, exc: Exception, *, raw: bytes
    ) -> bytes:
        """Handle a ``tools/list`` answer that could not be checked."""
        names = {str(t.get("name", "")) for t in tools if isinstance(t, dict)}
        why = f"the tool list could not be checked ({type(exc).__name__})"
        server = repr(self.server_name)
        if not self.enforce:
            self._report(
                f"monitor: server {server}: {why} (enforce mode would withhold "
                "every tool in this answer)"
            )
            return raw
        with self._lock:
            self.approved.difference_update(names)
            self._approved_now.difference_update(names)
        self._report(
            f"withheld: server {server}: {why}; every tool in this answer is "
            "withheld. Fix: run `credenzo lock --verify --connect` to see the tool"
        )
        filtered = dict(msg)
        filtered["result"] = {**result, "tools": []}
        return _encode(filtered)

    def _check_page(
        self, msg: dict, result: dict, tools: list, *, new_listing: bool, raw: bytes
    ) -> bytes:
        valid = [t for t in tools if isinstance(t, dict)]
        day = self._today()
        # A compared field of the wrong type (a description that is a list,
        # a schema that is a string) is left out of the digest, so the tool
        # could equal a lock record while it carries text that nothing read.
        # Such a tool cannot equal a lock record.
        undigested = {str(t.get("name", "")) for t in valid if not _well_typed(t)}
        valid = [t for t in valid if str(t.get("name", "")) not in undigested]
        try:
            definitions, current, spec_only = _digests(valid, day)
        except ValueError:  # CanonicalError: nested too deeply, or too large
            # A tool that cannot be digested cannot equal a lock record.
            undigested |= {
                str(t.get("name", "")) for t in valid if not _digestable(t, day)
            }
            valid = [t for t in valid if str(t.get("name", "")) not in undigested]
            definitions, current, spec_only = _digests(valid, day)
        last_page = not result.get("nextCursor")

        with self._lock:
            if new_listing:
                self._seen = set()
                self._withheld_now = {}
                self._approved_now = set()
            self._seen.update(current)
            self._seen.update(undigested)
            if self.record is None:
                page_withheld = dict.fromkeys([*current, *undigested], "RUN-003")
                diff = None
            else:
                diff = compare(self.record, current)
                alt = compare(self.record, spec_only)
                alt_changed = set(alt.contract_changed) | set(alt.text_changed)
                diff.contract_changed = [
                    n for n in diff.contract_changed if n in alt_changed
                ]
                diff.text_changed = [n for n in diff.text_changed if n in alt_changed]
                page_withheld = dict.fromkeys(diff.added, "LOCK-006")
                page_withheld.update(dict.fromkeys(diff.contract_changed, "LOCK-007"))
                page_withheld.update(dict.fromkeys(diff.text_changed, "LOCK-008"))
                locked = self.record.get("tools")
                locked = locked if isinstance(locked, dict) else {}
                for name in undigested:
                    page_withheld[name] = "LOCK-007" if name in locked else "LOCK-006"
        if self.poison is not None:
            hits = self.poison.over_threshold(  # type: ignore[attr-defined]
                [d for d in definitions if d["name"] not in page_withheld]
            )
            for name, (finding, severity) in hits.items():
                page_withheld[name] = finding
                self._poison_severity[name] = severity

        with self._lock:
            self._withheld_now.update(page_withheld)
            self._approved_now.difference_update(page_withheld)
            page_approved = set(current) - set(self._withheld_now)
            self._approved_now.update(page_approved)
            removed: list[str] = []
            if last_page:
                if self.record is not None:
                    locked = self.record.get("tools")
                    if isinstance(locked, dict):
                        removed = sorted(set(locked) - self._seen)
                # The listing is complete: it replaces the previous one.
                self.withheld = dict(self._withheld_now)
                self.approved = set(self._approved_now)
            else:
                self.withheld.update(page_withheld)
                self.approved.update(page_approved)
                self.approved.difference_update(page_withheld)

        self._report_page(page_withheld, removed)

        junk = any(not isinstance(t, dict) for t in tools)
        if not (self.enforce and (page_withheld or junk)):
            return raw
        # An entry that is not an object is not a tool: it is not forwarded.
        kept = [
            t
            for t in tools
            if isinstance(t, dict) and str(t.get("name", "")) not in page_withheld
        ]
        filtered = dict(msg)
        filtered["result"] = {**result, "tools": kept}
        return _encode(filtered)

    def _report_page(self, withheld: dict[str, str], removed: list[str]) -> None:
        by_finding: dict[str, list[str]] = {}
        for name, finding in withheld.items():
            by_finding.setdefault(finding, []).append(name)
        if removed:
            by_finding["LOCK-009"] = removed
        order = ["RUN-003", "LOCK-006", "LOCK-007", "LOCK-008", "LOCK-009"]
        order += sorted(f for f in by_finding if f not in order)
        for finding in order:
            names = sorted(by_finding.get(finding, []))
            if not names:
                continue
            key = (finding, tuple(names))
            with self._lock:
                if key in self._reported:
                    continue
                self._reported.add(key)
            self._report(self._message(finding, names))

    def _message(self, finding: str, names: list[str]) -> str:
        server = repr(self.server_name)
        if finding == "LOCK-009":
            return (
                f"{finding} server {server}: tool(s) {_names(names)}: removed since "
                "the tools were locked. Fix: if intended, run "
                "`credenzo lock --accept --connect`"
            )
        if finding == "RUN-003":
            head = f"{finding} server {server}: {_WHY[finding]}"
            fix = _FIX_NO_RECORD
        elif finding not in _WHY:
            severities = sorted({self._poison_severity.get(n, "?") for n in names})
            threshold = getattr(self.poison, "threshold", "?")
            head = (
                f"{finding} server {server}: tool(s) {_names(names)}: text matches "
                f"a {'/'.join(severities)} poisoning pattern (threshold: {threshold})"
            )
            fix = (
                "read the tool's text with `credenzo scan --connect`; if it's a "
                "false positive, raise runtime.poison_threshold in the policy"
            )
        else:
            head = (
                f"{finding} server {server}: tool(s) {_names(names)}: {_WHY[finding]}"
            )
            fix = _FIX
        if self.enforce:
            return f"withheld: {head}. Fix: {fix}"
        return f"monitor: {head} (enforce mode would withhold them). Fix: {fix}"


def _digests(valid: list[dict], day: str) -> tuple[list[dict], dict, dict]:
    """Return the definitions of *valid* and their digests in both forms.

    The second form is the tools as a lock written under mcp SDK 2.x digests
    them (non-spec annotation keys dropped); a match in either form counts.
    """
    definitions = [wire_definition(t) for t in valid]
    current = digests_of_definitions(definitions, day=day)
    spec_only = digests_of_definitions(
        [wire_definition(t, spec_annotations_only=True) for t in valid], day=day
    )
    return definitions, current, spec_only


#: The fields of a tool that the lock compares, by the type that the digest
#: reads. ``None`` (JSON ``null`` or no key) carries no text and is accepted.
_TEXT_FIELDS = ("title", "description")
_OBJECT_FIELDS = ("inputSchema", "outputSchema", "annotations")


def _well_typed(wire: dict) -> bool:
    """Whether each compared field of one tool has the type the digest reads.

    :func:`wire_definition` leaves a field of another type out of the digest.
    A tool with such a field is not approved, because the field can hold text
    that the lock never saw.
    """
    if not isinstance(wire.get("name"), str):
        return False
    if any(not isinstance(wire.get(k), str | None) for k in _TEXT_FIELDS):
        return False
    return all(isinstance(wire.get(k), dict | None) for k in _OBJECT_FIELDS)


def _digestable(wire: dict, day: str) -> bool:
    """Whether one tool, as it arrived, can be digested in both forms."""
    try:
        _digests([wire], day)
    except ValueError:
        return False
    return True


class _UnreadableError(Exception):
    """A server line that cannot be read as JSON."""


def _read(line: bytes, *, strict: bool) -> object:
    """Return the JSON value of one server line (``None`` for a blank line).

    The bytes are decoded as UTF-8 with replacement, as a client does that
    reads the line as text, so a wrong byte cannot hide the line from this
    check. With *strict*, an object that holds one key twice is not readable:
    two parsers can then read two different messages.

    Raises:
        _UnreadableError: The line is not JSON, is nested too deep, holds a
            number that is too long, or (with *strict*) holds one key twice.
    """
    text = line.decode("utf-8", errors="replace")
    if not text.strip():
        return None
    twice: list[bool] = []

    def pairs(items: list[tuple[str, object]]) -> dict:
        out = dict(items)
        if len(out) != len(items):
            twice.append(True)
        return out

    try:
        value = (
            json.loads(text, object_pairs_hook=pairs) if strict else json.loads(text)
        )
    except (ValueError, RecursionError, MemoryError) as exc:
        raise _UnreadableError(type(exc).__name__) from None
    if twice:
        raise _UnreadableError("one key is there twice")
    return value


def _encode(message: object) -> bytes:
    """Return *message* as one line of JSON.

    ASCII only, so a lone surrogate that the server sent as an escape goes
    back out as the same escape and cannot fail the encoding.
    """
    return json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n"


def _key(msg_id: object) -> str:
    """A hashable, type-preserving key for a JSON-RPC id (1 and "1" differ)."""
    return json.dumps(msg_id, sort_keys=True)


def _denial(msg_id: object, name: object, finding: str | None) -> dict:
    """The JSON-RPC error a withheld tool's ``tools/call`` gets instead.

    *finding* is ``None`` for a tool no checked ``tools/list`` has shown yet.
    """
    if finding is None:
        why = "it hasn't appeared in a tools/list Credenzo has checked"
        message = f"Credenzo withheld tool {name!r}: {why}"
    else:
        why = _WHY.get(finding, "its text matches a poisoning pattern")
        message = f"Credenzo withheld tool {name!r}: {finding}, {why}"
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": DENIED_TOOL_CODE,
            "message": message,
            "data": {"finding": finding, "tool": name},
        },
    }
