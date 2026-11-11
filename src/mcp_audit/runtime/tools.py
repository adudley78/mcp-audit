"""Runtime tool-list check for ``mcp-audit run`` (EPIC-0009 Story 1.4).

The relay hands this module every JSON-RPC line in both directions. When the
server answers a ``tools/list`` request, the tools it lists are digested the
way ``mcp-audit lock --connect`` digests them and compared with the server's
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

``notifications/tools/list_changed`` passes through; the client's next
``tools/list`` is compared afresh. A paginated list is compared as a whole:
added and changed tools are judged page by page, removed tools once the
last page (no ``nextCursor``) has arrived.

Only lines that parse as JSON-RPC objects are inspected; anything else
passes untouched. Enforce mode rewrites a ``tools/list`` response only when
it withholds something, so an unchanged server's bytes are relayed exactly.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Callable

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
_FIX = "review the change; if approved, run `mcp-audit lock --accept --connect`"
_FIX_NO_RECORD = "run `mcp-audit lock --connect` to record this server's tools"


def _say(message: str) -> None:
    try:
        sys.stderr.write(f"mcp-audit run: {message}\n")
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
    """

    def __init__(
        self,
        server_name: str,
        tools_record: dict | None,
        *,
        enforce: bool,
        report: Callable[[str], None] = _say,
        poison: object | None = None,
    ) -> None:
        self.server_name = server_name
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

        Returns:
            ``(to_server, to_client)``: the line to forward (``None`` to drop
            it) and a reply to send the client instead (``None`` for none).
        """
        msg = _parse(line)
        if msg is None:
            return line, None
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "tools/list" and msg_id is not None:
            params = msg.get("params")
            new_listing = not (isinstance(params, dict) and params.get("cursor"))
            with self._lock:
                self._pending[_key(msg_id)] = new_listing
            return line, None
        if method == "tools/call" and msg_id is not None and self.enforce:
            params = msg.get("params")
            name = params.get("name") if isinstance(params, dict) else None
            with self._lock:
                allowed = isinstance(name, str) and name in self.approved
                finding = self.withheld.get(name) if isinstance(name, str) else None
            if not allowed:
                return None, _denial(msg_id, name, finding)
        return line, None

    # ── server → client ────────────────────────────────────────────────────

    def server_line(self, line: bytes) -> bytes:
        """Inspect one server line; return what the client should receive."""
        msg = _parse(line)
        if msg is None or "id" not in msg or "result" not in msg:
            return line
        with self._lock:
            new_listing = self._pending.pop(_key(msg["id"]), None)
        if new_listing is None:
            return line
        result = msg["result"]
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return line
        return self._check_page(msg, result, tools, new_listing=new_listing, raw=line)

    def _check_page(
        self, msg: dict, result: dict, tools: list, *, new_listing: bool, raw: bytes
    ) -> bytes:
        valid = [t for t in tools if isinstance(t, dict)]
        definitions = [wire_definition(t) for t in valid]
        current = digests_of_definitions(definitions)
        # The same tools as a lock written under mcp SDK 2.x digests them
        # (non-spec annotation keys dropped); a match in either form counts.
        spec_only = digests_of_definitions(
            [wire_definition(t, spec_annotations_only=True) for t in valid]
        )
        last_page = not result.get("nextCursor")

        with self._lock:
            if new_listing:
                self._seen = set()
                self._withheld_now = {}
                self._approved_now = set()
            self._seen.update(current)
            if self.record is None:
                page_withheld = dict.fromkeys(current, "RUN-003")
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
        if self.poison is not None:
            hits = self.poison.over_threshold(  # type: ignore[attr-defined]
                [d for d in definitions if d["name"] not in page_withheld]
            )
            for name, (finding, severity) in hits.items():
                page_withheld[name] = finding
                self._poison_severity[name] = severity

        with self._lock:
            self._withheld_now.update(page_withheld)
            page_approved = set(current) - set(page_withheld)
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

        if not (self.enforce and page_withheld):
            return raw
        kept = [
            t
            for t in tools
            if not (isinstance(t, dict) and str(t.get("name", "")) in page_withheld)
        ]
        filtered = dict(msg)
        filtered["result"] = {**result, "tools": kept}
        return (
            json.dumps(filtered, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            + b"\n"
        )

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
                "`mcp-audit lock --accept --connect`"
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
                "read the tool's text with `mcp-audit scan --connect`; if it's a "
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


def _parse(line: bytes) -> dict | None:
    """Parse one JSON-RPC line, or ``None`` when it isn't a JSON object."""
    try:
        msg = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        return None
    return msg if isinstance(msg, dict) else None


def _key(msg_id: object) -> str:
    """A hashable, type-preserving key for a JSON-RPC id (1 and "1" differ)."""
    return json.dumps(msg_id, sort_keys=True)


def _denial(msg_id: object, name: object, finding: str | None) -> bytes:
    """The JSON-RPC error a withheld tool's ``tools/call`` gets instead.

    *finding* is ``None`` for a tool no checked ``tools/list`` has shown yet.
    """
    if finding is None:
        why = "it hasn't appeared in a tools/list mcp-audit has checked"
        message = f"mcp-audit withheld tool {name!r}: {why}"
    else:
        why = _WHY.get(finding, "its text matches a poisoning pattern")
        message = f"mcp-audit withheld tool {name!r}: {finding}, {why}"
    reply = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": DENIED_TOOL_CODE,
            "message": message,
            "data": {"finding": finding, "tool": name},
        },
    }
    return json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
