"""RFC 8785 JSON Canonicalization Scheme (JCS).

Signatures are only meaningful over a byte sequence that every implementation can
reproduce from the parsed document. ``json.dumps(..., sort_keys=True)`` is *almost*
right but sorts object keys by Unicode code point, whereas RFC 8785 §3.2.3 requires
sorting by UTF-16 code unit. The two orders disagree for any key containing a
non-BMP character (U+10000 and above sorts *before* U+E000 in UTF-16, and after it
by code point), so we sort on the UTF-16BE encoding of each key instead.

Stdlib only — the advisory subsystem must work in the PyInstaller binary.

Reference: https://www.rfc-editor.org/rfc/rfc8785
"""

from __future__ import annotations

import math
from typing import Any

__all__ = ["CanonicalError", "canonicalize", "canonicalize_str"]

# Recursion/size bound: a hostile document must refuse cleanly, not traceback.
MAX_DEPTH = 64
MAX_NODES = 100_000

# RFC 8785 §3.2.2.2 — the only two-character escapes JCS emits. Every other control
# character below U+0020 is escaped as \u00xx (lowercase hex).
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalError(ValueError):
    """Document is nested too deeply or too large to canonicalize safely."""


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of a JSON-compatible value.

    Args:
        value: A structure of dict / list / str / int / float / bool / None.

    Returns:
        Canonical UTF-8 bytes, ready to sign.

    Raises:
        TypeError: The structure contains a type JSON cannot represent.
        ValueError: The structure contains NaN or Infinity, which JSON forbids.
        CanonicalError: Nesting or node count exceeds the safety bound.
    """
    return canonicalize_str(value).encode("utf-8")


def canonicalize_str(value: Any) -> str:
    """Return the RFC 8785 canonical form as a ``str``. See :func:`canonicalize`."""
    out: list[str] = []
    _write(value, out, depth=0, nodes=[0])
    return "".join(out)


def _write(value: Any, out: list[str], depth: int, nodes: list[int]) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError(
            f"document is nested too deeply to canonicalize (limit {MAX_DEPTH})"
        )
    nodes[0] += 1
    if nodes[0] > MAX_NODES:
        raise CanonicalError(
            f"document is too large to canonicalize (limit {MAX_NODES} nodes)"
        )
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_serialize_string(value))
    elif isinstance(value, int):
        # bool is a subclass of int but was already handled above.
        out.append(_serialize_number(value))
    elif isinstance(value, float):
        out.append(_serialize_number(value))
    elif isinstance(value, dict):
        _write_object(value, out, depth, nodes)
    elif isinstance(value, (list, tuple)):
        _write_array(value, out, depth, nodes)
    else:
        raise TypeError(f"Not JSON-serializable for JCS: {type(value).__name__}")


def _write_object(value: dict, out: list[str], depth: int, nodes: list[int]) -> None:
    out.append("{")
    first = True
    for key in sorted(value, key=_utf16_sort_key):
        if not isinstance(key, str):
            raise TypeError(
                f"JCS object keys must be strings, got {type(key).__name__}"
            )
        if not first:
            out.append(",")
        first = False
        out.append(_serialize_string(key))
        out.append(":")
        _write(value[key], out, depth + 1, nodes)
    out.append("}")


def _write_array(value: Any, out: list[str], depth: int, nodes: list[int]) -> None:
    out.append("[")
    for index, item in enumerate(value):
        if index:
            out.append(",")
        _write(item, out, depth + 1, nodes)
    out.append("]")


def _utf16_sort_key(key: Any) -> bytes:
    """Sort key that orders strings by UTF-16 code unit, as RFC 8785 §3.2.3 requires.

    Comparing the UTF-16BE encoding bytewise is equivalent to comparing the code unit
    sequence numerically, because UTF-16BE writes the more significant byte first.
    """
    if not isinstance(key, str):
        raise TypeError(f"JCS object keys must be strings, got {type(key).__name__}")
    return key.encode("utf-16-be", errors="surrogatepass")


def _serialize_string(value: str) -> str:
    out = ['"']
    for char in value:
        escape = _ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif char < "\u0020":
            out.append(f"\\u{ord(char):04x}")
        else:
            # RFC 8785 §3.2.2.2: everything else is emitted literally as UTF-8.
            out.append(char)
    out.append('"')
    return "".join(out)


def _serialize_number(value: float) -> str:
    """Serialize a number per RFC 8785 §3.2.2.3 (ECMAScript ``Number::toString``)."""
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("JCS cannot serialize NaN or Infinity")
        if value == 0:
            # ECMAScript renders both +0 and -0 as "0".
            return "0"
        if value.is_integer() and abs(value) < 1e21:
            return str(int(value))
    return _es_number_to_string(value)


def _decimal_digits_and_point(value: float) -> tuple[str, int]:
    """Return ``(s, n)`` for a nonzero float, matching ECMA-262's Number::toString.

    ``s`` is the shortest round-tripping decimal digit string (no leading or trailing
    zeros) and ``n`` is the integer such that ``value == int(s) * 10 ** (n - len(s))``.
    This is exactly the pair the ECMAScript spec's steps 5-9 operate on.

    Python's ``repr()`` already computes the shortest round-tripping decimal for a
    float — correctly re-deriving *that* algorithm ourselves would be redundant and
    error-prone. What's needed here is only to recover ``(s, n)`` from whichever
    notation ``repr`` happened to choose (fixed or scientific), so the fixed/exponential
    *boundary* below can be decided by ECMAScript's own rule rather than Python's.
    """
    text = repr(abs(value))
    mantissa, _, exp_part = text.partition("e")
    exp = int(exp_part) if exp_part else 0
    int_part, _, frac_part = mantissa.partition(".")
    raw_digits = int_part + frac_part
    n = len(int_part) + exp
    stripped = raw_digits.lstrip("0")
    n -= len(raw_digits) - len(stripped)
    digits = stripped.rstrip("0") or "0"
    return digits, n


def _es_number_to_string(value: float) -> str:
    """Render a float exactly as ECMAScript's Number::toString would.

    See RFC 8785 §3.2.2.3.

    Implements ECMA-262's Number::toString steps 5-9 directly on the ``(s, n)`` pair
    from :func:`_decimal_digits_and_point`, rather than reformatting whatever notation
    Python's ``repr`` happened to choose. That distinction matters: Python's ``repr``
    switches from fixed to scientific notation at ``1e-5``, but ECMAScript only
    switches below ``1e-6`` (``1e-6`` itself must still render as ``"0.000001"``, not
    ``"1e-6"``). Reformatting repr's own exponent — the previous implementation —
    gets every value in that gap wrong, e.g. ``1e-5`` must render ``"0.00001"``, not
    ``"1e-5"``.
    """
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits, n = _decimal_digits_and_point(value)
    k = len(digits)

    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits

    # Exponential notation (n < -6 or n > 21).
    exponent = n - 1
    exp_sign = "+" if exponent >= 0 else "-"
    mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{sign}{mantissa}e{exp_sign}{abs(exponent)}"
