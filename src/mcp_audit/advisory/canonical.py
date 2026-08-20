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

__all__ = ["canonicalize", "canonicalize_str"]

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


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of a JSON-compatible value.

    Args:
        value: A structure of dict / list / str / int / float / bool / None.

    Returns:
        Canonical UTF-8 bytes, ready to sign.

    Raises:
        TypeError: The structure contains a type JSON cannot represent.
        ValueError: The structure contains NaN or Infinity, which JSON forbids.
    """
    return canonicalize_str(value).encode("utf-8")


def canonicalize_str(value: Any) -> str:
    """Return the RFC 8785 canonical form as a ``str``. See :func:`canonicalize`."""
    out: list[str] = []
    _write(value, out)
    return "".join(out)


def _write(value: Any, out: list[str]) -> None:
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
        _write_object(value, out)
    elif isinstance(value, (list, tuple)):
        _write_array(value, out)
    else:
        raise TypeError(f"Not JSON-serializable for JCS: {type(value).__name__}")


def _write_object(value: dict, out: list[str]) -> None:
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
        _write(value[key], out)
    out.append("}")


def _write_array(value: Any, out: list[str]) -> None:
    out.append("[")
    for index, item in enumerate(value):
        if index:
            out.append(",")
        _write(item, out)
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


def _es_number_to_string(value: float) -> str:
    """Render an integer or non-integral float the way ECMAScript would.

    Python's ``repr`` already produces the shortest round-tripping decimal, which is the
    same digit string ECMAScript picks; only the exponent formatting differs, and only
    outside the 1e-7 .. 1e21 window where ECMAScript switches to exponential notation.
    """
    if isinstance(value, int):
        return str(value)

    text = repr(value)
    if "e" not in text and "E" not in text:
        return text

    mantissa, _, exponent = text.partition("e")
    exp = int(exponent)
    mantissa = mantissa.rstrip("0").rstrip(".") if "." in mantissa else mantissa
    sign = "+" if exp >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exp)}"
