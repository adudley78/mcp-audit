"""Tests for the RFC 8785 (JCS) canonicalizer.

Canonicalization is the foundation the signatures rest on: if two implementations
disagree on the bytes for a given document, every signature we publish is unverifiable
by anyone else. The cases below are the ones where a naive
``json.dumps(sort_keys=True)`` gets it wrong.
"""

from __future__ import annotations

import json

import pytest

from mcp_audit.advisory.canonical import (
    MAX_DEPTH,
    CanonicalError,
    canonicalize,
    canonicalize_str,
)


class TestStructure:
    def test_output_is_utf8_bytes(self) -> None:
        assert canonicalize({"a": 1}) == b'{"a":1}'

    def test_no_insignificant_whitespace(self) -> None:
        assert canonicalize_str({"b": [1, 2], "a": {"c": None}}) == (
            '{"a":{"c":null},"b":[1,2]}'
        )

    def test_object_keys_are_sorted(self) -> None:
        assert canonicalize_str({"c": 1, "a": 2, "b": 3}) == '{"a":2,"b":3,"c":1}'

    def test_nested_objects_are_sorted_at_every_level(self) -> None:
        assert canonicalize_str({"z": {"y": 1, "x": 2}}) == '{"z":{"x":2,"y":1}}'

    def test_array_order_is_preserved(self) -> None:
        assert canonicalize_str([3, 1, 2]) == "[3,1,2]"

    def test_tuples_serialize_as_arrays(self) -> None:
        assert canonicalize_str((1, 2)) == "[1,2]"

    def test_empty_containers(self) -> None:
        assert canonicalize_str({"a": {}, "b": []}) == '{"a":{},"b":[]}'

    def test_booleans_and_null(self) -> None:
        assert canonicalize_str({"t": True, "f": False, "n": None}) == (
            '{"f":false,"n":null,"t":true}'
        )


class TestUtf16KeyOrdering:
    """RFC 8785 §3.2.3 sorts by UTF-16 code unit, not by Unicode code point.

    The two orders disagree for keys containing non-BMP characters, because UTF-16
    encodes those as a surrogate pair beginning at U+D800 — below U+E000, even though
    the code point itself is above it.
    """

    def test_non_bmp_key_sorts_before_a_higher_bmp_key(self) -> None:
        # U+1F600 (non-BMP) vs U+E000 (BMP private use).
        result = canonicalize_str({"\U0001f600": 1, "\ue000": 2})
        assert result.index('"\U0001f600"') < result.index('"\ue000"')

    def test_this_is_the_opposite_of_code_point_order(self) -> None:
        """Confirms the case is real: sort_keys orders these the other way."""
        naive = json.dumps(
            {"\U0001f600": 1, "\ue000": 2}, sort_keys=True, ensure_ascii=False
        )
        assert naive.index('"\ue000"') < naive.index("\U0001f600")

    def test_ascii_keys_are_unaffected(self) -> None:
        assert canonicalize_str({"b": 1, "A": 2, "a": 3}) == '{"A":2,"a":3,"b":1}'


class TestStringEscaping:
    def test_two_character_escapes(self) -> None:
        assert canonicalize_str('"\\\b\f\n\r\t') == r'"\"\\\b\f\n\r\t"'

    def test_other_control_characters_use_lowercase_hex(self) -> None:
        assert canonicalize_str("\u0001\u001f") == r'"\u0001\u001f"'

    def test_non_ascii_is_emitted_literally(self) -> None:
        assert canonicalize("café → ✓") == '"café → ✓"'.encode()

    def test_solidus_is_not_escaped(self) -> None:
        assert canonicalize_str("a/b") == '"a/b"'


class TestNumbers:
    def test_integers(self) -> None:
        assert canonicalize_str({"a": 0, "b": -7, "c": 10**15}) == (
            '{"a":0,"b":-7,"c":1000000000000000}'
        )

    def test_integral_floats_lose_the_decimal_point(self) -> None:
        assert canonicalize_str(1.0) == "1"

    def test_negative_zero_renders_as_zero(self) -> None:
        assert canonicalize_str(-0.0) == "0"

    def test_fractional_floats_use_shortest_round_trip(self) -> None:
        assert canonicalize_str(0.1) == "0.1"

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_numbers_are_rejected(self, value: float) -> None:
        with pytest.raises(ValueError, match="NaN or Infinity"):
            canonicalize(value)


class TestEcmaScriptNumberBoundary:
    """RFC 8785 §3.2.2.3 requires ECMAScript ``Number::toString`` semantics exactly.

    Python's ``repr()`` switches from fixed to scientific notation at ``1e-5``;
    ECMAScript only switches below ``1e-6`` (``1e-6`` itself still renders fixed).
    The previous implementation reformatted whichever notation ``repr`` picked
    instead of applying ECMAScript's own fixed/exponential boundary, so every value
    in that gap canonicalized to the wrong (but internally consistent) bytes — a
    spec-conformance bug, not a collision: two different documents could never
    produce identical canonical bytes from this, but the same document would not
    canonicalize to the bytes an independent RFC 8785 implementation computes,
    which breaks third-party signature verification of anything containing such a
    value. These are the exact counter-examples from the security review.
    """

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (1e-5, "0.00001"),
            (1e-6, "0.000001"),
            (2.5e-06, "0.0000025"),
            (9.999e-6, "0.000009999"),
        ],
    )
    def test_values_just_inside_the_ecmascript_fixed_window_stay_fixed(
        self, value: float, expected: str
    ) -> None:
        assert canonicalize_str(value) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (1e-7, "1e-7"),
            (2.5e-7, "2.5e-7"),
        ],
    )
    def test_values_below_the_ecmascript_window_use_exponential(
        self, value: float, expected: str
    ) -> None:
        assert canonicalize_str(value) == expected

    def test_negative_small_fraction_keeps_its_sign(self) -> None:
        assert canonicalize_str(-1e-5) == "-0.00001"

    def test_1e21_is_the_exponential_boundary(self) -> None:
        """n == 21 is the last integer that stays fixed; n == 22 goes exponential."""
        assert canonicalize_str(1e21) == "1e+21"

    def test_large_fixed_integer_below_the_boundary_has_no_decimal_point(self) -> None:
        assert canonicalize_str(1.23e20) == "123000000000000000000"


class TestRejections:
    def test_unsupported_type_raises(self) -> None:
        with pytest.raises(TypeError, match="Not JSON-serializable"):
            canonicalize({"a": {1, 2}})

    def test_non_string_object_key_raises(self) -> None:
        with pytest.raises(TypeError, match="object keys must be strings"):
            canonicalize({1: "a"})


class TestDeterminism:
    def test_input_key_order_does_not_affect_output(self) -> None:
        assert canonicalize({"a": 1, "b": 2}) == canonicalize({"b": 2, "a": 1})

    def test_reparsing_a_document_yields_identical_bytes(self) -> None:
        """This is what makes 'reformat the file, signature still valid' work."""
        document = {"z": [1, {"b": "x", "a": None}], "a": "café"}
        pretty = json.dumps(document, indent=4)
        assert canonicalize(json.loads(pretty)) == canonicalize(document)

    def test_output_is_parseable_back_to_the_original(self) -> None:
        document = {"a": [1, "two", None, True], "b": {"c": 0.5}}
        assert json.loads(canonicalize(document)) == document


def _nested(depth: int) -> dict:
    document: dict = {}
    cursor = document
    for _ in range(depth):
        cursor["n"] = {}
        cursor = cursor["n"]
    return document


class TestCanonicalBounds:
    def test_depth_at_the_limit_is_accepted(self) -> None:
        canonicalize(_nested(MAX_DEPTH))

    def test_depth_past_the_limit_raises_canonical_error(self) -> None:
        with pytest.raises(CanonicalError, match="nested too deeply"):
            canonicalize(_nested(MAX_DEPTH + 1))
