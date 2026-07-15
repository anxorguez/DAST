"""Unit tests for src/fuzzing/obfuscators.py."""

from __future__ import annotations

import pytest

from src.fuzzing.obfuscators import (
    ALL_ENCODINGS,
    ENCODING_BASE64,
    ENCODING_DOUBLE_URL,
    ENCODING_NONE,
    ENCODING_SQL_COMMENT,
    ENCODING_URL,
    apply,
    base64_encode,
    double_url_encode,
    sql_comment_encode,
    url_encode,
)


def test_apply_none_returns_payload_unchanged() -> None:
    assert apply("none", "x") == "x"


def test_apply_none_empty_string() -> None:
    assert apply("none", "") == ""


def test_url_encode_angle_brackets() -> None:
    assert url_encode("<script>") == "%3Cscript%3E"


def test_url_encode_space_produces_percent20_not_plus() -> None:
    assert url_encode(" ") == "%20"


def test_url_encode_reserved_chars_are_encoded() -> None:
    # = and & must be encoded so they don't break query param parsing
    result = url_encode("a=1&b=2")
    assert "=" not in result
    assert "&" not in result


def test_double_url_encode_angle_bracket() -> None:
    # < → %3C → %253C
    assert double_url_encode("<") == "%253C"


def test_double_url_encode_space() -> None:
    # space → %20 → %2520
    assert double_url_encode(" ") == "%2520"


def test_base64_encode_admin() -> None:
    assert base64_encode("admin") == "YWRtaW4="


def test_base64_encode_empty() -> None:
    assert base64_encode("") == ""


def test_base64_encode_unicode() -> None:
    # UTF-8 encoding then base64
    result = base64_encode("café")
    import base64 as _b64

    assert result == _b64.b64encode("café".encode()).decode("ascii")


def test_apply_invalid_encoding_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Unknown obfuscation encoding"):
        apply("invalid", "x")


def test_apply_url_matches_url_encode() -> None:
    payload = "<script>alert(1)</script>"
    assert apply(ENCODING_URL, payload) == url_encode(payload)


def test_apply_double_url_matches_double_url_encode() -> None:
    payload = "' OR 1=1--"
    assert apply(ENCODING_DOUBLE_URL, payload) == double_url_encode(payload)


def test_apply_base64_matches_base64_encode() -> None:
    payload = "rO0ABXNyABhqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="
    assert apply(ENCODING_BASE64, payload) == base64_encode(payload)


def test_all_encodings_contains_five_values() -> None:
    assert len(ALL_ENCODINGS) == 5
    assert ENCODING_NONE in ALL_ENCODINGS
    assert ENCODING_URL in ALL_ENCODINGS
    assert ENCODING_DOUBLE_URL in ALL_ENCODINGS
    assert ENCODING_BASE64 in ALL_ENCODINGS
    assert ENCODING_SQL_COMMENT in ALL_ENCODINGS


def test_sql_comment_encode_basic() -> None:
    """Whitespace replaced by /**/."""
    assert sql_comment_encode("' OR 1=1--") == "'/**/OR/**/1=1--"


def test_sql_comment_encode_multiple_spaces() -> None:
    """Multiple whitespace chars collapse to a single /**/."""
    assert sql_comment_encode("UNION  SELECT  1,2,3") == "UNION/**/SELECT/**/1,2,3"


def test_sql_comment_encode_no_whitespace() -> None:
    """Payload without whitespace is returned unchanged."""
    assert sql_comment_encode("'--") == "'--"


def test_apply_sql_comment() -> None:
    """apply() dispatches to sql_comment_encode."""
    assert apply(ENCODING_SQL_COMMENT, "' OR 1=1") == "'/**/OR/**/1=1"


def test_sql_comment_in_all_encodings() -> None:
    """sql_comment is listed in ALL_ENCODINGS."""
    assert "sql_comment" in ALL_ENCODINGS


def test_apply_dispatches_all_known_encodings() -> None:
    payload = "test_payload_123"
    for enc in ALL_ENCODINGS:
        result = apply(enc, payload)
        assert isinstance(result, str)


def test_double_url_encode_wire_form() -> None:
    """double_url_encode produce la forma de wire correcta para WAF-bypass.

    El resultado se envía verbatim por base_scanner._send. PHP parse_str
    realiza un solo urldecode, por lo que el valor final en PHP es el
    payload single-URL-encoded (%27%20OR, no ' OR).
    """
    from urllib.parse import unquote

    raw = "' OR 1=1"
    wire = double_url_encode(raw)

    # Wire form: debe ser el single-URL-encoded del payload, con los % re-encoded
    assert wire == "%2527%2520OR%25201%253D1"

    # PHP single-decode: un solo unquote del valor wire
    php_value = unquote(wire)
    assert php_value == "%27%20OR%201%3D1"

    # Confirmar que NO es el payload original (no hay injection en PHP)
    assert php_value != raw
