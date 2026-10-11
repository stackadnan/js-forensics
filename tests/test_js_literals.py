import pytest

from js_forensics.analysis.js_literals import (
    InvalidEscape,
    atob,
    decode_string_body,
    escape_for_display,
    number_to_string,
    parse_number_literal,
    quote_string,
    simplify_escapes,
    to_int32,
    to_uint32,
)


@pytest.mark.parametrize(
    ("body", "value"),
    [
        (r"plain", "plain"),
        (r"\x68\x69", "hi"),
        (r"\u0041", "A"),
        (r"\u{1F600}", "\U0001f600"),
        (r"\uD83D\uDE00", "\U0001f600"),
        (r"\101", "A"),
        (r"\0", "\x00"),
        (r"\n\t\r\b\f\v", "\n\t\r\b\f\v"),
        (r"\q\'\"\\", "q'\"\\"),
        ("a\\\nb", "ab"),  # escaped line break is a continuation
        (r"\08", "\x008"),
    ],
)
def test_decode_string_body(body, value):
    assert decode_string_body(body) == value


def test_lone_surrogate_is_preserved():
    assert decode_string_body(r"\uD83D") == "\ud83d"


@pytest.mark.parametrize("body", [r"\x4", r"\u12", r"\u{110000}", "abc\\", r"\u{}"])
def test_invalid_escapes_are_rejected(body):
    with pytest.raises(InvalidEscape):
        decode_string_body(body)


@pytest.mark.parametrize(
    ("body", "quote", "expected"),
    [
        (r"\x68\x65llo", '"', "hello"),
        (r"\u0077orld", "'", "world"),
        (r"\x22", '"', r"\""),
        (r"\x27", '"', "'"),
        (r"\x27", "'", r"\'"),
        (r"\x5c", '"', r"\\"),
        (r"\uD83D\uDE00", '"', "\U0001f600"),
        (r"\101", '"', "A"),
        # Left as written: control characters, bidi overrides, lone surrogates,
        # and escapes that are not numeric.
        (r"\x00\x0a\x1b", '"', r"\x00\x0a\x1b"),
        (r"\u202e", '"', r"\u202e"),
        (r"\uD83D", '"', r"\uD83D"),
        (r"\n\t\'", '"', r"\n\t\'"),
    ],
)
def test_simplify_escapes(body, quote, expected):
    simplified = simplify_escapes(body, quote)
    assert simplified == expected
    assert decode_string_body(simplified) == decode_string_body(body)


@pytest.mark.parametrize(
    ("value", "literal"),
    [
        ("hi", '"hi"'),
        ('a"b\n', r'"a\"b\n"'),
        ("back\\slash", r'"back\\slash"'),
        ("\x00\x7f", r'"\x00\x7f"'),
        ("\ud83d", r'"\ud83d"'),
        ("\u2028", r'"\u2028"'),
        ("\U0001f600", '"\U0001f600"'),
        ("\U000e0001", r'"\udb40\udc01"'),  # invisible tag character
    ],
)
def test_quote_string(value, literal):
    assert quote_string(value) == literal
    assert decode_string_body(literal[1:-1]) == value


def test_escape_for_display_neutralises_terminal_escapes():
    assert escape_for_display("\x1b[31mred") == r"\x1b[31mred"


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("0", 0.0),
        ("42", 42.0),
        ("0x1F", 31.0),
        ("0XfF", 255.0),
        ("0b101", 5.0),
        ("0o17", 15.0),
        ("1_000", 1000.0),
        (".5", 0.5),
        ("5.", 5.0),
        ("1e3", 1000.0),
        ("1.5E-2", 0.015),
        ("017", None),  # legacy octal
        ("08", None),
        ("10n", None),  # BigInt
        ("1e999", None),  # Infinity
    ],
)
def test_parse_number_literal(text, value):
    assert parse_number_literal(text) == value


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (1.0, "1"),
        (100.0, "100"),
        (-2.5, "-2.5"),
        (-0.0, "0"),
        (0.1 + 0.2, "0.30000000000000004"),
        (0.000001, "0.000001"),
        (1e-7, "1e-7"),
        (1.5e-10, "1.5e-10"),
        (1e20, "100000000000000000000"),
        (123456789012345680000.0, "123456789012345680000"),
        (1e21, "1e+21"),
        (1.2e21, "1.2e+21"),
        (2.0**53, "9007199254740992"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (1234.5678, "1234.5678"),
    ],
)
def test_number_to_string_matches_javascript(value, text):
    assert number_to_string(value) == text


def test_int32_conversions():
    assert to_int32(2.0**31) == -(2**31)
    assert to_int32(2.0**32 + 5) == 5
    assert to_int32(-1.0) == -1
    assert to_int32(3.9) == 3
    assert to_int32(-3.9) == -3
    assert to_uint32(-1.0) == 2**32 - 1


@pytest.mark.parametrize(
    ("encoded", "decoded"),
    [
        ("aGVsbG8=", "hello"),
        ("aGVsbG8", "hello"),
        (" aGVs\nbG8= ", "hello"),
        ("/w==", "\xff"),
        ("AAH/", "\x00\x01\xff"),
        ("", ""),
    ],
)
def test_atob(encoded, decoded):
    assert atob(encoded) == decoded


@pytest.mark.parametrize("encoded", ["a", "ab=c", "a-b_", "aGVsbG8==="])
def test_atob_rejects_what_the_browser_rejects(encoded):
    with pytest.raises(ValueError):
        atob(encoded)
