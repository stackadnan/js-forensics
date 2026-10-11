"""JavaScript literal semantics implemented in Python.

These functions reproduce what the language specification says a string or
number literal means, so that literals can be decoded and re-emitted without
running any JavaScript. They work on text only and know nothing about syntax
trees.

A JavaScript string is a sequence of UTF-16 code units. Here it is held as a
Python ``str`` in which surrogate pairs are combined into one character and
unpaired surrogates stay as lone surrogate code points.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_ESCAPE = re.compile(
    r"""\\(?:
        x(?P<hex>[0-9a-fA-F]{2})
      | u\{(?P<brace>[0-9a-fA-F]+)\}
      | u(?P<unicode>[0-9a-fA-F]{4})
      | (?P<octal>[0-3][0-7]{0,2}|[4-7][0-7]?)
      | (?P<continuation>\r\n|[\r\n\u2028\u2029])
      | (?P<other>.)
    )""",
    re.VERBOSE | re.DOTALL,
)
_SINGLE_CHARACTER_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v"}
_SHORT_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f", "\v": "\\v"}
_SURROGATE = re.compile("[\ud800-\udfff]")
_MAX_CODE_POINT = 0x10FFFF


class InvalidEscape(ValueError):
    """The literal contains an escape sequence JavaScript would reject."""


@dataclass(frozen=True, slots=True)
class StringPiece:
    """One lexical piece of a string literal body.

    ``kind`` is ``text`` for unescaped characters, ``hex``/``unicode``/``octal``
    for numeric escapes, ``continuation`` for an escaped line break, and
    ``simple`` for everything else (``\\n``, ``\\'``, ``\\0``, ...).
    """

    kind: str
    raw: str
    value: str


def split_string_body(body: str) -> list[StringPiece]:
    """Split the text between a literal's quotes into text runs and escapes."""
    pieces: list[StringPiece] = []
    position = 0
    while True:
        backslash = body.find("\\", position)
        if backslash == -1:
            if position < len(body):
                pieces.append(StringPiece("text", body[position:], body[position:]))
            return pieces
        if backslash > position:
            pieces.append(StringPiece("text", body[position:backslash], body[position:backslash]))
        match = _ESCAPE.match(body, backslash)
        if match is None:
            raise InvalidEscape("string ends with an unfinished escape sequence")
        pieces.append(_piece_from_escape(match))
        position = match.end()


def _piece_from_escape(match: re.Match[str]) -> StringPiece:
    raw = match.group(0)
    if match.group("hex") is not None:
        return StringPiece("hex", raw, chr(int(match.group("hex"), 16)))
    if match.group("unicode") is not None:
        return StringPiece("unicode", raw, chr(int(match.group("unicode"), 16)))
    if match.group("brace") is not None:
        code_point = int(match.group("brace"), 16)
        if code_point > _MAX_CODE_POINT:
            raise InvalidEscape(f"{raw} is beyond the last Unicode code point")
        return StringPiece("unicode", raw, chr(code_point))
    if match.group("octal") is not None:
        # A bare \0 is the NUL escape and is valid everywhere; longer forms are
        # legacy octal escapes that only sloppy-mode code may use.
        kind = "simple" if match.group("octal") == "0" else "octal"
        return StringPiece(kind, raw, chr(int(match.group("octal"), 8)))
    if match.group("continuation") is not None:
        return StringPiece("continuation", raw, "")
    other = match.group("other")
    if other in "xu":
        raise InvalidEscape(f"malformed \\{other} escape")
    return StringPiece("simple", raw, _SINGLE_CHARACTER_ESCAPES.get(other, other))


def combine_surrogates(text: str) -> str:
    """Join adjacent high/low surrogates into the character they encode."""
    if _SURROGATE.search(text) is None:
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def decode_string_body(body: str) -> str:
    """Return the string value of a literal body (the text between quotes)."""
    return combine_surrogates("".join(piece.value for piece in split_string_body(body)))


def _is_displayable(character: str) -> bool:
    """True for characters a reader can see, which excludes controls,
    format characters such as bidi overrides, and non-ASCII spaces."""
    return character.isprintable()


def _escape_character(character: str) -> str:
    code_point = ord(character)
    if code_point <= 0xFF:
        return f"\\x{code_point:02x}"
    if code_point <= 0xFFFF:
        return f"\\u{code_point:04x}"
    offset = code_point - 0x10000
    return f"\\u{0xD800 + (offset >> 10):04x}\\u{0xDC00 + (offset & 0x3FF):04x}"


def escape_for_display(value: str, quote: str | None = None, *, is_source: bool = False) -> str:
    """Render text with every non-displayable character escaped.

    With ``quote`` set, the result is a valid JavaScript literal body for that
    quote character. Without it, the result is meant for humans: reports and
    terminals must never receive raw control characters from analyzed input.
    ``is_source`` marks an excerpt of JavaScript source, whose backslashes are
    already part of the code and are shown as written.
    """
    parts = []
    for character in value:
        if (character == "\\" and not is_source) or character == quote:
            parts.append("\\" + character)
        elif character in _SHORT_ESCAPES:
            parts.append(_SHORT_ESCAPES[character])
        elif _is_displayable(character):
            parts.append(character)
        else:
            parts.append(_escape_character(character))
    return "".join(parts)


def quote_string(value: str, quote: str = '"') -> str:
    """Build a JavaScript string literal with the given value."""
    return quote + escape_for_display(value, quote) + quote


def simplify_escapes(body: str, quote: str) -> str:
    """Replace numeric escapes of displayable characters with the characters.

    Each escape is rewritten on its own and everything else is copied
    verbatim, so the literal's value cannot change. Escapes of characters that
    are not displayable are kept as written.
    """
    pieces = split_string_body(body)
    rewritten = []
    index = 0
    while index < len(pieces):
        piece = pieces[index]
        index += 1
        if piece.kind not in ("hex", "unicode", "octal"):
            rewritten.append(piece.raw)
            continue
        character = piece.value
        following = pieces[index] if index < len(pieces) else None
        if (
            "\ud800" <= character <= "\udbff"
            and following is not None
            and following.kind == "unicode"
            and "\udc00" <= following.value <= "\udfff"
        ):
            character = combine_surrogates(character + following.value)
            if _is_displayable(character):
                rewritten.append(character)
                index += 1
                continue
            character = piece.value
        if not _is_displayable(character):
            rewritten.append(piece.raw)
        elif character in ("\\", quote):
            rewritten.append("\\" + character)
        else:
            rewritten.append(character)
    return "".join(rewritten)


_DECIMAL_LITERAL = re.compile(r"(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
_RADIX_PREFIXES = {"0x": 16, "0o": 8, "0b": 2}


def parse_number_literal(text: str) -> float | None:
    """Value of a numeric literal, or None for forms that are not folded.

    BigInt literals and legacy octal-like literals (``017``, ``08``) return
    None: the first is a different type and the second depends on strict mode.
    """
    literal = text.replace("_", "")
    if literal.endswith("n"):
        return None
    radix = _RADIX_PREFIXES.get(literal[:2].lower())
    if radix is not None:
        try:
            return float(int(literal[2:], radix))
        except (ValueError, OverflowError):
            return None
    if len(literal) > 1 and literal[0] == "0" and literal[1].isdigit():
        return None
    if _DECIMAL_LITERAL.fullmatch(literal) is None:
        return None
    value = float(literal)
    return value if math.isfinite(value) else None


def number_to_string(value: float) -> str:
    """Number::toString for a finite double, as JavaScript prints it.

    Python's ``repr`` and JavaScript both produce the shortest digit string
    that round-trips; only the layout rules differ, and those are applied here.
    """
    if not math.isfinite(value):
        raise ValueError("only finite numbers have a literal form")
    if value == 0:
        return "0"
    if value < 0:
        return "-" + number_to_string(-value)

    mantissa, _, exponent_text = repr(value).partition("e")
    integer_part, _, fraction_part = mantissa.partition(".")
    digits = integer_part + fraction_part
    # ``point`` is where the decimal point sits relative to the first digit.
    point = len(integer_part) + (int(exponent_text) if exponent_text else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    digit_count = len(digits)

    if digit_count <= point <= 21:
        return digits + "0" * (point - digit_count)
    if 0 < point <= 21:
        return digits[:point] + "." + digits[point:]
    if -6 < point <= 0:
        return "0." + "0" * -point + digits
    exponent = point - 1
    sign = "+" if exponent > 0 else "-"
    fraction = "." + digits[1:] if digit_count > 1 else ""
    return f"{digits[0]}{fraction}e{sign}{abs(exponent)}"


def wrap_int32(integer: int) -> int:
    """Reduce an integer modulo 2**32 into the signed 32-bit range."""
    wrapped = integer & 0xFFFFFFFF
    return wrapped - 0x100000000 if wrapped >= 0x80000000 else wrapped


def to_int32(value: float) -> int:
    """ToInt32 for a finite double."""
    return wrap_int32(int(value))


def to_uint32(value: float) -> int:
    return int(value) & 0xFFFFFFFF


_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_VALUES = {character: index for index, character in enumerate(_BASE64_ALPHABET)}
_ASCII_WHITESPACE = re.compile(r"[\t\n\f\r ]")


def atob(encoded: str) -> str:
    """The WHATWG "forgiving-base64 decode" that ``atob()`` performs.

    Returns the decoded bytes as a string of code points 0-255, exactly as the
    browser function does. Raises ValueError where ``atob`` would throw.
    """
    data = _ASCII_WHITESPACE.sub("", encoded)
    if len(data) % 4 == 0:
        if data.endswith("=="):
            data = data[:-2]
        elif data.endswith("="):
            data = data[:-1]
    if len(data) % 4 == 1:
        raise ValueError("invalid base64 length")

    decoded = []
    buffer = 0
    buffered_bits = 0
    for character in data:
        value = _BASE64_VALUES.get(character)
        if value is None:
            raise ValueError(f"invalid base64 character {character!r}")
        buffer = (buffer << 6) | value
        buffered_bits += 6
        if buffered_bits >= 8:
            buffered_bits -= 8
            decoded.append(chr((buffer >> buffered_bits) & 0xFF))
    return "".join(decoded)
