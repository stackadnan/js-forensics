from pathlib import Path

import pytest

from js_forensics.errors import InputError, JavaScriptSyntaxError
from js_forensics.parser import ParsedSource, parse_file

from .conftest import FIXTURES, parse

MODERN_SYNTAX = r"""
class A extends B { #secret = 1; static count = 2; static { init(); }
  get value() { return this.#secret; } async *items() { yield* other(); } }
const f = async (a, {b, c: [d, ...e]} = {}) => { await a?.b?.[c]?.(d) ?? 5; x ||= 1; y ??= 3; };
outer: for await (const x of y) { if (x) continue outer; }
import def, * as ns from "mod"; import { a as b } from "m2"; export default function () {}
export const big = 1n ** 2n, sep = 1_000_000, re = /ab+c/giu, t = tag`x${1}y`;
try { risky(); } catch { } finally { }
const mod = await import("./x.js"); import.meta.url;
"""


def test_modern_syntax_parses_without_errors():
    assert not ParsedSource(MODERN_SYNTAX.encode()).has_errors


def test_syntax_error_is_raised_with_location():
    with pytest.raises(JavaScriptSyntaxError) as raised:
        parse_file(FIXTURES / "malformed.js")
    error = raised.value
    assert error.total >= 1
    assert error.issues[0].location.line == 1
    assert "malformed.js" in str(error)
    assert "line 1" in str(error)


def test_tolerant_parse_keeps_errors_visible():
    parsed = parse_file(FIXTURES / "malformed.js", tolerant=True)
    assert parsed.has_errors
    assert parsed.syntax_issues()
    with pytest.raises(JavaScriptSyntaxError):
        parsed.require_valid()


def test_missing_closing_token_is_reported():
    parsed = ParsedSource(b"foo(1;")
    assert parsed.has_errors
    assert any("missing" in issue.message for issue in parsed.syntax_issues())


def test_empty_file_is_a_valid_program():
    parsed = parse_file(FIXTURES / "empty.js")
    assert not parsed.has_errors
    assert parsed.line_count == 0
    assert parsed.index.named_node_count == 1  # just the program node


def test_locations_are_one_based_lines_and_columns():
    parsed = parse("var a = 1;\n  call(a);\n")
    call = parsed.index.of_type("call_expression")[0]
    location = parsed.location(call)
    assert (location.line, location.column) == (2, 3)
    assert (location.end_line, location.end_column) == (2, 10)


def test_columns_count_characters_not_bytes():
    parsed = parse('var s = "héllo wörld"; call();')
    call = parsed.index.of_type("call_expression")[0]
    assert parsed.location(call).column == 24
    assert parsed.text(call) == "call()"


def test_byte_order_mark_is_ignored(tmp_path: Path):
    path = tmp_path / "bom.js"
    path.write_bytes(b"\xef\xbb\xbfvar a = 1;")
    parsed = parse_file(path)
    assert not parsed.has_errors
    assert parsed.source == b"var a = 1;"


def test_missing_file(tmp_path: Path):
    with pytest.raises(InputError, match="does not exist"):
        parse_file(tmp_path / "nope.js")


def test_directory_is_rejected(tmp_path: Path):
    with pytest.raises(InputError, match="is a directory"):
        parse_file(tmp_path)


def test_oversized_file_is_rejected(tmp_path: Path):
    path = tmp_path / "big.js"
    path.write_text("var a = 1;\n" * 100)
    with pytest.raises(InputError, match="larger than the 50-byte limit"):
        parse_file(path, max_bytes=50)
    assert not parse_file(path, max_bytes=2000).has_errors


def test_non_utf8_file_is_rejected(tmp_path: Path):
    path = tmp_path / "latin1.js"
    path.write_bytes('var s = "caf\xe9";'.encode("latin-1"))
    with pytest.raises(InputError, match="not valid UTF-8"):
        parse_file(path)


def test_parent_and_field_lookup():
    parsed = parse("target = value;")
    left, right = parsed.index.of_type("identifier")
    assignment = parsed.index.parent(left)
    assert assignment is not None and assignment.type == "assignment_expression"
    assert parsed.index.field(left) == "left"
    assert parsed.index.field(right) == "right"


def test_deeply_nested_input_does_not_exhaust_the_stack():
    depth = 20_000
    parsed = ParsedSource(("(" * depth + "1" + ")" * depth).encode())
    assert not parsed.has_errors
    assert parsed.index.max_expression_depth >= depth
