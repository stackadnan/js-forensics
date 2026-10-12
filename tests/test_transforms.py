from collections.abc import Callable

import pytest

from js_forensics.deobfuscation.edits import TextEdit, apply_edits
from js_forensics.deobfuscation.transforms import (
    TransformOutcome,
    decode_static_calls,
    fold_constants,
    format_statements,
    simplify_string_escapes,
)
from js_forensics.parser import ParsedSource

from .conftest import parse, parse_fixture

Transform = Callable[[ParsedSource], TransformOutcome]


def run(transform: Transform, source: str) -> tuple[str, TransformOutcome]:
    parsed = parse(source)
    outcome = transform(parsed)
    result = apply_edits(parsed.source, outcome.edits).decode("utf-8")
    assert not ParsedSource(result.encode()).has_errors, f"output does not parse: {result!r}"
    return result, outcome


def assert_unchanged(transform: Transform, source: str) -> TransformOutcome:
    result, outcome = run(transform, source)
    assert result == source
    assert outcome.edits == []
    return outcome


def test_apply_edits_rejects_overlap():
    with pytest.raises(ValueError, match="overlapping"):
        apply_edits(b"abcdef", [TextEdit(0, 3, b"x"), TextEdit(2, 4, b"y")])
    assert apply_edits(b"abcdef", [TextEdit(4, 6, b"Z"), TextEdit(0, 1, b"")]) == b"bcdZ"


# --- simplify_string_escapes ------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (r'var a = "\x68\x65\x6c\x6c\x6f";', 'var a = "hello";'),
        (r"var a = '\u0077orld';", "var a = 'world';"),
        (r"var a = '\x27';", r"var a = '\'';"),
        (r'var a = "\x22\x5c";', r'var a = "\"\\";'),
        (r'var o = {"\x61": 1};', 'var o = {"a": 1};'),
        (r'var a = "\101\x42";', 'var a = "AB";'),
        (r'var a = "\uD83D\uDE00";', 'var a = "\U0001f600";'),
        (r'var a = "\x41\n\x00";', r'var a = "A\n\x00";'),
    ],
)
def test_escapes_are_simplified(source, expected):
    result, outcome = run(simplify_string_escapes, source)
    assert result == expected
    assert len(outcome.changes) == 1


@pytest.mark.parametrize(
    "source",
    [
        'var a = "plain";',
        r'var a = "\n\t\\";',
        r'var a = "\x00\x1b\u202e";',  # nothing displayable to reveal
        r"var a = `\x68\x69`;",  # template literals are not rewritten
        r'var a = "\uD83D";',  # lone surrogate
    ],
)
def test_escapes_left_alone(source):
    outcome = assert_unchanged(simplify_string_escapes, source)
    assert outcome.skipped == []


def test_statement_level_string_is_not_turned_into_a_directive():
    # "\x75se strict" is not a directive; "use strict" would be.
    outcome = assert_unchanged(simplify_string_escapes, r'"\x75se strict"; var a = 1;')
    assert outcome.skipped_count == 1
    assert "directive" in outcome.skipped[0].reason


def test_invalid_escape_is_skipped_with_a_reason():
    parsed = ParsedSource(rb'var a = "\u12"; var b = "\x41";')
    outcome = simplify_string_escapes(parsed)
    assert apply_edits(parsed.source, outcome.edits) == rb'var a = "\u12"; var b = "A";'
    assert [item.reason for item in outcome.skipped] == [r"malformed \u escape"]


# --- decode_static_calls ----------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("var a = String.fromCharCode(104, 105);", 'var a = "hi";'),
        ("var a = String.fromCharCode(0x60 + 8, 0x69);", 'var a = "hi";'),
        ('var a = atob("aGk=");', 'var a = "hi";'),
        ('var a = window.atob("aGk=").length;', 'var a = "hi".length;'),
        ('var a = atob("AAE=");', r'var a = "\x00\x01";'),
        ('var a = atob("Ig==");', r'var a = "\"";'),
        ("var a = String.fromCodePoint(128512);", 'var a = "\U0001f600";'),
        ('function f(){return atob("aGk=")}', 'function f(){return "hi"}'),
        ('var a = f(atob("aGk="), String.fromCharCode(33));', 'var a = f("hi", "!");'),
    ],
)
def test_decoder_calls_are_replaced(source, expected):
    result, _ = run(decode_static_calls, source)
    assert result == expected


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("var a = String.fromCharCode(n);", "argument 1 is not static"),
        ('var a = atob(payload + "x");', "argument 1 is not static"),
        ('function atob(s) { return s; } var a = atob("aGk=");', "may not be the built-in"),
        ('var a = atob("not base64!");', "would throw"),
        ('atob("dXNlIHN0cmljdA==");', "directive"),
    ],
)
def test_unresolvable_decoder_calls_are_reported(source, reason):
    outcome = assert_unchanged(decode_static_calls, source)
    assert outcome.skipped_count == 1
    assert reason in outcome.skipped[0].reason


def test_unrelated_calls_are_ignored_silently():
    outcome = assert_unchanged(
        decode_static_calls, 'var a = decode("aGk="), b = s.fromCharCode(1);'
    )
    assert outcome.skipped == []


# --- fold_constants ---------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("var a = 1 + 2;", "var a = 3;"),
        ("var a = 1 + 2 * 3;", "var a = 7;"),
        ('var a = "a" + "b" + c;', 'var a = "ab" + c;'),
        ('var a = "id-" + 4 + n;', 'var a = "id-4" + n;'),
        ("var a = !0, b = !1;", "var a = true, b = false;"),
        ("var a = 2 ** 3 ** 2;", "var a = 512;"),
        ("var a = x ? 1 + 1 : 2 * 3;", "var a = x ? 2 : 6;"),
        ('if ("abc" === "abc") {}', "if (true) {}"),
        ("var a = f(0x10 | 0x01, -(-2));", "var a = f(17, 2);"),
        ("var a = 0.1 + 0.2;", "var a = 0.30000000000000004;"),
        ("var a = [1 - 3, 5 % 3];", "var a = [-2, 2];"),
        # Replacements must not merge with neighbouring tokens.
        ("function f(){return(1+2)*3}", "function f(){return 9}"),
        ("function f(){return!0}", "function f(){return true}"),
        ("var a = x-~5;", "var a = x- -6;"),
        ("var a = x-(~5);", "var a = x-(-6);"),
        ("var a = (1+2)in o;", "var a = (3)in o;"),
        ("var a = typeof(1+2)*3;", "var a = typeof(3)*3;"),
        ("for (var k of[]) {} var a = !0in o;", "for (var k of[]) {} var a = true in o;"),
    ],
)
def test_constants_are_folded(source, expected):
    result, _ = run(fold_constants, source)
    assert result == expected


@pytest.mark.parametrize(
    "source",
    [
        "var a = b + 1;",
        'var a = c + "a" + "b";',  # (c + "a") + "b" has no constant subexpression
        "var a = n + 1 + 2;",  # n may be a string, so 1 + 2 must not be combined
        "var a = -5;",
        "var a = [];",
        'var a = f() + "x";',
        "var a = i++ + 1;",
        '"use " + "strict";',  # folding would create a directive
        "var a = b || 1;",
    ],
)
def test_non_constant_expressions_are_left_alone_silently(source):
    outcome = assert_unchanged(fold_constants, source)
    assert outcome.skipped == []


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("var a = 1 / 0;", "by zero"),
        ('var a = "5" * 2;', "coercion"),
        ("var a = 1 + true;", "boolean"),
        ("var a = 0 * -1;", "negative zero"),
        ("var a = 2 ** 0.5;", "integer operands"),
        ('var a = "1" == 1;', "different types"),
        ("var a = 9007199254740993n + 1n;", "not folded"),
    ],
)
def test_constant_but_unsupported_expressions_are_reported(source, reason):
    outcome = assert_unchanged(fold_constants, source)
    assert outcome.skipped_count == 1
    assert reason in outcome.skipped[0].reason
    assert outcome.skipped[0].location.line == 1


def test_negative_result_cannot_join_the_previous_line():
    # Without a semicolon after `b`, a line starting with `-6` would turn the
    # two statements into the single expression `b - 6 && c()`.
    source = "var a = b\n~5 && c()"
    outcome = assert_unchanged(fold_constants, source)
    assert "merge with the line above" in outcome.skipped[0].reason
    # Mid-statement the same fold is fine.
    assert (
        run(fold_constants, "var a = b;\nvar d = ~5 && c()")[0] == "var a = b;\nvar d = -6 && c()"
    )


def test_folding_is_idempotent():
    once, _ = run(fold_constants, parse_fixture("constant_folding.js").source.decode())
    twice, outcome = run(fold_constants, once)
    assert twice == once
    assert outcome.edits == []


def test_constant_folding_fixture():
    result, outcome = run(fold_constants, parse_fixture("constant_folding.js").source.decode())
    assert result.splitlines()[:14] == [
        "var sum = 7;",
        'var text = "concat12";',
        'var mixed = "3px";',
        "var truthy = true, falsy = false;",
        "var bits = 31;",
        "var shifted = 15;",
        "var power = 512;",
        "var fraction = 0.30000000000000004;",
        "var same = true;",
        "var negated = 22;",
        "var division = 1 / 0;",
        'var coerced = "5" * 2;',
        "var unknown = sum + 1 + 2;",
        'var prefix = "id-4" + sum;',
    ]
    assert [item.reason for item in outcome.skipped] == [
        "`/` by zero yields Infinity or NaN",
        "`*` with a string operand needs coercion",
    ]


# --- format_statements ------------------------------------------------------


def test_minified_code_gets_one_statement_per_line():
    result, _ = run(format_statements, parse_fixture("minified.js").source.decode())
    assert result == (
        "function f(a){\n"
        "  if(a){\n"
        "    return 1\n"
        "  }else{\n"
        "    return 2\n"
        "  }\n"
        "}\n"
        "var b=f(1),c=[1,2,3].map(function(n){\n"
        "  return n*2\n"
        "});\n"
        "switch(b){\n"
        "  case 1:\n"
        "    c.push(4);\n"
        "    break;\n"
        "  default:\n"
        "    c.pop()\n"
        "}\n"
        'console.log(b,c.join(","));\n'
    )


def test_class_members_are_separated():
    result, _ = run(format_statements, "class A{x=1;static y;m(){return 1}}")
    assert result == "class A{\n  x=1;\n  static y;\n  m(){\n    return 1\n  }\n}\n"


@pytest.mark.parametrize(
    "source",
    [
        "",
        "var a = 1;\n",
        "function f() {}\nvar o = {};\n",
        "a(); // trailing comment stays on its line\nb();\n",
        "/* lead */ a();\n",
        "// header\n\nvar a = 1;\n\n// second\nvar b = 2;\n",
        "function f() {\n  return a\n    + b;\n}\n",
        "var t = `line one\n  ${a ? `x` : 1}\nline three`;\n",
        "label: for (;;) {\n  break label;\n}\n",
    ],
)
def test_already_laid_out_code_is_unchanged(source):
    assert_unchanged(format_statements, source)


def test_only_whitespace_between_statements_changes():
    source = "function f(){return\n1}var s=`a;b{c}`;if(x)y();else{z()}"
    result, _ = run(format_statements, source)
    # The line break after `return` is inside a statement and is preserved,
    # as is the template literal's content.
    assert result == (
        "function f(){\n  return\n  1\n}\nvar s=`a;b{c}`;\nif(x)y();else{\n  z()\n}\n"
    )
    assert "".join(result.split()) == "".join(source.split())


def test_formatting_is_idempotent_on_every_fixture():
    for name in ("minified.js", "readable.js", "string_array.js", "endpoints.js", "escapes.js"):
        once, _ = run(format_statements, parse_fixture(name).source.decode())
        twice, outcome = run(format_statements, once)
        assert twice == once, name
        assert outcome.edits == [], name


def test_indentation_stops_growing_for_extreme_nesting():
    depth = 200
    result, _ = run(format_statements, "{" * depth + "a()" + "}" * depth)
    widest = max(len(line) - len(line.lstrip(" ")) for line in result.splitlines())
    assert widest == 48  # 24 levels of two spaces, however deep the blocks go
