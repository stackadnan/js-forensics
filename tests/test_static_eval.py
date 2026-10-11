import pytest
from tree_sitter import Node

from js_forensics.analysis.identifiers import collect_bindings
from js_forensics.analysis.static_eval import StaticEvaluator, Unresolvable, to_source
from js_forensics.parser import ParsedSource

from .conftest import parse


def _assigned_expression(parsed: ParsedSource) -> Node:
    """The right-hand side of the last ``x = <expr>`` in the source."""
    value = parsed.index.of_type("assignment_expression")[-1].child_by_field_name("right")
    assert value is not None
    return value


def evaluate(expression: str, *, decoders: bool = False, prelude: str = ""):
    parsed = parse(f"{prelude}\nx = {expression};")
    evaluator = StaticEvaluator(
        parsed,
        resolve_decoders=decoders,
        rebound_names=collect_bindings(parsed).rebound_names - {"x"},
    )
    return evaluator.evaluate(_assigned_expression(parsed))


@pytest.mark.parametrize(
    ("expression", "value"),
    [
        ('"a" + "b"', "ab"),
        ("1 + 2", 3.0),
        ('"a" + 1 + 2', "a12"),
        ('1 + 2 + "a"', "3a"),
        ("0.1 + 0.2", 0.30000000000000004),
        ("7 % 3", 1.0),
        ("-7 % 3", -1.0),
        ("7 / 2", 3.5),
        ("2 ** 10", 1024.0),
        ("2 ** 3 ** 2", 512.0),
        ("1 << 31", -2147483648.0),
        ("1 << 32", 1.0),
        ("-1 >>> 0", 4294967295.0),
        ("-8 >> 1", -4.0),
        ("5 & 3", 1.0),
        ("5 | 3", 7.0),
        ("5 ^ 3", 6.0),
        ("~5", -6.0),
        ("4294967296 | 0", 0.0),
        ("-(-2)", 2.0),
        ("(1 + 2) * 3", 9.0),
        ("0x10 + 0b11 + 0o7", 26.0),
        ("!0", True),
        ("!1", False),
        ('!""', True),
        ('!"a"', False),
        ("!!1", True),
        ('"a" === "a"', True),
        ('"a" !== "a"', False),
        ("1 == 1", True),
        ("1 != 2", True),
        ("true === false", False),
        ("2 < 3", True),
        ("3 >= 4", False),
        (r'"\x41" + "B"', "AB"),
        ('1e21 + ""', "1e+21"),
        ('"n=" + 0.5', "n=0.5"),
        ('"v" + -0', "v0"),
        ("`a${1 + 1}b`", "a2b"),
        (r'"\uD83D" + "\uDE00"', "\U0001f600"),
    ],
)
def test_constant_expressions(expression, value):
    result = evaluate(expression)
    assert result == value
    assert type(result) is type(value)


@pytest.mark.parametrize(
    ("expression", "reason"),
    [
        ("1 / 0", "by zero"),
        ("5 % 0", "by zero"),
        ('"5" * 2', "coercion"),
        ('"b" < "a"', "coercion"),
        ("1 + true", "boolean"),
        ('"1" == 1', "different types"),
        ("2 ** 0.5", "integer operands"),
        ("2 ** 1000", "not exactly representable"),
        ("1e308 * 10", "Infinity"),
        ("a + 1", "`a` is a variable"),
        ("10n + 1n", "not folded"),
        ("017 + 1", "not folded"),
        ("1 && 2", "not folded"),
        ("typeof 1", "not folded"),
        ("[] + []", "not a static value"),
        ("f(1) + 2", "not a static value"),
        ('+"3"', "not folded"),
        ("`a${b}`", "substitution"),
    ],
)
def test_unsupported_expressions_report_a_reason(expression, reason):
    with pytest.raises(Unresolvable) as raised:
        evaluate(expression)
    assert reason in raised.value.reason


@pytest.mark.parametrize(
    ("expression", "value"),
    [
        ("String.fromCharCode(72, 105)", "Hi"),
        ("String.fromCharCode(0x48, 0x60 + 9)", "Hi"),
        ('String["fromCharCode"](72)', "H"),
        ("String.fromCharCode(65601)", "A"),  # wraps modulo 2**16
        ("String.fromCharCode(0xD83D, 0xDE00)", "\U0001f600"),
        ("String.fromCharCode()", ""),
        ("String.fromCodePoint(128512)", "\U0001f600"),
        ('atob("aGk=")', "hi"),
        ('window.atob("aGk=")', "hi"),
        ('atob("aG" + "k=") + "!"', "hi!"),
    ],
)
def test_decoder_calls(expression, value):
    assert evaluate(expression, decoders=True) == value


@pytest.mark.parametrize(
    ("expression", "prelude", "reason"),
    [
        ("String.fromCharCode(n)", "", "argument 1 is not static"),
        ("String.fromCharCode(...codes)", "", "not a plain list"),
        ("String.fromCodePoint(-1)", "", "RangeError"),
        ('atob("!")', "", "would throw"),
        ("atob(1)", "", "single string argument"),
        ('atob("aGk=")', "function atob(s) { return s; }", "may not be the built-in"),
        ("String.fromCharCode(72)", "String = {};", "may not be the built-in"),
        ('atob("aGk=")', "with (scope) { probe(); }", "uses `with`"),
        ('decode("aGk=")', "", "not a static value"),
    ],
)
def test_decoder_calls_left_unresolved(expression, prelude, reason):
    with pytest.raises(Unresolvable) as raised:
        evaluate(expression, decoders=True, prelude=prelude)
    assert reason in raised.value.reason


def test_decoder_calls_are_off_by_default():
    with pytest.raises(Unresolvable):
        evaluate('atob("aGk=")')


@pytest.mark.parametrize(
    ("value", "source"),
    [('a"b', r'"a\"b"'), (3.0, "3"), (-2.5, "-2.5"), (True, "true"), (False, "false")],
)
def test_to_source(value, source):
    assert to_source(value) == source


def test_negative_zero_has_no_source_form():
    with pytest.raises(Unresolvable, match="negative zero"):
        to_source(evaluate("0 * -1"))


def test_long_concatenation_chain_is_evaluated_iteratively():
    terms = 20_000
    assert evaluate(" + ".join(['"a"'] * terms)) == "a" * terms


def test_long_unresolvable_chain_fails_fast():
    parsed = parse("x = y" + ' + "a"' * 20_000 + ";")
    evaluator = StaticEvaluator(parsed)
    # Every operator in the chain shares the one failure, so asking about
    # each of them is linear overall rather than quadratic.
    results = [evaluator.try_evaluate(node) for node in parsed.index.of_type("binary_expression")]
    assert results == [None] * 20_000


def test_deep_nesting_is_refused_not_crashed():
    with pytest.raises(Unresolvable, match="nested too deeply"):
        evaluate("(" * 500 + "1" + ")" * 500)


@pytest.mark.parametrize(
    ("expression", "text", "is_complete"),
    [
        ('"/api/" + "users"', "/api/users", True),
        ('"/api/" + id', "/api/${id}", False),
        ('base + "/users"', "${base}/users", False),
        ('"/a/" + 1 + x', "/a/1${x}", False),
        ('n + 1 + "/x"', "${n + 1}/x", False),
        ('1 + 2 + "/x"', "3/x", True),
        ("`/u/${id}/p`", "/u/${id}/p", False),
        ("`/u/${1 + 1}/p`", "/u/2/p", True),
    ],
)
def test_partial_string(expression, text, is_complete):
    parsed = parse(f"x = {expression};")
    partial = StaticEvaluator(parsed).partial_string(_assigned_expression(parsed))
    assert partial is not None
    assert (partial.text, partial.is_complete) == (text, is_complete)


@pytest.mark.parametrize("expression", ["a + b", "1 + 2", "url", "`${a}${b}`", "f()"])
def test_partial_string_needs_some_static_text(expression):
    parsed = parse(f"x = {expression};")
    assert StaticEvaluator(parsed).partial_string(_assigned_expression(parsed)) is None


def test_long_concatenation_does_not_keep_every_intermediate_string():
    import tracemalloc

    # 4,000 pieces of 200 characters join into 800 KB. Caching the value of
    # each of the 4,000 nested operators would take about 1.6 GB.
    parsed = parse("x = " + " + ".join(['"' + "a" * 200 + '"'] * 4000) + ";")
    evaluator = StaticEvaluator(parsed)
    tracemalloc.start()
    try:
        value = evaluator.evaluate(_assigned_expression(parsed))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert value == "a" * 800_000
    assert peak < 50 * 1024 * 1024


def test_oversized_concatenation_is_refused():
    parsed = parse("x = " + " + ".join(['"' + "a" * 1000 + '"'] * 1100) + ";")
    with pytest.raises(Unresolvable, match="exceeds the size limit"):
        StaticEvaluator(parsed).evaluate(_assigned_expression(parsed))
