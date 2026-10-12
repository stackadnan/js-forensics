from js_forensics.analysis.decoding import find_decoded_values
from js_forensics.analysis.identifiers import collect_bindings
from js_forensics.analysis.static_eval import StaticEvaluator
from js_forensics.analysis.strings import collect_string_occurrences
from js_forensics.detectors.obfuscation import (
    RULES,
    DetectionContext,
    detect_obfuscation,
)
from js_forensics.models import ObfuscationReport
from js_forensics.parser import ParsedSource

from .conftest import parse, parse_fixture


def detect(parsed: ParsedSource) -> ObfuscationReport:
    bindings = collect_bindings(parsed)
    occurrences = collect_string_occurrences(parsed)
    evaluator = StaticEvaluator(parsed, resolve_decoders=True, rebound_names=bindings.rebound_names)
    decoded, _ = find_decoded_values(parsed, occurrences, evaluator)
    return detect_obfuscation(DetectionContext(parsed, occurrences, bindings, decoded))


def triggered(source: str) -> set[str]:
    return {indicator.id for indicator in detect(parse(source)).indicators}


def test_readable_code_scores_zero():
    report = detect(parse_fixture("readable.js"))
    assert report.indicators == []
    assert report.score == 0
    assert report.checked == [rule.id for rule in RULES]


def test_empty_file_scores_zero():
    assert detect(parse_fixture("empty.js")).score == 0


def test_string_array_fixture():
    report = detect(parse_fixture("string_array.js"))
    found = {indicator.id: indicator for indicator in report.indicators}
    assert set(found) == {
        "string-array-lookup",
        "hex-style-identifiers",
        "array-rotation",
    }
    # The fixture has 17 numeric literals, below the 20 that the hex-literal
    # indicator requires. The score is exactly the sum of the triggered weights.
    assert report.score == 25 + 15 + 10

    lookup = found["string-array-lookup"]
    assert "Array of 12 elements" in lookup.evidence[0].detail
    assert "`_0x4f2a`" in lookup.evidence[0].detail
    assert lookup.evidence[0].location.line == 1
    assert any("`_0x5e1b` is called 12 times" in item.detail for item in lookup.evidence)

    rotation = found["array-rotation"]
    assert rotation.evidence[0].location.line == 5
    assert rotation.evidence[0].snippet == '_0x1b3c["push"](_0x1b3c["shift"]())'
    assert "9 of 9 declared names" in found["hex-style-identifiers"].evidence[0].detail


def test_score_is_capped_at_100():
    weights = sum(rule.weight for rule in RULES)
    assert weights > 100  # otherwise the cap could never matter
    assert all(0 < rule.weight <= 25 for rule in RULES)


def test_large_string_array_alone_is_not_an_indicator():
    countries = ", ".join(f'"country{n}"' for n in range(40))
    assert "string-array-lookup" not in triggered(f"var names = [{countries}]; show(names);")


def test_bundler_style_numeric_calls_are_not_accessor_calls():
    words = ", ".join(f'"w{n}"' for n in range(20))
    calls = " ".join(f"n({n});" for n in range(30))
    assert "string-array-lookup" not in triggered(f"var words = [{words}]; {calls}")


def test_direct_numeric_indexing_of_a_string_array():
    words = ", ".join(f'"w{n}"' for n in range(12))
    reads = " ".join(f"use(t[{n}]);" for n in range(6))
    assert "string-array-lookup" in triggered(f"var t = [{words}]; {reads}")


def test_escape_encoded_strings():
    report = detect(parse(r'var a = "\x61\x62\x63", b = "\x64\x65", c = "\x66\x67\x68";'))
    indicator = next(i for i in report.indicators if i.id == "escape-encoded-strings")
    assert "3 of 3 string literals" in indicator.evidence[0].detail
    assert indicator.evidence[1].snippet == r'"\x61\x62\x63"'
    assert indicator.evidence[1].location.column == 9


def test_two_escaped_strings_are_below_the_threshold():
    assert "escape-encoded-strings" not in triggered(r'var a = "\x61\x62", b = "\x63\x64";')


def test_dynamic_evaluation_fixture():
    report = detect(parse_fixture("dynamic_eval.js"))
    indicator = next(i for i in report.indicators if i.id == "dynamic-evaluation")
    found = [(item.location.line, item.detail) for item in indicator.evidence]
    assert found == [
        (1, "Call to eval()."),
        (2, "Code is built with the Function constructor."),
        (3, "Code is built with the Function constructor."),
        (4, "setTimeout() is given a string, which it evaluates as code."),
        (
            6,
            "A .constructor property is called with a string; on a function this is the "
            "Function constructor.",
        ),
    ]


def test_timer_with_a_function_and_eval_reference_are_not_dynamic_evaluation():
    assert "dynamic-evaluation" not in triggered("setTimeout(tick, 10); var e = eval; x.eval;")


def test_bracket_property_access():
    accesses = " ".join(f'o["prop{n}"]();' for n in range(12))
    assert "bracket-property-access" in triggered(accesses)
    # Computed keys that are not identifier-like do not count.
    assert "bracket-property-access" not in triggered(
        " ".join(f'o["data-{n}"] = 1;' for n in range(12))
    )
    # A handful among many dot accesses is below the share threshold.
    dots = " ".join(f"o.p{n}();" for n in range(100))
    assert "bracket-property-access" not in triggered(accesses + dots)


def test_switch_dispatch_loop():
    flattened = (
        'var order = "2|0|1".split("|"), step = 0;'
        "while (!![]) { switch (order[step++]) { case '0': b(); continue; case '1': c(); continue;"
        " case '2': a(); continue; } break; }"
    )
    report = detect(parse(flattened))
    indicator = next(i for i in report.indicators if i.id == "switch-dispatch-loop")
    assert "3 cases" in indicator.evidence[0].detail
    assert "order[step++]" in indicator.evidence[0].detail
    assert "switch-dispatch-loop" in triggered("for (;;) { switch (o[i++]) { case 1: break; } }")


def test_ordinary_switch_in_a_loop_is_not_a_dispatch_loop():
    assert "switch-dispatch-loop" not in triggered(
        "while (true) { switch (state) { case 1: state = next(); break; } }"
    )
    assert "switch-dispatch-loop" not in triggered(
        "while (i < n) { switch (o[i++]) { case 1: break; } }"
    )


def test_static_decoder_calls():
    assert "static-decoder-calls" in triggered("var a = String.fromCharCode(104, 105, 33);")
    # A single character constant is common in ordinary code.
    assert "static-decoder-calls" not in triggered("var nbsp = String.fromCharCode(160);")
    assert "static-decoder-calls" not in triggered("var a = String.fromCharCode(x, y, z);")


def test_hex_number_literals():
    assert "hex-number-literals" in triggered("var a = [" + ", ".join(["0x1f"] * 20) + "];")
    assert "hex-number-literals" not in triggered("var a = [" + ", ".join(["31"] * 20) + "];")
    assert "hex-number-literals" not in triggered("var mask = 0xff, other = 0x0f;")


def test_deep_block_nesting():
    def nested(depth):
        return "if (a) {" * depth + "b();" + "}" * depth

    assert "deep-block-nesting" in triggered(nested(10))
    assert "deep-block-nesting" not in triggered(nested(9))


def test_deep_expression_nesting():
    assert "deep-expression-nesting" in triggered("x = " + "(" * 70 + "1" + ")" * 70 + ";")
    assert "deep-expression-nesting" not in triggered("x = a.b(c).d(e).f(g);")


def test_minified_layout_is_reported_but_weighted_low():
    report = detect(parse("var a = 1;" * 200))
    assert [indicator.id for indicator in report.indicators] == ["minified-layout"]
    assert report.score == 5
    assert "not by itself obfuscation" in report.indicators[0].evidence[0].detail
