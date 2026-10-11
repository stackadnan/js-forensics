from js_forensics.analysis.statistics import compute_statistics, describe_file

from .conftest import FIXTURES, parse, parse_fixture


def test_readable_fixture_counts():
    stats = compute_statistics(parse_fixture("readable.js"))
    assert stats.function_declarations == 1  # formatPrice
    assert stats.function_expressions == 1  # legacy
    assert stats.arrow_functions == 1  # double
    assert stats.methods == 2  # constructor, total
    assert stats.classes == 1
    assert stats.variable_declarations == {"var": 1, "let": 2, "const": 3}
    assert stats.string_literals == 4
    assert stats.template_literals == 0
    assert stats.number_literals == 8
    assert stats.function_calls == 7
    assert stats.new_expressions == 1
    assert stats.loops == {"for": 0, "for_in_of": 1, "while": 1, "do_while": 0}
    assert stats.if_statements == 1
    assert stats.ternary_expressions == 1
    assert stats.switch_statements == 0
    assert stats.comments == 1
    assert stats.max_block_depth == 2


def test_identifier_counts_exclude_property_names():
    stats = compute_statistics(parse("var a = b.c; a.d(a);"))
    # a (declaration), b, a, a. The property names c and d are not identifiers.
    assert stats.identifier_occurrences == 4
    assert stats.unique_identifiers == 2


def test_each_loop_kind_is_counted():
    stats = compute_statistics(
        parse("for (;;) {} for (k in o) {} for (v of l) {} while (a) {} do {} while (b);")
    )
    assert stats.loops == {"for": 1, "for_in_of": 2, "while": 1, "do_while": 1}


def test_file_description():
    path = FIXTURES / "minified.js"
    info = describe_file(parse_fixture("minified.js"))
    assert info.size_bytes == path.stat().st_size
    assert info.line_count == 1
    assert info.max_line_length == info.size_bytes
    assert len(info.sha256) == 64


def test_empty_file_statistics():
    parsed = parse_fixture("empty.js")
    stats = compute_statistics(parsed)
    assert stats.function_calls == 0
    assert stats.syntax_nodes == 1
    assert describe_file(parsed).line_count == 0
