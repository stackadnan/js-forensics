import pytest

from js_forensics.analysis.decoding import find_decoded_values
from js_forensics.analysis.identifiers import collect_bindings
from js_forensics.analysis.static_eval import StaticEvaluator
from js_forensics.analysis.strings import (
    classify_string,
    collect_string_occurrences,
    summarize_strings,
)
from js_forensics.parser import ParsedSource

from .conftest import parse, parse_fixture


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ("https://api.example.com/v1/users?page=2", "url"),
        ("wss://live.example.com/feed", "url"),
        ("//cdn.example.com/lib.js", "url"),
        ("api.example.com", "domain"),
        ("example.co.uk:8443", "domain"),
        ("/api/v1/users", "api_path"),
        ("/users/${id}/posts", "api_path"),
        ("/search?q=term", "api_path"),
        ("Content-Type", "http_header"),
        ("authorization", "http_header"),
        ("X-Requested-With", "http_header"),
        ("Set-Cookie", "cookie"),
        ("sid=abc123; Path=/; HttpOnly", "cookie"),
        ('<div class="x">hi</div>', "html"),
        ("</span>", "html"),
        ('{"a": 1}', "json"),
        ("[1, 2, 3]", "json"),
        # Ambiguous or unrelated strings stay unclassified.
        ("hello world", "other"),
        ("file.js", "other"),
        ("user.name", "other"),
        ("/", "other"),
        ("a < b > c", "other"),
        ("{not json}", "other"),
        ("https://", "other"),
        ("", "other"),
    ],
)
def test_classify_string(value, category):
    assert classify_string(value) == category


def test_deeply_nested_json_like_string_does_not_crash():
    assert classify_string("[" * 100_000 + "]" * 100_000) in ("json", "other")


def test_escaped_literals_are_decoded_and_flagged():
    occurrences = collect_string_occurrences(parse_fixture("escapes.js"))
    by_value = {occurrence.value: occurrence for occurrence in occurrences}
    assert by_value["hello"].escape_encoded
    assert by_value["world"].escape_encoded
    assert "\U0001f600" in by_value
    assert by_value['"\\"'].has_escapes
    # One needless escape in a long plain string is not "escape-encoded".
    assert not by_value["tab\there A"].escape_encoded
    assert by_value["tab\there A"].has_escapes


def test_literal_with_invalid_escape_keeps_its_raw_text():
    parsed = ParsedSource(rb'var a = "\u12";')
    values = [occurrence.value for occurrence in collect_string_occurrences(parsed)]
    assert values == [r"\u12"]


def test_template_literals_keep_substitutions_as_placeholders():
    parsed = parse("var a = `/users/${user.id}/posts`, b = `plain\\n`;")
    occurrences = collect_string_occurrences(parsed)
    assert [(o.value, o.kind) for o in occurrences] == [
        ("/users/${user.id}/posts", "template"),
        ("plain\n", "template"),
    ]


def test_summary_groups_duplicates_and_keeps_locations():
    parsed = parse('a("/api/x");\nb("/api/x");\nc("other");')
    strings = summarize_strings(parsed, collect_string_occurrences(parsed))
    grouped = {string.value: string for string in strings}
    assert grouped["/api/x"].occurrences == 2
    assert grouped["/api/x"].category == "api_path"
    assert [(loc.line, loc.column) for loc in grouped["/api/x"].locations] == [(1, 3), (2, 3)]
    assert grouped["other"].occurrences == 1


def test_credential_context_is_detected_from_names():
    parsed = parse(
        'var apiKey = "k1"; var o = {password: "p1", "client_secret": "s1", name: "n1"};'
        'config.authToken = "t1"; var title = "x1";'
    )
    flagged = {
        occurrence.value
        for occurrence in collect_string_occurrences(parsed)
        if occurrence.in_credential_context
    }
    assert flagged == {"k1", "p1", "s1", "t1"}


def _decoded(name: str):
    parsed = parse_fixture(name)
    occurrences = collect_string_occurrences(parsed)
    evaluator = StaticEvaluator(
        parsed, resolve_decoders=True, rebound_names=collect_bindings(parsed).rebound_names
    )
    return find_decoded_values(parsed, occurrences, evaluator)


def test_decoder_calls_are_resolved_statically():
    decoded, unresolved = _decoded("base64.js")
    assert [(item.technique, item.value, item.location.line) for item in decoded] == [
        ("atob", "https://api.example.com/v1/users", 1),
        ("String.fromCharCode", "hi!", 2),
        ("String.fromCodePoint", "\U0001f600", 3),
        ("atob", "\x00\x01\xff", 4),
    ]
    assert len(unresolved) == 1
    assert unresolved[0].subject == "atob"
    assert unresolved[0].location.line == 5
    assert "argument 1 is not static" in unresolved[0].reason


def test_escape_encoded_literals_are_reported_as_decoded():
    decoded, unresolved = _decoded("escapes.js")
    assert [(item.technique, item.value) for item in decoded] == [
        ("escape-sequences", "hello"),
        ("escape-sequences", "world"),
        ("escape-sequences", '"\\"'),
    ]
    assert unresolved == []
