import io
import json
import re

import pytest
from rich.console import Console

from js_forensics.analyzer import SCHEMA_VERSION, analyze
from js_forensics.models import AnalysisReport
from js_forensics.parser import ParsedSource
from js_forensics.reporting import terminal
from js_forensics.reporting.html_report import render_html
from js_forensics.reporting.json_report import to_json
from js_forensics.reporting.redaction import Redactor, mask

from .conftest import parse, parse_fixture

TOP_LEVEL_KEYS = {
    "schema_version", "tool", "file", "parse", "statistics", "obfuscation", "strings",
    "decoded_values", "unresolved_decodes", "identifiers", "browser_apis", "endpoints",
    "domains", "unresolved_network_calls", "transformations", "redaction_enabled", "warnings",
    "limitations",
}  # fmt: skip


def render_text(report: AnalysisReport) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=120, color_system=None, markup=False, highlight=False)
    terminal.render_report(console, report)
    return buffer.getvalue()


# --- JSON -------------------------------------------------------------------


def test_json_report_has_the_documented_top_level_shape():
    report = json.loads(to_json(analyze(parse_fixture("endpoints.js"))))
    assert set(report) == TOP_LEVEL_KEYS
    assert report["schema_version"] == SCHEMA_VERSION == "1.0"
    assert report["tool"]["name"] == "js-forensics"
    assert report["parse"] == {
        "parser": "tree-sitter-javascript",
        "has_errors": False,
        "error_count": 0,
        "errors": [],
    }
    assert report["transformations"] is None
    assert report["file"]["line_count"] == 19
    assert report["endpoints"][0] == {
        "url": "https://api.example.com/v1/users",
        "method": "GET",
        "source": "fetch",
        "resolution": "static",
        "occurrences": 2,
        "locations": [
            {"line": 1, "column": 1, "end_line": 1, "end_column": 42},
            {"line": 2, "column": 1, "end_line": 2, "end_column": 42},
        ],
        "redacted": False,
    }


def test_json_report_is_stable_for_the_same_input():
    first = to_json(analyze(parse_fixture("string_array.js")))
    second = to_json(analyze(parse_fixture("string_array.js")))
    assert first == second


def test_json_survives_strings_that_are_not_valid_unicode_text():
    # A lone surrogate is a legal JavaScript string but cannot be UTF-8.
    report = analyze(ParsedSource(rb'var a = "\uD83D", b = "\x00\x1b";'))
    text = to_json(report)
    text.encode("utf-8")
    values = [string["value"] for string in json.loads(text)["strings"]]
    assert values == ["\ud83d", "\x00\x1b"]


def test_empty_file_report():
    report = json.loads(to_json(analyze(parse_fixture("empty.js"))))
    assert report["file"]["size_bytes"] == 0
    assert report["strings"] == [] and report["endpoints"] == [] and report["browser_apis"] == []
    assert report["obfuscation"]["score"] == 0


def test_tolerant_analysis_carries_a_warning():
    report = analyze(parse_fixture("malformed.js"), with_transformations=True)
    assert report.parse.has_errors
    assert report.parse.errors[0].location.line == 1
    assert any("syntax error" in warning for warning in report.warnings)
    assert any("Transformations were skipped" in warning for warning in report.warnings)
    assert report.transformations is None


def test_transformation_history_is_included_on_request():
    report = analyze(parse_fixture("obfuscated_sample.js"), with_transformations=True)
    assert report.transformations is not None
    assert [record.name for record in report.transformations.records] == [
        "format-statements",
        "simplify-string-escapes",
        "decode-static-calls",
        "fold-constants",
    ]
    assert json.loads(to_json(report))["transformations"]["changed"] is True


# --- HTML -------------------------------------------------------------------


def test_html_escapes_untrusted_text():
    page = render_html(analyze(parse_fixture("untrusted_text.js"), redact=False))
    # The report has no script element of its own, so any occurrence would
    # have come from the analyzed file.
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in page
    assert 'onerror="' not in page


def test_html_has_no_active_content_and_a_restrictive_policy():
    page = render_html(analyze(parse_fixture("endpoints.js")))
    assert "default-src 'none'" in page
    assert not re.search(r"<(script|iframe|object|embed|link|form)\b", page, re.IGNORECASE)
    assert not re.search(r"\son[a-z]+\s*=", page, re.IGNORECASE)
    assert "javascript:" not in page.lower()
    # Extracted URLs are shown as text, never as links.
    assert 'href="http' not in page


def test_html_does_not_contain_raw_control_or_bidi_characters():
    page = render_html(analyze(parse_fixture("untrusted_text.js"), redact=False))
    assert "\x1b" not in page and "\u202e" not in page
    assert "\\x1b[31mred" in page
    assert "safe\\u202egnp.exe" in page
    page.encode("utf-8")


def test_html_escapes_the_file_path():
    parsed = ParsedSource(b"var a = 1;", path='<b onmouseover="x">.js')
    page = render_html(analyze(parsed))
    assert "<b onmouseover" not in page
    assert "&lt;b onmouseover=&quot;x&quot;&gt;.js" in page


def test_html_sections():
    page = render_html(analyze(parse_fixture("obfuscated_sample.js"), with_transformations=True))
    for heading in (
        "File overview and statistics",
        "Obfuscation indicators",
        "Extracted strings",
        "Browser API references",
        "Potential network endpoints",
        "Transformation history",
        "Warnings and limitations",
    ):
        assert f">{heading}</h2>" in page
    assert "String array with numeric lookups" not in page  # indices are hex but too few
    assert "Escape-encoded string literals" in page
    assert "atob(&quot;L3YxL3Nlc3Npb24=&quot;)" in page
    assert "No request was made" in page
    assert "It is not a probability" in page


def test_html_omits_transformations_unless_requested():
    page = render_html(analyze(parse_fixture("obfuscated_sample.js")))
    assert "Transformation history" not in page


def test_html_reports_syntax_errors():
    page = render_html(analyze(parse_fixture("malformed.js")))
    assert 'class="warning"' in page
    assert "Syntax errors</h3>" in page


# --- terminal ---------------------------------------------------------------


def test_terminal_summary_sections():
    text = render_text(analyze(parse_fixture("endpoints.js")))
    for expected in (
        "Obfuscation indicators (heuristic score",
        "Browser APIs referenced",
        "Potential network endpoints",
        "https://api.example.com/v1/users",
        "Limitations",
        "not a probability",
    ):
        assert expected in text


def test_terminal_output_neutralises_control_characters_and_markup():
    parsed = parse('var a = "\\x1b[31mred", b = "[bold red]not markup[/bold red]";')
    text = render_text(analyze(parsed))
    assert "\x1b" not in text
    buffer = io.StringIO()
    console = Console(file=buffer, width=120, color_system=None, markup=False, highlight=False)
    terminal.render_strings(console, analyze(parsed).strings)
    listing = buffer.getvalue()
    assert "\\x1b[31mred" in listing
    assert "[bold red]not markup[/bold red]" in listing


# --- redaction --------------------------------------------------------------

SECRETS = (
    "live_9f8e7d6c5b4a3f2e1d0c",
    "hunter2secret",
    "abcdef0123456789",
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "0a1b2c3d4e5f6a7b8c9d",
)


def test_likely_credentials_are_masked_in_every_format():
    report = analyze(parse_fixture("untrusted_text.js"), with_transformations=True)
    for rendered in (to_json(report), render_html(report), render_text(report)):
        for secret in SECRETS:
            assert secret not in rendered
    assert report.redaction_enabled
    redacted = [string for string in report.strings if string.redacted]
    assert len(redacted) == 4
    endpoint = report.endpoints[0]
    assert endpoint.redacted
    assert endpoint.url == (
        "https://admin:hunt…[redacted 13 chars]@internal.example.com/data"
        "?token=abcd…[redacted 16 chars]&page=2"
    )
    # Non-secret parts of the same findings are kept.
    assert [domain.domain for domain in report.domains] == ["internal.example.com"]


def test_redaction_can_be_turned_off():
    report = analyze(parse_fixture("untrusted_text.js"), redact=False)
    rendered = to_json(report)
    assert not report.redaction_enabled
    for secret in SECRETS:
        assert secret in rendered
    assert not any(string.redacted for string in report.strings)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("Authorization: Bearer abc.def-ghi_jkl123", "abc.def-ghi_jkl123"),
        ("https://x.test/cb?api_key=s3cr3tvalue&x=1", "s3cr3tvalue"),
        ("sid=4f9a8b7c6d5e; Path=/; HttpOnly", "4f9a8b7c6d5e"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow", "MIIEow"),
    ],
)
def test_secret_patterns(text, secret):
    redacted, changed = Redactor().redact(text)
    assert changed
    assert secret not in redacted
    assert "redacted" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "hello world",
        "/api/v1/users?page=2&sort=name",
        "https://example.com/a?token=${token}",
        "Content-Type",
        "key=1",
    ],
)
def test_ordinary_text_is_not_redacted(text):
    assert Redactor().redact(text) == (text, False)


def test_known_secret_values_are_masked_wherever_they_appear():
    redactor = Redactor(["s3cretvalue99"])
    assert redactor.text('login("s3cretvalue99")') == f'login("{mask("s3cretvalue99")}")'
    assert mask("s3cretvalue99") == "s3cr…[redacted 13 chars]"
