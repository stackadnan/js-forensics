"""Standalone HTML report.

The page contains no script at all, and a Content-Security-Policy meta tag
forbids scripts in case that ever regresses. Every piece of text passes
through ``_text`` (display escaping, then HTML escaping); there is no path
that writes analyzed content into the page unescaped.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Sequence

from js_forensics import config
from js_forensics.analysis.js_literals import escape_for_display
from js_forensics.models import AnalysisReport, SourceLocation, Unresolved

_STYLE = """
:root { color-scheme: light dark; --border: #c8ccd1; --muted: #5f6672; --accent: #0b57d0;
  --warn-bg: #fff4ce; --warn-fg: #5c4400; --code-bg: #f1f3f4; }
@media (prefers-color-scheme: dark) {
  :root { --border: #454a52; --muted: #a0a7b3; --accent: #8ab4f8; --warn-bg: #4a3c00;
    --warn-fg: #ffe9a6; --code-bg: #26292e; } }
body { font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 1100px;
  padding: 24px 16px; }
h1 { font-size: 1.5rem; margin: 0 0 4px; } h2 { font-size: 1.15rem; margin: 32px 0 8px; }
h3 { font-size: 1rem; margin: 16px 0 4px; }
p.muted, td.muted, .muted { color: var(--muted); }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { border-bottom: 1px solid var(--border); padding: 4px 8px; text-align: left;
  vertical-align: top; }
th { font-size: 0.85rem; color: var(--muted); font-weight: 600; }
code { font: 13px/1.4 ui-monospace, monospace; background: var(--code-bg); padding: 1px 4px;
  border-radius: 3px; overflow-wrap: anywhere; white-space: pre-wrap; }
.scroll { overflow-x: auto; }
.warning { background: var(--warn-bg); color: var(--warn-fg); padding: 8px 12px;
  border-radius: 4px; margin: 8px 0; }
.score { font-size: 2rem; font-weight: 700; color: var(--accent); }
nav a { color: var(--accent); margin-right: 12px; }
"""


def _text(value: object) -> str:
    return html.escape(escape_for_display(str(value)), quote=True)


def _code(value: object) -> str:
    return f"<code>{_text(value)}</code>"


def _source(excerpt: str) -> str:
    """An excerpt of analyzed JavaScript, shown as written."""
    escaped = html.escape(escape_for_display(excerpt, is_source=True), quote=True)
    return f"<code>{escaped}</code>"


def _position(location: SourceLocation | None) -> str:
    return f"{location.line}:{location.column}" if location is not None else "-"


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]], total: int) -> str:
    """Build a table from cells that are already safe HTML."""
    if total == 0:
        return '<p class="muted">None found.</p>'
    head = "".join(f"<th>{_text(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    note = ""
    if total > config.MAX_HTML_TABLE_ROWS:
        note = (
            f'<p class="muted">Showing the first {config.MAX_HTML_TABLE_ROWS:,} of {total:,} '
            "rows. The JSON report has all of them.</p>"
        )
    return f'<div class="scroll"><table><tr>{head}</tr>{body}</table></div>{note}'


def _unresolved_table(items: list[Unresolved]) -> str:
    rows = (
        (_text(item.subject), _position(item.location), _text(item.reason), _source(item.snippet))
        for item in items
    )
    return _table(("Subject", "At", "Why it was left alone", "Source"), rows, len(items))


def _overview(report: AnalysisReport) -> str:
    file, stats = report.file, report.statistics
    loops = ", ".join(f"{count} {name.replace('_', '-')}" for name, count in stats.loops.items())
    declarations = ", ".join(
        f"{count} {keyword}" for keyword, count in stats.variable_declarations.items()
    )
    facts = (
        ("Path", _code(file.path)),
        ("SHA-256", _code(file.sha256)),
        ("Size", f"{file.size_bytes:,} bytes in {file.line_count:,} lines"),
        ("Longest line", f"{file.max_line_length:,} bytes"),
        ("Parser", _text(report.parse.parser)),
        (
            "Functions",
            f"{stats.function_declarations} declarations, {stats.function_expressions} "
            f"expressions, {stats.arrow_functions} arrow functions, {stats.methods} methods",
        ),
        ("Classes", str(stats.classes)),
        ("Variable declarations", _text(declarations)),
        (
            "Identifiers",
            f"{stats.identifier_occurrences:,} occurrences of {stats.unique_identifiers:,} names",
        ),
        (
            "Literals",
            f"{stats.string_literals} strings, {stats.template_literals} templates, "
            f"{stats.number_literals} numbers, {stats.regex_literals} regular expressions",
        ),
        ("Calls", f"{stats.function_calls} calls, {stats.new_expressions} new expressions"),
        ("Loops", _text(loops)),
        (
            "Conditionals",
            f"{stats.if_statements} if, {stats.ternary_expressions} ternary, "
            f"{stats.switch_statements} switch",
        ),
        ("Deepest block nesting", str(stats.max_block_depth)),
        ("Comments", str(stats.comments)),
    )
    rows = "".join(f"<tr><th>{_text(label)}</th><td>{value}</td></tr>" for label, value in facts)
    return f"<table>{rows}</table>"


def _obfuscation(report: AnalysisReport) -> str:
    obfuscation = report.obfuscation
    parts = [
        f'<p><span class="score">{obfuscation.score}</span> / 100 heuristic score</p>',
        '<p class="muted">The score is the capped sum of the weights of the indicators that '
        f"triggered, out of {len(obfuscation.checked)} checked. It is not a probability and "
        "not a judgement about what the code does.</p>",
    ]
    if not obfuscation.indicators:
        parts.append('<p class="muted">None of the checked indicators triggered.</p>')
    for indicator in obfuscation.indicators:
        parts.append(f"<h3>{_text(indicator.title)} (+{indicator.weight})</h3>")
        parts.append(f"<p>{_text(indicator.explanation)}</p>")
        rows = (
            (
                _position(evidence.location),
                _text(evidence.detail),
                _source(evidence.snippet) if evidence.snippet else "",
            )
            for evidence in indicator.evidence
        )
        parts.append(_table(("At", "Evidence", "Source"), rows, len(indicator.evidence)))
    return "".join(parts)


def _transformations(report: AnalysisReport) -> str:
    history = report.transformations
    if history is None:
        return ""
    parts = [
        '<h2 id="transformations">Transformation history</h2>',
        f"<p>Input SHA-256 {_code(history.input_sha256)}, output SHA-256 "
        f"{_code(history.output_sha256)}. Locations refer to the input of each stage, which "
        "is the output of the stage before it.</p>",
    ]
    for record in history.records:
        if record.reverted_reason is not None:
            status = f"reverted: {record.reverted_reason}"
        else:
            status = f"{record.change_count} change(s)" if record.changed else "no change"
        parts.append(f"<h3>{_text(record.name)}: {_text(status)}</h3>")
        parts.append(f"<p>{_text(record.description)}</p>")
        if record.changes:
            rows = (
                (_position(change.location), _source(change.before), _source(change.after))
                for change in record.changes
            )
            parts.append(_table(("At", "Before", "After"), rows, len(record.changes)))
            if record.change_count > len(record.changes):
                parts.append(
                    f'<p class="muted">{record.change_count - len(record.changes)} further '
                    "change(s) not listed.</p>"
                )
        if record.skipped:
            parts.append(f"<p>{record.skipped_count} recognised but left unchanged:</p>")
            parts.append(_unresolved_table(record.skipped))
    return "".join(parts)


def render_html(report: AnalysisReport) -> str:
    limit = config.MAX_HTML_TABLE_ROWS
    strings = _table(
        ("Category", "Kind", "First at", "Count", "Value"),
        (
            (
                _text(string.category),
                _text(string.kind),
                _position(string.locations[0]),
                str(string.occurrences),
                _code(string.value),
            )
            for string in report.strings[:limit]
        ),
        len(report.strings),
    )
    decoded = _table(
        ("Technique", "At", "Decoded value", "Source"),
        (
            (
                _text(item.technique),
                _position(item.location),
                _code(item.value),
                _source(item.source),
            )
            for item in report.decoded_values[:limit]
        ),
        len(report.decoded_values),
    )
    apis = _table(
        ("API", "Category", "Usage", "Count", "Confidence", "First at", "Note"),
        (
            (
                _code(finding.api),
                _text(finding.category),
                _text(finding.usage),
                str(finding.count),
                _text(finding.confidence),
                _position(finding.locations[0]),
                _text(finding.note or ""),
            )
            for finding in report.browser_apis
        ),
        len(report.browser_apis),
    )
    endpoints = _table(
        ("Method", "URL", "Found in", "Resolution", "Count", "First at"),
        (
            (
                _text(endpoint.method),
                _code(endpoint.url),
                _text(endpoint.source),
                _text(endpoint.resolution),
                str(endpoint.occurrences),
                _position(endpoint.locations[0]),
            )
            for endpoint in report.endpoints[:limit]
        ),
        len(report.endpoints),
    )
    domains = _table(
        ("Domain", "Occurrences"),
        ((_code(domain.domain), str(domain.occurrences)) for domain in report.domains),
        len(report.domains),
    )
    identifiers = report.identifiers
    identifier_rows = (
        ""
        if not identifiers.findings
        else _table(
            ("Name", "Declared as", "Declarations", "References", "First at"),
            (
                (
                    _code(finding.name),
                    _text(", ".join(finding.declared_as)),
                    str(finding.declaration_count),
                    str(finding.reference_count),
                    _position(finding.location),
                )
                for finding in identifiers.findings
            ),
            len(identifiers.findings),
        )
    )
    warnings = "".join(f'<p class="warning">{_text(warning)}</p>' for warning in report.warnings)
    syntax_errors = ""
    if report.parse.has_errors:
        syntax_errors = "<h3>Syntax errors</h3>" + _table(
            ("At", "Message"),
            ((_position(issue.location), _text(issue.message)) for issue in report.parse.errors),
            len(report.parse.errors),
        )
    limitations = "".join(f"<li>{_text(item)}</li>" for item in report.limitations)
    redaction = (
        "Likely credentials were masked in this report."
        if report.redaction_enabled
        else "Credential redaction was turned off for this report."
    )
    not_decoded = ""
    if report.unresolved_decodes:
        not_decoded = "<h3>Not decoded</h3>" + _unresolved_table(report.unresolved_decodes)
    unresolved_calls = ""
    if report.unresolved_network_calls:
        unresolved_calls = "<h3>Request calls with a non-static URL</h3>" + _unresolved_table(
            report.unresolved_network_calls
        )
    tool_version = _text(report.tool["version"])
    history_link = (
        '<a href="#transformations">Transformations</a>' if report.transformations else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JS Forensics report: {_text(report.file.path)}</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>JS Forensics report</h1>
<p class="muted">{_code(report.file.path)} analysed statically by js-forensics
{tool_version}. The file was not executed.</p>
<nav><a href="#overview">Overview</a><a href="#obfuscation">Obfuscation</a>
<a href="#strings">Strings</a><a href="#apis">Browser APIs</a>
<a href="#endpoints">Endpoints</a>{history_link}<a href="#limitations">Limitations</a></nav>
{warnings}
<h2 id="overview">File overview and statistics</h2>
{_overview(report)}
{syntax_errors}
<h2 id="obfuscation">Obfuscation indicators</h2>
{_obfuscation(report)}
<h2 id="identifiers">Identifiers</h2>
<p>{identifiers.declared_names} declared names, of which {identifiers.hex_style_names} are
hex-style and {identifiers.short_names} are one or two characters long (average length
{identifiers.average_name_length}). Counts are by name and do not distinguish scopes.</p>
{identifier_rows}
<h2 id="decoded">Decoded values</h2>
{decoded}
{not_decoded}
<h2 id="strings">Extracted strings</h2>
{strings}
<h2 id="apis">Browser API references</h2>
<p class="muted">A reference shows that the source mentions an API. It does not show that
the code runs.</p>
{apis}
<h2 id="endpoints">Potential network endpoints</h2>
<p class="muted">Found by reading the source. No request was made to any of them.</p>
{endpoints}
<h3>Domains</h3>
{domains}
{unresolved_calls}
{_transformations(report)}
<h2 id="limitations">Warnings and limitations</h2>
<p>{_text(redaction)}</p>
<ul>{limitations}</ul>
</body>
</html>
"""
