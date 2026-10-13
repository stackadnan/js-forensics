"""Terminal rendering with Rich.

Analyzed text is always wrapped in ``Text`` (never parsed as Rich markup) and
passed through ``escape_for_display`` so control characters and ANSI escapes
from a hostile file cannot reach the terminal.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from js_forensics.analysis.js_literals import escape_for_display
from js_forensics.models import (
    AnalysisReport,
    DomainFinding,
    Endpoint,
    ExtractedString,
    SourceLocation,
    TransformationHistory,
    Unresolved,
)

VALUE_WIDTH = 100
SUMMARY_ROWS = 15


def shown(value: str, limit: int = VALUE_WIDTH, *, is_source: bool = False) -> Text:
    """Analyzed text made safe to print. ``is_source`` is for code excerpts."""
    text = escape_for_display(value, is_source=is_source)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return Text(text)


def position(location: SourceLocation | None) -> str:
    return f"{location.line}:{location.column}" if location is not None else "-"


def _table(*columns: str) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    for column in columns:
        table.add_column(column, overflow="fold")
    return table


def _heading(console: Console, title: str) -> None:
    console.print()
    console.print(Text(title, style="bold underline"))


def _more(console: Console, total: int, listed: int, hint: str) -> None:
    if total > listed:
        console.print(Text(f"… {total - listed} more. {hint}", style="dim"))


def render_strings(console: Console, strings: list[ExtractedString]) -> None:
    table = _table("Category", "At", "Count", "Value")
    for string in strings:
        table.add_row(
            string.category,
            position(string.locations[0]),
            str(string.occurrences),
            shown(string.value),
        )
    console.print(table)
    console.print(Text(f"{len(strings)} distinct string(s).", style="dim"))


def render_endpoints(
    console: Console,
    endpoints: list[Endpoint],
    domains: list[DomainFinding],
    unresolved: list[Unresolved],
) -> None:
    if endpoints:
        table = _table("Method", "URL", "Source", "Resolved", "At")
        for endpoint in endpoints:
            table.add_row(
                endpoint.method,
                shown(endpoint.url),
                endpoint.source,
                endpoint.resolution,
                position(endpoint.locations[0]),
            )
        console.print(table)
    else:
        console.print("No potential endpoints found.")
    if domains:
        console.print()
        console.print(
            Text("Domains: ", style="bold")
            + Text(", ".join(escape_for_display(domain.domain) for domain in domains))
        )
    if unresolved:
        console.print()
        table = _table("Unresolved call", "At", "Reason")
        for item in unresolved:
            table.add_row(item.subject, position(item.location), item.reason)
        console.print(table)
    console.print()
    console.print(
        Text(
            "Endpoints are strings found in the source. No request was made, and a listing "
            "here does not show that the code ever makes one.",
            style="dim",
        )
    )


def render_transformations(console: Console, history: TransformationHistory) -> None:
    table = _table("Transformation", "Changes", "Skipped", "Status")
    for record in history.records:
        if record.reverted_reason is not None:
            status = f"reverted: {record.reverted_reason}"
        else:
            status = "changed" if record.changed else "no change"
        table.add_row(record.name, str(record.change_count), str(record.skipped_count), status)
    console.print(table)
    for record in history.records:
        for skipped in record.skipped[:SUMMARY_ROWS]:
            console.print(
                Text(f"  skipped {position(skipped.location)} ", style="dim")
                + shown(skipped.snippet, 60, is_source=True)
                + Text(f" - {skipped.reason}", style="dim")
            )


def render_report(console: Console, report: AnalysisReport) -> None:
    file, stats = report.file, report.statistics
    console.print(Text(f"JS Forensics {report.tool['version']}", style="bold"), Text(file.path))
    for warning in report.warnings:
        console.print(Text(f"Warning: {warning}", style="yellow"))

    _heading(console, "File")
    overview = _table("", "")
    overview.show_header = False
    declarations = stats.variable_declarations
    loops = sum(stats.loops.values())
    for label, value in (
        ("Size", f"{file.size_bytes:,} bytes, {file.line_count:,} lines"),
        ("Longest line", f"{file.max_line_length:,} bytes"),
        ("SHA-256", file.sha256),
        (
            "Functions",
            f"{stats.function_declarations} declarations, {stats.function_expressions} "
            f"expressions, {stats.arrow_functions} arrows, {stats.methods} methods",
        ),
        (
            "Variables",
            f"{declarations.get('var', 0)} var, {declarations.get('let', 0)} let, "
            f"{declarations.get('const', 0)} const",
        ),
        (
            "Identifiers",
            f"{stats.identifier_occurrences:,} occurrences, {stats.unique_identifiers:,} unique",
        ),
        (
            "Literals",
            f"{stats.string_literals} strings, {stats.template_literals} templates, "
            f"{stats.number_literals} numbers, {stats.regex_literals} regexes",
        ),
        ("Calls", f"{stats.function_calls} calls, {stats.new_expressions} new"),
        (
            "Control flow",
            f"{loops} loops, {stats.if_statements} if, {stats.ternary_expressions} ternaries, "
            f"{stats.switch_statements} switch",
        ),
    ):
        overview.add_row(label, value)
    console.print(overview)

    _heading(console, f"Obfuscation indicators (heuristic score {report.obfuscation.score}/100)")
    console.print(
        Text(
            "The score adds fixed weights for the indicators below. It is not a probability "
            "and not a verdict on what the code does.",
            style="dim",
        )
    )
    if not report.obfuscation.indicators:
        console.print("None of the checked indicators triggered.")
    for indicator in report.obfuscation.indicators:
        console.print(Text(f"[+{indicator.weight}] {indicator.title}", style="bold"))
        for evidence in indicator.evidence:
            line = Text(f"    {position(evidence.location)}  {evidence.detail}")
            if evidence.snippet:
                line += Text("  ") + shown(evidence.snippet, 70, is_source=True)
            console.print(line)

    identifiers = report.identifiers
    _heading(console, "Identifiers")
    console.print(
        f"{identifiers.declared_names} declared names: {identifiers.hex_style_names} hex-style "
        f"(_0x…), {identifiers.short_names} of 1-2 characters, "
        f"average length {identifiers.average_name_length}."
    )

    if report.decoded_values or report.unresolved_decodes:
        _heading(console, "Decoded values")
        if report.decoded_values:
            table = _table("Technique", "At", "Value")
            for decoded in report.decoded_values[:SUMMARY_ROWS]:
                table.add_row(decoded.technique, position(decoded.location), shown(decoded.value))
            console.print(table)
        _more(console, len(report.decoded_values), SUMMARY_ROWS, "Use --format json for all.")
        for item in report.unresolved_decodes[:SUMMARY_ROWS]:
            console.print(
                Text(f"  not decoded {position(item.location)} {item.subject}: {item.reason}")
            )

    _heading(console, "Browser APIs referenced")
    if report.browser_apis:
        table = _table("API", "Category", "Usage", "Count", "Confidence", "First at")
        for finding in report.browser_apis:
            table.add_row(
                finding.api,
                finding.category,
                finding.usage,
                str(finding.count),
                finding.confidence,
                position(finding.locations[0]),
            )
        console.print(table)
    else:
        console.print("None found.")

    _heading(console, "Potential network endpoints")
    render_endpoints(
        console, report.endpoints, report.domains, report.unresolved_network_calls[:SUMMARY_ROWS]
    )

    _heading(console, "Strings")
    by_category: dict[str, int] = {}
    for string in report.strings:
        by_category[string.category] = by_category.get(string.category, 0) + 1
    summary = ", ".join(f"{count} {category}" for category, count in sorted(by_category.items()))
    console.print(f"{len(report.strings)} distinct: {summary}." if summary else "None found.")
    notable = [string for string in report.strings if string.category != "other"]
    if notable:
        table = _table("Category", "At", "Value")
        for string in notable[:SUMMARY_ROWS]:
            table.add_row(string.category, position(string.locations[0]), shown(string.value))
        console.print(table)
        _more(console, len(notable), SUMMARY_ROWS, "Use the `strings` command for all.")

    if report.transformations is not None:
        _heading(console, "Transformations")
        render_transformations(console, report.transformations)

    _heading(console, "Limitations")
    for limitation in report.limitations:
        console.print(Text(f"- {limitation}"))
