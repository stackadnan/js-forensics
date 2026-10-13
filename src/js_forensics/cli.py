"""Command-line interface.

Exit codes are defined in ``js_forensics.errors.ExitCode``. Machine-readable
output goes to stdout or ``--output``; diagnostics always go to stderr, so
``js-forensics analyze x.js --format json | jq`` works.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from js_forensics import __version__, config
from js_forensics.analysis.strings import CATEGORIES
from js_forensics.analyzer import SCHEMA_VERSION, analyze
from js_forensics.deobfuscation.pipeline import (
    run_pipeline,
    write_pipeline_outputs,
    write_text_output,
)
from js_forensics.errors import JavaScriptSyntaxError, JSForensicsError
from js_forensics.models import AnalysisReport
from js_forensics.parser import ParsedSource, parse_file
from js_forensics.reporting import terminal
from js_forensics.reporting.html_report import render_html
from js_forensics.reporting.json_report import to_json

app = typer.Typer(
    name="js-forensics",
    help="Static analysis of minified, obfuscated, or suspicious JavaScript. "
    "Analyzed files are never executed and no URL found in them is contacted.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


class ReportFormat(str, Enum):
    html = "html"
    json = "json"


FileArgument = Annotated[
    Path,
    typer.Argument(
        metavar="FILE",
        help="JavaScript file to analyze. It is only read.",
        show_default=False,
        # Readability is checked when the file is opened, so that every input
        # problem is reported the same way and with the same exit code.
        readable=False,
    ),
]
MaxBytesOption = Annotated[
    int,
    typer.Option("--max-bytes", min=1, help="Refuse input files larger than this many bytes."),
]
TolerantOption = Annotated[
    bool,
    typer.Option(
        "--tolerant", help="Analyze a file with syntax errors anyway and mark results as partial."
    ),
]
NoRedactOption = Annotated[
    bool, typer.Option("--no-redact", help="Show likely credentials instead of masking them.")
]
OutputOption = Annotated[
    Path | None,
    typer.Option(
        "--output", "-o", help="Write to this file instead of standard output.", show_default=False
    ),
]
FormatOption = Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")]


def _console(file: io.StringIO | None = None, *, stderr: bool = False) -> Console:
    # Markup and highlighting are off so that text taken from an analyzed
    # file is printed literally and never interpreted as Rich markup.
    if file is not None:
        return Console(file=file, width=120, color_system=None, markup=False, highlight=False)
    # Diagnostics are not hard-wrapped: a long file path must not split an
    # error message across lines when stderr is captured or piped.
    return Console(stderr=stderr, soft_wrap=stderr, markup=False, highlight=False)


def _fail(error: JSForensicsError) -> typer.Exit:
    stderr = _console(stderr=True)
    stderr.print(Text(f"Error: {error}", style="red"))
    if isinstance(error, JavaScriptSyntaxError):
        for issue in error.issues:
            stderr.print(
                Text(f"  line {issue.location.line}, column {issue.location.column}: ")
                + terminal.shown(issue.message)
            )
        if error.total > len(error.issues):
            stderr.print(Text(f"  … and {error.total - len(error.issues)} more"))
        stderr.print(
            "Fix the file, or pass --tolerant to an analysis command to inspect the parts "
            "that did parse."
        )
    return typer.Exit(int(error.exit_code))


def _load(file: Path, max_bytes: int, tolerant: bool = False) -> ParsedSource:
    try:
        parsed = parse_file(file, max_bytes, tolerant=tolerant)
    except JSForensicsError as error:
        raise _fail(error) from None
    if parsed.has_errors:
        _console(stderr=True).print(
            Text(
                f"Warning: {file} has {len(parsed.index.error_nodes)} syntax error(s); "
                "results are partial.",
                style="yellow",
            )
        )
    return parsed


def _write(content: str, output: Path, source_file: Path) -> None:
    try:
        write_text_output(output, content.encode("utf-8"), protected=source_file)
    except JSForensicsError as error:
        raise _fail(error) from None
    _console(stderr=True).print(f"Wrote {output}")


def _emit_json(payload: object, output: Path | None, source_file: Path) -> None:
    content = to_json(payload)
    if output is None:
        typer.echo(content, nl=False)
    else:
        _write(content, output, source_file)


def _emit_text(render: Callable[[Console], None], output: Path | None, source_file: Path) -> None:
    if output is None:
        render(_console())
        return
    buffer = io.StringIO()
    render(_console(buffer))
    _write(buffer.getvalue(), output, source_file)


def _analyze(
    file: Path, max_bytes: int, tolerant: bool, no_redact: bool, *, transformations: bool = False
) -> AnalysisReport:
    parsed = _load(file, max_bytes, tolerant)
    return analyze(parsed, redact=not no_redact, with_transformations=transformations)


def _show_version(requested: bool) -> None:
    if requested:
        typer.echo(f"js-forensics {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_show_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    pass


@app.command("analyze")
def analyze_command(
    file: FileArgument,
    output_format: FormatOption = OutputFormat.text,
    output: OutputOption = None,
    tolerant: TolerantOption = False,
    no_redact: NoRedactOption = False,
    max_bytes: MaxBytesOption = config.DEFAULT_MAX_INPUT_BYTES,
) -> None:
    """Summarize a file: statistics, obfuscation indicators, strings, browser
    APIs, and potential endpoints.

    Example: js-forensics analyze sample.js --format json --output report.json
    """
    report = _analyze(file, max_bytes, tolerant, no_redact)
    if output_format is OutputFormat.json:
        _emit_json(report, output, file)
    else:
        _emit_text(lambda console: terminal.render_report(console, report), output, file)


@app.command("strings")
def strings_command(
    file: FileArgument,
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help=f"Only list strings in this category: {', '.join(CATEGORIES)}.",
            show_default=False,
        ),
    ] = None,
    output_format: FormatOption = OutputFormat.text,
    output: OutputOption = None,
    tolerant: TolerantOption = False,
    no_redact: NoRedactOption = False,
    max_bytes: MaxBytesOption = config.DEFAULT_MAX_INPUT_BYTES,
) -> None:
    """List string and template literals with a heuristic category.

    Example: js-forensics strings sample.js --category url
    """
    if category is not None and category not in CATEGORIES:
        raise typer.BadParameter(
            f"{category!r} is not a category. Choose from: {', '.join(CATEGORIES)}.",
            param_hint="--category",
        )
    report = _analyze(file, max_bytes, tolerant, no_redact)
    strings = [s for s in report.strings if category is None or s.category == category]
    if output_format is OutputFormat.json:
        payload = {"schema_version": SCHEMA_VERSION, "file": report.file.path, "strings": strings}
        _emit_json(payload, output, file)
    else:
        _emit_text(lambda console: terminal.render_strings(console, strings), output, file)


@app.command("endpoints")
def endpoints_command(
    file: FileArgument,
    output_format: FormatOption = OutputFormat.text,
    output: OutputOption = None,
    tolerant: TolerantOption = False,
    no_redact: NoRedactOption = False,
    max_bytes: MaxBytesOption = config.DEFAULT_MAX_INPUT_BYTES,
) -> None:
    """List potential network endpoints found in the source. Nothing is
    contacted.

    Example: js-forensics endpoints sample.js --format json
    """
    report = _analyze(file, max_bytes, tolerant, no_redact)
    if output_format is OutputFormat.json:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "file": report.file.path,
            "endpoints": report.endpoints,
            "domains": report.domains,
            "unresolved_network_calls": report.unresolved_network_calls,
        }
        _emit_json(payload, output, file)
    else:
        _emit_text(
            lambda console: terminal.render_endpoints(
                console, report.endpoints, report.domains, report.unresolved_network_calls
            ),
            output,
            file,
        )


@app.command("deobfuscate")
def deobfuscate_command(
    file: FileArgument,
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir", "-d", help="Directory for the transformed file and its history."
        ),
    ] = Path("js-forensics-output"),
    no_stages: Annotated[
        bool, typer.Option("--no-stages", help="Do not write the intermediate stage files.")
    ] = False,
    max_bytes: MaxBytesOption = config.DEFAULT_MAX_INPUT_BYTES,
) -> None:
    """Apply the safe transformations and write the result to a new file.

    Writes <name>.deobfuscated.js, transformations.json, and one file per
    stage under stages/. The input file is never modified. Only formatting,
    escape simplification, static decoder calls, and constant folding are
    applied; this does not undo string-array or control-flow obfuscation.

    Example: js-forensics deobfuscate sample.js --output-dir output/
    """
    parsed = _load(file, max_bytes)
    result = run_pipeline(parsed)
    try:
        written = write_pipeline_outputs(result, file, output_dir, keep_stages=not no_stages)
    except JSForensicsError as error:
        raise _fail(error) from None

    console = _console()
    terminal.render_transformations(console, result.history)
    console.print()
    if not result.history.changed:
        console.print("No transformation applied; the output is identical to the input.")
    # Paths are echoed unwrapped so they can be copied from a narrow terminal.
    typer.echo(f"Output:  {written['output']}")
    typer.echo(f"History: {written['history']}")


@app.command("report")
def report_command(
    file: FileArgument,
    report_format: Annotated[
        ReportFormat, typer.Option("--format", "-f", help="Report format.")
    ] = ReportFormat.html,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Report file. Defaults to <name>.report.<format> in the current directory.",
            show_default=False,
        ),
    ] = None,
    transformations: Annotated[
        bool,
        typer.Option(
            "--transformations",
            help="Also run the deobfuscation pipeline and include its history in the report.",
        ),
    ] = False,
    tolerant: TolerantOption = False,
    no_redact: NoRedactOption = False,
    max_bytes: MaxBytesOption = config.DEFAULT_MAX_INPUT_BYTES,
) -> None:
    """Write a standalone HTML report, or the same data as JSON.

    Example: js-forensics report sample.js --format html --output report.html
    """
    report = _analyze(file, max_bytes, tolerant, no_redact, transformations=transformations)
    if output is None:
        output = Path(f"{file.stem}.report.{report_format.value}")
    content = render_html(report) if report_format is ReportFormat.html else to_json(report)
    _write(content, output, file)
