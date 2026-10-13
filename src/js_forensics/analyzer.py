"""Runs every analysis over one parsed file and assembles the report."""

from __future__ import annotations

from js_forensics import __version__
from js_forensics.analysis.decoding import find_decoded_values
from js_forensics.analysis.identifiers import analyze_identifiers, collect_bindings
from js_forensics.analysis.static_eval import StaticEvaluator
from js_forensics.analysis.statistics import compute_statistics, describe_file
from js_forensics.analysis.strings import (
    StringOccurrence,
    classify_string,
    collect_string_occurrences,
    summarize_strings,
)
from js_forensics.deobfuscation.pipeline import run_pipeline
from js_forensics.detectors.browser_apis import detect_browser_apis
from js_forensics.detectors.endpoints import discover_endpoints
from js_forensics.detectors.obfuscation import DetectionContext, detect_obfuscation
from js_forensics.models import AnalysisReport, ParseInfo, TransformationHistory
from js_forensics.parser import PARSER_NAME, ParsedSource
from js_forensics.reporting.redaction import MIN_CONTEXT_SECRET_LENGTH, Redactor, redact_report

SCHEMA_VERSION = "1.0"

LIMITATIONS = (
    "All findings come from static inspection. The file was not executed, so nothing here "
    "shows that a code path runs, an API is called, or a URL is contacted.",
    "Values are resolved only when they are constant at the point of use. Variables are not "
    "tracked, so strings assembled at runtime or fetched through a string-array accessor are "
    "not recovered.",
    "Code passed to eval(), the Function constructor, or string timers is not analysed.",
    "Identifier counts are name-based and do not distinguish scopes.",
    "String categories, the obfuscation score, and credential redaction are heuristics and "
    "can be wrong in both directions.",
    "Syntax is checked against the tree-sitter JavaScript grammar, which also accepts JSX "
    "and does not enforce every early error a JavaScript engine would report.",
)


def _context_secrets(occurrences: list[StringOccurrence]) -> set[str]:
    """Literal values assigned to something named like a credential."""
    return {
        occurrence.value
        for occurrence in occurrences
        if occurrence.in_credential_context
        and len(occurrence.value) >= MIN_CONTEXT_SECRET_LENGTH
        and not any(character.isspace() for character in occurrence.value)
        and classify_string(occurrence.value) == "other"
    }


def analyze(
    parsed: ParsedSource, *, redact: bool = True, with_transformations: bool = False
) -> AnalysisReport:
    """Analyze a parsed file.

    A parse with syntax errors is still analyzed (the caller decided to be
    tolerant), but the report says so and transformations are not attempted.
    """
    bindings = collect_bindings(parsed)
    evaluator = StaticEvaluator(parsed, resolve_decoders=True, rebound_names=bindings.rebound_names)
    occurrences = collect_string_occurrences(parsed)
    decoded_values, unresolved_decodes = find_decoded_values(parsed, occurrences, evaluator)
    discovery = discover_endpoints(parsed, occurrences, evaluator)
    obfuscation = detect_obfuscation(
        DetectionContext(parsed, occurrences, bindings, decoded_values)
    )

    warnings = []
    error_count = len(parsed.index.error_nodes)
    if error_count:
        warnings.append(
            f"The file has {error_count} syntax error(s). Results cover only the parts that "
            "parsed and may be incomplete or misleading."
        )
    transformations: TransformationHistory | None = None
    if with_transformations:
        if error_count:
            warnings.append("Transformations were skipped because the file has syntax errors.")
        else:
            transformations = run_pipeline(parsed).history
            for record in transformations.records:
                if record.reverted_reason is not None:
                    warnings.append(
                        f"Transformation {record.name} was reverted: {record.reverted_reason}."
                    )

    report = AnalysisReport(
        schema_version=SCHEMA_VERSION,
        tool={"name": "js-forensics", "version": __version__},
        file=describe_file(parsed),
        parse=ParseInfo(
            parser=PARSER_NAME,
            has_errors=bool(error_count),
            error_count=error_count,
            errors=parsed.syntax_issues(),
        ),
        statistics=compute_statistics(parsed),
        obfuscation=obfuscation,
        strings=summarize_strings(parsed, occurrences),
        decoded_values=decoded_values,
        unresolved_decodes=unresolved_decodes,
        identifiers=analyze_identifiers(parsed, bindings),
        browser_apis=detect_browser_apis(parsed, bindings),
        endpoints=discovery.endpoints,
        domains=discovery.domains,
        unresolved_network_calls=discovery.unresolved_calls,
        transformations=transformations,
        redaction_enabled=redact,
        warnings=warnings,
        limitations=list(LIMITATIONS),
    )
    if redact:
        redact_report(report, Redactor(_context_secrets(occurrences)))
    return report
