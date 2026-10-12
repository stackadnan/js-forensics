"""The individual source transformations.

Each one takes a parsed file and returns the edits it wants plus a record of
what it changed and what it recognised but left alone. None of them mutates
anything; the pipeline applies and validates the edits.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from tree_sitter import Node

from js_forensics import config
from js_forensics.analysis.identifiers import collect_bindings
from js_forensics.analysis.js_literals import InvalidEscape, quote_string, simplify_escapes
from js_forensics.analysis.static_eval import StaticEvaluator, Unresolvable, to_source
from js_forensics.deobfuscation.edits import TextEdit, replace_node
from js_forensics.deobfuscation.formatter import statement_layout_edits
from js_forensics.models import Change, Unresolved
from js_forensics.parser import ParsedSource

_STATEMENT_LEVEL_REASON = (
    "the expression is a whole statement; replacing it with a string literal could "
    'create a directive such as "use strict"'
)


@dataclass(slots=True)
class TransformOutcome:
    edits: list[TextEdit] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    skipped: list[Unresolved] = field(default_factory=list)
    skipped_count: int = 0


@dataclass(frozen=True, slots=True)
class Transformation:
    name: str
    description: str
    run: Callable[[ParsedSource], TransformOutcome]


def _record_change(outcome: TransformOutcome, parsed: ParsedSource, node: Node, text: str) -> None:
    outcome.edits.append(replace_node(parsed.source, node, text))
    if len(outcome.changes) < config.MAX_CHANGES_RECORDED:
        after = text if len(text) <= config.SNIPPET_LENGTH else text[: config.SNIPPET_LENGTH] + "…"
        outcome.changes.append(Change(parsed.snippet(node), after, parsed.location(node)))


def _record_skip(
    outcome: TransformOutcome, parsed: ParsedSource, node: Node, subject: str, reason: str
) -> None:
    outcome.skipped_count += 1
    if len(outcome.skipped) < config.MAX_UNRESOLVED_REPORTED:
        outcome.skipped.append(
            Unresolved(subject, reason, parsed.location(node), parsed.snippet(node))
        )


def _is_whole_statement(parsed: ParsedSource, node: Node) -> bool:
    owner = parsed.index.parent(node)
    return owner is not None and owner.type == "expression_statement"


def _begins_statement(parsed: ParsedSource, node: Node) -> bool:
    """True if ``node`` is the first thing in an expression statement.

    A statement that starts at the same offset as an expression can only be
    one that contains it, so comparing offsets is enough.
    """
    return node.start_byte in parsed.index.statement_starts


def format_statements(parsed: ParsedSource) -> TransformOutcome:
    """Put each statement on its own indented line."""
    outcome = TransformOutcome(edits=statement_layout_edits(parsed))
    return outcome


def simplify_string_escapes(parsed: ParsedSource) -> TransformOutcome:
    r"""Rewrite ``"\x68\x69"`` as ``"hi"``.

    Only numeric escapes of displayable characters are rewritten, one escape
    at a time, so the value of each literal is unchanged.
    """
    outcome = TransformOutcome()
    for node in parsed.index.of_type("string"):
        text = parsed.text(node)
        if "\\" not in text:
            continue
        owner = parsed.index.parent(node)
        # JSX attribute strings do not process escapes at all.
        if owner is not None and owner.type.startswith("jsx"):
            continue
        quote, body = text[0], text[1:-1]
        try:
            simplified = simplify_escapes(body, quote)
        except InvalidEscape as error:
            _record_skip(outcome, parsed, node, "string literal", str(error))
            continue
        if simplified == body:
            continue
        if _is_whole_statement(parsed, node):
            _record_skip(outcome, parsed, node, "string literal", _STATEMENT_LEVEL_REASON)
            continue
        _record_change(outcome, parsed, node, quote + simplified + quote)
    return outcome


def decode_static_calls(parsed: ParsedSource) -> TransformOutcome:
    """Replace decoder calls on constants with the string they return.

    Covers ``String.fromCharCode``, ``String.fromCodePoint`` and ``atob``. The
    results are computed here from the specification of those functions; the
    analyzed file is never run.
    """
    outcome = TransformOutcome()
    evaluator = StaticEvaluator(
        parsed, resolve_decoders=True, rebound_names=collect_bindings(parsed).rebound_names
    )
    replaced_until = 0
    for call in parsed.index.of_type("call_expression"):
        if call.start_byte < replaced_until:
            continue
        decoder = evaluator.decoder_name(call)
        if decoder is None:
            continue
        try:
            value = evaluator.evaluate(call)
        except Unresolvable as failure:
            _record_skip(outcome, parsed, call, decoder, failure.reason)
            continue
        if _is_whole_statement(parsed, call):
            _record_skip(outcome, parsed, call, decoder, _STATEMENT_LEVEL_REASON)
            continue
        assert isinstance(value, str)
        _record_change(outcome, parsed, call, quote_string(value))
        replaced_until = call.end_byte
    return outcome


def fold_constants(parsed: ParsedSource) -> TransformOutcome:
    """Replace operator expressions on literals with their value.

    The supported subset is documented in ``analysis/static_eval.py``.
    Expressions that mention a variable are ignored silently; expressions made
    only of literals that still cannot be folded are reported as skipped.
    """
    outcome = TransformOutcome()
    evaluator = StaticEvaluator(parsed)
    reported_failures: set[int] = set()
    replaced_until = 0
    for node in parsed.index.of_type("binary_expression", "unary_expression"):
        if node.start_byte < replaced_until:
            continue
        try:
            value = evaluator.evaluate(node)
            replacement = to_source(value)
        except Unresolvable as failure:
            # A failing operand fails every expression around it for the same
            # recorded reason; only the outermost one is reported.
            if not failure.is_dynamic and id(failure.failure) not in reported_failures:
                reported_failures.add(id(failure.failure))
                _record_skip(outcome, parsed, node, "constant expression", failure.reason)
            continue
        if _is_whole_statement(parsed, node) or replacement == parsed.text(node):
            continue
        if (
            replacement.startswith("-")
            and not parsed.text(node).startswith("-")
            and _begins_statement(parsed, node)
        ):
            # After a line that relies on automatic semicolon insertion, a
            # statement that starts with `-` would join the previous line.
            _record_skip(
                outcome,
                parsed,
                node,
                "constant expression",
                "a negative result at the start of a statement could merge with the line above",
            )
            continue
        _record_change(outcome, parsed, node, replacement)
        replaced_until = node.end_byte
    return outcome


DEFAULT_TRANSFORMATIONS: tuple[Transformation, ...] = (
    Transformation(
        "format-statements",
        "Put each statement on its own indented line (whitespace between statements only).",
        format_statements,
    ),
    Transformation(
        "simplify-string-escapes",
        "Rewrite \\x, \\u and octal escapes of displayable characters as the characters.",
        simplify_string_escapes,
    ),
    Transformation(
        "decode-static-calls",
        "Replace String.fromCharCode, String.fromCodePoint and atob calls on constants with "
        "the resulting string literal.",
        decode_static_calls,
    ),
    Transformation(
        "fold-constants",
        "Replace operator expressions whose operands are all literals with their value.",
        fold_constants,
    ),
)
