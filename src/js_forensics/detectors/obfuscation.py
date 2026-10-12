"""Obfuscation indicators and the heuristic score derived from them.

Each indicator is a documented structural rule with a fixed threshold and a
fixed weight. The score is the sum of the weights of the indicators that
triggered, capped at 100. It summarises how many known patterns are present;
it is not a probability and says nothing about whether the code is harmful.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from tree_sitter import Node

from js_forensics import config
from js_forensics.analysis.identifiers import HEX_STYLE_NAME, Bindings
from js_forensics.analysis.strings import StringOccurrence
from js_forensics.analysis.syntax import (
    call_arguments,
    dotted_name,
    static_property_name,
    string_literal_value,
    strip_global_object,
)
from js_forensics.models import DecodedValue, Evidence, Indicator, ObfuscationReport
from js_forensics.parser import ParsedSource

ESCAPED_STRING_MIN_COUNT = 3
STRING_ARRAY_MIN_ELEMENTS = 10
STRING_ARRAY_MIN_STRING_SHARE = 0.9
STRING_ARRAY_MIN_INDEX_LOOKUPS = 5
STRING_ARRAY_MIN_ACCESSOR_CALLS = 10
BRACKET_ACCESS_MIN_COUNT = 10
BRACKET_ACCESS_MIN_SHARE = 0.25
HEX_NAME_MIN_COUNT = 5
HEX_NUMBER_MIN_LITERALS = 20
HEX_NUMBER_MIN_SHARE = 0.5
DECODER_RESULT_MIN_LENGTH = 3
BLOCK_DEPTH_THRESHOLD = 10
EXPRESSION_DEPTH_THRESHOLD = 60
LONG_LINE_BYTES = 1000
AVERAGE_LINE_BYTES = 200

_IDENTIFIER_NAME = re.compile(r"[A-Za-z_$][\w$]*")
_ALWAYS_TRUE_CONDITIONS = frozenset({"(true)", "(!0)", "(1)", "(!![])", "(!!1)"})
_TIMER_FUNCTIONS = frozenset({"setTimeout", "setInterval"})


@dataclass(slots=True)
class DetectionContext:
    parsed: ParsedSource
    strings: list[StringOccurrence]
    bindings: Bindings
    decoded_values: list[DecodedValue]

    def evidence(self, node: Node, detail: str) -> Evidence:
        return Evidence(
            detail=detail,
            location=self.parsed.location(node),
            snippet=self.parsed.snippet(node),
        )


@dataclass(frozen=True, slots=True)
class IndicatorRule:
    id: str
    title: str
    weight: int
    explanation: str
    detect: Callable[[DetectionContext], list[Evidence]]


def _capped(evidence: list[Evidence]) -> list[Evidence]:
    return evidence[: config.MAX_EVIDENCE_PER_INDICATOR]


def _escape_encoded_strings(context: DetectionContext) -> list[Evidence]:
    encoded = [occurrence for occurrence in context.strings if occurrence.escape_encoded]
    if len(encoded) < ESCAPED_STRING_MIN_COUNT:
        return []
    summary = Evidence(
        detail=f"{len(encoded)} of {len(context.strings)} string literals spell printable "
        "ASCII text with \\x or \\u escapes."
    )
    examples = [
        context.evidence(occurrence.node, "Escape-encoded literal.") for occurrence in encoded
    ]
    return [summary, *_capped(examples)]


def _string_arrays(context: DetectionContext) -> list[tuple[Node, str | None, int]]:
    """Large array literals made almost entirely of strings, with their name."""
    parsed = context.parsed
    arrays = []
    for array in parsed.index.of_type("array"):
        elements = [child for child in array.named_children if child.type != "comment"]
        if len(elements) < STRING_ARRAY_MIN_ELEMENTS:
            continue
        string_count = sum(1 for element in elements if element.type == "string")
        if string_count < STRING_ARRAY_MIN_STRING_SHARE * len(elements):
            continue
        owner = parsed.index.parent(array)
        name = None
        if owner is not None and owner.type in ("variable_declarator", "assignment_expression"):
            target = owner.child_by_field_name("name") or owner.child_by_field_name("left")
            if target is not None and target.type == "identifier":
                name = parsed.text(target)
        arrays.append((array, name, len(elements)))
    return arrays


def _string_array_lookups(context: DetectionContext) -> list[Evidence]:
    parsed = context.parsed
    arrays = _string_arrays(context)
    if not arrays:
        return []
    array_names = {name for _, name, _ in arrays if name is not None}

    index_lookups: Counter[str] = Counter()
    for subscript in parsed.index.of_type("subscript_expression"):
        target = subscript.child_by_field_name("object")
        key = subscript.child_by_field_name("index")
        if target is not None and key is not None and key.type == "number":
            name = parsed.text(target) if target.type == "identifier" else None
            if name in array_names:
                index_lookups[name] += 1

    # Accessor functions are called as f(0x1a2). Requiring a hex literal or a
    # hex-style callee keeps bundler calls such as webpack's n(123) out.
    accessor_calls: Counter[str] = Counter()
    for call in parsed.index.of_type("call_expression"):
        callee = call.child_by_field_name("function")
        arguments = call_arguments(call)
        if callee is None or callee.type != "identifier" or not arguments:
            continue
        first = arguments[0]
        if first.type != "number":
            continue
        name = parsed.text(callee)
        is_hex_literal = parsed.text(first).lower().startswith("0x")
        if is_hex_literal or HEX_STYLE_NAME.fullmatch(name):
            accessor_calls[name] += 1

    lookups = []
    for name, count in index_lookups.most_common():
        if count >= STRING_ARRAY_MIN_INDEX_LOOKUPS:
            lookups.append(
                Evidence(detail=f"`{name}` is indexed with a numeric literal {count} times.")
            )
    for name, count in accessor_calls.most_common():
        if count >= STRING_ARRAY_MIN_ACCESSOR_CALLS:
            lookups.append(
                Evidence(
                    detail=f"`{name}` is called {count} times with a numeric literal as its "
                    "first argument, as a string-array accessor would be."
                )
            )
    if not lookups:
        return []
    array_evidence = [
        context.evidence(
            array,
            f"Array of {size} elements, at least {STRING_ARRAY_MIN_STRING_SHARE:.0%} strings"
            + (f", bound to `{name}`." if name else "."),
        )
        for array, name, size in arrays
    ]
    return [*_capped(array_evidence), *_capped(lookups)]


def _array_rotation(context: DetectionContext) -> list[Evidence]:
    """``x.push(x.shift())``, the loop body that rotates a string array."""
    parsed = context.parsed
    found = []
    for call in parsed.index.of_type("call_expression"):
        callee = call.child_by_field_name("function")
        arguments = call_arguments(call)
        if callee is None or not arguments or len(arguments) != 1:
            continue
        inner = arguments[0]
        if static_property_name(parsed, callee) != "push" or inner.type != "call_expression":
            continue
        inner_callee = inner.child_by_field_name("function")
        if inner_callee is None or static_property_name(parsed, inner_callee) != "shift":
            continue
        pushed_to = callee.child_by_field_name("object")
        shifted_from = inner_callee.child_by_field_name("object")
        if (
            pushed_to is not None
            and shifted_from is not None
            and parsed.text(pushed_to) == parsed.text(shifted_from)
        ):
            found.append(context.evidence(call, "An array is rotated by pushing its own head."))
    return _capped(found)


def _bracket_property_access(context: DetectionContext) -> list[Evidence]:
    parsed = context.parsed
    bracket_accesses = []
    for subscript in parsed.index.of_type("subscript_expression"):
        key = subscript.child_by_field_name("index")
        if key is None or key.type != "string":
            continue
        name = string_literal_value(parsed, key)
        if name is not None and _IDENTIFIER_NAME.fullmatch(name):
            bracket_accesses.append(subscript)
    total = len(bracket_accesses) + parsed.index.count("member_expression")
    if len(bracket_accesses) < BRACKET_ACCESS_MIN_COUNT:
        return []
    if len(bracket_accesses) < BRACKET_ACCESS_MIN_SHARE * total:
        return []
    summary = Evidence(
        detail=f"{len(bracket_accesses)} of {total} property accesses use a string in "
        'brackets (obj["name"]) where dot notation would work.'
    )
    examples = [context.evidence(node, "Bracket access.") for node in bracket_accesses]
    return [summary, *_capped(examples)]


def _dynamic_evaluation(context: DetectionContext) -> list[Evidence]:
    parsed = context.parsed
    found = []
    for call in parsed.index.of_type("call_expression", "new_expression"):
        callee = call.child_by_field_name("function") or call.child_by_field_name("constructor")
        if callee is None:
            continue
        arguments = call_arguments(call) or []
        names = dotted_name(parsed, callee)
        name = ".".join(strip_global_object(names)) if names else None
        first_is_string = bool(arguments) and arguments[0].type in ("string", "template_string")
        if name == "eval" and call.type == "call_expression":
            found.append(context.evidence(call, "Call to eval()."))
        elif name == "Function":
            found.append(context.evidence(call, "Code is built with the Function constructor."))
        elif name in _TIMER_FUNCTIONS and first_is_string:
            found.append(
                context.evidence(call, f"{name}() is given a string, which it evaluates as code.")
            )
        elif static_property_name(parsed, callee) == "constructor" and first_is_string:
            found.append(
                context.evidence(
                    call,
                    "A .constructor property is called with a string; on a function this is "
                    "the Function constructor.",
                )
            )
    return _capped(found)


def _hex_style_identifiers(context: DetectionContext) -> list[Evidence]:
    declared = context.bindings.declarations
    hex_names = [name for name in declared if HEX_STYLE_NAME.fullmatch(name)]
    if len(hex_names) < HEX_NAME_MIN_COUNT:
        return []
    summary = Evidence(
        detail=f"{len(hex_names)} of {len(declared)} declared names look like _0x1a2b."
    )
    examples = [
        context.evidence(declared[name][0][1], f"Declaration of `{name}`.") for name in hex_names
    ]
    return [summary, *_capped(examples)]


def _switch_dispatch_loops(context: DetectionContext) -> list[Evidence]:
    """An endless loop whose body switches on ``order[i++]``.

    This is the shape control-flow flattening leaves behind: the original
    statement order is stored in an array and replayed by the switch.
    """
    parsed = context.parsed
    found = []
    for loop in parsed.index.of_type("while_statement", "for_statement"):
        condition = loop.child_by_field_name("condition")
        if loop.type == "while_statement":
            text = parsed.text(condition).replace(" ", "") if condition is not None else ""
            if text not in _ALWAYS_TRUE_CONDITIONS:
                continue
        # tree-sitter represents a missing `for` condition as an empty statement.
        elif condition is not None and condition.type != "empty_statement":
            continue
        body = loop.child_by_field_name("body")
        if body is None:
            continue
        for statement in body.named_children:
            if statement.type != "switch_statement":
                continue
            selector = statement.child_by_field_name("value")
            if selector is None or selector.named_child_count != 1:
                continue
            lookup = selector.named_children[0]
            key = lookup.child_by_field_name("index")
            if (
                lookup.type == "subscript_expression"
                and key is not None
                and key.type == "update_expression"
            ):
                switch_body = statement.child_by_field_name("body")
                cases = switch_body.named_child_count if switch_body is not None else 0
                found.append(
                    context.evidence(
                        loop,
                        f"Endless loop dispatching {cases} cases through "
                        f"`{parsed.snippet(lookup, 40)}`.",
                    )
                )
    return _capped(found)


def _hex_number_literals(context: DetectionContext) -> list[Evidence]:
    parsed = context.parsed
    numbers = parsed.index.of_type("number")
    hex_count = sum(
        1
        for number in numbers
        if parsed.source[number.start_byte : number.start_byte + 2].lower() == b"0x"
    )
    if len(numbers) < HEX_NUMBER_MIN_LITERALS or hex_count < HEX_NUMBER_MIN_SHARE * len(numbers):
        return []
    return [Evidence(detail=f"{hex_count} of {len(numbers)} numeric literals are hexadecimal.")]


def _static_decoder_calls(context: DetectionContext) -> list[Evidence]:
    found = [
        Evidence(
            detail=f"{decoded.technique} call with constant arguments.",
            location=decoded.location,
            snippet=decoded.source,
        )
        for decoded in context.decoded_values
        if decoded.technique != "escape-sequences"
        and len(decoded.value) >= DECODER_RESULT_MIN_LENGTH
    ]
    return _capped(found)


def _deep_block_nesting(context: DetectionContext) -> list[Evidence]:
    index = context.parsed.index
    if index.max_block_depth < BLOCK_DEPTH_THRESHOLD or index.deepest_block is None:
        return []
    return [
        Evidence(
            detail=f"Blocks are nested {index.max_block_depth} levels deep.",
            location=context.parsed.location(index.deepest_block),
        )
    ]


def _deep_expression_nesting(context: DetectionContext) -> list[Evidence]:
    index = context.parsed.index
    if index.max_expression_depth < EXPRESSION_DEPTH_THRESHOLD or index.deepest_expression is None:
        return []
    return [
        Evidence(
            detail=f"A single statement contains syntax nested {index.max_expression_depth} "
            "levels deep.",
            location=context.parsed.location(index.deepest_expression),
        )
    ]


def _minified_layout(context: DetectionContext) -> list[Evidence]:
    source = context.parsed.source
    line_count = context.parsed.line_count
    if line_count == 0:
        return []
    longest = max(len(line) for line in source.split(b"\n"))
    average = len(source) / line_count
    if longest < LONG_LINE_BYTES and average < AVERAGE_LINE_BYTES:
        return []
    return [
        Evidence(
            detail=f"The longest line is {longest:,} bytes and the average is {average:,.0f} "
            "bytes. This is what minifiers produce and is not by itself obfuscation."
        )
    ]


RULES: tuple[IndicatorRule, ...] = (
    IndicatorRule(
        "string-array-lookup",
        "String array with numeric lookups",
        25,
        f"A literal array of at least {STRING_ARRAY_MIN_ELEMENTS} strings is combined with at "
        f"least {STRING_ARRAY_MIN_INDEX_LOOKUPS} numeric index reads or "
        f"{STRING_ARRAY_MIN_ACCESSOR_CALLS} accessor calls. Obfuscators move every string into "
        "such a table.",
        _string_array_lookups,
    ),
    IndicatorRule(
        "escape-encoded-strings",
        "Escape-encoded string literals",
        15,
        f"At least {ESCAPED_STRING_MIN_COUNT} literals are written mostly as \\x or \\u escapes "
        "of printable ASCII characters, which hides their text from a plain search.",
        _escape_encoded_strings,
    ),
    IndicatorRule(
        "hex-style-identifiers",
        "Hex-style identifier names",
        15,
        f"At least {HEX_NAME_MIN_COUNT} declared names match _0x followed by hex digits, a "
        "naming scheme several obfuscators generate.",
        _hex_style_identifiers,
    ),
    IndicatorRule(
        "switch-dispatch-loop",
        "Switch-dispatch loop",
        15,
        "An endless loop switches on successive elements of an array. Control-flow flattening "
        "produces this shape.",
        _switch_dispatch_loops,
    ),
    IndicatorRule(
        "array-rotation",
        "Array rotation",
        10,
        "An array is rotated with push(shift()). String-array obfuscation uses this to shuffle "
        "its table at start-up; ordinary queue code occasionally does the same.",
        _array_rotation,
    ),
    IndicatorRule(
        "dynamic-evaluation",
        "Dynamic code evaluation",
        10,
        "The file calls eval(), the Function constructor, or a timer with a string argument. "
        "Code evaluated this way is invisible to static analysis.",
        _dynamic_evaluation,
    ),
    IndicatorRule(
        "bracket-property-access",
        "Indirect property access",
        10,
        f"At least {BRACKET_ACCESS_MIN_COUNT} property accesses, and at least "
        f"{BRACKET_ACCESS_MIN_SHARE:.0%} of all of them, use a string literal in brackets.",
        _bracket_property_access,
    ),
    IndicatorRule(
        "static-decoder-calls",
        "Decoder calls with constant arguments",
        10,
        "String.fromCharCode, String.fromCodePoint, or atob is called with constants that "
        f"decode to at least {DECODER_RESULT_MIN_LENGTH} characters, so a readable literal was "
        "avoided.",
        _static_decoder_calls,
    ),
    IndicatorRule(
        "hex-number-literals",
        "Hexadecimal numeric literals",
        5,
        f"With at least {HEX_NUMBER_MIN_LITERALS} numeric literals in the file, at least "
        f"{HEX_NUMBER_MIN_SHARE:.0%} are hexadecimal.",
        _hex_number_literals,
    ),
    IndicatorRule(
        "deep-block-nesting",
        "Deeply nested blocks",
        5,
        f"Statement blocks are nested at least {BLOCK_DEPTH_THRESHOLD} levels deep.",
        _deep_block_nesting,
    ),
    IndicatorRule(
        "deep-expression-nesting",
        "Deeply nested expressions",
        5,
        f"One statement contains syntax nested at least {EXPRESSION_DEPTH_THRESHOLD} levels "
        "deep, measured from its enclosing block.",
        _deep_expression_nesting,
    ),
    IndicatorRule(
        "minified-layout",
        "Minified layout",
        5,
        f"A line is at least {LONG_LINE_BYTES:,} bytes long or lines average at least "
        f"{AVERAGE_LINE_BYTES} bytes.",
        _minified_layout,
    ),
)


def detect_obfuscation(context: DetectionContext) -> ObfuscationReport:
    indicators = []
    for rule in RULES:
        evidence = rule.detect(context)
        if evidence:
            indicators.append(
                Indicator(rule.id, rule.title, rule.weight, rule.explanation, evidence)
            )
    score = min(100, sum(indicator.weight for indicator in indicators))
    return ObfuscationReport(
        score=score, indicators=indicators, checked=[rule.id for rule in RULES]
    )
