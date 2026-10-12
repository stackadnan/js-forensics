"""Reporting of strings that were hidden behind an encoding.

Two encodings are recognised: literals spelled with numeric escapes, and
calls to the decoder built-ins with statically known arguments. Decoder calls
that cannot be resolved are reported with the reason instead of being dropped.
"""

from __future__ import annotations

from js_forensics import config
from js_forensics.analysis.static_eval import StaticEvaluator, Unresolvable
from js_forensics.analysis.strings import StringOccurrence
from js_forensics.models import DecodedValue, Unresolved
from js_forensics.parser import ParsedSource


def find_decoded_values(
    parsed: ParsedSource,
    occurrences: list[StringOccurrence],
    evaluator: StaticEvaluator,
) -> tuple[list[DecodedValue], list[Unresolved]]:
    """``evaluator`` must have been created with ``resolve_decoders=True``."""
    decoded = [
        DecodedValue(
            technique="escape-sequences",
            source=parsed.snippet(occurrence.node),
            value=occurrence.value,
            location=parsed.location(occurrence.node),
        )
        for occurrence in occurrences
        if occurrence.escape_encoded
    ]
    unresolved: list[Unresolved] = []
    for call in parsed.index.of_type("call_expression"):
        decoder = evaluator.decoder_name(call)
        if decoder is None:
            continue
        try:
            value = evaluator.evaluate(call)
        except Unresolvable as failure:
            if len(unresolved) < config.MAX_UNRESOLVED_REPORTED:
                unresolved.append(
                    Unresolved(
                        subject=decoder,
                        reason=failure.reason,
                        location=parsed.location(call),
                        snippet=parsed.snippet(call),
                    )
                )
            continue
        decoded.append(
            DecodedValue(
                technique=decoder,
                source=parsed.snippet(call),
                value=str(value),
                location=parsed.location(call),
            )
        )
    decoded.sort(key=lambda item: (item.location.line, item.location.column))
    return decoded, unresolved
