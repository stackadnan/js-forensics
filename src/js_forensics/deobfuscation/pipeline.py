"""Runs transformations in order and records what each one did.

Every stage's output is parsed again before it is accepted. A stage whose
output no longer parses, or (for the formatter) no longer has the same
tokens, is discarded and recorded as reverted, so a bug in one transformation
cannot silently corrupt the result.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from js_forensics.deobfuscation.edits import apply_edits
from js_forensics.deobfuscation.transforms import DEFAULT_TRANSFORMATIONS, Transformation
from js_forensics.errors import OutputError
from js_forensics.models import TransformationHistory, TransformationRecord
from js_forensics.parser import ParsedSource

FORMAT_STAGE = "format-statements"
# A stage may not grow the source past this. Formatting ordinary minified code
# adds a few percent; only pathological nesting gets near the limit.
MAX_GROWTH_FACTOR = 4
GROWTH_ALLOWANCE = 64 * 1024


@dataclass(slots=True)
class PipelineResult:
    source: bytes
    history: TransformationHistory
    # (stage name, source after that stage) for the stages that changed it.
    stages: list[tuple[str, bytes]]


def _tokens(parsed: ParsedSource) -> Iterator[tuple[str, bytes]]:
    cursor = parsed.tree.walk()
    while True:
        if not cursor.goto_first_child():
            node = cursor.node
            assert node is not None
            yield node.type, parsed.source[node.start_byte : node.end_byte]
            while not cursor.goto_next_sibling():
                if not cursor.goto_parent():
                    return


def _token_digest(parsed: ParsedSource) -> bytes:
    """Digest of the token sequence, ignoring the whitespace between tokens."""
    digest = hashlib.sha256()
    for token_type, text in _tokens(parsed):
        digest.update(token_type.encode("utf-8"))
        digest.update(len(text).to_bytes(8, "big"))
        digest.update(text)
    return digest.digest()


def run_pipeline(
    parsed: ParsedSource,
    transformations: Sequence[Transformation] = DEFAULT_TRANSFORMATIONS,
) -> PipelineResult:
    """Apply ``transformations`` to an error-free parse."""
    parsed.require_valid()
    current: ParsedSource | None = parsed
    current_source = parsed.source
    records = []
    stages = []
    for transformation in transformations:
        if current is None:  # the previous stage's output was rejected
            current = ParsedSource(current_source, path=parsed.path)
        outcome = transformation.run(current)
        record = TransformationRecord(
            name=transformation.name,
            description=transformation.description,
            changed=False,
            change_count=len(outcome.edits),
            changes=outcome.changes,
            skipped_count=outcome.skipped_count,
            skipped=outcome.skipped,
        )
        records.append(record)
        if not outcome.edits:
            continue

        transformed = apply_edits(current_source, outcome.edits)
        if len(transformed) > MAX_GROWTH_FACTOR * len(current_source) + GROWTH_ALLOWANCE:
            record.reverted_reason = "the transformed source grew beyond the size limit"
        else:
            is_format_stage = transformation.name == FORMAT_STAGE
            tokens_before = _token_digest(current) if is_format_stage else b""
            # Two syntax trees of a large file are expensive, so the old one
            # is released before the new one is built.
            current = None
            candidate = ParsedSource(transformed, path=parsed.path)
            if candidate.has_errors:
                record.reverted_reason = "the transformed source no longer parsed"
            elif is_format_stage and _token_digest(candidate) != tokens_before:
                record.reverted_reason = "formatting changed the token sequence"
            else:
                record.changed = True
                current, current_source = candidate, transformed
                stages.append((transformation.name, transformed))
        if record.reverted_reason is not None:
            record.change_count = 0
            record.changes = []

    history = TransformationHistory(
        input_sha256=parsed.sha256,
        output_sha256=hashlib.sha256(current_source).hexdigest(),
        changed=current_source != parsed.source,
        records=records,
    )
    return PipelineResult(current_source, history, stages)


def write_text_output(path: Path, content: bytes, protected: Path | None = None) -> None:
    """Write an output file, refusing to replace the analyzed input."""
    try:
        if protected is not None and path.exists() and path.samefile(protected):
            raise OutputError(
                f"Refusing to overwrite the input file {protected}. Choose a different output path."
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    except OSError as error:
        raise OutputError(f"{path} could not be written: {error.strerror or error}.") from None


def write_pipeline_outputs(
    result: PipelineResult, input_path: Path, output_dir: Path, *, keep_stages: bool = True
) -> dict[str, Path]:
    """Write the final source, the history, and optionally each stage.

    The input file is never a target: output names carry a
    ``.deobfuscated.js`` suffix and every write checks against ``input_path``.
    """
    written = {"output": output_dir / f"{input_path.stem}.deobfuscated.js"}
    write_text_output(written["output"], result.source, protected=input_path)

    written["history"] = output_dir / "transformations.json"
    history_json = json.dumps(asdict(result.history), indent=2) + "\n"
    write_text_output(written["history"], history_json.encode("utf-8"), protected=input_path)

    if keep_stages:
        for number, (name, source) in enumerate(result.stages, start=1):
            stage_path = output_dir / "stages" / f"{number:02d}-{name}.js"
            write_text_output(stage_path, source, protected=input_path)
            written[f"stage:{name}"] = stage_path
    return written
