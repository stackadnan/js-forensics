import json
from pathlib import Path

import pytest

from js_forensics.deobfuscation.edits import TextEdit
from js_forensics.deobfuscation.pipeline import run_pipeline, write_pipeline_outputs
from js_forensics.deobfuscation.transforms import (
    DEFAULT_TRANSFORMATIONS,
    Transformation,
    TransformOutcome,
)
from js_forensics.errors import JavaScriptSyntaxError, OutputError
from js_forensics.parser import ParsedSource

from .conftest import FIXTURES, parse, parse_fixture

STAGE_NAMES = [
    "format-statements",
    "simplify-string-escapes",
    "decode-static-calls",
    "fold-constants",
]


def test_pipeline_output_matches_the_reviewed_expectation():
    result = run_pipeline(parse_fixture("obfuscated_sample.js"))
    expected = (FIXTURES / "obfuscated_sample.expected.js").read_text()
    assert result.source.decode() == expected


def test_history_records_every_stage():
    parsed = parse_fixture("obfuscated_sample.js")
    history = run_pipeline(parsed).history
    assert [record.name for record in history.records] == STAGE_NAMES
    assert [record.changed for record in history.records] == [True, True, True, True]
    assert [record.change_count for record in history.records] == [13, 4, 2, 4]
    assert history.changed
    assert history.input_sha256 == parsed.sha256
    assert history.output_sha256 != history.input_sha256

    decode = history.records[2]
    assert [(change.before, change.after) for change in decode.changes] == [
        ('atob("L3YxL3Nlc3Npb24=")', '"/v1/session"'),
        ("String.fromCharCode(0x50,0x4f,0x53,0x54)", '"POST"'),
    ]
    # Locations refer to the stage's own input, which is already formatted.
    assert decode.changes[0].location.line == 3


def test_stages_feed_each_other():
    # The escape stage reveals "a", the decoder stage produces "b", and only
    # then can folding join them.
    result = run_pipeline(parse(r'var s = "\x61" + String.fromCharCode(98) + "c";'))
    assert result.source == b'var s = "abc";\n'
    # Formatting only adds the missing final newline here.
    assert [name for name, _ in result.stages] == STAGE_NAMES
    assert result.stages[1][1] == b'var s = "a" + String.fromCharCode(98) + "c";\n'
    assert result.stages[2][1] == b'var s = "a" + "b" + "c";\n'


def test_unchanged_input_reports_no_change():
    source = b"var total = price * quantity;\n"
    result = run_pipeline(ParsedSource(source))
    assert result.source == source
    assert not result.history.changed
    assert result.stages == []
    assert all(not record.changed for record in result.history.records)
    assert result.history.input_sha256 == result.history.output_sha256


def test_pipeline_is_idempotent_on_every_fixture():
    for path in sorted(FIXTURES.glob("*.js")):
        if path.name == "malformed.js":
            continue
        first = run_pipeline(ParsedSource(path.read_bytes()))
        second = run_pipeline(ParsedSource(first.source))
        assert second.source == first.source, path.name
        assert not second.history.changed, path.name


def test_skipped_expressions_are_carried_into_the_history():
    history = run_pipeline(parse_fixture("constant_folding.js")).history
    fold = history.records[3]
    assert fold.skipped_count == 2
    assert [item.snippet for item in fold.skipped] == ["1 / 0", '"5" * 2']


def test_syntax_errors_are_refused():
    with pytest.raises(JavaScriptSyntaxError):
        run_pipeline(parse_fixture("malformed.js"))


def test_stage_that_breaks_the_syntax_is_reverted():
    def corrupt(parsed: ParsedSource) -> TransformOutcome:
        return TransformOutcome(edits=[TextEdit(0, 3, b"var var (")])

    broken = Transformation("corrupt", "Deliberately invalid edit.", corrupt)
    result = run_pipeline(parse("var a = 1 + 2;"), [broken, *DEFAULT_TRANSFORMATIONS])
    record = result.history.records[0]
    assert not record.changed
    assert record.reverted_reason == "the transformed source no longer parsed"
    assert record.change_count == 0
    # Later stages still run on the last good source.
    assert result.source == b"var a = 3;\n"


def test_formatter_output_with_different_tokens_is_reverted():
    def not_just_whitespace(parsed: ParsedSource) -> TransformOutcome:
        return TransformOutcome(edits=[TextEdit(8, 9, b"2")])

    stage = Transformation("format-statements", "Changes a token.", not_just_whitespace)
    result = run_pipeline(parse("var a = 1;\n"), [stage])
    assert result.history.records[0].reverted_reason == "formatting changed the token sequence"
    assert result.source == b"var a = 1;\n"


def test_outputs_are_written_next_to_each_other(tmp_path: Path):
    source_path = FIXTURES / "obfuscated_sample.js"
    original = source_path.read_bytes()
    result = run_pipeline(ParsedSource(original))
    written = write_pipeline_outputs(result, source_path, tmp_path / "out")

    assert written["output"] == tmp_path / "out" / "obfuscated_sample.deobfuscated.js"
    assert written["output"].read_bytes() == result.source
    stage_files = sorted(path.name for path in (tmp_path / "out" / "stages").iterdir())
    assert stage_files == [f"{n:02d}-{name}.js" for n, name in enumerate(STAGE_NAMES, start=1)]
    assert (tmp_path / "out" / "stages" / stage_files[-1]).read_bytes() == result.source
    history = json.loads(written["history"].read_text())
    assert [record["name"] for record in history["records"]] == STAGE_NAMES
    assert source_path.read_bytes() == original


def test_stage_files_are_optional(tmp_path: Path):
    result = run_pipeline(parse_fixture("obfuscated_sample.js"))
    write_pipeline_outputs(result, FIXTURES / "obfuscated_sample.js", tmp_path, keep_stages=False)
    assert not (tmp_path / "stages").exists()


def test_the_input_file_is_never_overwritten(tmp_path: Path):
    # The output name resolves to the input itself through a symlink.
    source_path = tmp_path / "x.js"
    source_path.write_text("var a = 1 + 2;")
    (tmp_path / "x.deobfuscated.js").symlink_to(source_path)
    result = run_pipeline(ParsedSource(source_path.read_bytes()))
    with pytest.raises(OutputError, match="Refusing to overwrite the input file"):
        write_pipeline_outputs(result, source_path, tmp_path)
    assert source_path.read_text() == "var a = 1 + 2;"


def test_large_input_completes(tmp_path: Path):
    lines = [f'var v{n} = "\\x76" + {n} + (1 + 2) * {n};' for n in range(20_000)]
    parsed = ParsedSource("\n".join(lines).encode())
    assert len(parsed.source) > 700_000
    result = run_pipeline(parsed)
    # "v" + 1 + (1 + 2) * 1 is ("v" + 1) + 3, which is "v13".
    assert result.source.startswith(b'var v0 = "v00";\nvar v1 = "v13";\nvar v2 = "v26";\n')
    assert result.history.records[3].change_count == 20_000


def test_stage_that_would_bloat_the_file_is_reverted():
    # Thousands of nested blocks: one line per brace, each indented.
    depth = 5_000
    source = "{" * depth + "a(1 + 2)" + "}" * depth
    result = run_pipeline(parse(source))
    formatting = result.history.records[0]
    assert formatting.reverted_reason == "the transformed source grew beyond the size limit"
    assert not formatting.changed
    # The other stages still run on the unformatted source.
    assert result.source.decode() == "{" * depth + "a(3)" + "}" * depth
