"""Optional cross-checks against Node.js.

The package itself never runs JavaScript. These tests do, as an oracle, and
only for expressions and fixtures written for this repository: they confirm
that folded values equal what a real engine computes and that pipeline output
behaves like its input. They are skipped when ``node`` is not installed.
Never point them at a sample of unknown origin.
"""

import json
import shutil
import subprocess

import pytest

from js_forensics.analysis.static_eval import StaticEvaluator, to_source
from js_forensics.deobfuscation.pipeline import run_pipeline
from js_forensics.parser import ParsedSource

from .conftest import FIXTURES, parse

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

EXPRESSIONS = [
    '"a" + 1 + 2', '1 + 2 + "a"', "0.1 + 0.2", "1 / 3", "7 % 3", "-7 % 3", "7 % -3", "5.5 % 2",
    "2 ** 10", "2 ** 3 ** 2", "(-2) ** 3", "1 << 31", "1 << 32", "1 << -1", "-1 >>> 0",
    "-1 >>> 28", "-8 >> 1", "2147483648 | 0", "4294967295 & 4294967295", "5 ^ 3", "~5", "~-1",
    "~2147483648", "1e21 + 1", '1e21 + ""', '1e-7 + ""', '123456789012345680000 + ""',
    '0.000001 + ""', '1.5e300 * 1.5e-300 + ""', '9007199254740993 + ""', '0x7fffffff + 1 + ""',
    '100 / 3 + "px"', '"v" + -0', '"x" + 1.0', '"x" + 0.1 * 3', "!0", "!1", '!""', '!"0"',
    "!!-1", "1 === 1", '"a" !== "b"', "2 < 3", "3 <= 3", "1 == 1.0", "-(-2)", "+5", "- -5",
    "(1 + 2) * 3 - 4 / 2", "1_000 * 2", "0b1010 + 0o17 + 0xff", ".5 + 5.", "`a${1 + 1}b${'c'}`",
    "String.fromCharCode(72, 105)", "String.fromCharCode(65601, 0x1F600)",
    "String.fromCharCode(-1) + String.fromCharCode(1.9)", "String.fromCodePoint(128512, 65)",
    'atob("aGVsbG8=")', 'atob("aGVsbG8")', 'atob(" aGVs bG8= ")', 'atob("/+8=")',
    'atob("aGk=") + String.fromCharCode(33)',
]  # fmt: skip


def node(script: str) -> str:
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, timeout=60, check=True
    )
    return completed.stdout


def test_folded_values_equal_what_node_computes():
    pairs = []
    for expression in EXPRESSIONS:
        parsed = parse(f"x = {expression};")
        value_node = parsed.index.of_type("assignment_expression")[0].child_by_field_name("right")
        evaluator = StaticEvaluator(parsed, resolve_decoders=True)
        pairs.append(f"[{expression}, {to_source(evaluator.evaluate(value_node))}]")
    script = (
        f"const pairs = [{', '.join(pairs)}];"
        "console.log(JSON.stringify(pairs.map(([actual, folded]) => Object.is(actual, folded))));"
    )
    matches = json.loads(node(script))
    mismatched = [expr for expr, same in zip(EXPRESSIONS, matches, strict=True) if not same]
    assert mismatched == []


# Runs a script in an empty context with stubbed browser globals and prints
# everything it logged or tried to send.
HARNESS = """
const vm = require("vm"), fs = require("fs");
const calls = [];
const record = (name) => (...args) => { calls.push([name, JSON.stringify(args)]); };
const context = {
  console: { log: record("log") }, fetch: record("fetch"), String, Math, JSON,
  atob: (text) => Buffer.from(text, "base64").toString("latin1"),
  setTimeout: (callback, delay) => { calls.push(["timeout", delay]); callback(); },
  window: { payload: "" },
};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), context, { timeout: 5000 });
console.log(JSON.stringify(calls));
"""
SELF_CONTAINED_FIXTURES = [
    "readable.js", "minified.js", "escapes.js", "base64.js", "string_array.js",
    "constant_folding.js", "obfuscated_sample.js",
]  # fmt: skip


@pytest.mark.parametrize("name", SELF_CONTAINED_FIXTURES)
def test_pipeline_output_behaves_like_its_input(name, tmp_path):
    original = FIXTURES / name
    parsed = ParsedSource(original.read_bytes())
    transformed = tmp_path / name
    transformed.write_bytes(run_pipeline(parsed).source)

    def observed(path) -> str:
        completed = subprocess.run(
            [NODE, "-e", HARNESS, str(path)], capture_output=True, text=True, timeout=60
        )
        assert completed.returncode == 0, completed.stderr
        return completed.stdout

    before, after = observed(original), observed(transformed)
    assert json.loads(before), "the fixture should log something to compare"
    assert after == before
