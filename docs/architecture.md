# Architecture

## Layout

```
src/js_forensics/
  cli.py              Typer commands; maps errors to exit codes
  analyzer.py         Runs every analysis and assembles an AnalysisReport
  models.py           Result dataclasses (the JSON schema)
  config.py           Size limits and caps
  errors.py           Exceptions and exit codes
  parser/source.py    Reading, parsing, SyntaxIndex, locations
  analysis/
    js_literals.py    String escapes, number formatting, atob (text only)
    syntax.py         Helpers for reading tree-sitter nodes
    static_eval.py    Constant-expression evaluator
    statistics.py     Node counts
    strings.py        Literal extraction and classification
    decoding.py       Decoded-value reporting
    identifiers.py    Bindings and naming patterns
  detectors/
    obfuscation.py    Indicator rules and score
    browser_apis.py   API catalogue and matching
    endpoints.py      Request-call recognition
  deobfuscation/
    edits.py          Byte-range edits
    formatter.py      Statement-per-line layout
    transforms.py     The four transformations
    pipeline.py       Stage sequencing, validation, output files
  reporting/
    redaction.py      Credential masking
    json_report.py, terminal.py, html_report.py
```

Data flows one way: `parser` produces a `ParsedSource`; `analysis` and
`detectors` read it and return models; `reporting` renders models. Nothing in
`analysis` or `detectors` writes files or prints, and nothing in `reporting`
looks at syntax nodes.

## Parser choice

The parser is [tree-sitter](https://tree-sitter.github.io/) with the
`tree-sitter-javascript` grammar. The alternatives considered were the pure
Python ESTree parsers `esprima` (last released 2018) and `pyjsparser` (2019),
which stop at roughly ES2017 and are unmaintained. tree-sitter is MIT
licensed, actively released, ships wheels for every supported Python, parses
current syntax (optional chaining, private fields, class static blocks,
top-level await, numeric separators), and handles a megabyte in about a
second.

Two consequences shape the rest of the code.

**It never fails.** tree-sitter recovers from errors and always returns a
tree, with `ERROR` and missing nodes where recovery happened.
`ParsedSource.require_valid()` turns the presence of any such node into
`JavaScriptSyntaxError`. Analysis commands call it unless `--tolerant` is
given; the pipeline always does.

**It is a concrete syntax tree with byte ranges, not an ESTree with a
printer.** There is no code generator, so transformations do not rebuild the
program. They replace the byte range of a node with new text and leave
everything else untouched. This rules out structural rewrites that need a
printer (they would be a separate project), and in exchange makes each
transformation easy to reason about: only the listed ranges changed.

One upstream problem was found during development: in tree-sitter 0.26.0,
calling `Node.end_point` many times crashed the interpreter. Line and column
are therefore computed from byte offsets in `ParsedSource._line_and_column`,
and the code does not use `start_point` or `end_point` at all.

## SyntaxIndex

`Node.parent` in tree-sitter re-descends from the root, so calling it per
node is quadratic on a deep tree, and hostile input can be arbitrarily deep.
`SyntaxIndex` walks the tree once with a cursor and records, for the node
types listed in `INDEXED_TYPES`, the nodes grouped by type, each node's parent
and field name, and a count of every type. Analyses query the index
(`index.of_type("call_expression")`) instead of walking the tree themselves.
To query a new node type, add it to `INDEXED_TYPES`; `of_type` raises a
`KeyError` naming the type if you forget.

No analysis recurses over the tree in Python. Walks use the cursor or an
explicit stack, and the evaluator caps its recursion depth, so nesting depth
cannot exhaust the interpreter stack.

## Static evaluator

`StaticEvaluator.evaluate(node)` returns a `str`, `float`, or `bool`, or
raises `Unresolvable` with a reason. It implements the specified behaviour of
a deliberately small set of operators; the module docstring lists what is
excluded and why. Python's own operators are used only where they coincide
with JavaScript's on IEEE doubles (`+ - * /` and `fmod`); integer conversion,
shifts, number-to-string, and string escapes are written out in
`js_literals.py`.

Three properties matter for hostile input:

- Left-nested operator chains (`a + b + c + ...`) are evaluated with a loop,
  not recursion.
- Only the value of a whole chain is cached. Caching each intermediate string
  of a long concatenation is quadratic in memory.
- A failure is cached as a small `Failure` record and shared by every
  enclosing operator, so asking about each node of a failing chain is linear.

`partial_string` builds on this for endpoint discovery: it returns the
constant parts of a concatenation or template with `${source}` placeholders
for the rest.

Decoder calls are resolved only when `resolve_decoders=True` and none of the
names involved is declared or assigned anywhere in the file.

## Transformations and the pipeline

A transformation is a function `ParsedSource -> TransformOutcome`. The
outcome holds edits, a list of changes for the history, and a list of things
it recognised but skipped. It does not apply anything.

`run_pipeline` applies each outcome, parses the result, and accepts it only if
it has no syntax errors, did not grow past the size guard, and, for the
formatter, has exactly the same token sequence as before. A rejected stage is
recorded with `reverted_reason` and the pipeline continues from the last good
source.

Hazards the transformations guard against, each covered by a test:

- **Directive creation.** Replacing a statement-level expression with a string
  literal could create `"use strict"`. Whole-statement expressions are never
  replaced.
- **Token merging.** `return(1+2)*3` must become `return 9`, not `return9`,
  and `x-~5` must become `x- -6`, not `x--6`. `edits.replace_node` pads where
  needed.
- **Automatic semicolon insertion.** A statement that starts with `-6` would
  join a preceding line that has no semicolon. Such folds are skipped.
- **Shadowed built-ins.** `atob` and `String` are not trusted if the file
  declares or assigns them, or uses `with`.
- **Formatting inside statements.** A line break after `return` changes
  meaning, so the formatter only touches whitespace between statements.

### Adding a transformation

1. Write a function in `transforms.py` returning a `TransformOutcome`.
   Use `_record_change` and `_record_skip`.
2. Append a `Transformation` to `DEFAULT_TRANSFORMATIONS` in the position it
   should run.
3. Add tests with exact expected output, tests for input that must stay
   unchanged, and an idempotence check. If the fixture is self-contained, add
   it to `SELF_CONTAINED_FIXTURES` in `tests/test_node_differential.py`.

Do not add a transformation that removes code or renames identifiers without
a rule you can state and test.

### Adding an obfuscation indicator

Write a function `DetectionContext -> list[Evidence]` in
`detectors/obfuscation.py` that returns an empty list when the indicator does
not trigger, name its thresholds as module constants, and add an
`IndicatorRule` to `RULES` with a weight and an explanation that states the
threshold. Add a positive test, a negative test just under the threshold, and
a test with ordinary code that looks similar. Document it in `docs/usage.md`.

## Reports

`analyze()` returns one `AnalysisReport`. Redaction runs once on that object,
so every renderer sees the same masked values. Renderers never receive raw
analyzed text without passing it through `escape_for_display`, which escapes
control and invisible characters, and the HTML renderer additionally
HTML-escapes it. The HTML page has no script and a
`default-src 'none'` Content-Security-Policy as a second line of defence.
