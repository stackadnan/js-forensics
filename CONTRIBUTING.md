# Contributing

JS Forensics is a small static-analysis tool that people point at code they
do not trust. Contributions are judged on correctness and on keeping that
safe, more than on how many patterns they cover: a change that handles one
case and says clearly what it leaves alone is preferred to one that handles
ten by guessing. Keep changes focused, write code a reviewer can follow, and
do not claim something works unless a test shows it.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Security problems are reported privately, as described in
[SECURITY.md](SECURITY.md), not through issues or pull requests.

## Setup

Python 3.10 or newer.

```console
$ python -m venv .venv && source .venv/bin/activate
$ pip install -e ".[dev]"
```

## Checks

Run all of these before opening a pull request:

```console
$ pytest
$ ruff format --check src tests
$ ruff check src tests
$ mypy
```

`mypy` runs in strict mode over `src`.

Some tests in `tests/test_node_differential.py` use Node.js as an oracle and
are skipped when `node` is not installed. They run only expressions and
fixtures written for this repository. The package itself must never invoke a
JavaScript runtime.

## Tests

- Put behaviour in a test with a known expected value. For a transformation
  that means the exact output text, plus cases that must stay unchanged.
- Keep fixtures in `tests/fixtures/` small and aimed at one pattern.
- Do not commit real malware or third-party code as a fixture. Write a
  minimal file that shows the pattern.
- Tests run with sockets disabled (`tests/conftest.py`). If a test needs the
  network, the feature is out of scope.
- Do not relax an assertion to make a change pass. If the expectation was
  wrong, say why in the commit.

## Things that will not be merged

- Anything that evaluates, imports, or executes the analyzed file, or sends
  it or its contents anywhere.
- Anything that contacts a URL found in an analyzed file.
- Transformations that guess: renaming by inferred meaning, removing code
  that merely looks dead, or folding expressions whose result depends on
  coercion rules that are not implemented and tested.
- Findings without evidence, or wording that presents a static observation as
  runtime behaviour.
- New runtime dependencies without a reason the standard library cannot meet.

## Documentation

If you change the CLI, an indicator, a category, or the JSON output, update
`README.md`, `docs/usage.md`, and `docs/output-schema.md` in the same change,
and add a line to `CHANGELOG.md`. Examples in the documentation must be real
output.

[docs/architecture.md](docs/architecture.md) describes the code layout and
how to add a transformation or an indicator.
