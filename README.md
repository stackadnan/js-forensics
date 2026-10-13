<p align="center">
  <img src="https://raw.githubusercontent.com/stackadnan/js-forensics/main/docs/assets/banner.png" alt="JS Forensics: static analysis for minified and obfuscated JavaScript. Example: an escaped string, an atob call and a String.fromCharCode call rewritten as plain string literals." width="100%">
</p>

# JS Forensics

JS Forensics is a static-analysis toolkit for JavaScript that is minified,
obfuscated, or simply unfamiliar. It parses a file, reports what is in it, and
applies a small set of safe, traceable clean-up transformations.

It never executes the file it analyzes and never contacts a URL it finds.

Status: v0.1.0, alpha. The analyses are heuristic and the transformations are
deliberately conservative. See [Known limitations](#known-limitations) before
relying on a result.

## What it does

- Parses modern JavaScript with tree-sitter and reports syntax errors with
  line and column.
- Counts functions, declarations, identifiers, literals, calls, loops, and
  conditionals from the syntax tree.
- Detects twelve documented obfuscation indicators and shows the evidence for
  each one.
- Extracts string literals and sorts them into URLs, domains, API paths, HTTP
  header names, cookie strings, HTML, JSON, and everything else.
- Decodes escape-heavy literals and constant `String.fromCharCode`,
  `String.fromCodePoint`, and `atob` calls without running them.
- Folds constant expressions such as `"a" + "b"`, `0x3e8 * 0x3c`, and `!0`.
- Reports hex-style (`_0x1a2b`) and very short identifier names.
- Lists references to browser APIs (cookies, storage, network, canvas, WebGL,
  audio, WebRTC) and whether each is read, written, called, or constructed.
- Lists potential network endpoints with the HTTP method when the source
  determines it.
- Writes a terminal summary, JSON, or a standalone HTML report.

## Installation

Python 3.10 to 3.14 is supported.

```console
$ pip install js-forensics
$ js-forensics --version
js-forensics 0.1.0
```

To install from source instead:

```console
$ git clone https://github.com/stackadnan/js-forensics.git
$ cd js-forensics
$ python -m venv .venv && source .venv/bin/activate
$ pip install .
```

The Quick start examples use `examples/sample.js` from the repository.

## Quick start

The repository ships a small obfuscated file to try things on.

```console
$ js-forensics analyze examples/sample.js
$ js-forensics analyze examples/sample.js --format json --output report.json
$ js-forensics strings examples/sample.js
$ js-forensics endpoints examples/sample.js
$ js-forensics deobfuscate examples/sample.js --output-dir output/
$ js-forensics report examples/sample.js --format html --output report.html
```

`analyze` prints a summary. Part of the output for the sample:

```text
Obfuscation indicators (heuristic score 45/100)
The score adds fixed weights for the indicators below. It is not a probability and not a verdict on
what the code does.
[+15] Escape-encoded string literals
    -  4 of 8 string literals spell printable ASCII text with \x or \u escapes.
    1:109  Escape-encoded literal.  "\x74\x6f\x6b\x65\x6e"
[+15] Hex-style identifier names
    -  6 of 6 declared names look like _0x1a2b.
[+10] Decoder calls with constant arguments
    1:167  atob call with constant arguments.  atob("L3YxL3Nlc3Npb24=")
[+5] Minified layout

Decoded values
Technique            At     Value
escape-sequences     1:14   https://api.example.com
escape-sequences     1:109  token
atob                 1:167  /v1/session
String.fromCharCode  1:271  POST

Browser APIs referenced
API    Category  Usage  Count  Confidence  First at
fetch  network   call   1      high        1:335

Potential network endpoints
Method   URL                      Source               Resolved  At
UNKNOWN  /v1/session              constant-expression  static    1:167
UNKNOWN  https://api.example.com  string-literal       static    1:14

Unresolved call  At     Reason
fetch            1:335  the URL argument is not a static string
```

`deobfuscate` turns the one-line sample into this, and records every change in
`output/transformations.json`:

```js
var _0x3e1f=["https://api.example.com","token"];
function _0x2b7c(_0x1d){
  var _0x4a="/v1/session";
  if(true){
    return _0x3e1f[0x0]+_0x4a+"?"+_0x3e1f[0x1]+"="+_0x1d
  }
  return false
}
var _0x51="POST",_0x77=60000;
fetch(_0x2b7c("abc"),{method:_0x51,keepalive:!![]});
setTimeout(function(){
  console["log"]("done",_0x77)
},1000);
```

The names stay as they were and the array lookups are not inlined. That is
the current boundary of what the tool does, not an oversight.

## Commands

| Command | Purpose |
| --- | --- |
| `analyze FILE` | Summary of everything below. `--format text\|json`. |
| `strings FILE` | String and template literals with categories. `--category` filters. |
| `endpoints FILE` | Potential network endpoints, domains, and request calls whose URL is dynamic. |
| `deobfuscate FILE` | Run the transformation pipeline. Writes to `--output-dir` (default `js-forensics-output/`). |
| `report FILE` | Standalone report. `--format html\|json`; `--transformations` adds the pipeline history. |

Options shared by the analysis commands: `--output/-o`, `--tolerant` (analyze
a file despite syntax errors and mark the results as partial), `--no-redact`,
and `--max-bytes` (default 2 MiB).

Exit codes: `0` success, `2` invalid command line, `3` input file missing,
unreadable, too large, or not UTF-8, `4` JavaScript syntax error, `5` output
could not be written. `1` is an unexpected internal error.

[docs/usage.md](https://github.com/stackadnan/js-forensics/blob/main/docs/usage.md) is the full reference, including the counting
rules and every indicator's threshold. [docs/output-schema.md](https://github.com/stackadnan/js-forensics/blob/main/docs/output-schema.md)
describes the JSON.

## Supported analysis techniques

| Area | How it works |
| --- | --- |
| Statistics | Counts of syntax-node types. No regular expressions over source text. |
| Obfuscation indicators | Twelve structural rules with fixed thresholds and weights. The score is the capped sum of the weights that triggered. |
| String classification | Pattern heuristics. One category per string; ambiguous strings stay `other`. |
| Static decoding | Reimplementations of JavaScript string escapes, `String.fromCharCode`, `String.fromCodePoint`, and `atob`, applied only to constant arguments. |
| Constant folding | A static evaluator for strings, numbers, and booleans covering arithmetic, bitwise, comparison of same-typed values, `!`, and string concatenation. |
| Browser APIs | A catalogue of global names and member chains, plus a few distinctive method names matched with lower confidence. |
| Endpoints | Arguments of `fetch`, `XMLHttpRequest.open`, `WebSocket`, `EventSource`, `navigator.sendBeacon`, `axios`, and `$.ajax`/`$.get`/`$.post`, plus URL-like string literals and constant expressions. |

## Deobfuscation pipeline

Four stages run in order, each on the output of the one before:

1. `format-statements` puts each statement on its own line. It only changes
   whitespace between statements.
2. `simplify-string-escapes` rewrites `"\x68\x69"` as `"hi"`.
3. `decode-static-calls` replaces decoder calls on constants with the string
   they return.
4. `fold-constants` replaces constant operator expressions with their value.

Transformations edit exact source ranges; the program is not regenerated from
its syntax tree, so untouched code stays byte-for-byte as it was. After every
stage the result is parsed again, and a stage whose output does not parse is
discarded and reported as reverted. Each stage's output is saved under
`stages/` so you can diff them.

An expression that cannot be resolved safely is left unchanged. Decoder calls
and all-constant expressions that were skipped are listed with the reason, for
example `1 / 0` ("`/` by zero yields Infinity or NaN").

## Security boundaries

Every input is treated as hostile.

- The analyzed file is read and parsed. It is never evaluated, imported, or
  passed to a JavaScript runtime.
- No network access happens. URLs are extracted as text and nothing is
  resolved or fetched. The test suite fails if a socket is opened.
- The original file is never modified. Outputs go to a separate path and a
  write that would land on the input is refused.
- Input size is limited (2 MiB by default), nesting depth is bounded in the
  evaluator, and a transformation that would grow a file more than fourfold is
  reverted.
- HTML reports contain no script, carry a `default-src 'none'`
  Content-Security-Policy, and escape all text taken from the file. Extracted
  URLs are shown as text, not links.
- Terminal and HTML output escape control characters, so a file cannot inject
  ANSI sequences or bidirectional overrides into what you read.
- Likely credentials (JWTs, common API-key formats, bearer tokens, URL
  passwords, secret-looking query parameters and cookie values, and literals
  assigned to names like `password` or `apiKey`) are masked in reports. This
  is pattern matching and will miss some. `--no-redact` turns it off. The
  deobfuscated JavaScript itself is never redacted.
- A finding describes source text. "References `document.cookie`" does not
  mean a cookie was read, and a listed endpoint does not mean a request is
  made.

## Known limitations

- No data-flow analysis. Values are resolved only where they are constant at
  the point of use, so string-array lookups (`_0x1f2a(0x1b)`), strings built
  across statements, and values held in variables are not recovered.
- No renaming, no dead-code removal, and no control-flow unflattening.
- Code inside `eval`, `Function`, and string timers is not analyzed.
- Constant folding skips anything that needs type coercion beyond
  string-plus-number, such as `"5" * 2`, `[] + []`, `+"3"`, logical and
  conditional operators, and string comparison with `<`.
- Template literals are extracted but never rewritten.
- The formatter adds line breaks between statements only. Long expressions
  and comma sequences stay on one line.
- Decoder calls are resolved on the assumption that `String` and `atob` are
  the built-ins. They are skipped when the file declares or assigns those
  names or uses `with`, but runtime monkey-patching cannot be seen.
- Identifier counts are by name and ignore scope.
- The parser is tree-sitter's JavaScript grammar. It also accepts JSX and
  does not report every early error an engine would. TypeScript is not
  supported.
- Only UTF-8 input is accepted.
- Memory use is high. On the development machine, a full analysis with
  transformations of 1 MB of dense minified source took about 9 seconds and
  peaked near 370 MB. This is why the default input limit is 2 MiB.

## Contributing

See [CONTRIBUTING.md](https://github.com/stackadnan/js-forensics/blob/main/CONTRIBUTING.md) for setup, the checks to run, and the
rules for adding detectors and transformations.
[docs/architecture.md](https://github.com/stackadnan/js-forensics/blob/main/docs/architecture.md) explains how the code is laid
out.

## License

MIT. See [LICENSE](https://github.com/stackadnan/js-forensics/blob/main/LICENSE).

Security problems should be reported privately; see
[SECURITY.md](https://github.com/stackadnan/js-forensics/blob/main/SECURITY.md).
