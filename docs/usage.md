# Usage reference

## Commands

Every command takes one JavaScript file. The file is opened read-only.

### `js-forensics analyze FILE`

Prints the full summary: file statistics, obfuscation indicators, identifier
naming, decoded values, browser API references, potential endpoints, and a
string overview.

| Option | Meaning |
| --- | --- |
| `--format`, `-f` `text\|json` | Output format. Default `text`. |
| `--output`, `-o PATH` | Write to a file instead of standard output. |
| `--tolerant` | Analyze despite syntax errors. The report carries a warning and `parse.has_errors` is true. |
| `--no-redact` | Do not mask likely credentials. |
| `--max-bytes N` | Refuse larger files. Default 2097152 (2 MiB). |

### `js-forensics strings FILE`

Lists every distinct string and template literal with its category, first
location, and number of occurrences. `--category NAME` keeps one category:
`url`, `domain`, `api_path`, `http_header`, `cookie`, `html`, `json`, or
`other`. Takes the same options as `analyze`.

### `js-forensics endpoints FILE`

Lists potential endpoints, the domains they mention, and request calls whose
URL argument could not be resolved. Takes the same options as `analyze`.

### `js-forensics deobfuscate FILE`

Runs the transformation pipeline and writes:

- `<output-dir>/<name>.deobfuscated.js`, the result;
- `<output-dir>/transformations.json`, what each stage changed and skipped;
- `<output-dir>/stages/NN-<stage>.js`, the source after each stage that
  changed something.

| Option | Meaning |
| --- | --- |
| `--output-dir`, `-d DIR` | Where to write. Default `js-forensics-output`. |
| `--no-stages` | Skip the `stages/` files. |
| `--max-bytes N` | As above. |

There is no `--tolerant` here: a file with syntax errors is not transformed.
Existing files in the output directory with the same names are replaced; the
input file never is.

### `js-forensics report FILE`

Writes a standalone HTML report (default) or the JSON report.

| Option | Meaning |
| --- | --- |
| `--format`, `-f` `html\|json` | Default `html`. |
| `--output`, `-o PATH` | Default `<name>.report.<format>` in the current directory. |
| `--transformations` | Also run the pipeline and include its history. Nothing but the report is written. |
| `--tolerant`, `--no-redact`, `--max-bytes` | As for `analyze`. |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Unexpected internal error. |
| 2 | Invalid command line: unknown option, unsupported `--format`, missing argument. |
| 3 | Input problem: the file does not exist, is a directory, cannot be read, exceeds `--max-bytes`, or is not UTF-8. |
| 4 | The JavaScript has syntax errors (and `--tolerant` was not given). |
| 5 | The output could not be written, or would overwrite the input. |

Results go to standard output or `--output`. Warnings, errors, and "Wrote ..."
notices go to standard error, so JSON on standard output is always clean.

## Locations

Locations are `line:column`, both starting at 1. Columns count Unicode code
points. Lines are separated by `\n`.

## Statistics: counting rules

All counts are numbers of syntax nodes.

| Field | What is counted |
| --- | --- |
| `function_declarations` | `function f() {}` and `function* f() {}` statements. |
| `function_expressions` | `function` and `function*` used as expressions. |
| `arrow_functions` | `=>` functions. |
| `methods` | Methods, getters, and setters in classes and object literals, including `constructor`. |
| `classes` | Class declarations and class expressions. |
| `variable_declarations` | Declarators per keyword: `var a, b` counts 2 under `var`. The binding of `for (const x of xs)` counts once. Parameters are not included. |
| `identifier_occurrences` | Every identifier used as a variable name, in declarations and references. Property names (`obj.name`, `{name: 1}`) are not identifiers. |
| `unique_identifiers` | Distinct names among those. |
| `string_literals` | Quoted strings, including property keys and import sources. |
| `template_literals` | Backtick literals, tagged or not. |
| `number_literals`, `regex_literals` | Numeric (including BigInt) and regular-expression literals. |
| `function_calls` | Call expressions, including method calls and tagged templates. |
| `new_expressions` | `new X(...)`. |
| `loops` | `for`, `for_in_of` (`for...in`, `for...of`, `for await`), `while`, `do_while`. |
| `if_statements` | `if` statements; an `else if` is a second `if`. |
| `ternary_expressions`, `switch_statements` | As named. |
| `comments` | Line, block, and HTML-style comments. |
| `syntax_nodes` | All named nodes in the tree. |
| `max_block_depth` | Deepest nesting of `{ ... }` statement blocks. |

## Obfuscation indicators

Each indicator either triggers or does not. The score is the sum of the
weights of the triggered indicators, capped at 100. The weights total 130, so
the cap matters only when nearly everything triggers.

The score is a summary of which known patterns are present. It is not a
probability that the file is obfuscated, and it says nothing about whether the
code is malicious. Minified library code typically scores 5.

| Id | Weight | Triggers when |
| --- | --- | --- |
| `string-array-lookup` | 25 | An array literal of at least 10 elements, at least 90% of them strings, exists, and either a variable holding such an array is indexed with a numeric literal at least 5 times, or one function is called at least 10 times with a numeric literal first argument where the literal is hexadecimal or the function has a hex-style name. |
| `escape-encoded-strings` | 15 | At least 3 string literals each contain 2 or more `\x`/`\u`/octal escapes of printable ASCII characters, making up at least half the literal's length. |
| `hex-style-identifiers` | 15 | At least 5 declared names match `_0x` followed by hex digits. |
| `switch-dispatch-loop` | 15 | A `while` loop with an always-true literal condition, or a `for` loop with no condition, directly contains a `switch` whose selector is `array[index++]`. |
| `array-rotation` | 10 | A call of the form `x.push(x.shift())` exists. |
| `dynamic-evaluation` | 10 | The file calls `eval(...)`, calls or constructs `Function(...)`, passes a string literal to `setTimeout`/`setInterval`, or calls a `.constructor` property with a string literal. |
| `bracket-property-access` | 10 | At least 10 property accesses use a string literal that is a valid identifier (`obj["name"]`), and they are at least 25% of all property accesses. |
| `static-decoder-calls` | 10 | `String.fromCharCode`, `String.fromCodePoint`, or `atob` is called with constant arguments that decode to at least 3 characters. |
| `hex-number-literals` | 5 | The file has at least 20 numeric literals and at least half are hexadecimal. |
| `deep-block-nesting` | 5 | Statement blocks nest at least 10 deep. |
| `deep-expression-nesting` | 5 | Some statement's syntax tree is at least 60 levels deep below its enclosing block. |
| `minified-layout` | 5 | A line is at least 1,000 bytes, or lines average at least 200 bytes. |

Each triggered indicator lists up to five pieces of evidence with locations.

## String categories

A string gets the first category that matches, in this order.

| Category | Rule |
| --- | --- |
| `url` | Starts with `http://`, `https://`, `ws://`, `wss://`, or `ftp://`, or is protocol-relative (`//host.tld/...`). No whitespace. |
| `html` | Contains an HTML tag, a closing tag, a comment opener, or a doctype. |
| `json` | Starts and ends with `{}` or `[]` and parses as JSON. |
| `cookie` | Is `cookie`, `cookies`, or `set-cookie`, or contains a cookie attribute such as `; path=` or `; HttpOnly`. |
| `http_header` | Is one of about 45 standard header names, or looks like `X-Something`. |
| `domain` | Dotted host name ending in one of about 60 common top-level domains, optionally with a port. Names such as `file.js` or `user.name` are not domains. |
| `api_path` | Starts with a single `/`, contains a letter, and consists of path characters with an optional query string. |
| `other` | Everything else. |

Template literals are included with their substitutions kept as written, for
example `/users/${id}`.

## Decoding

`decoded_values` lists strings that were hidden behind an encoding:

- `escape-sequences`: literals written mostly as numeric escapes.
- `String.fromCharCode`, `String.fromCodePoint`, `atob`: calls whose
  arguments are constant. `String["fromCharCode"](...)`, `window.atob(...)`,
  and arguments that are themselves constant expressions are recognised.

`unresolved_decodes` lists calls to those functions that were not resolved,
with the reason: a non-constant argument, a spread argument, input the real
function would reject, or a file that declares or assigns `String`/`atob`.

`atob` results are byte strings, as in the browser. Bytes that are not
printable are shown as `\xNN`.

## Constant folding

Folded:

- `+` on strings and numbers in any mix (`"a" + 1`, `1 + "a"`, `1 + 2`);
- `-`, `*`, `/`, `%` on numbers; `**` on integers with an exactly
  representable result;
- `&`, `|`, `^`, `~`, `<<`, `>>`, `>>>` on numbers;
- `<`, `>`, `<=`, `>=` on numbers; `===`, `!==`, `==`, `!=` on two values of
  the same type;
- `!` on a string, number, or boolean; unary `-` and `+` on numbers;
- parentheses and template literals around the above.

Never folded: anything involving a variable, call, array, object, `null`,
`undefined`, or BigInt; division or remainder by zero; results that are
`Infinity`, `NaN`, or negative zero; arithmetic on strings other than `+`;
arithmetic on booleans; `&&`, `||`, `??`, `?:`, `typeof`, `void`; legacy
octal literals such as `017`.

An expression that is a whole statement is never replaced, because a bare
string statement can become a directive such as `"use strict"`.

## Identifier analysis

A name is `hex-style` when it matches `_0x` plus hex digits, and `short` when
it has one or two characters. Hex-style names are listed with how they are
declared (`var`, `let`, `const`, `function`, `class`, `parameter`,
`catch-parameter`, `import`), how many declarations and references share the
name, and where the first declaration is. Short names are only counted.

Counts are by name across the whole file. Two different variables called `a`
in different functions are counted together.

No names are suggested or changed.

## Browser API references

`usage` is `call` (`fetch(...)`), `construct` (`new WebSocket(...)`), `write`
(`document.cookie = ...`), or `read` for any other mention.

`confidence` is:

- `high` for a global name or member chain from the catalogue, such as
  `document.cookie` or `navigator.sendBeacon`. A leading `window.`, `self.`,
  or `globalThis.` is ignored, and `obj["name"]` is treated as `obj.name`.
- `medium` for a distinctive method name on an unknown receiver, such as
  `x.getContext("webgl")` or `x.toDataURL()`.
- `low` when the file itself declares or assigns the name, for example a
  function parameter called `document`.

Catalogue, by category:

- core: `window`, `document`, `navigator`, `location`, `history`
- cookies: `document.cookie`
- storage: `localStorage`, `sessionStorage` (and their `getItem`, `setItem`,
  `removeItem`), `indexedDB`
- network: `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`,
  `navigator.sendBeacon`
- dom: `document.createElement`, `document.write`
- canvas: `HTMLCanvasElement`, `CanvasRenderingContext2D`, `OffscreenCanvas`,
  `getContext("2d")`, `createElement("canvas")`, `toDataURL`, `getImageData`
- webgl: `WebGLRenderingContext`, `WebGL2RenderingContext`,
  `getContext("webgl")`, `getContext("webgl2")`
- audio: `AudioContext`, `webkitAudioContext`, `OfflineAudioContext`,
  `createOscillator`, `createAnalyser`, `createDynamicsCompressor`
- webrtc: `RTCPeerConnection`, `webkitRTCPeerConnection`, `RTCDataChannel`,
  `RTCSessionDescription`, `navigator.mediaDevices`, `getUserMedia`,
  `createDataChannel`, `createOffer`, `onicecandidate`
- device-info: `navigator.userAgent`, `platform`, `languages`, `plugins`,
  `webdriver`, `hardwareConcurrency`, `deviceMemory`; `document.referrer`;
  `screen`

## Endpoint discovery

| `source` | Recognised form | `method` |
| --- | --- | --- |
| `fetch` | `fetch(url)` and `fetch(url, {method: "..."})` | The literal method; `GET` when there is no options argument or the options literal provably has no `method`; otherwise `UNKNOWN`. |
| `XMLHttpRequest.open` | `x.open("METHOD", url)` where the first argument is a constant HTTP method name | That method. |
| `WebSocket` | `new WebSocket(url)` | `UNKNOWN` (not an HTTP request method). |
| `EventSource` | `new EventSource(url)` | `GET`. |
| `navigator.sendBeacon` | `navigator.sendBeacon(url, data)` | `POST`. |
| `axios` | `axios(url)`, `axios({url, method})`, `axios.get/post/put/delete/patch/head/options(url)`, `axios.request({...})` | From the call or config; `UNKNOWN` if not constant. |
| `jQuery` | `$.ajax({url, type})`, `$.ajax(url, {...})`, `$.get`, `$.getJSON`, `$.getScript`, `$.post` (also via `jQuery`) | From the call or config. |
| `constant-expression` | A constant expression or decoder call that evaluates to a URL or path | `UNKNOWN`. |
| `string-literal` | A string or template literal categorised `url` or `api_path` that is not already a request argument | `UNKNOWN`. |

`resolution` is `static` when the whole URL is known and `partial` when it
contains `${...}` placeholders for parts that are not constant, as in
`"/api/items/" + id` reported as `/api/items/${id}`.

Identical endpoints (same method, URL, and source) are merged; `occurrences`
is the total and `locations` holds up to 20 of them.

`domains` are the hosts of absolute URLs plus strings categorised `domain`.
`unresolved_network_calls` lists recognised request calls whose URL argument
has no constant part.

Known noise: XML namespace URLs such as `http://www.w3.org/2000/svg` are
reported like any other URL string.

## Redaction

With redaction on (the default), report text is searched for:

- JSON Web Tokens;
- AWS access key ids, GitHub tokens, Slack tokens, Google API keys, Stripe
  live keys;
- PEM private key blocks;
- `Bearer` and `Basic` credentials;
- passwords in `scheme://user:password@host` URLs;
- values of query parameters named `token`, `access_token`, `key`, `api_key`,
  `secret`, `password`, `passwd`, `sig`, `signature`, or `auth`;
- the value of a cookie in a `name=value; Path=...` string;
- string literals of 8 or more non-space characters assigned to a variable or
  property whose name contains `password`, `passwd`, `passphrase`, `pwd`,
  `secret`, `token`, `apiKey`, `credential`, `private_key`, `access_key`,
  `session_id`, or `bearer`, or ends in `auth` or `authorization`, when the
  literal is not otherwise categorised.

A match is replaced by its first four characters and
`…[redacted N chars]`. Affected entries have `redacted: true`.

## Limits

| Limit | Value |
| --- | --- |
| Input size | 2 MiB by default (`--max-bytes`). |
| Locations kept per finding | 20; `occurrences`/`count` still holds the true total. |
| Evidence items per indicator | A summary line plus at most 5 examples of each kind. |
| Hex-style identifiers listed | 200. |
| Changes and skipped items listed per transformation | 200 each; the counts are exact. |
| Rows per HTML table | 2,000; the JSON report is complete. |
| Expression nesting the evaluator follows | 100 levels. |
| Largest string the evaluator builds | 1,000,000 characters. |
| Growth allowed per transformation stage | 4 times the input plus 64 KiB. |
