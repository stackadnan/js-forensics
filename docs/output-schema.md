# JSON output schema

Schema version `1.0`. A field may be added in a later 1.x version; fields are
not removed or changed in meaning without a new major schema version.

Output is ASCII-only JSON. Analyzed strings can contain lone UTF-16
surrogates, which JSON can express as escapes but UTF-8 cannot encode.

## Report

Produced by `analyze --format json` and `report --format json`.

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | string | `"1.0"`. |
| `tool` | object | `name` and `version` of the producer. |
| `file` | object | See [File](#file). |
| `parse` | object | See [Parse](#parse). |
| `statistics` | object | Syntax-node counts; fields are listed in `usage.md`. `variable_declarations` and `loops` are objects keyed by kind. |
| `obfuscation` | object | See [Obfuscation](#obfuscation). |
| `strings` | array | See [String](#string). |
| `decoded_values` | array | See [Decoded value](#decoded-value). |
| `unresolved_decodes` | array of [Unresolved](#unresolved) | Decoder calls that were not resolved. |
| `identifiers` | object | See [Identifiers](#identifiers). |
| `browser_apis` | array | See [Browser API finding](#browser-api-finding). |
| `endpoints` | array | See [Endpoint](#endpoint). |
| `domains` | array | `{domain, occurrences}`, most frequent first. |
| `unresolved_network_calls` | array of [Unresolved](#unresolved) | Request calls with a non-constant URL. |
| `transformations` | object or null | See [Transformation history](#transformation-history). Null unless requested. |
| `redaction_enabled` | boolean | Whether likely credentials were masked. |
| `warnings` | array of string | Conditions that make the results partial, such as syntax errors. |
| `limitations` | array of string | Standing limits of static analysis that apply to every report. |

### Location

`{line, column, end_line, end_column}`, all 1-based integers. Columns count
code points. The end position is exclusive.

### File

| Field | Type | Description |
| --- | --- | --- |
| `path` | string | Path as given on the command line. |
| `size_bytes` | integer | Size after removing a UTF-8 byte order mark. |
| `sha256` | string | Hex digest of those bytes. |
| `line_count` | integer | Number of lines; 0 for an empty file. |
| `max_line_length` | integer | Longest line, in bytes. |

### Parse

| Field | Type | Description |
| --- | --- | --- |
| `parser` | string | `"tree-sitter-javascript"`. |
| `has_errors` | boolean | True only in `--tolerant` runs. |
| `error_count` | integer | Total error and missing-token nodes. |
| `errors` | array | Up to 20 `{message, location}`. |

### Obfuscation

| Field | Type | Description |
| --- | --- | --- |
| `score` | integer | 0 to 100: capped sum of the weights of `indicators`. Not a probability. |
| `indicators` | array | Triggered indicators: `{id, title, weight, explanation, evidence}`. |
| `checked` | array of string | Ids of every indicator that was evaluated. |

Each `evidence` item is `{detail, location, snippet}`. `location` and
`snippet` are null for summary lines.

### String

| Field | Type | Description |
| --- | --- | --- |
| `value` | string | Decoded value. For templates, substitutions are kept as `${source}`. |
| `category` | string | `url`, `domain`, `api_path`, `http_header`, `cookie`, `html`, `json`, or `other`. |
| `kind` | string | `string` or `template`. |
| `occurrences` | integer | How many literals have this value. |
| `locations` | array of Location | Up to 20. |
| `has_escapes` | boolean | Some occurrence used a numeric escape. |
| `redacted` | boolean | `value` was masked. |

### Decoded value

| Field | Type | Description |
| --- | --- | --- |
| `technique` | string | `escape-sequences`, `String.fromCharCode`, `String.fromCodePoint`, or `atob`. |
| `source` | string | Excerpt of the original expression. |
| `value` | string | The decoded string. |
| `location` | Location | |
| `redacted` | boolean | |

### Unresolved

Something that was recognised and deliberately left alone.

| Field | Type | Description |
| --- | --- | --- |
| `subject` | string | What it is: a decoder or request API name, `string literal`, or `constant expression`. |
| `reason` | string | Why it was not resolved. |
| `location` | Location | |
| `snippet` | string | Source excerpt. |

### Identifiers

| Field | Type | Description |
| --- | --- | --- |
| `declared_names` | integer | Distinct declared names. |
| `hex_style_names` | integer | Names like `_0x1a2b`. |
| `short_names` | integer | Names of one or two characters. |
| `average_name_length` | number | |
| `findings` | array | Hex-style names, most referenced first: `{name, flags, declared_as, declaration_count, reference_count, location}`. |
| `findings_truncated` | boolean | More than 200 existed. |

Counts are by name and do not distinguish scopes.

### Browser API finding

| Field | Type | Description |
| --- | --- | --- |
| `api` | string | For example `document.cookie`. |
| `category` | string | `core`, `cookies`, `storage`, `network`, `dom`, `canvas`, `webgl`, `audio`, `webrtc`, or `device-info`. |
| `usage` | string | `call`, `construct`, `write`, or `read`. |
| `confidence` | string | `high`, `medium`, or `low`. |
| `count` | integer | References with this api, usage, and confidence. |
| `locations` | array of Location | Up to 20. |
| `note` | string or null | Why confidence is not high. |

### Endpoint

| Field | Type | Description |
| --- | --- | --- |
| `url` | string | URL or path. May contain `${...}` placeholders. |
| `method` | string | An HTTP method, or `UNKNOWN`. |
| `source` | string | `fetch`, `XMLHttpRequest.open`, `WebSocket`, `EventSource`, `navigator.sendBeacon`, `axios`, `jQuery`, `constant-expression`, or `string-literal`. |
| `resolution` | string | `static` or `partial`. |
| `occurrences` | integer | |
| `locations` | array of Location | Up to 20. |
| `redacted` | boolean | |

### Transformation history

Also the content of `transformations.json` written by `deobfuscate` (which is
never redacted).

| Field | Type | Description |
| --- | --- | --- |
| `input_sha256`, `output_sha256` | string | Digests before and after the pipeline. |
| `changed` | boolean | Whether the output differs from the input. |
| `records` | array | One per stage, in order. |

Each record:

| Field | Type | Description |
| --- | --- | --- |
| `name`, `description` | string | The stage. |
| `changed` | boolean | The stage's output was accepted and differs from its input. |
| `change_count` | integer | Number of edits. |
| `changes` | array | Up to 200 `{before, after, location}`. Empty for `format-statements`. |
| `skipped_count` | integer | Items recognised but left unchanged. |
| `skipped` | array of Unresolved | Up to 200 of them. |
| `reverted_reason` | string or null | Set when the stage's output was rejected. |

Locations in a record refer to that stage's input, which is the previous
stage's output (see the `stages/` files), not the original file.

## `strings --format json`

`{schema_version, file, strings}` where `file` is the path and `strings` is an
array of [String](#string), filtered by `--category` if given.

## `endpoints --format json`

`{schema_version, file, endpoints, domains, unresolved_network_calls}` with
the same element types as the report.
