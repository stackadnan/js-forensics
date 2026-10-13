# Changelog

## 0.1.0 - 2026-10-11

First release.

### Added

- `js-forensics` command with `analyze`, `strings`, `endpoints`,
  `deobfuscate`, and `report` subcommands, and stable exit codes.
- JavaScript parsing with tree-sitter, including syntax-error reporting and a
  `--tolerant` mode for partial analysis.
- File and syntax statistics.
- Twelve obfuscation indicators with evidence and a documented heuristic
  score.
- String extraction with heuristic categories.
- Static decoding of escape sequences and of constant `String.fromCharCode`,
  `String.fromCodePoint`, and `atob` calls.
- Conservative constant folding for strings, numbers, and booleans.
- Identifier naming analysis.
- Browser API reference detection with usage roles.
- Network endpoint discovery for `fetch`, `XMLHttpRequest.open`, `WebSocket`,
  `EventSource`, `navigator.sendBeacon`, axios, and jQuery.
- A four-stage transformation pipeline that validates each stage and records
  what changed and what was skipped.
- Terminal, JSON, and standalone HTML reports, with likely credentials
  redacted by default.
