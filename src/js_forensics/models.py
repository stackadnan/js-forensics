"""Result types shared by the analyses, detectors, and report writers.

Every type is a plain dataclass so a report serializes with
``dataclasses.asdict``. ``docs/output-schema.md`` describes the JSON shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """A 1-based source range. Columns count Unicode code points."""

    line: int
    column: int
    end_line: int
    end_column: int


@dataclass(slots=True)
class SyntaxIssue:
    message: str
    location: SourceLocation


@dataclass(slots=True)
class FileInfo:
    path: str
    size_bytes: int
    sha256: str
    line_count: int
    max_line_length: int


@dataclass(slots=True)
class ParseInfo:
    parser: str
    has_errors: bool
    error_count: int
    errors: list[SyntaxIssue]


@dataclass(slots=True)
class Statistics:
    """Syntax-node counts. The counting rules are listed in docs/usage.md."""

    function_declarations: int = 0
    function_expressions: int = 0
    arrow_functions: int = 0
    methods: int = 0
    classes: int = 0
    variable_declarations: dict[str, int] = field(default_factory=dict)
    identifier_occurrences: int = 0
    unique_identifiers: int = 0
    string_literals: int = 0
    template_literals: int = 0
    number_literals: int = 0
    regex_literals: int = 0
    function_calls: int = 0
    new_expressions: int = 0
    loops: dict[str, int] = field(default_factory=dict)
    if_statements: int = 0
    ternary_expressions: int = 0
    switch_statements: int = 0
    comments: int = 0
    syntax_nodes: int = 0
    max_block_depth: int = 0


@dataclass(slots=True)
class Evidence:
    detail: str
    location: SourceLocation | None = None
    snippet: str | None = None


@dataclass(slots=True)
class Indicator:
    id: str
    title: str
    weight: int
    explanation: str
    evidence: list[Evidence]


@dataclass(slots=True)
class ObfuscationReport:
    """``score`` is the capped sum of the triggered indicators' weights."""

    score: int
    indicators: list[Indicator]
    checked: list[str]


@dataclass(slots=True)
class ExtractedString:
    value: str
    category: str
    kind: str  # "string" or "template"
    occurrences: int
    locations: list[SourceLocation]
    has_escapes: bool = False
    redacted: bool = False


@dataclass(slots=True)
class DecodedValue:
    technique: str
    source: str
    value: str
    location: SourceLocation
    redacted: bool = False


@dataclass(slots=True)
class Unresolved:
    """Something a static step recognised but deliberately left alone."""

    subject: str
    reason: str
    location: SourceLocation
    snippet: str


@dataclass(slots=True)
class IdentifierFinding:
    name: str
    flags: list[str]
    declared_as: list[str]
    declaration_count: int
    reference_count: int
    location: SourceLocation


@dataclass(slots=True)
class IdentifierReport:
    declared_names: int
    hex_style_names: int
    short_names: int
    average_name_length: float
    findings: list[IdentifierFinding]
    findings_truncated: bool


@dataclass(slots=True)
class BrowserApiFinding:
    api: str
    category: str
    usage: str  # "call", "construct", "write", or "read"
    confidence: str  # "high", "medium", or "low"
    count: int
    locations: list[SourceLocation]
    note: str | None = None


@dataclass(slots=True)
class Endpoint:
    url: str
    method: str
    source: str
    resolution: str  # "static" or "partial"
    occurrences: int
    locations: list[SourceLocation]
    redacted: bool = False


@dataclass(slots=True)
class DomainFinding:
    domain: str
    occurrences: int


@dataclass(slots=True)
class Change:
    before: str
    after: str
    location: SourceLocation


@dataclass(slots=True)
class TransformationRecord:
    """What one pipeline stage did.

    Locations refer to that stage's input, which is the previous stage's
    output rather than the original file.
    """

    name: str
    description: str
    changed: bool
    change_count: int
    changes: list[Change]
    skipped_count: int
    skipped: list[Unresolved]
    reverted_reason: str | None = None


@dataclass(slots=True)
class TransformationHistory:
    input_sha256: str
    output_sha256: str
    changed: bool
    records: list[TransformationRecord]


@dataclass(slots=True)
class AnalysisReport:
    schema_version: str
    tool: dict[str, str]
    file: FileInfo
    parse: ParseInfo
    statistics: Statistics
    obfuscation: ObfuscationReport
    strings: list[ExtractedString]
    decoded_values: list[DecodedValue]
    unresolved_decodes: list[Unresolved]
    identifiers: IdentifierReport
    browser_apis: list[BrowserApiFinding]
    endpoints: list[Endpoint]
    domains: list[DomainFinding]
    unresolved_network_calls: list[Unresolved]
    transformations: TransformationHistory | None
    redaction_enabled: bool
    warnings: list[str]
    limitations: list[str]
