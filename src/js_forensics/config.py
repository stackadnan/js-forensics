"""Limits and thresholds shared across the package.

Analyzed files are untrusted, so every list that grows with the input is
capped here rather than at the call site.
"""

# Memory use is proportional to the number of syntax nodes. Dense minified
# code measured at roughly 350 MB per megabyte of source for a full analysis
# with transformations, so the default keeps a run under about 1 GB.
DEFAULT_MAX_INPUT_BYTES = 2 * 1024 * 1024

MAX_SYNTAX_ERRORS_REPORTED = 20
MAX_LOCATIONS_PER_FINDING = 20
MAX_EVIDENCE_PER_INDICATOR = 5
MAX_IDENTIFIER_FINDINGS = 200
MAX_UNRESOLVED_REPORTED = 200
MAX_CHANGES_RECORDED = 200
MAX_HTML_TABLE_ROWS = 2000

SNIPPET_LENGTH = 120

# The static evaluator recurses on nested expressions; anything deeper is
# reported as unresolved instead of risking Python's recursion limit.
MAX_EVALUATION_DEPTH = 100
MAX_STATIC_STRING_LENGTH = 1_000_000
