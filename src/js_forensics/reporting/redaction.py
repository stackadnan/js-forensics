"""Redaction of likely credentials before a report is rendered.

Redaction is pattern-based and best-effort. It lowers the chance that a
report pasted into a ticket leaks a secret; it is not a guarantee that none
gets through. The deobfuscated JavaScript output is never redacted, because
that would change the program.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import partial

from js_forensics.models import AnalysisReport, TransformationHistory, Unresolved

MIN_CONTEXT_SECRET_LENGTH = 8
_VISIBLE_PREFIX = 4

# (pattern, group to mask). Group 0 masks the whole match.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), 0),  # JWT
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),  # AWS access key id
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), 0),  # GitHub token
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), 0),  # Slack token
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),  # Google API key
    (re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"), 0),  # Stripe live key
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.DOTALL), 0),
    (re.compile(r"\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{12,})", re.IGNORECASE), 1),
    (re.compile(r"://[^/\s:@]+:([^/\s@]+)@"), 1),  # password in URL userinfo
    (
        re.compile(
            r"[?&](?:access_token|token|api_?key|key|secret|password|passwd|sig|signature|auth)"
            r"=((?!\$\{)[^&#\s]{6,})",
            re.IGNORECASE,
        ),
        1,
    ),
    (
        re.compile(
            r"^[\w.-]+=([^;\s]{6,})(?=;\s*(?:path|expires|max-age|domain|secure|samesite|httponly))",
            re.IGNORECASE,
        ),
        1,
    ),  # cookie value in a Set-Cookie style string
)


def mask(secret: str) -> str:
    return f"{secret[:_VISIBLE_PREFIX]}…[redacted {len(secret)} chars]"


class Redactor:
    """Masks secrets by pattern, plus any exact values supplied up front."""

    def __init__(self, known_secrets: Iterable[str] = ()) -> None:
        # Longest first, so a secret that contains another is masked whole.
        self._known_secrets = sorted(set(known_secrets), key=len, reverse=True)

    def redact(self, text: str) -> tuple[str, bool]:
        original = text
        for secret in self._known_secrets:
            if secret in text:
                text = text.replace(secret, mask(secret))
        for pattern, group in _SECRET_PATTERNS:
            text = pattern.sub(partial(_mask_group, group=group), text)
        return text, text != original

    def text(self, value: str) -> str:
        return self.redact(value)[0]


def _mask_group(match: re.Match[str], group: int) -> str:
    whole = match.group(0)
    if group == 0:
        return mask(whole)
    start, end = match.start(group) - match.start(), match.end(group) - match.start()
    return whole[:start] + mask(whole[start:end]) + whole[end:]


def _redact_unresolved(redactor: Redactor, items: list[Unresolved]) -> None:
    for item in items:
        item.snippet = redactor.text(item.snippet)


def redact_history(redactor: Redactor, history: TransformationHistory) -> None:
    for record in history.records:
        for change in record.changes:
            change.before = redactor.text(change.before)
            change.after = redactor.text(change.after)
        _redact_unresolved(redactor, record.skipped)


def redact_report(report: AnalysisReport, redactor: Redactor) -> None:
    """Mask likely secrets in every source-derived text field, in place."""
    for string in report.strings:
        string.value, string.redacted = redactor.redact(string.value)
    for decoded in report.decoded_values:
        decoded.value, decoded.redacted = redactor.redact(decoded.value)
        decoded.source = redactor.text(decoded.source)
    for endpoint in report.endpoints:
        endpoint.url, endpoint.redacted = redactor.redact(endpoint.url)
    for indicator in report.obfuscation.indicators:
        for evidence in indicator.evidence:
            if evidence.snippet is not None:
                evidence.snippet = redactor.text(evidence.snippet)
    _redact_unresolved(redactor, report.unresolved_decodes)
    _redact_unresolved(redactor, report.unresolved_network_calls)
    if report.transformations is not None:
        redact_history(redactor, report.transformations)
