"""String literal extraction and heuristic classification."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from tree_sitter import Node

from js_forensics import config
from js_forensics.analysis.js_literals import InvalidEscape, combine_surrogates, split_string_body
from js_forensics.analysis.syntax import static_property_name
from js_forensics.models import ExtractedString
from js_forensics.parser import ParsedSource

CATEGORIES = ("url", "domain", "api_path", "http_header", "cookie", "html", "json", "other")

_URL = re.compile(
    r"(?:(?:https?|wss?|ftp)://[^\s]+|//[a-z0-9.-]+\.[a-z]{2,}(?:[/:?#][^\s]*)?)", re.IGNORECASE
)
_DOMAIN = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?P<tld>[a-z]{2,24})(?::\d{1,5})?", re.IGNORECASE
)
# A dotted name is only called a domain when it ends in one of these; without
# the list, `file.js` and `user.name` would all qualify.
_COMMON_TLDS = frozenset(
    "com net org io co dev app ai edu gov mil int info biz xyz online site top cloud tech me tv cc "
    "ru cn uk de fr jp br in it es nl au ca ch se no fi pl kr us eu ir tr ua za mx ar id vn".split()
)
_API_PATH = re.compile(r"/(?!/)[\w\-.~%/:@{}$]*[\w\-}/](?:\?[^\s]*)?(?:#[^\s]*)?")
_HTML = re.compile(
    r"<[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?/?>|</[a-zA-Z][a-zA-Z0-9-]*\s*>|<!(?:--|DOCTYPE)"
)
_COOKIE_ATTRIBUTE = re.compile(
    r";\s*(?:path|expires|max-age|domain|samesite)\s*=|;\s*(?:secure|httponly)\b", re.IGNORECASE
)
_COOKIE_NAMES = frozenset({"cookie", "cookies", "set-cookie"})
_CUSTOM_HEADER = re.compile(r"x-[a-z0-9]+(?:-[a-z0-9]+)*", re.IGNORECASE)
_KNOWN_HEADERS = frozenset(
    "accept accept-charset accept-encoding accept-language access-control-allow-origin "
    "access-control-allow-credentials access-control-allow-headers access-control-allow-methods "
    "authorization cache-control connection content-disposition content-encoding content-length "
    "content-security-policy content-type dnt etag host if-modified-since if-none-match "
    "last-modified location origin pragma proxy-authorization range referer referrer-policy "
    "sec-ch-ua sec-fetch-dest sec-fetch-mode sec-fetch-site strict-transport-security "
    "transfer-encoding upgrade user-agent vary www-authenticate".split()
)
_JSON_ATTEMPT_LIMIT = 100_000

_CREDENTIAL_NAME = re.compile(
    r"pass(?:word|wd|phrase)|pwd|secret|token|api[_-]?key|credential|private[_-]?key|access[_-]?key"
    r"|auth(?:orization)?$|session[_-]?id|bearer",
    re.IGNORECASE,
)
_PRINTABLE_ASCII = re.compile(r"[\x20-\x7e]")


@dataclass(slots=True)
class StringOccurrence:
    """One string or template literal in the source."""

    node: Node
    value: str
    kind: str
    has_escapes: bool = False
    # True when most of the literal is spelled with numeric escapes for
    # characters that needed none, e.g. "\x68\x65\x6c\x6c\x6f".
    escape_encoded: bool = False
    # True when the literal is the value of something named like a credential.
    in_credential_context: bool = False


def classify_string(value: str) -> str:
    """Assign one heuristic category; ambiguous strings stay ``other``."""
    text = value.strip()
    if not text:
        return "other"
    if _URL.fullmatch(text):
        return "url"
    if _HTML.search(text):
        return "html"
    if _looks_like_json(text):
        return "json"
    lowered = text.lower()
    if lowered in _COOKIE_NAMES or _COOKIE_ATTRIBUTE.search(text):
        return "cookie"
    if lowered in _KNOWN_HEADERS or _CUSTOM_HEADER.fullmatch(text):
        return "http_header"
    domain = _DOMAIN.fullmatch(text)
    if domain and domain.group("tld").lower() in _COMMON_TLDS:
        return "domain"
    if _API_PATH.fullmatch(text) and any(character.isalpha() for character in text):
        return "api_path"
    return "other"


def _looks_like_json(text: str) -> bool:
    if len(text) > _JSON_ATTEMPT_LIMIT or text[0] + text[-1] not in ("{}", "[]"):
        return False
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


def _credential_context(parsed: ParsedSource, node: Node) -> bool:
    index = parsed.index
    owner = index.parent(node)
    if owner is None:
        return False
    name: str | None = None
    if owner.type == "pair" and index.field(node) == "value":
        key = owner.child_by_field_name("key")
        name = parsed.text(key).strip("\"'") if key is not None else None
    elif owner.type == "variable_declarator" and index.field(node) == "value":
        target = owner.child_by_field_name("name")
        name = parsed.text(target) if target is not None and target.type == "identifier" else None
    elif owner.type == "assignment_expression" and index.field(node) == "right":
        target = owner.child_by_field_name("left")
        if target is not None and target.type == "identifier":
            name = parsed.text(target)
        elif target is not None:
            name = static_property_name(parsed, target)
    return name is not None and _CREDENTIAL_NAME.search(name) is not None


def _string_occurrence(parsed: ParsedSource, node: Node) -> StringOccurrence:
    body = parsed.text(node)[1:-1]
    if "\\" not in body:
        return StringOccurrence(node, body, "string")
    try:
        pieces = split_string_body(body)
    except InvalidEscape:
        return StringOccurrence(node, body, "string")
    value = combine_surrogates("".join(piece.value for piece in pieces))
    numeric_escapes = [piece for piece in pieces if piece.kind in ("hex", "unicode", "octal")]
    needless = sum(1 for piece in numeric_escapes if _PRINTABLE_ASCII.fullmatch(piece.value))
    return StringOccurrence(
        node,
        value,
        "string",
        has_escapes=bool(numeric_escapes),
        escape_encoded=needless >= 2 and needless * 2 >= len(value),
    )


def _template_occurrence(parsed: ParsedSource, node: Node) -> StringOccurrence:
    """Template literals keep their substitutions as ``${source}`` text."""
    parts = []
    for child in node.named_children:
        text = parsed.text(child)
        if child.type == "template_substitution":
            parts.append(parsed.snippet(child, 40))
        elif child.type == "escape_sequence":
            try:
                parts.append("".join(piece.value for piece in split_string_body(text)))
            except InvalidEscape:
                parts.append(text)
        else:
            parts.append(text)
    return StringOccurrence(node, combine_surrogates("".join(parts)), "template")


def collect_string_occurrences(parsed: ParsedSource) -> list[StringOccurrence]:
    """Every string and template literal, in source order."""
    occurrences = []
    for node in parsed.index.of_type("string", "template_string"):
        if node.type == "string":
            occurrence = _string_occurrence(parsed, node)
        else:
            occurrence = _template_occurrence(parsed, node)
        occurrence.in_credential_context = _credential_context(parsed, node)
        occurrences.append(occurrence)
    return occurrences


def summarize_strings(
    parsed: ParsedSource, occurrences: list[StringOccurrence]
) -> list[ExtractedString]:
    """Group identical literals, keeping the first locations of each."""
    grouped: dict[tuple[str, str], ExtractedString] = {}
    for occurrence in occurrences:
        key = (occurrence.value, occurrence.kind)
        entry = grouped.get(key)
        if entry is None:
            entry = grouped[key] = ExtractedString(
                value=occurrence.value,
                category=classify_string(occurrence.value),
                kind=occurrence.kind,
                occurrences=0,
                locations=[],
            )
        entry.occurrences += 1
        entry.has_escapes = entry.has_escapes or occurrence.has_escapes
        if len(entry.locations) < config.MAX_LOCATIONS_PER_FINDING:
            entry.locations.append(parsed.location(occurrence.node))
    return list(grouped.values())
