"""Static discovery of potential network endpoints.

Endpoints come from two places: arguments of recognised request APIs, and
string literals that look like URLs or absolute paths. Nothing here contacts
a URL, and a listed endpoint is a string found in the source, not evidence
that a request is ever made.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from urllib.parse import urlsplit

from tree_sitter import Node

from js_forensics import config
from js_forensics.analysis.static_eval import PartialString, StaticEvaluator
from js_forensics.analysis.strings import StringOccurrence, classify_string
from js_forensics.analysis.syntax import (
    call_arguments,
    dotted_name,
    object_property,
    static_property_name,
    strip_global_object,
)
from js_forensics.models import DomainFinding, Endpoint, Unresolved
from js_forensics.parser import ParsedSource

UNKNOWN_METHOD = "UNKNOWN"
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

_AXIOS_VERBS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})
_JQUERY_NAMES = frozenset({"$", "jQuery"})
_JQUERY_SHORTHANDS = {"get": "GET", "getJSON": "GET", "getScript": "GET", "post": "POST"}
_CONSTRUCTORS = {"WebSocket": UNKNOWN_METHOD, "EventSource": "GET"}
_URL_NOT_STATIC = "the URL argument is not a static string"


@dataclass(slots=True)
class _Request:
    """A recognised request call before its URL has been resolved."""

    source: str
    url_node: Node | None
    method: str


@dataclass(slots=True)
class EndpointDiscovery:
    endpoints: list[Endpoint]
    domains: list[DomainFinding]
    unresolved_calls: list[Unresolved]


class _EndpointCollector:
    def __init__(self, parsed: ParsedSource, evaluator: StaticEvaluator) -> None:
        self.parsed = parsed
        self.evaluator = evaluator
        self.grouped: dict[tuple[str, str, str], Endpoint] = {}
        self.unresolved: list[Unresolved] = []
        self.argument_ranges: list[tuple[int, int]] = []

    def add(self, url: PartialString, method: str, source: str, node: Node) -> None:
        key = (method, url.text, source)
        endpoint = self.grouped.get(key)
        if endpoint is None:
            endpoint = self.grouped[key] = Endpoint(
                url=url.text,
                method=method,
                source=source,
                resolution="static" if url.is_complete else "partial",
                occurrences=0,
                locations=[],
            )
        endpoint.occurrences += 1
        if len(endpoint.locations) < config.MAX_LOCATIONS_PER_FINDING:
            endpoint.locations.append(self.parsed.location(node))

    def add_request(self, request: _Request, call: Node) -> None:
        url = self.evaluator.partial_string(request.url_node) if request.url_node else None
        if url is None:
            if len(self.unresolved) < config.MAX_UNRESOLVED_REPORTED:
                self.unresolved.append(
                    Unresolved(
                        subject=request.source,
                        reason=_URL_NOT_STATIC,
                        location=self.parsed.location(call),
                        snippet=self.parsed.snippet(call),
                    )
                )
            return
        assert request.url_node is not None
        self.argument_ranges.append((request.url_node.start_byte, request.url_node.end_byte))
        self.add(url, request.method, request.source, call)

    def static_method(self, node: Node | None) -> str | None:
        """An HTTP method name if ``node`` is a static string naming one."""
        if node is None:
            return None
        value = self.evaluator.try_evaluate(node)
        if isinstance(value, str) and value.upper() in HTTP_METHODS:
            return value.upper()
        return None

    def method_from_options(self, options: Node | None, keys: tuple[str, ...], default: str) -> str:
        """Read the method out of an options object literal.

        ``default`` applies only when the literal provably has none of
        ``keys``; anything less certain is UNKNOWN.
        """
        if options is None:
            return default
        if options.type != "object":
            return UNKNOWN_METHOD
        literal_is_certain = True
        for key in keys:
            value, is_certain = object_property(self.parsed, options, key)
            if value is not None:
                return self.static_method(value) or UNKNOWN_METHOD
            literal_is_certain = literal_is_certain and is_certain
        return default if literal_is_certain else UNKNOWN_METHOD

    def request_from_config(self, source: str, options: Node, keys: tuple[str, ...]) -> _Request:
        """A request described by one object literal with a ``url`` property."""
        if options.type != "object":
            return _Request(source, None, UNKNOWN_METHOD)
        url_node, _ = object_property(self.parsed, options, "url")
        return _Request(source, url_node, self.method_from_options(options, keys, "GET"))


def _recognise_call(collector: _EndpointCollector, call: Node) -> _Request | None:
    parsed = collector.parsed
    callee = call.child_by_field_name("function")
    arguments = call_arguments(call)
    if callee is None or not arguments:
        return None
    first = arguments[0]
    second = arguments[1] if len(arguments) > 1 else None
    names = strip_global_object(dotted_name(parsed, callee) or [])
    last_name = static_property_name(parsed, callee)

    if names == ["fetch"]:
        return _Request("fetch", first, collector.method_from_options(second, ("method",), "GET"))
    if names == ["navigator", "sendBeacon"]:
        return _Request("navigator.sendBeacon", first, "POST")

    # XMLHttpRequest.open(method, url) is told apart from window.open(url) by
    # its first argument being an HTTP method name.
    if last_name == "open" and second is not None:
        method = collector.static_method(first)
        if method is not None:
            return _Request("XMLHttpRequest.open", second, method)

    if names == ["axios"]:
        if first.type == "object":
            return collector.request_from_config("axios", first, ("method",))
        return _Request("axios", first, collector.method_from_options(second, ("method",), "GET"))
    if len(names) == 2 and names[0] == "axios":
        if names[1] in _AXIOS_VERBS:
            return _Request("axios", first, names[1].upper())
        if names[1] == "request":
            return collector.request_from_config("axios", first, ("method",))

    if len(names) == 2 and names[0] in _JQUERY_NAMES:
        if names[1] in _JQUERY_SHORTHANDS:
            return _Request("jQuery", first, _JQUERY_SHORTHANDS[names[1]])
        if names[1] == "ajax":
            if first.type == "object":
                return collector.request_from_config("jQuery", first, ("type", "method"))
            method = collector.method_from_options(second, ("type", "method"), "GET")
            return _Request("jQuery", first, method)
    return None


def _recognise_constructor(collector: _EndpointCollector, expression: Node) -> _Request | None:
    constructor = expression.child_by_field_name("constructor")
    arguments = call_arguments(expression)
    if constructor is None or not arguments:
        return None
    names = strip_global_object(dotted_name(collector.parsed, constructor) or [])
    if len(names) == 1 and names[0] in _CONSTRUCTORS:
        return _Request(names[0], arguments[0], _CONSTRUCTORS[names[0]])
    return None


def _add_constant_expressions(collector: _EndpointCollector) -> None:
    """Report URLs that only exist once an expression is evaluated, such as
    ``"https://" + "example.com"`` or ``atob("...")``."""
    parsed = collector.parsed
    request_ranges = sorted(collector.argument_ranges)
    resolved_until = 0
    for node in parsed.index.of_type("binary_expression", "call_expression"):
        if node.start_byte < resolved_until or _is_inside(request_ranges, node.start_byte):
            continue
        if node.type == "call_expression" and collector.evaluator.decoder_name(node) is None:
            continue
        value = collector.evaluator.try_evaluate(node)
        if value is None:
            continue
        # Whatever the value is, the expressions nested inside this one need
        # no second look.
        resolved_until = node.end_byte
        if isinstance(value, str) and classify_string(value) in ("url", "api_path"):
            collector.argument_ranges.append((node.start_byte, node.end_byte))
            collector.add(
                PartialString(value.strip(), True), UNKNOWN_METHOD, "constant-expression", node
            )


def _is_inside(sorted_ranges: list[tuple[int, int]], offset: int) -> bool:
    preceding = bisect.bisect_right(sorted_ranges, (offset, float("inf"))) - 1
    return preceding >= 0 and offset < sorted_ranges[preceding][1]


def _host_of(url: str) -> str | None:
    if "://" not in url and not url.startswith("//"):
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    # A placeholder inside the authority means the host itself is dynamic.
    if not host or "$" in host or "{" in host:
        return None
    return host


def discover_endpoints(
    parsed: ParsedSource,
    occurrences: list[StringOccurrence],
    evaluator: StaticEvaluator,
) -> EndpointDiscovery:
    """``evaluator`` should resolve decoder calls so that encoded URLs passed
    to request APIs are found."""
    collector = _EndpointCollector(parsed, evaluator)
    for node in parsed.index.of_type("call_expression", "new_expression"):
        if node.type == "call_expression":
            request = _recognise_call(collector, node)
        else:
            request = _recognise_constructor(collector, node)
        if request is not None:
            collector.add_request(request, node)

    _add_constant_expressions(collector)

    domain_counts: dict[str, int] = {}
    argument_ranges = sorted(collector.argument_ranges)
    for occurrence in occurrences:
        category = classify_string(occurrence.value)
        if category == "domain":
            domain = occurrence.value.strip().lower()
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        if category not in ("url", "api_path"):
            continue
        # Literals already reported as a request argument are not repeated.
        if _is_inside(argument_ranges, occurrence.node.start_byte):
            continue
        has_placeholder = occurrence.kind == "template" and "${" in occurrence.value
        collector.add(
            PartialString(occurrence.value.strip(), not has_placeholder),
            UNKNOWN_METHOD,
            "string-literal",
            occurrence.node,
        )

    endpoints = list(collector.grouped.values())
    for endpoint in endpoints:
        host = _host_of(endpoint.url)
        if host is not None:
            domain_counts[host] = domain_counts.get(host, 0) + endpoint.occurrences
    domains = [
        DomainFinding(domain, count)
        for domain, count in sorted(domain_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    return EndpointDiscovery(endpoints, domains, collector.unresolved)
