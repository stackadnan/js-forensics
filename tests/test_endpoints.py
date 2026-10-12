from js_forensics.analysis.identifiers import collect_bindings
from js_forensics.analysis.static_eval import StaticEvaluator
from js_forensics.analysis.strings import collect_string_occurrences
from js_forensics.detectors.endpoints import EndpointDiscovery, discover_endpoints
from js_forensics.parser import ParsedSource

from .conftest import parse, parse_fixture


def discover(parsed: ParsedSource) -> EndpointDiscovery:
    evaluator = StaticEvaluator(
        parsed, resolve_decoders=True, rebound_names=collect_bindings(parsed).rebound_names
    )
    return discover_endpoints(parsed, collect_string_occurrences(parsed), evaluator)


def found(source: str) -> list[tuple[str, str, str, str]]:
    return [
        (endpoint.method, endpoint.url, endpoint.source, endpoint.resolution)
        for endpoint in discover(parse(source)).endpoints
    ]


def test_fixture_endpoints():
    discovery = discover(parse_fixture("endpoints.js"))
    endpoints = [
        (e.method, e.url, e.source, e.resolution, e.occurrences) for e in discovery.endpoints
    ]
    assert endpoints == [
        ("GET", "https://api.example.com/v1/users", "fetch", "static", 2),
        ("POST", "/api/orders", "fetch", "static", 1),
        ("GET", "/api/items/${itemId}", "fetch", "partial", 1),
        ("UNKNOWN", "/api/users/${userId}/posts", "fetch", "partial", 1),
        ("PUT", "/api/profile", "XMLHttpRequest.open", "static", 1),
        ("UNKNOWN", "wss://live.example.com/feed", "WebSocket", "static", 1),
        ("GET", "/events", "EventSource", "static", 1),
        ("POST", "https://metrics.example.org/collect", "navigator.sendBeacon", "static", 1),
        ("GET", "/api/axios/list", "axios", "static", 1),
        ("DELETE", "/api/axios/config", "axios", "static", 1),
        ("PATCH", "/api/jquery", "jQuery", "static", 1),
        ("POST", "/api/jquery/post", "jQuery", "static", 1),
        ("GET", "/api/hidden", "fetch", "static", 1),
        ("UNKNOWN", "/popup", "string-literal", "static", 1),
        ("UNKNOWN", "https://docs.example.com/guide", "string-literal", "static", 1),
    ]


def test_duplicate_endpoints_keep_every_location():
    first = discover(parse_fixture("endpoints.js")).endpoints[0]
    assert [(location.line, location.column) for location in first.locations] == [(1, 1), (2, 1)]


def test_fixture_domains():
    domains = {d.domain: d.occurrences for d in discover(parse_fixture("endpoints.js")).domains}
    assert domains == {
        "api.example.com": 2,
        "live.example.com": 1,
        "metrics.example.org": 1,
        "docs.example.com": 1,
        "cdn.example.net": 1,
    }


def test_request_with_dynamic_url_is_listed_as_unresolved():
    unresolved = discover(parse_fixture("endpoints.js")).unresolved_calls
    assert [(item.subject, item.location.line, item.snippet) for item in unresolved] == [
        ("fetch", 6, "fetch(buildUrl())")
    ]
    assert "not a static string" in unresolved[0].reason


def test_fetch_method_is_only_reported_when_determined():
    assert found('fetch("/a");') == [("GET", "/a", "fetch", "static")]
    assert found('fetch("/a", {method: "post"});') == [("POST", "/a", "fetch", "static")]
    assert found('fetch("/a", {headers: h});') == [("GET", "/a", "fetch", "static")]
    assert found('fetch("/a", options);') == [("UNKNOWN", "/a", "fetch", "static")]
    assert found('fetch("/a", {...options});') == [("UNKNOWN", "/a", "fetch", "static")]
    assert found('fetch("/a", {method: verb});') == [("UNKNOWN", "/a", "fetch", "static")]
    assert found('fetch("/a", {method});') == [("UNKNOWN", "/a", "fetch", "static")]
    assert found('fetch("/a", {["met" + "hod"]: "PUT"});') == [("UNKNOWN", "/a", "fetch", "static")]


def test_open_is_only_an_xhr_call_with_a_method_argument():
    assert found('request.open("POST", "/submit", true);') == [
        ("POST", "/submit", "XMLHttpRequest.open", "static")
    ]
    assert found('window.open("/popup", "_blank");') == [
        ("UNKNOWN", "/popup", "string-literal", "static")
    ]
    assert found("request.open(method, url);") == []


def test_http_client_calls():
    assert found('axios.put("/a/" + id, body);') == [("PUT", "/a/${id}", "axios", "partial")]
    assert found('axios("/a");') == [("GET", "/a", "axios", "static")]
    assert found('axios("/a", {method: "patch"});') == [("PATCH", "/a", "axios", "static")]
    assert found('axios.request({url: "/a", method: m});') == [("UNKNOWN", "/a", "axios", "static")]
    assert found('jQuery.getJSON("/a.json");') == [("GET", "/a.json", "jQuery", "static")]
    assert found('$.ajax("/a", {method: "DELETE"});') == [("DELETE", "/a", "jQuery", "static")]


def test_urls_hidden_behind_static_expressions_are_found():
    assert found('var u = "https://" + "example.com" + "/api";') == [
        ("UNKNOWN", "https://example.com/api", "constant-expression", "static")
    ]
    assert found('var u = atob("aHR0cHM6Ly9leGFtcGxlLmNvbS9h");') == [
        ("UNKNOWN", "https://example.com/a", "constant-expression", "static")
    ]
    assert found(r'var u = "\x2f\x61\x70\x69\x2f\x78";') == [
        ("UNKNOWN", "/api/x", "string-literal", "static")
    ]


def test_template_literal_urls_are_partial():
    assert found("var u = `https://${host}/api/v2`;") == [
        ("UNKNOWN", "https://${host}/api/v2", "string-literal", "partial")
    ]
    # A dynamic host is not reported as a domain.
    assert discover(parse("var u = `https://${host}/api/v2`;")).domains == []


def test_non_endpoint_strings_are_ignored():
    assert found('var a = "hello", b = "text/html", c = "a/b", d = "/";') == []
