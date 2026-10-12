import pytest

from js_forensics.analysis.identifiers import collect_bindings
from js_forensics.detectors.browser_apis import detect_browser_apis
from js_forensics.parser import ParsedSource

from .conftest import parse, parse_fixture


def detect(parsed: ParsedSource):
    return detect_browser_apis(parsed, collect_bindings(parsed))


STORAGE_READ = ("localStorage.getItem", "call")
USER_MEDIA = ("navigator.mediaDevices.getUserMedia", "call")


def usages(source: str) -> set[tuple[str, str]]:
    return {(finding.api, finding.usage) for finding in detect(parse(source))}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('fetch("/x");', {("fetch", "call")}),
        ("var later = fetch;", {("fetch", "read")}),
        ('window.fetch("/x");', {("window", "read"), ("fetch", "call")}),
        ('document.cookie = "a=1";', {("document.cookie", "write")}),
        ('document.cookie += "; b=2";', {("document.cookie", "write")}),
        ('document.cookie.split(";");', {("document.cookie", "read")}),
        ("new WebSocket(url);", {("WebSocket", "construct")}),
        ("new window.XMLHttpRequest();", {("window", "read"), ("XMLHttpRequest", "construct")}),
        ('window["localStorage"].getItem("k");', {("window", "read"), STORAGE_READ}),
        ('localStorage["setItem"]("k", "v");', {("localStorage.setItem", "call")}),
        ("sessionStorage.length;", {("sessionStorage", "read")}),
        ("navigator.mediaDevices.getUserMedia({});", {USER_MEDIA}),
        ("navigator.sendBeacon(u, d);", {("navigator.sendBeacon", "call")}),
        ("new AudioContext();", {("AudioContext", "construct")}),
        ("new RTCPeerConnection(cfg);", {("RTCPeerConnection", "construct")}),
        ("window[name];", {("window", "read")}),
        ("document.body.appendChild(el);", {("document", "read")}),
        # Not browser globals: properties and object keys that share a name.
        ("client.fetch(); var o = {fetch: 1, document: 2};", set()),
        ("api.navigator.userAgent;", set()),
        ("var total = 1; total.toFixed(2);", set()),
    ],
)  # fmt: skip
def test_api_usage_roles(source, expected):
    assert usages(source) == expected


def test_property_name_matches_are_medium_confidence():
    findings = detect(
        parse(
            'el.getContext("2d"); el.getContext("experimental-webgl");'
            "el.toDataURL(); q.sendBeacon(u);"
        )
    )
    assert {(f.api, f.category, f.usage, f.confidence) for f in findings} == {
        ('getContext("2d")', "canvas", "call", "medium"),
        ('getContext("webgl")', "webgl", "call", "medium"),
        ("canvas.toDataURL", "canvas", "call", "medium"),
        ("sendBeacon", "network", "call", "medium"),
    }
    assert all("receiver" in (finding.note or "") for finding in findings)


def test_get_context_with_unknown_argument_is_not_reported():
    assert usages("el.getContext(kind); list.getContext;") == set()


def test_locally_declared_name_lowers_confidence():
    findings = detect(parse("function f(document) { return document.title; }"))
    assert [(f.api, f.usage, f.confidence) for f in findings] == [("document", "read", "low")]
    assert "declared" in (findings[0].note or "")


def test_fixture_findings_and_counts():
    findings = {(f.api, f.usage): f for f in detect(parse_fixture("browser_apis.js"))}
    assert set(findings) == {
        ("navigator.userAgent", "read"),
        ("document.cookie", "write"),
        ("document.cookie", "read"),
        ("window", "read"),
        ("localStorage.setItem", "call"),
        ("sessionStorage.getItem", "call"),
        ("XMLHttpRequest", "construct"),
        ("WebSocket", "construct"),
        ("navigator.sendBeacon", "call"),
        ("document.createElement", "call"),
        ('createElement("canvas")', "call"),
        ('getContext("webgl")', "call"),
        ('getContext("2d")', "call"),
        ("canvas.toDataURL", "call"),
        ("AudioContext", "construct"),
        ("AudioContext.createOscillator", "call"),
        ("RTCPeerConnection", "construct"),
        ("navigator.mediaDevices.getUserMedia", "call"),
        ("fetch", "read"),
        ("document", "read"),
    }
    cookie_write = findings[("document.cookie", "write")]
    assert (cookie_write.count, cookie_write.category) == (1, "cookies")
    assert (cookie_write.locations[0].line, cookie_write.locations[0].column) == (2, 1)
    # `document` is a parameter of isolated(), which the note points out.
    shadowed = findings[("document", "read")]
    assert shadowed.confidence == "low"


def test_repeated_references_are_counted_once_per_site():
    findings = detect(parse('fetch("/a"); fetch("/b"); fetch("/c");'))
    assert [(f.api, f.count, len(f.locations)) for f in findings] == [("fetch", 3, 3)]
