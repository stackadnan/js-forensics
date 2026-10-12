"""Detection of references to browser APIs.

A finding means the source text mentions an API in a particular syntactic
role. It does not mean the code path runs, and for property-name matches it
does not even establish what object the property belongs to.
"""

from __future__ import annotations

from tree_sitter import Node

from js_forensics import config
from js_forensics.analysis.identifiers import Bindings
from js_forensics.analysis.syntax import (
    GLOBAL_OBJECT_NAMES,
    call_arguments,
    member_links,
    string_literal_value,
)
from js_forensics.models import BrowserApiFinding
from js_forensics.parser import ParsedSource

# Dotted global name -> category. The longest matching prefix of an access
# chain wins, so `navigator.sendBeacon(...)` is reported once, not also as
# `navigator`.
GLOBAL_APIS: dict[str, str] = {
    "window": "core",
    "document": "core",
    "navigator": "core",
    "location": "core",
    "history": "core",
    "document.cookie": "cookies",
    "document.createElement": "dom",
    "document.write": "dom",
    "document.referrer": "device-info",
    "localStorage": "storage",
    "localStorage.getItem": "storage",
    "localStorage.setItem": "storage",
    "localStorage.removeItem": "storage",
    "sessionStorage": "storage",
    "sessionStorage.getItem": "storage",
    "sessionStorage.setItem": "storage",
    "sessionStorage.removeItem": "storage",
    "indexedDB": "storage",
    "fetch": "network",
    "XMLHttpRequest": "network",
    "WebSocket": "network",
    "EventSource": "network",
    "navigator.sendBeacon": "network",
    "HTMLCanvasElement": "canvas",
    "CanvasRenderingContext2D": "canvas",
    "OffscreenCanvas": "canvas",
    "WebGLRenderingContext": "webgl",
    "WebGL2RenderingContext": "webgl",
    "AudioContext": "audio",
    "webkitAudioContext": "audio",
    "OfflineAudioContext": "audio",
    "RTCPeerConnection": "webrtc",
    "webkitRTCPeerConnection": "webrtc",
    "RTCDataChannel": "webrtc",
    "RTCSessionDescription": "webrtc",
    "navigator.mediaDevices": "webrtc",
    "navigator.mediaDevices.getUserMedia": "webrtc",
    "navigator.userAgent": "device-info",
    "navigator.platform": "device-info",
    "navigator.languages": "device-info",
    "navigator.plugins": "device-info",
    "navigator.webdriver": "device-info",
    "navigator.hardwareConcurrency": "device-info",
    "navigator.deviceMemory": "device-info",
    "screen": "device-info",
}

# Property names distinctive enough to report without knowing the receiver.
PROPERTY_APIS: dict[str, tuple[str, str]] = {
    "sendBeacon": ("sendBeacon", "network"),
    "toDataURL": ("canvas.toDataURL", "canvas"),
    "getImageData": ("canvas.getImageData", "canvas"),
    "createOscillator": ("AudioContext.createOscillator", "audio"),
    "createAnalyser": ("AudioContext.createAnalyser", "audio"),
    "createDynamicsCompressor": ("AudioContext.createDynamicsCompressor", "audio"),
    "createDataChannel": ("RTCPeerConnection.createDataChannel", "webrtc"),
    "createOffer": ("RTCPeerConnection.createOffer", "webrtc"),
    "onicecandidate": ("RTCPeerConnection.onicecandidate", "webrtc"),
    "getUserMedia": ("getUserMedia", "webrtc"),
}
_CONTEXT_TYPES = {
    "2d": ('getContext("2d")', "canvas"),
    "bitmaprenderer": ('getContext("bitmaprenderer")', "canvas"),
    "webgl": ('getContext("webgl")', "webgl"),
    "experimental-webgl": ('getContext("webgl")', "webgl"),
    "webgl2": ('getContext("webgl2")', "webgl"),
}
_PROPERTY_MATCH_NOTE = "Matched by property name only; the receiver's type is not known."
_SHADOWED_NOTE = "This name is also declared or assigned in the file, so it may not be the global."

_ROLE_BY_FIELD = {
    ("call_expression", "function"): "call",
    ("new_expression", "constructor"): "construct",
    ("assignment_expression", "left"): "write",
    ("augmented_assignment_expression", "left"): "write",
}
_MAX_CHAIN_PARTS = max(name.count(".") for name in GLOBAL_APIS) + 1


class _Findings:
    def __init__(self, parsed: ParsedSource) -> None:
        self._parsed = parsed
        self._grouped: dict[tuple[str, str, str], BrowserApiFinding] = {}

    def add(
        self, api: str, category: str, usage: str, confidence: str, node: Node, note: str | None
    ) -> None:
        key = (api, usage, confidence)
        finding = self._grouped.get(key)
        if finding is None:
            finding = self._grouped[key] = BrowserApiFinding(
                api=api,
                category=category,
                usage=usage,
                confidence=confidence,
                count=0,
                locations=[],
                note=note,
            )
        finding.count += 1
        if len(finding.locations) < config.MAX_LOCATIONS_PER_FINDING:
            finding.locations.append(self._parsed.location(node))

    def sorted(self) -> list[BrowserApiFinding]:
        return sorted(self._grouped.values(), key=lambda f: (f.category, f.api, f.usage))


def _role(parsed: ParsedSource, node: Node) -> str:
    """How an expression is used: called, constructed, assigned to, or read."""
    owner = parsed.index.parent(node)
    if owner is None:
        return "read"
    return _ROLE_BY_FIELD.get((owner.type, parsed.index.field(node) or ""), "read")


def _argument_match(parsed: ParsedSource, name: str, access: Node) -> tuple[str, str] | None:
    """Matches that depend on a method's first argument, such as
    ``getContext("webgl")`` or ``createElement("canvas")``."""
    owner = parsed.index.parent(access)
    if owner is None or _role(parsed, access) != "call":
        return None
    arguments = call_arguments(owner)
    if not arguments:
        return None
    first = arguments[0]
    argument = string_literal_value(parsed, first) if first.type == "string" else None
    if argument is None:
        return None
    if name == "getContext":
        return _CONTEXT_TYPES.get(argument.lower())
    if name == "createElement" and argument.lower() == "canvas":
        return ('createElement("canvas")', "canvas")
    return None


def detect_browser_apis(parsed: ParsedSource, bindings: Bindings) -> list[BrowserApiFinding]:
    index = parsed.index
    findings = _Findings(parsed)
    rebound = bindings.rebound_names
    declared_node_ids = {node.id for sites in bindings.declarations.values() for _, node in sites}
    inner_access_ids: set[int] = set()

    def report_chain(base: Node, links: list[tuple[str, Node]]) -> None:
        """Report the access chain ``base.link1.link2...``."""
        names: list[str] = []
        nodes: list[Node] = []
        if base.type == "identifier" and base.id not in declared_node_ids:
            names, nodes = [parsed.text(base)], [base]
        matched = 0
        if names:
            names += [name for name, _ in links]
            nodes += [node for _, node in links]
            # `window.fetch` is reported as `window` plus `fetch`.
            start = 0
            if names[0] in GLOBAL_OBJECT_NAMES and len(names) > 1 and names[1] in GLOBAL_APIS:
                if names[0] in GLOBAL_APIS:
                    findings.add(names[0], GLOBAL_APIS[names[0]], "read", "high", nodes[0], None)
                start = 1
            for end in range(min(len(names), start + _MAX_CHAIN_PARTS), start, -1):
                api = ".".join(names[start:end])
                if api in GLOBAL_APIS:
                    is_shadowed = names[start] in rebound and start == 0
                    findings.add(
                        api,
                        GLOBAL_APIS[api],
                        _role(parsed, nodes[end - 1]),
                        "low" if is_shadowed else "high",
                        nodes[end - 1],
                        _SHADOWED_NOTE if is_shadowed else None,
                    )
                    matched = end - 1  # number of links the match consumed
                    break
            if matched:
                # document.createElement("canvas") is both a DOM call and a
                # canvas reference; here the receiver is known.
                name, access = links[matched - 1]
                argument_api = _argument_match(parsed, name, access)
                if argument_api is not None:
                    findings.add(*argument_api, "call", "high", access, None)
        for name, access in links[matched:]:
            property_api = PROPERTY_APIS.get(name) or _argument_match(parsed, name, access)
            if property_api is not None:
                api, category = property_api
                findings.add(
                    api, category, _role(parsed, access), "medium", access, _PROPERTY_MATCH_NOTE
                )

    for access in index.of_type("member_expression", "subscript_expression"):
        if access.id in inner_access_ids:
            continue
        base, links = member_links(parsed, access)
        inner_access_ids.update(node.id for _, node in links)
        inner_access_ids.add(base.id)
        if links:
            report_chain(base, links)

    for identifier in index.of_type("identifier"):
        if identifier.id not in inner_access_ids:
            report_chain(identifier, [])
    return findings.sorted()
