"""Small helpers for reading tree-sitter JavaScript nodes."""

from __future__ import annotations

from tree_sitter import Node

from js_forensics.analysis.js_literals import InvalidEscape, decode_string_body
from js_forensics.parser import ParsedSource

GLOBAL_OBJECT_NAMES = frozenset({"window", "self", "globalThis"})

_MEMBER_TYPES = ("member_expression", "subscript_expression")


def string_literal_value(parsed: ParsedSource, node: Node) -> str | None:
    """Decoded value of a ``string`` node, or None if its escapes are invalid."""
    try:
        return decode_string_body(parsed.text(node)[1:-1])
    except InvalidEscape:
        return None


def static_property_name(parsed: ParsedSource, node: Node) -> str | None:
    """Property name of ``a.b`` or ``a["b"]``; None when it is computed."""
    if node.type == "member_expression":
        name = node.child_by_field_name("property")
        return parsed.text(name) if name is not None else None
    if node.type == "subscript_expression":
        index = node.child_by_field_name("index")
        if index is not None and index.type == "string":
            return string_literal_value(parsed, index)
    return None


def member_links(parsed: ParsedSource, node: Node) -> tuple[Node, list[tuple[str, Node]]]:
    """Unwind ``a.b["c"]`` into its base object and static property links.

    Returns the innermost object that is not itself a static member access,
    and ``[(name, access_node), ...]`` from innermost to outermost.
    """
    links: list[tuple[str, Node]] = []
    current = node
    while current.type in _MEMBER_TYPES:
        name = static_property_name(parsed, current)
        target = current.child_by_field_name("object")
        if name is None or target is None:
            break
        links.append((name, current))
        current = target
    links.reverse()
    return current, links


def dotted_name(parsed: ParsedSource, node: Node) -> list[str] | None:
    """``["a", "b", "c"]`` for ``a.b.c``, or None if the base is not a plain
    identifier or any property is computed."""
    base, links = member_links(parsed, node)
    if base.type != "identifier":
        return None
    return [parsed.text(base), *(name for name, _ in links)]


def strip_global_object(names: list[str]) -> list[str]:
    """Drop a leading ``window.``/``self.``/``globalThis.`` qualifier."""
    if len(names) > 1 and names[0] in GLOBAL_OBJECT_NAMES:
        return names[1:]
    return names


def call_arguments(call: Node) -> list[Node] | None:
    """Argument nodes of a call or ``new`` expression.

    Returns None for tagged templates and for argument lists containing a
    spread, because positions are then not statically known.
    """
    arguments = call.child_by_field_name("arguments")
    if arguments is None or arguments.type != "arguments":
        return None
    nodes = [child for child in arguments.named_children if child.type != "comment"]
    if any(child.type == "spread_element" for child in nodes):
        return None
    return nodes


def object_property(parsed: ParsedSource, literal: Node, name: str) -> tuple[Node | None, bool]:
    """Look up a property in an object literal.

    Returns ``(value_node, is_certain)``. ``is_certain`` is False when the
    literal has spreads or computed keys that could also define the property.
    """
    is_certain = True
    value: Node | None = None
    for member in literal.named_children:
        if member.type == "pair":
            key = member.child_by_field_name("key")
            if key is None:
                continue
            if key.type == "property_identifier":
                key_name: str | None = parsed.text(key)
            elif key.type == "string":
                key_name = string_literal_value(parsed, key)
            else:
                key_name = None
                is_certain = False
            if key_name == name:
                value = member.child_by_field_name("value")
        elif member.type != "comment":
            # Spreads, shorthand properties, and methods can all supply a key.
            if (
                member.type in ("spread_element", "method_definition")
                or parsed.text(member) == name
            ):
                is_certain = False
    return value, is_certain
