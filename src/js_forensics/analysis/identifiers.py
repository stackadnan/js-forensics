"""Identifier bindings and naming-pattern analysis.

Counts are name-based: the analysis does not resolve scopes, so two unrelated
variables that share a name are reported together. That is stated in the
output rather than hidden, and it errs toward caution where other modules ask
"could this name have been redefined?".
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from tree_sitter import Node

from js_forensics import config
from js_forensics.models import IdentifierFinding, IdentifierReport
from js_forensics.parser import ParsedSource

HEX_STYLE_NAME = re.compile(r"_0x[0-9a-fA-F]+")
SHORT_NAME_LENGTH = 2

_FUNCTION_TYPES = (
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
)
_PATTERN_CONTAINERS = ("object_pattern", "array_pattern", "formal_parameters")
_BINDING_LEAVES = ("identifier", "shorthand_property_identifier_pattern")


@dataclass(slots=True)
class Bindings:
    declarations: dict[str, list[tuple[str, Node]]] = field(default_factory=dict)
    reference_counts: Counter[str] = field(default_factory=Counter)
    assigned_names: set[str] = field(default_factory=set)

    @property
    def rebound_names(self) -> frozenset[str]:
        """Names the file declares or assigns, so they may shadow a global."""
        return frozenset(self.declarations) | frozenset(self.assigned_names)


def _binding_targets(pattern: Node) -> list[Node]:
    """Identifier nodes a declaration pattern binds, including destructuring."""
    targets = []
    pending = [pattern]
    while pending:
        node = pending.pop()
        if node.type in _BINDING_LEAVES:
            targets.append(node)
        elif node.type in _PATTERN_CONTAINERS:
            pending.extend(node.named_children)
        elif node.type == "pair_pattern":
            value = node.child_by_field_name("value")
            if value is not None:
                pending.append(value)
        elif node.type in ("assignment_pattern", "object_assignment_pattern"):
            left = node.child_by_field_name("left")
            if left is not None:
                pending.append(left)
        elif node.type == "rest_pattern":
            pending.extend(node.named_children)
    return targets


def _declaration_sites(parsed: ParsedSource) -> list[tuple[str, Node]]:
    """Every ``(kind, pattern_node)`` in the file that introduces bindings."""
    index = parsed.index
    sites: list[tuple[str, Node]] = []

    def add(kind: str, pattern: Node | None) -> None:
        if pattern is not None:
            sites.append((kind, pattern))

    for declarator in index.of_type("variable_declarator"):
        declaration = index.parent(declarator)
        kind = "var"
        if declaration is not None and declaration.type == "lexical_declaration":
            keyword = declaration.child_by_field_name("kind")
            kind = parsed.text(keyword) if keyword is not None else "let"
        add(kind, declarator.child_by_field_name("name"))
    for loop in index.of_type("for_in_statement"):
        keyword = loop.child_by_field_name("kind")
        if keyword is not None:
            add(parsed.text(keyword), loop.child_by_field_name("left"))
    for function in index.of_type(*_FUNCTION_TYPES):
        add("function", function.child_by_field_name("name"))
    for class_node in index.of_type("class_declaration", "class"):
        add("class", class_node.child_by_field_name("name"))
    for parameters in index.of_type("formal_parameters"):
        add("parameter", parameters)
    for arrow in index.of_type("arrow_function"):
        add("parameter", arrow.child_by_field_name("parameter"))
    for clause in index.of_type("catch_clause"):
        add("catch-parameter", clause.child_by_field_name("parameter"))
    for clause in index.of_type("import_clause", "namespace_import"):
        for child in clause.named_children:
            if child.type == "identifier":
                add("import", child)
    for specifier in index.of_type("import_specifier"):
        add(
            "import",
            specifier.child_by_field_name("alias") or specifier.child_by_field_name("name"),
        )
    return sites


def collect_bindings(parsed: ParsedSource) -> Bindings:
    index = parsed.index
    bindings = Bindings()
    binding_node_ids: set[int] = set()

    sites = _declaration_sites(parsed)
    sites.sort(key=lambda site: site[1].start_byte)
    for kind, pattern in sites:
        for target in _binding_targets(pattern):
            binding_node_ids.add(target.id)
            bindings.declarations.setdefault(parsed.text(target), []).append((kind, target))

    for node in index.of_type("identifier", "shorthand_property_identifier"):
        if node.id not in binding_node_ids:
            bindings.reference_counts[parsed.text(node)] += 1

    for assignment in index.of_type("assignment_expression", "augmented_assignment_expression"):
        assigned = assignment.child_by_field_name("left")
        if assigned is not None and assigned.type == "identifier":
            bindings.assigned_names.add(parsed.text(assigned))
    for update in index.of_type("update_expression"):
        assigned = update.child_by_field_name("argument")
        if assigned is not None and assigned.type == "identifier":
            bindings.assigned_names.add(parsed.text(assigned))
    for loop in index.of_type("for_in_statement"):
        assigned = loop.child_by_field_name("left")
        if loop.child_by_field_name("kind") is None and assigned is not None:
            bindings.assigned_names.update(parsed.text(node) for node in _binding_targets(assigned))
    return bindings


def analyze_identifiers(parsed: ParsedSource, bindings: Bindings) -> IdentifierReport:
    """Summarise naming patterns and list the hex-style names.

    Short names are only counted, not listed: minified code has thousands of
    them and a list would bury everything else.
    """
    names = list(bindings.declarations)
    hex_style = [name for name in names if HEX_STYLE_NAME.fullmatch(name)]
    short_count = sum(1 for name in names if len(name) <= SHORT_NAME_LENGTH)

    findings = []
    for name in hex_style:
        declarations = bindings.declarations[name]
        findings.append(
            IdentifierFinding(
                name=name,
                flags=["hex-style"],
                declared_as=sorted({kind for kind, _ in declarations}),
                declaration_count=len(declarations),
                reference_count=bindings.reference_counts[name],
                location=parsed.location(declarations[0][1]),
            )
        )
    findings.sort(key=lambda finding: (-finding.reference_count, finding.name))

    return IdentifierReport(
        declared_names=len(names),
        hex_style_names=len(hex_style),
        short_names=short_count,
        average_name_length=round(sum(map(len, names)) / len(names), 2) if names else 0.0,
        findings=findings[: config.MAX_IDENTIFIER_FINDINGS],
        findings_truncated=len(findings) > config.MAX_IDENTIFIER_FINDINGS,
    )
