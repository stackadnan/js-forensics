"""File and syntax statistics, counted from syntax nodes."""

from __future__ import annotations

from js_forensics.models import FileInfo, Statistics
from js_forensics.parser import ParsedSource

_LOOP_TYPES = {
    "for": "for_statement",
    "for_in_of": "for_in_statement",
    "while": "while_statement",
    "do_while": "do_statement",
}


def describe_file(parsed: ParsedSource) -> FileInfo:
    lines = parsed.source.split(b"\n")
    return FileInfo(
        path=parsed.path,
        size_bytes=len(parsed.source),
        sha256=parsed.sha256,
        line_count=parsed.line_count,
        max_line_length=max(len(line) for line in lines),
    )


def compute_statistics(parsed: ParsedSource) -> Statistics:
    index = parsed.index
    declarations = {"var": 0, "let": 0, "const": 0}
    for declarator in index.of_type("variable_declarator"):
        declaration = index.parent(declarator)
        keyword = "var"
        if declaration is not None and declaration.type == "lexical_declaration":
            kind = declaration.child_by_field_name("kind")
            keyword = parsed.text(kind) if kind is not None else "let"
        declarations[keyword] = declarations.get(keyword, 0) + 1
    # `for (const x of xs)` declares a binding without a declarator node.
    for loop in index.of_type("for_in_statement"):
        kind = loop.child_by_field_name("kind")
        if kind is not None:
            keyword = parsed.text(kind)
            declarations[keyword] = declarations.get(keyword, 0) + 1

    identifiers = index.of_type("identifier")
    return Statistics(
        function_declarations=index.count("function_declaration", "generator_function_declaration"),
        function_expressions=index.count("function_expression", "generator_function"),
        arrow_functions=index.count("arrow_function"),
        methods=index.count("method_definition"),
        classes=index.count("class_declaration", "class"),
        variable_declarations=declarations,
        identifier_occurrences=len(identifiers),
        unique_identifiers=len({parsed.source[n.start_byte : n.end_byte] for n in identifiers}),
        string_literals=index.count("string"),
        template_literals=index.count("template_string"),
        number_literals=index.count("number"),
        regex_literals=index.count("regex"),
        function_calls=index.count("call_expression"),
        new_expressions=index.count("new_expression"),
        loops={name: index.count(node_type) for name, node_type in _LOOP_TYPES.items()},
        if_statements=index.count("if_statement"),
        ternary_expressions=index.count("ternary_expression"),
        switch_statements=index.count("switch_statement"),
        comments=index.count("comment", "html_comment"),
        syntax_nodes=index.named_node_count,
        max_block_depth=index.max_block_depth,
    )
