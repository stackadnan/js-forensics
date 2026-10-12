"""Statement-per-line formatting.

This is not a pretty-printer. It only rewrites the whitespace between
statements (and class members and switch cases) so each starts on its own
indented line. Whitespace inside a statement is never touched, because that
is where a line break can change meaning (``return`` followed by a newline,
template literals, and so on). Between two statements a line break is always
safe to add.
"""

from __future__ import annotations

from js_forensics.deobfuscation.edits import TextEdit
from js_forensics.parser import ParsedSource

INDENT = b"  "
# Indentation stops growing here. Without a cap, input made of thousands of
# nested blocks would expand quadratically.
MAX_INDENT_LEVEL = 24

_BRACE_CONTAINERS = ("statement_block", "class_body", "switch_body")
_CASE_CONTAINERS = ("switch_case", "switch_default")


def statement_layout_edits(parsed: ParsedSource) -> list[TextEdit]:
    source = parsed.source
    edits: list[TextEdit] = []
    cursor = parsed.tree.walk()
    # For each ancestor: its node type and the indent level of its children.
    ancestors: list[tuple[str, int]] = []
    previous_token_end = 0
    previous_token_type = ""

    while True:
        node = cursor.node
        assert node is not None
        if ancestors:
            owner_type, level = ancestors[-1]
            starts_line = False
            if owner_type in _BRACE_CONTAINERS or owner_type == "program":
                if node.type == "}":
                    starts_line = previous_token_type != "{"  # noqa: S105 - a token type
                    level -= 1
                else:
                    starts_line = node.is_named
            elif owner_type in _CASE_CONTAINERS:
                starts_line = cursor.field_name == "body"

            gap = source[previous_token_end : node.start_byte]
            has_line_break = b"\n" in gap
            # A comment sharing a line with code stays attached to that code.
            beside_comment = "comment" in (node.type, previous_token_type) and not has_line_break
            if starts_line and not beside_comment and not gap.strip():
                if previous_token_end == 0:
                    wanted = b""
                else:
                    blank_line = b"\n" if gap.count(b"\n") > 1 else b""
                    wanted = blank_line + b"\n" + INDENT * min(level, MAX_INDENT_LEVEL)
                if gap != wanted:
                    edits.append(TextEdit(previous_token_end, node.start_byte, wanted))

        if cursor.goto_first_child():
            inherited = ancestors[-1][1] if ancestors else 0
            is_container = node.type in _BRACE_CONTAINERS or node.type in _CASE_CONTAINERS
            ancestors.append((node.type, inherited + 1 if is_container else inherited))
            continue
        previous_token_end = node.end_byte
        previous_token_type = node.type
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                trailing = source[previous_token_end:]
                if source and not trailing.strip() and trailing != b"\n":
                    edits.append(TextEdit(previous_token_end, len(source), b"\n"))
                return edits
            ancestors.pop()
