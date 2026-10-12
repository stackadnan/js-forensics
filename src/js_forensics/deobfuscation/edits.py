"""Source-range edits.

Transformations do not regenerate the program from its syntax tree. They
replace the byte ranges of specific nodes and leave every other byte as the
author wrote it, which keeps the set of things that can go wrong small.
"""

from __future__ import annotations

from dataclasses import dataclass

from tree_sitter import Node


@dataclass(frozen=True, slots=True)
class TextEdit:
    start: int
    end: int
    replacement: bytes


def _is_identifier_byte(byte: int) -> bool:
    # Any non-ASCII byte may be part of a Unicode identifier.
    return byte >= 0x80 or chr(byte).isalnum() or byte in b"_$"


def replace_node(source: bytes, node: Node, text: str) -> TextEdit:
    """Edit that replaces ``node`` with ``text`` without merging tokens.

    Replacing ``(1+2)*3`` in ``return(1+2)*3`` with ``9`` must give
    ``return 9``, and a negative result after ``-`` must not form ``--``.
    """
    replacement = text.encode("utf-8")
    before = source[node.start_byte - 1] if node.start_byte > 0 else None
    after = source[node.end_byte] if node.end_byte < len(source) else None
    if before is not None and (
        (_is_identifier_byte(before) and _is_identifier_byte(replacement[0]))
        or (before == ord("-") and replacement[0] == ord("-"))
    ):
        replacement = b" " + replacement
    if after is not None and _is_identifier_byte(after) and _is_identifier_byte(replacement[-1]):
        replacement += b" "
    return TextEdit(node.start_byte, node.end_byte, replacement)


def apply_edits(source: bytes, edits: list[TextEdit]) -> bytes:
    """Apply non-overlapping edits. Raises ValueError if any two overlap."""
    parts = []
    position = 0
    for edit in sorted(edits, key=lambda item: (item.start, item.end)):
        if edit.start < position:
            raise ValueError(f"overlapping edits at byte {edit.start}")
        parts.append(source[position : edit.start])
        parts.append(edit.replacement)
        position = edit.end
    parts.append(source[position:])
    return b"".join(parts)
