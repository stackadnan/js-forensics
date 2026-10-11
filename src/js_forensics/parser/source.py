"""Loading and parsing untrusted JavaScript with tree-sitter.

tree-sitter always returns a tree, even for broken input, so this module is
where a failed parse is turned into an explicit error. Nothing here evaluates
the source.
"""

from __future__ import annotations

import bisect
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path

import tree_sitter_javascript
from tree_sitter import Language, Node, Parser, Tree

from js_forensics import config
from js_forensics.errors import InputError, JavaScriptSyntaxError
from js_forensics.models import SourceLocation, SyntaxIssue

PARSER_NAME = "tree-sitter-javascript"

_LANGUAGE = Language(tree_sitter_javascript.language())
_UTF8_BOM = b"\xef\xbb\xbf"
_UTF8_CONTINUATION_BYTE = re.compile(rb"[\x80-\xbf]")
_LINE_FEED = re.compile(rb"\n")
_WHITESPACE_RUN = re.compile(r"\s+")


# Node types the analyses look up. Only these are kept in memory; every other
# type is merely counted. Add a type here before querying it with ``of_type``.
INDEXED_TYPES = frozenset(
    {
        "array",
        "arrow_function",
        "assignment_expression",
        "augmented_assignment_expression",
        "binary_expression",
        "call_expression",
        "catch_clause",
        "class",
        "class_declaration",
        "for_in_statement",
        "for_statement",
        "formal_parameters",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "identifier",
        "import_clause",
        "import_specifier",
        "member_expression",
        "namespace_import",
        "new_expression",
        "number",
        "shorthand_property_identifier",
        "string",
        "subscript_expression",
        "template_string",
        "unary_expression",
        "update_expression",
        "variable_declarator",
        "while_statement",
    }
)


class SyntaxIndex:
    """Syntax nodes of the queried types, with O(1) parent lookup.

    ``Node.parent`` re-descends from the root on every call, which turns
    quadratic on the very deep trees that hostile input can produce. The index
    is built in one cursor walk and records parents as it goes.
    """

    def __init__(self, tree: Tree) -> None:
        self._by_type: defaultdict[str, list[Node]] = defaultdict(list)
        self._counts: Counter[str] = Counter()
        # Start offsets of expression statements, for "does this expression
        # begin a statement?" without walking up the tree.
        self.statement_starts: set[int] = set()
        self._parents: dict[int, Node] = {}
        self._fields: dict[int, str] = {}
        self.error_nodes: list[Node] = []
        self.named_node_count = 0
        self.max_block_depth = 0
        self.deepest_block: Node | None = None
        self.max_expression_depth = 0
        self.deepest_expression: Node | None = None
        self._walk(tree)

    def _walk(self, tree: Tree) -> None:
        cursor = tree.walk()
        ancestors: list[Node] = []
        # Tree depth at which each enclosing statement block starts; the
        # distance to the innermost one approximates expression nesting.
        block_depths: list[int] = [0]
        while True:
            node = cursor.node
            assert node is not None
            if node.is_missing or node.type == "ERROR":
                self.error_nodes.append(node)
            if node.is_named:
                node_type = node.type
                self.named_node_count += 1
                self._counts[node_type] += 1
                if node_type in INDEXED_TYPES:
                    self._by_type[node_type].append(node)
                    if ancestors:
                        self._parents[node.id] = ancestors[-1]
                    field_name = cursor.field_name
                    if field_name is not None:
                        self._fields[node.id] = field_name
                elif node_type == "expression_statement":
                    self.statement_starts.add(node.start_byte)
                expression_depth = len(ancestors) - block_depths[-1]
                if expression_depth > self.max_expression_depth:
                    self.max_expression_depth = expression_depth
                    self.deepest_expression = node

            if cursor.goto_first_child():
                ancestors.append(node)
                if node.type == "statement_block":
                    block_depths.append(len(ancestors))
                    if len(block_depths) - 1 > self.max_block_depth:
                        self.max_block_depth = len(block_depths) - 1
                        self.deepest_block = node
                continue
            while not cursor.goto_next_sibling():
                if not cursor.goto_parent():
                    return
                if ancestors.pop().type == "statement_block":
                    block_depths.pop()

    def of_type(self, *types: str) -> list[Node]:
        """Nodes of the given types in source order, outer nodes first."""
        unindexed = set(types) - INDEXED_TYPES
        if unindexed:
            raise KeyError(f"{sorted(unindexed)} must be added to INDEXED_TYPES to be queried")
        if len(types) == 1:
            return self._by_type.get(types[0], [])
        merged = [node for node_type in types for node in self._by_type.get(node_type, [])]
        merged.sort(key=lambda node: (node.start_byte, -node.end_byte))
        return merged

    def count(self, *types: str) -> int:
        """How many named nodes of these types exist (any type, indexed or not)."""
        return sum(self._counts[node_type] for node_type in types)

    def parent(self, node: Node) -> Node | None:
        """Parent of a node of an indexed type."""
        return self._parents.get(node.id)

    def field(self, node: Node) -> str | None:
        """The field name an indexed node has in its parent, such as ``left``."""
        return self._fields.get(node.id)


class ParsedSource:
    """Source bytes, their syntax tree, and helpers for describing nodes."""

    def __init__(self, source: bytes, path: str = "<memory>") -> None:
        self.source = source
        self.path = path
        self.tree = Parser(_LANGUAGE).parse(source)
        self.index = SyntaxIndex(self.tree)
        self._line_starts = [0, *(match.end() for match in _LINE_FEED.finditer(source))]
        # Byte offsets of UTF-8 continuation bytes, used to convert byte
        # columns to character columns. Empty for the common ASCII-only file.
        self._continuation_offsets = (
            []
            if source.isascii()
            else [match.start() for match in _UTF8_CONTINUATION_BYTE.finditer(source)]
        )

    @property
    def has_errors(self) -> bool:
        return bool(self.index.error_nodes)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.source).hexdigest()

    @property
    def line_count(self) -> int:
        if not self.source:
            return 0
        return self.source.count(b"\n") + (0 if self.source.endswith(b"\n") else 1)

    def text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8")

    def snippet(self, node: Node, limit: int = config.SNIPPET_LENGTH) -> str:
        """Single-line excerpt of a node's source for use as evidence."""
        # Decode a bounded slice so a huge node does not cost a huge copy.
        raw = self.source[node.start_byte : min(node.end_byte, node.start_byte + limit * 4)]
        collapsed = _WHITESPACE_RUN.sub(" ", raw.decode("utf-8", errors="ignore")).strip()
        if len(collapsed) > limit or node.end_byte - node.start_byte > len(raw):
            return collapsed[: limit - 1] + "…"
        return collapsed

    def location(self, node: Node) -> SourceLocation:
        line, column = self._line_and_column(node.start_byte)
        end_line, end_column = self._line_and_column(node.end_byte)
        return SourceLocation(line, column, end_line, end_column)

    def _line_and_column(self, byte_offset: int) -> tuple[int, int]:
        """1-based line and character column of a byte offset.

        Positions are derived from byte offsets rather than from
        ``Node.start_point``/``end_point``: in tree-sitter 0.26.0 repeated
        ``end_point`` access crashed the interpreter during development.
        """
        line_index = bisect.bisect_right(self._line_starts, byte_offset) - 1
        line_start = self._line_starts[line_index]
        column = byte_offset - line_start
        if self._continuation_offsets:
            column -= bisect.bisect_left(
                self._continuation_offsets, byte_offset
            ) - bisect.bisect_left(self._continuation_offsets, line_start)
        return line_index + 1, column + 1

    def syntax_issues(self, limit: int = config.MAX_SYNTAX_ERRORS_REPORTED) -> list[SyntaxIssue]:
        issues = []
        for node in self.index.error_nodes[:limit]:
            if node.is_missing:
                message = f"missing {node.type!r}"
            else:
                message = f"unexpected syntax near {self.snippet(node, 40)!r}"
            issues.append(SyntaxIssue(message=message, location=self.location(node)))
        return issues

    def require_valid(self) -> None:
        """Raise unless the source parsed without any error or missing node."""
        if self.has_errors:
            raise JavaScriptSyntaxError(
                self.path, self.syntax_issues(), total=len(self.index.error_nodes)
            )


def read_source(path: Path, max_bytes: int = config.DEFAULT_MAX_INPUT_BYTES) -> bytes:
    """Read a JavaScript file as UTF-8 bytes, enforcing the size limit."""
    try:
        if path.is_dir():
            raise InputError(f"{path} is a directory; pass a JavaScript file.")
        with path.open("rb") as handle:
            # Reading one byte past the limit detects oversized input without
            # trusting a stat() result that can change under us.
            source = handle.read(max_bytes + 1)
    except FileNotFoundError:
        raise InputError(f"{path} does not exist. Check the path and try again.") from None
    except OSError as error:
        raise InputError(f"{path} could not be read: {error.strerror or error}.") from None

    if len(source) > max_bytes:
        raise InputError(
            f"{path} is larger than the {max_bytes:,}-byte limit. "
            "Raise the limit with --max-bytes if you have the memory for it."
        )
    if source.startswith(_UTF8_BOM):
        source = source[len(_UTF8_BOM) :]
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InputError(
            f"{path} is not valid UTF-8 (byte offset {error.start}). "
            "Convert it first, for example with `iconv -t utf-8`."
        ) from None
    return source


def parse_file(
    path: Path,
    max_bytes: int = config.DEFAULT_MAX_INPUT_BYTES,
    *,
    tolerant: bool = False,
) -> ParsedSource:
    """Parse a file. Syntax errors raise unless ``tolerant`` is set."""
    parsed = ParsedSource(read_source(path, max_bytes), path=str(path))
    if not tolerant:
        parsed.require_valid()
    return parsed
