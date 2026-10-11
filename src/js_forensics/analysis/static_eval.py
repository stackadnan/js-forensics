"""Static evaluation of constant JavaScript expressions.

The evaluator computes the value of an expression only when the language
specification fixes that value regardless of runtime state. It never runs the
analyzed program: operators are reimplemented here for strings, numbers, and
booleans, and anything else raises ``Unresolvable`` with the reason.

Deliberately unsupported, because each needs coercion rules that are easy to
get subtly wrong: string-to-number conversion, boolean arithmetic, relational
comparison of strings, logical and conditional operators, arrays, objects.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from tree_sitter import Node

from js_forensics import config
from js_forensics.analysis import js_literals
from js_forensics.analysis.syntax import (
    call_arguments,
    dotted_name,
    string_literal_value,
    strip_global_object,
)
from js_forensics.parser import ParsedSource

StaticValue = str | float | bool

DECODER_BUILTINS = ("String.fromCharCode", "String.fromCodePoint", "atob")

_MAX_SAFE_INTEGER = 2**53 - 1
_PLACEHOLDER_SOURCE_LENGTH = 40


@dataclass(frozen=True, slots=True, eq=False)
class Failure:
    """Why an expression has no static value.

    This record, not the exception, is what gets cached per node: a stored
    exception would keep its traceback and every frame in it alive.
    """

    reason: str
    # Depth failures depend on where evaluation started, so they are not
    # cached against the inner nodes they pass through.
    depth_limited: bool = False
    # True when the expression depends on runtime state (a variable, a call).
    # False when every input is constant but the operation itself is outside
    # the supported subset, which is worth telling the user.
    is_dynamic: bool = False


class Unresolvable(Exception):
    """The expression has no value that can be determined statically."""

    def __init__(
        self,
        reason: str = "",
        *,
        depth_limited: bool = False,
        is_dynamic: bool = False,
        failure: Failure | None = None,
    ) -> None:
        self.failure = failure or Failure(reason, depth_limited, is_dynamic)
        super().__init__(self.failure.reason)

    @property
    def reason(self) -> str:
        return self.failure.reason

    @property
    def depth_limited(self) -> bool:
        return self.failure.depth_limited

    @property
    def is_dynamic(self) -> bool:
        return self.failure.is_dynamic


@dataclass(frozen=True, slots=True)
class PartialString:
    """A string whose unknown parts are written as ``${source}`` placeholders."""

    text: str
    is_complete: bool


def to_string(value: StaticValue) -> str:
    """ToString for the value types the evaluator produces."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return js_literals.number_to_string(value)
    return value


def to_source(value: StaticValue) -> str:
    """JavaScript source text for a value. Raises for negative zero, which
    has no literal that survives every surrounding context."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if value == 0 and math.copysign(1.0, value) < 0:
            raise Unresolvable("the result is negative zero, which has no literal form")
        return js_literals.number_to_string(value)
    return js_literals.quote_string(value)


def _require_finite(value: float) -> float:
    if not math.isfinite(value):
        raise Unresolvable("the result is Infinity or NaN, which has no literal form")
    return value


def _exponentiate(base: float, exponent: float) -> float:
    # Engines differ in the last bit of fractional powers, so only exact
    # integer results are folded.
    if not (base.is_integer() and exponent.is_integer() and 0 <= exponent <= 1024):
        raise Unresolvable("`**` is only folded for integer operands")
    result = int(base) ** int(exponent)
    if abs(result) > _MAX_SAFE_INTEGER:
        raise Unresolvable("the result of `**` is not exactly representable")
    return float(result)


def _apply_numeric(operator: str, left: float, right: float) -> StaticValue:
    if operator == "+":
        return _require_finite(left + right)
    if operator == "-":
        return _require_finite(left - right)
    if operator == "*":
        return _require_finite(left * right)
    if operator in ("/", "%"):
        if right == 0:
            raise Unresolvable(f"`{operator}` by zero yields Infinity or NaN")
        return _require_finite(left / right) if operator == "/" else math.fmod(left, right)
    if operator == "**":
        return _exponentiate(left, right)
    if operator == "&":
        return float(js_literals.to_int32(left) & js_literals.to_int32(right))
    if operator == "|":
        return float(js_literals.to_int32(left) | js_literals.to_int32(right))
    if operator == "^":
        return float(js_literals.to_int32(left) ^ js_literals.to_int32(right))
    shift = js_literals.to_uint32(right) & 31
    if operator == "<<":
        return float(js_literals.wrap_int32(js_literals.to_int32(left) << shift))
    if operator == ">>":
        return float(js_literals.to_int32(left) >> shift)
    if operator == ">>>":
        return float(js_literals.to_uint32(left) >> shift)
    if operator == "<":
        return left < right
    if operator == ">":
        return left > right
    if operator == "<=":
        return left <= right
    if operator == ">=":
        return left >= right
    raise Unresolvable(f"operator `{operator}` is not folded")


def apply_binary(operator: str, left: StaticValue, right: StaticValue) -> StaticValue:
    if operator in ("===", "==", "!==", "!="):
        # Loose and strict equality agree when both operands have the same
        # type, which is the only case handled.
        if type(left) is not type(right):
            raise Unresolvable(f"`{operator}` between different types is not folded")
        return (left == right) == operator.startswith("=")
    if isinstance(left, bool) or isinstance(right, bool):
        raise Unresolvable(f"`{operator}` with a boolean operand needs coercion")
    if isinstance(left, float) and isinstance(right, float):
        return _apply_numeric(operator, left, right)
    if operator == "+":
        joined = js_literals.combine_surrogates(to_string(left) + to_string(right))
        if len(joined) > config.MAX_STATIC_STRING_LENGTH:
            raise Unresolvable("the concatenated string exceeds the size limit")
        return joined
    raise Unresolvable(f"`{operator}` with a string operand needs coercion")


def apply_unary(operator: str, operand: StaticValue) -> StaticValue:
    if operator == "!":
        return not operand  # "", 0, and false are the falsy values in range
    if isinstance(operand, float):
        if operator == "-":
            return -operand
        if operator == "+":
            return operand
        if operator == "~":
            return float(~js_literals.to_int32(operand))
    raise Unresolvable(f"unary `{operator}` is not folded for this operand")


def _describe(node: Node, parsed: ParsedSource) -> str:
    if node.type == "identifier":
        return f"`{parsed.text(node)}` is a variable whose value is not tracked"
    return f"{node.type.replace('_', ' ')} is not a static value"


def _operator(node: Node, parsed: ParsedSource) -> str:
    operator = node.child_by_field_name("operator")
    return parsed.text(operator) if operator is not None else ""


class StaticEvaluator:
    """Evaluates expression nodes of one parsed file, caching per node.

    ``resolve_decoders`` additionally resolves calls to the decoder built-ins
    listed in ``DECODER_BUILTINS``. Those are only trusted when the file never
    declares or assigns the names involved (``rebound_names``).
    """

    def __init__(
        self,
        parsed: ParsedSource,
        *,
        resolve_decoders: bool = False,
        rebound_names: frozenset[str] = frozenset(),
    ) -> None:
        self._parsed = parsed
        self._resolve_decoders = resolve_decoders
        self._rebound_names = rebound_names
        self._uses_with = bool(parsed.index.count("with_statement"))
        self._cache: dict[int, StaticValue | Failure] = {}

    def evaluate(self, node: Node) -> StaticValue:
        """Value of ``node``; raises ``Unresolvable`` with the reason."""
        return self._evaluate(node, 0)

    def try_evaluate(self, node: Node) -> StaticValue | None:
        try:
            return self.evaluate(node)
        except Unresolvable:
            return None

    def _evaluate(self, node: Node, depth: int) -> StaticValue:
        cached = self._cache.get(node.id)
        if cached is not None:
            if isinstance(cached, Failure):
                raise Unresolvable(failure=cached)
            return cached
        if depth > config.MAX_EVALUATION_DEPTH:
            raise Unresolvable("the expression is nested too deeply", depth_limited=True)
        try:
            value = self._evaluate_uncached(node, depth)
        except Unresolvable as failure:
            if not failure.depth_limited or depth == 0:
                self._cache[node.id] = failure.failure
            raise
        self._cache[node.id] = value
        return value

    def _evaluate_uncached(self, node: Node, depth: int) -> StaticValue:
        parsed = self._parsed
        if node.type == "string":
            value = string_literal_value(parsed, node)
            if value is None:
                raise Unresolvable("the string literal contains an invalid escape sequence")
            return value
        if node.type == "number":
            number = js_literals.parse_number_literal(parsed.text(node))
            if number is None:
                raise Unresolvable(f"numeric literal `{parsed.snippet(node, 30)}` is not folded")
            return number
        if node.type in ("true", "false"):
            return node.type == "true"
        if node.type == "parenthesized_expression" and node.named_child_count == 1:
            inner = node.named_children[0]
            return self._evaluate(inner, depth + 1)
        if node.type == "unary_expression":
            argument = node.child_by_field_name("argument")
            if argument is None:
                raise Unresolvable("malformed unary expression")
            return apply_unary(_operator(node, parsed), self._evaluate(argument, depth + 1))
        if node.type == "binary_expression":
            return self._evaluate_binary(node, depth)
        if node.type == "template_string":
            partial = self._template_string(node, depth)
            if not partial.is_complete:
                raise Unresolvable(
                    "the template literal has a substitution that is not static", is_dynamic=True
                )
            return partial.text
        if node.type == "call_expression" and self._resolve_decoders:
            return self._evaluate_decoder_call(node, depth)
        raise Unresolvable(_describe(node, parsed), is_dynamic=True)

    def _evaluate_binary(self, node: Node, depth: int) -> StaticValue:
        """Evaluate a left-nested operator chain without recursing down it.

        ``a + b + c + ...`` parses as a tree as deep as the chain is long, and
        obfuscated files contain chains of thousands of operands. Only the
        value of the whole chain is cached: keeping every intermediate string
        of a long concatenation would take quadratic memory, and for the same
        reason string pieces are collected and joined once.
        """
        chain: list[Node] = []
        current = node
        while current.type == "binary_expression" and current.id not in self._cache:
            chain.append(current)
            left = current.child_by_field_name("left")
            if left is None:
                raise Unresolvable("malformed binary expression")
            current = left

        # ``chain`` runs from the outermost operator to the innermost, so
        # operators are applied from its end.
        pending = chain
        pieces: list[str] | None = None  # an unjoined string value, when set
        length = 0
        try:
            value = self._evaluate(current, depth + 1)
            while pending:
                binary = pending[-1]
                right_node = binary.child_by_field_name("right")
                if right_node is None:
                    raise Unresolvable("malformed binary expression")
                right = self._evaluate(right_node, depth + 1)
                operator = _operator(binary, self._parsed)
                is_string = pieces is not None or isinstance(value, str)
                if operator == "+" and is_string and not isinstance(right, bool):
                    if pieces is None:
                        assert isinstance(value, str)
                        pieces, length = [value], len(value)
                    piece = to_string(right)
                    pieces.append(piece)
                    length += len(piece)
                    if length > config.MAX_STATIC_STRING_LENGTH:
                        raise Unresolvable("the concatenated string exceeds the size limit")
                else:
                    if pieces is not None:
                        value, pieces = js_literals.combine_surrogates("".join(pieces)), None
                    value = apply_binary(operator, value, right)
                pending.pop()
        except Unresolvable as failure:
            # Every operator above the failing one depends on it.
            if not failure.depth_limited:
                for binary in pending:
                    self._cache[binary.id] = failure.failure
            raise
        if pieces is not None:
            value = js_literals.combine_surrogates("".join(pieces))
        return value

    def decoder_name(self, call: Node) -> str | None:
        """Which decoder built-in a call targets, if any."""
        callee = call.child_by_field_name("function")
        if callee is None:
            return None
        names = dotted_name(self._parsed, callee)
        if names is None:
            return None
        name = ".".join(strip_global_object(names))
        return name if name in DECODER_BUILTINS else None

    def _evaluate_decoder_call(self, call: Node, depth: int) -> StaticValue:
        name = self.decoder_name(call)
        if name is None:
            raise Unresolvable(_describe(call, self._parsed), is_dynamic=True)
        callee = call.child_by_field_name("function")
        assert callee is not None
        for used_name in dotted_name(self._parsed, callee) or []:
            if used_name in self._rebound_names:
                raise Unresolvable(
                    f"`{used_name}` is declared or assigned in this file, "
                    "so it may not be the built-in"
                )
        if self._uses_with:
            raise Unresolvable("the file uses `with`, which can rebind any name")
        arguments = call_arguments(call)
        if arguments is None:
            raise Unresolvable("the arguments are not a plain list")
        values = []
        for position, argument in enumerate(arguments, start=1):
            try:
                values.append(self._evaluate(argument, depth + 1))
            except Unresolvable as failure:
                raise Unresolvable(
                    f"argument {position} is not static: {failure.reason}",
                    depth_limited=failure.depth_limited,
                    is_dynamic=failure.is_dynamic,
                ) from None
        return _call_decoder(name, values)

    def _template_string(self, node: Node, depth: int) -> PartialString:
        parsed = self._parsed
        parts = []
        is_complete = True
        for child in node.named_children:
            if child.type == "template_substitution":
                inner = child.named_children[0] if child.named_child_count == 1 else None
                try:
                    if inner is None:
                        raise Unresolvable("empty or compound substitution")
                    parts.append(to_string(self._evaluate(inner, depth + 1)))
                except Unresolvable:
                    is_complete = False
                    source = parsed.snippet(inner or child, _PLACEHOLDER_SOURCE_LENGTH)
                    parts.append("${" + source + "}" if inner is not None else source)
            elif child.type == "escape_sequence":
                try:
                    parts.append(js_literals.decode_string_body(parsed.text(child)))
                except js_literals.InvalidEscape:
                    raise Unresolvable("the template literal has an invalid escape") from None
            else:
                # Raw line endings in a template are normalised to LF.
                parts.append(parsed.text(child).replace("\r\n", "\n").replace("\r", "\n"))
        return PartialString(js_literals.combine_surrogates("".join(parts)), is_complete)

    def partial_string(self, node: Node) -> PartialString | None:
        """Best-effort string for URL-like expressions.

        Fully static expressions give a complete string. Concatenations and
        templates with unknown parts give a string with ``${source}``
        placeholders, provided at least one part is a static string; otherwise
        the result is None.
        """
        try:
            value = self.evaluate(node)
        except Unresolvable:
            pass
        else:
            return PartialString(value, True) if isinstance(value, str) else None

        if node.type == "template_string":
            try:
                partial = self._template_string(node, 0)
            except Unresolvable:
                return None
            has_static_text = any(child.type == "string_fragment" for child in node.named_children)
            return partial if has_static_text else None
        if node.type == "binary_expression" and _operator(node, self._parsed) == "+":
            return self._partial_concatenation(node)
        return None

    def _partial_concatenation(self, node: Node) -> PartialString | None:
        parsed = self._parsed
        operands: list[Node] = []
        # prefixes[i] is the expression made of everything before operands[i].
        prefixes: list[Node | None] = []
        current = node
        while current.type == "binary_expression" and _operator(current, parsed) == "+":
            left = current.child_by_field_name("left")
            right = current.child_by_field_name("right")
            if left is None or right is None:
                return None
            operands.append(right)
            prefixes.append(left)
            current = left
        operands.append(current)
        prefixes.append(None)
        operands.reverse()
        prefixes.reverse()

        values = [self.try_evaluate(operand) for operand in operands]
        first_string = next(
            (position for position, value in enumerate(values) if isinstance(value, str)), None
        )
        if first_string is None:
            return None

        # Operands before the first string are added together as whatever
        # types they turn out to be, so they form a single unknown unless the
        # exact prefix expression is itself static.
        text = ""
        is_complete = True
        if first_string > 0:
            prefix_expression = prefixes[first_string]
            assert prefix_expression is not None
            prefix = self.try_evaluate(prefix_expression)
            if prefix is None:
                is_complete = False
                source = parsed.snippet(prefix_expression, _PLACEHOLDER_SOURCE_LENGTH)
                text = "${" + source + "}"
            else:
                text = to_string(prefix)
        for operand, value in zip(operands[first_string:], values[first_string:], strict=True):
            if value is None:
                is_complete = False
                text += "${" + parsed.snippet(operand, _PLACEHOLDER_SOURCE_LENGTH) + "}"
            else:
                text += to_string(value)
        return PartialString(js_literals.combine_surrogates(text), is_complete)


def _call_decoder(name: str, arguments: list[StaticValue]) -> str:
    if name == "atob":
        if len(arguments) != 1 or not isinstance(arguments[0], str):
            raise Unresolvable("`atob` is only resolved for a single string argument")
        try:
            return js_literals.atob(arguments[0])
        except ValueError as error:
            raise Unresolvable(f"`atob` would throw: {error}") from None

    code_points = []
    for value in arguments:
        if not isinstance(value, float) or isinstance(value, bool):
            raise Unresolvable(f"`{name}` is only resolved for numeric arguments")
        code_points.append(value)
    if name == "String.fromCharCode":
        # ToUint16: truncate, then wrap modulo 2**16.
        return js_literals.combine_surrogates(
            "".join(chr(int(value) & 0xFFFF) for value in code_points)
        )
    for value in code_points:
        if not value.is_integer() or not 0 <= value <= 0x10FFFF:
            raise Unresolvable("`String.fromCodePoint` would throw a RangeError")
    return js_literals.combine_surrogates("".join(chr(int(value)) for value in code_points))
