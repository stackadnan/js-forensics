from js_forensics.analysis.identifiers import analyze_identifiers, collect_bindings

from .conftest import parse, parse_fixture


def test_declaration_kinds():
    bindings = collect_bindings(
        parse(
            """
            var a = 1; let b = 2; const c = 3;
            function d(e, {f, g: h} = {}, ...i) {}
            class J {}
            const k = (l) => l, m = n => n;
            try {} catch (o) {}
            import p, * as q from "x"; import { r, s as t } from "y";
            for (const u of list) {}
            var [v, w = 1] = pair, {x: {y}} = nested;
            """
        )
    )
    kinds = {name: sites[0][0] for name, sites in bindings.declarations.items()}
    assert kinds == {
        "a": "var", "b": "let", "c": "const", "d": "function", "e": "parameter",
        "f": "parameter", "h": "parameter", "i": "parameter", "J": "class", "k": "const",
        "l": "parameter", "m": "const", "n": "parameter", "o": "catch-parameter",
        "p": "import", "q": "import", "r": "import", "t": "import", "u": "const",
        "v": "var", "w": "var", "y": "var",
    }  # fmt: skip


def test_reference_counts_exclude_declarations_and_properties():
    bindings = collect_bindings(parse("var count = 0; count++; use(count, obj.count, {count});"))
    assert len(bindings.declarations["count"]) == 1
    # count++, use(count, ...), and the shorthand {count}; obj.count is a property.
    assert bindings.reference_counts["count"] == 3


def test_assigned_names_are_tracked_for_shadowing_checks():
    bindings = collect_bindings(parse("atob = fake; total += 1; index++; for (key in o) {}"))
    assert bindings.assigned_names == {"atob", "total", "index", "key"}
    assert {"atob", "key"} <= bindings.rebound_names


def test_hex_style_names_are_reported_with_evidence():
    parsed = parse_fixture("string_array.js")
    report = analyze_identifiers(parsed, collect_bindings(parsed))
    assert report.hex_style_names == 9
    assert report.declared_names == 9
    assert not report.findings_truncated
    accessor = next(finding for finding in report.findings if finding.name == "_0x5e1b")
    assert accessor.declared_as == ["var"]
    assert accessor.declaration_count == 1
    assert accessor.reference_count == 12
    assert accessor.location.line == 10
    # Sorted by how often the name is referenced.
    assert report.findings[0].name == "_0x5e1b"


def test_readable_code_has_no_hex_style_names():
    parsed = parse_fixture("readable.js")
    report = analyze_identifiers(parsed, collect_bindings(parsed))
    assert report.hex_style_names == 0
    assert report.findings == []
    assert report.short_names == 0
    assert report.average_name_length > 4


def test_short_names_are_counted():
    parsed = parse("var a, bc, def; function f(x) {}")
    report = analyze_identifiers(parsed, collect_bindings(parsed))
    assert report.short_names == 4  # a, bc, f, x
    assert report.declared_names == 5
