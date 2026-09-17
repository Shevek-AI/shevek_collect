from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

import shevek_collect.parsing.tree_sitter_parser as parser_module
from shevek_collect.parsing.tree_sitter_parser import TreeSitterUnavailable, parse_source
from shevek_collect.syntax_extract import (
    SyntaxTraversalLimit,
    _julia_call_details,
    _julia_parameter_details,
    _scopes_from_tree,
    _symbols_from_tree,
    _walk,
    extract_syntax,
)


@pytest.mark.parametrize(
    ("path", "content", "expected_symbol"),
    [
        ("app.py", "class A:\n    def f(self, x):\n        return x\n", ("method", "f")),
        ("app.js", "export function f(x) { return g(x); }", ("function", "f")),
        ("app.ts", "export function f(x: number): number { return x + 1; }", ("function", "f")),
        ("app.tsx", "export const App = () => <div/>;", ("arrow_function", "App")),
        ("App.java", "class App { void run(int x) { System.out.println(x); } }", ("method", "run")),
        ("App.cs", "class App { void Run(int x) { Console.WriteLine(x); } }", ("method", "Run")),
        ("app.jl", "module Demo\nf(x::Int) = x\nend\n", ("method", "f")),
    ],
)
def test_extract_syntax_supported_languages(
    path: str,
    content: str,
    expected_symbol: tuple[str, str],
) -> None:
    result = extract_syntax(path, content)

    assert result["parse"]["status"] == "parsed"
    symbols = result["syntax"]["symbols"]
    assert expected_symbol in {(item["kind"], item["name"]) for item in symbols}


def test_extract_syntax_css_structure() -> None:
    result = extract_syntax(
        "app.css",
        ":root { --spacing: 1rem; } .card { color: red; } @media (max-width: 10px) { .x { display: none; } }",
    )

    assert result["parse"]["status"] == "parsed"
    kinds = {item["kind"] for item in result["syntax"]["styles"]}
    assert {"css_rule", "css_variable", "media_query"} <= kinds


def test_malformed_source_reports_parse_errors() -> None:
    result = extract_syntax("broken.py", "def broken(:\n    return 1\n")

    assert result["parse"]["status"] == "parsed_with_errors"
    assert result["parse"]["has_error_nodes"] is True
    assert result["parse"]["error_node_count"] + result["parse"]["missing_node_count"] > 0


def test_unsupported_extension_is_explicit() -> None:
    result = extract_syntax("README.adoc", "= title")

    assert result["parse"]["status"] == "unsupported_language"
    assert result["syntax"] == {
        "schema_version": "shevek.syntax_observations.v2",
        "symbols": [],
        "imports": [],
        "call_sites": [],
        "references": [],
        "scopes": [],
        "exports": [],
        "publics": [],
        "includes": [],
        "styles": [],
        "style_imports": [],
    }


def test_surrogate_content_is_replaced_without_crashing() -> None:
    result = extract_syntax("app.py", "value = '\ud800'\n")

    assert result["parse"]["status"] in {"parsed", "parsed_with_errors"}


def test_extraction_is_deterministic() -> None:
    content = "import os\n\ndef f(x):\n    return os.path.join('a', x)\n"

    assert extract_syntax("app.py", content) == extract_syntax("app.py", content)


@dataclass
class FakeNode:
    type: str = "module"
    children: list[Any] = field(default_factory=list)
    start_byte: int = 0
    end_byte: int = 0
    start_point: tuple[int, int] = (0, 0)
    end_point: tuple[int, int] = (0, 0)
    is_missing: bool = False
    is_named: bool = True
    fields: dict[str, Any] = field(default_factory=dict)

    @property
    def named_children(self) -> list[Any]:
        return self.children

    def child_by_field_name(self, name: str) -> Any | None:
        return self.fields.get(name)


def _deep_tree(depth: int) -> FakeNode:
    root = FakeNode()
    node = root
    for _ in range(depth):
        child = FakeNode()
        node.children.append(child)
        node = child
    return root


def test_walk_handles_deep_ast_without_python_recursion() -> None:
    root = _deep_tree(5_000)

    assert sum(1 for _ in _walk(root)) == 5_001
    assert _symbols_from_tree(root, b"", "python", "deep.py", []) == []


def test_walk_enforces_explicit_node_budget() -> None:
    root = _deep_tree(20)

    with pytest.raises(SyntaxTraversalLimit, match="10 node traversal limit"):
        list(_walk(root, max_nodes=10))


def test_parser_unavailable_preserves_known_language() -> None:
    from shevek_collect.syntax_extract import parser_unavailable_result

    result = parser_unavailable_result(
        "src/App.cs", TreeSitterUnavailable("missing grammar")
    )

    assert result["language"] == "csharp"
    assert result["parse"]["status"] == "parser_unavailable"
    assert result["syntax"]["schema_version"] == "shevek.syntax_observations.v2"


def test_missing_grammar_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    original = parser_module.LANGUAGE_FACTORIES["python"]
    monkeypatch.setitem(
        parser_module.LANGUAGE_FACTORIES,
        "python",
        lambda: (_ for _ in ()).throw(ImportError("missing grammar")),
    )
    try:
        with pytest.raises(TreeSitterUnavailable, match="grammar is not available"):
            parse_source("app.py", "x = 1\n")
    finally:
        monkeypatch.setitem(parser_module.LANGUAGE_FACTORIES, "python", original)


def _fake_span(source: str, node_type: str, text: str, *, start: int = 0, children=None, fields=None) -> FakeNode:
    begin = source.index(text, start)
    end = begin + len(text)
    start_line = source[:begin].count("\n")
    end_line = source[:end].count("\n")
    return FakeNode(
        type=node_type,
        children=list(children or []),
        start_byte=begin,
        end_byte=end,
        start_point=(start_line, 0),
        end_point=(end_line, 0),
        fields=dict(fields or {}),
    )


def test_julia_method_metadata_groups_multiple_dispatch_methods() -> None:
    source_text = (
        "module Demo\n"
        "area(x::Int; scale=1) = scale*x\n"
        "area(x::Float64) = x\n"
        "end\n"
    )
    source = source_text.encode()
    module_name = _fake_span(source_text, "identifier", "Demo")

    left_one = _fake_span(source_text, "call_expression", "area(x::Int; scale=1)")
    left_one.children = [
        _fake_span(source_text, "identifier", "area"),
        _fake_span(source_text, "argument_list", "(x::Int; scale=1)"),
    ]
    right_one = _fake_span(source_text, "identifier", "scale*x")
    assignment_one = _fake_span(
        source_text,
        "assignment",
        "area(x::Int; scale=1) = scale*x",
        children=[left_one, right_one],
        fields={"left": left_one, "right": right_one},
    )

    second_start = source_text.index("area(x::Float64)")
    left_two = _fake_span(
        source_text, "call_expression", "area(x::Float64)", start=second_start
    )
    left_two.children = [
        _fake_span(source_text, "identifier", "area", start=second_start),
        _fake_span(source_text, "argument_list", "(x::Float64)", start=second_start),
    ]
    right_two = _fake_span(source_text, "identifier", "x", start=source_text.index(" = x", second_start))
    assignment_two = _fake_span(
        source_text,
        "assignment",
        "area(x::Float64) = x",
        start=second_start,
        children=[left_two, right_two],
        fields={"left": left_two, "right": right_two},
    )
    module = _fake_span(
        source_text,
        "module_definition",
        source_text.rstrip(),
        children=[module_name, assignment_one, assignment_two],
        fields={"name": module_name},
    )
    root = FakeNode(
        type="source_file",
        children=[module],
        start_byte=0,
        end_byte=len(source),
        end_point=(source_text.count("\n"), 0),
    )

    symbols = _symbols_from_tree(root, source, "julia", "src/demo.jl", [])
    methods = [symbol for symbol in symbols if symbol["kind"] == "method"]

    assert len(methods) == 2
    assert {method["qualname"] for method in methods} == {"Demo.area"}
    assert len({method["symbol_id"] for method in methods}) == 2
    assert {method["declaration_group_id"] for method in methods} == {
        "julia:function:Demo.area"
    }
    first = next(method for method in methods if "scale" in method["signature"])
    assert first["language_details"]["min_positional_arity"] == 1
    assert first["language_details"]["max_positional_arity"] == 1
    assert first["language_details"]["keyword_names"] == ["scale"]


def test_julia_call_shape_and_parameter_shape_are_conservative() -> None:
    details = _julia_parameter_details("(x::Int, y=1, rest...; scale=1, kwargs...)")
    assert details["min_positional_arity"] == 1
    assert details["max_positional_arity"] is None
    assert details["keyword_names"] == ["scale", "kwargs"]
    assert details["required_keyword_names"] == []
    assert details["accepts_keyword_splat"] is True

    required = _julia_parameter_details("(x; mode, kwargs...)")
    assert required["required_keyword_names"] == ["mode"]

    source_text = "area(1; scale=2)"
    name = _fake_span(source_text, "identifier", "area")
    arguments = _fake_span(source_text, "argument_list", "(1; scale=2)")
    call = _fake_span(
        source_text,
        "call_expression",
        source_text,
        children=[name, arguments],
        fields={"arguments": arguments},
    )
    call_details = _julia_call_details(call, source_text.encode())
    assert call_details["positional_argument_count"] == 1
    assert call_details["keyword_names"] == ["scale"]


def test_julia_scope_records_top_level_soft_scope_shadowing() -> None:
    source_text = "x = 0\nfor i in 1:3\n    x += i\nend\n"
    source = source_text.encode()
    global_name = _fake_span(source_text, "identifier", "x")
    global_assignment = _fake_span(
        source_text,
        "assignment",
        "x = 0",
        children=[global_name],
        fields={"left": global_name},
    )
    loop_start = source_text.index("x += i")
    loop_name = _fake_span(source_text, "identifier", "x", start=loop_start)
    update = _fake_span(
        source_text,
        "compound_assignment_expression",
        "x += i",
        start=loop_start,
        children=[loop_name],
        fields={"left": loop_name},
    )
    loop = _fake_span(
        source_text,
        "for_statement",
        "for i in 1:3\n    x += i\nend",
        children=[update],
    )
    root = FakeNode(
        type="source_file",
        children=[global_assignment, loop],
        start_byte=0,
        end_byte=len(source),
        end_point=(source_text.count("\n"), 0),
    )

    scopes = _scopes_from_tree(root, source, "julia", "src/demo.jl")
    soft = next(scope for scope in scopes if scope["scope_class"] == "soft")
    assert soft["ambiguous_global_assignments"] == ["x"]


def test_julia_global_binding_extraction_skips_local_scope_assignments() -> None:
    source_text = 'const VOCAB = ["a"]\nfor i in 1:2\n    temp = i\nend\n'
    source = source_text.encode()

    vocab_name = _fake_span(source_text, "identifier", "VOCAB")
    vocab_value = _fake_span(source_text, "vector_expression", '["a"]')
    vocab_assignment = _fake_span(
        source_text,
        "assignment",
        'VOCAB = ["a"]',
        children=[vocab_name, vocab_value],
        fields={"left": vocab_name, "right": vocab_value},
    )
    const_node = _fake_span(
        source_text,
        "const_statement",
        'const VOCAB = ["a"]',
        children=[vocab_assignment],
    )

    temp_name = _fake_span(source_text, "identifier", "temp")
    temp_value = _fake_span(source_text, "identifier", "i", start=source_text.index("temp"))
    temp_assignment = _fake_span(
        source_text,
        "assignment",
        "temp = i",
        children=[temp_name, temp_value],
        fields={"left": temp_name, "right": temp_value},
    )
    loop = _fake_span(
        source_text,
        "for_statement",
        "for i in 1:2\n    temp = i\nend",
        children=[temp_assignment],
    )
    root = FakeNode(
        type="source_file",
        children=[const_node, loop],
        start_byte=0,
        end_byte=len(source),
        end_point=(source_text.count("\n"), 0),
    )

    symbols = _symbols_from_tree(root, source, "julia", "src/syntax.jl", [])

    assert [(symbol["kind"], symbol["name"]) for symbol in symbols] == [
        ("constant", "VOCAB")
    ]


def test_structure_mode_sanitizer_removes_literal_bearing_syntax_fields() -> None:
    from shevek_collect.syntax_extract import sanitize_syntax_for_structure_mode

    syntax = {
        "symbols": [
            {
                "kind": "method",
                "name": "configure",
                "qualname": "Demo.configure",
                "signature": (
                    'configure(x::Val{:PRIVATE_TYPE_LITERAL} = "PRIVATE_DEFAULT"; '
                    'mode = "PRIVATE_MODE")'
                ),
                "parameters_text": (
                    '(x::Val{:PRIVATE_TYPE_LITERAL} = "PRIVATE_DEFAULT"; '
                    'mode = "PRIVATE_MODE")'
                ),
                "inputs": ["x"],
                "language_details": {
                    "keyword_names": ["mode"],
                    "positional_parameter_types": ["Val{:PRIVATE_TYPE_LITERAL}"],
                },
            }
        ],
        "imports": [
            {"target": "Demo.Tools", "raw_text": "using Demo.Tools: private_helper"}
        ],
        "includes": [
            {"target": "support.jl", "raw_text": 'include("PRIVATE_INCLUDE_LITERAL")'}
        ],
    }

    sanitize_syntax_for_structure_mode(syntax)

    rendered = json.dumps(syntax, sort_keys=True)
    assert "PRIVATE_DEFAULT" not in rendered
    assert "PRIVATE_MODE" not in rendered
    assert "PRIVATE_TYPE_LITERAL" not in rendered
    assert "PRIVATE_INCLUDE_LITERAL" not in rendered
    symbol = syntax["symbols"][0]
    assert symbol["signature"] == "method configure(x; mode)"
    assert symbol["parameters_text"] is None
    assert "positional_parameter_types" not in symbol["language_details"]
    assert "raw_text" not in syntax["imports"][0]
    assert "raw_text" not in syntax["includes"][0]


def test_cpp_source_extensions_are_first_class() -> None:
    from shevek_collect.parsing.languages import language_for_path, language_label

    for path in (
        "src/engine.cpp",
        "src/engine.cc",
        "src/engine.cxx",
        "include/engine.hpp",
        "include/engine.hh",
        "include/engine.hxx",
        "include/engine.h",
    ):
        assert language_for_path(path) == "cpp"
    assert language_label("cpp") == "cpp"
    assert language_for_path("src/legacy.c") is None


def test_cpp_extracts_namespaces_types_functions_calls_and_includes() -> None:
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")

    result = extract_syntax(
        "src/engine.cpp",
        r'''#include <vector>
#include "engine.hpp"
namespace widget::core {
class Engine {
public:
    int run(int value) { return helper(value); }
    int tick(int value);
};
int helper(int value) { return value + 1; }
int Engine::tick(int value) { return helper(value); }
}
''',
    )

    assert result["language"] == "cpp"
    assert result["parse"]["status"] == "parsed"
    symbols = result["syntax"]["symbols"]
    by_qual = {str(item["qualname"]): item for item in symbols}
    assert "widget.core.Engine" in by_qual
    assert "widget.core.Engine.run" in by_qual
    assert "widget.core.helper" in by_qual
    assert "widget.core.Engine.tick" in by_qual
    assert "helper" in {str(call["callee"]) for call in by_qual["widget.core.Engine.run"]["raw_calls"]}
    assert {item["target"] for item in result["syntax"]["includes"]} == {"vector", "engine.hpp"}
    assert {item["target"] for item in result["syntax"]["imports"]} == {"vector", "engine.hpp"}


def test_cpp_name_normalization_handles_templates_and_member_access() -> None:
    from shevek_collect.syntax_extract import _cpp_normalize_qualified

    assert _cpp_normalize_qualified("widget::Engine::run<std::vector<int>>") == "widget.Engine.run"
    assert _cpp_normalize_qualified("this->run") == "this.run"
