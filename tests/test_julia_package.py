from __future__ import annotations

from shevek_collect.julia_package import compose_julia_snapshot, extract_project_toml


def _call(source: str, text: str, callee: str) -> dict[str, object]:
    start = source.index(text)
    end = start + len(text)
    return {
        "callee": callee,
        "kind": "call_expression",
        "start_byte": start,
        "end_byte": end,
        "start_line": source[:start].count("\n") + 1,
        "end_line": source[:end].count("\n") + 1,
        "positional_argument_count": 1,
        "keyword_names": [],
        "has_positional_splat": False,
        "has_keyword_splat": False,
        "is_macro_call": False,
        "containing_symbol": None,
        "containing_symbol_id": None,
    }


def _method(path: str, name: str, source: str) -> dict[str, object]:
    start = source.index(name)
    return {
        "symbol_id": f"{path}::{name}@1:{start}",
        "kind": "method",
        "name": name,
        "qualname": name,
        "signature": f"{name}(x)",
        "parameters_text": "(x)",
        "inputs": ["x"],
        "imports": [],
        "raw_calls": [],
        "declaration_group_id": f"julia:function:{name}",
        "is_exported": False,
        "language_details": {
            "declaring_module": None,
            "generic_function_name": name,
            "min_positional_arity": 1,
            "max_positional_arity": 1,
            "keyword_names": [],
            "required_keyword_names": [],
            "accepts_keyword_splat": False,
        },
        "start_byte": start,
        "end_byte": len(source),
        "start_line": 1,
        "end_line": source.count("\n") + 1,
    }


def _record(path: str, syntax: dict[str, object], *, language: str = "julia") -> dict[str, object]:
    return {
        "path": path,
        "language": language,
        "parse": {"status": "parsed"},
        "syntax": syntax,
    }


def _syntax(
    *,
    symbols: list[dict[str, object]] | None = None,
    calls: list[dict[str, object]] | None = None,
    imports: list[dict[str, object]] | None = None,
    exports: list[str] | None = None,
    scopes: list[dict[str, object]] | None = None,
    package: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "symbols": symbols or [],
        "imports": imports or [],
        "call_sites": calls or [],
        "scopes": scopes or [],
        "styles": [],
        "style_imports": [],
        "exports": exports or [],
        "publics": [],
        "includes": [],
        **({"package": package} if package is not None else {}),
    }


def test_extract_project_toml_preserves_package_contract() -> None:
    result = extract_project_toml(
        "Project.toml",
        """
name = "Demo"
uuid = "00000000-0000-0000-0000-000000000000"
version = "0.1.0"
authors = ["Private Person <private@example.com>"]

[deps]
Lux = "11111111-1111-1111-1111-111111111111"

[compat]
julia = "1.10"
""".strip(),
    )

    assert result["language"] == "toml"
    assert result["parse"]["status"] == "parsed"
    package = result["syntax"]["package"]
    assert package["name"] == "Demo"
    assert "authors" not in package
    assert package["deps"] == {"Lux": "11111111-1111-1111-1111-111111111111"}
    assert package["compat"] == {"julia": "1.10"}


def test_compose_julia_package_resolves_includes_exports_and_top_level_workflows() -> None:
    entry = (
        "module Demo\n"
        "using Lux\n"
        "export VOCAB, train!\n"
        "include(\"syntax.jl\")\n"
        "include(\"training.jl\")\n"
        "end\n"
    )
    syntax_source = "const VOCAB = [\"a\", \"b\"]\n"
    training_source = "train!(model) = model\ninitialise()\n"
    experiment_source = "using Demo\nmodel = TinyModel()\ntrain!(model)\n"

    module_end = len(entry)
    module_symbol = {
        "symbol_id": "src/Demo.jl::Demo",
        "kind": "module",
        "name": "Demo",
        "qualname": "Demo",
        "signature": "module Demo",
        "parameters_text": None,
        "inputs": [],
        "imports": ["Lux"],
        "raw_calls": [],
        "declaration_group_id": None,
        "is_exported": False,
        "language_details": {"declaring_module": None, "is_public": False},
        "start_byte": 0,
        "end_byte": module_end,
        "start_line": 1,
        "end_line": entry.count("\n") + 1,
    }
    project = _record(
        "Project.toml",
        _syntax(package={"name": "Demo", "project_path": "Project.toml"}),
        language="toml",
    )
    records = [
        project,
        _record(
            "src/Demo.jl",
            _syntax(
                symbols=[module_symbol],
                calls=[
                    _call(entry, 'include("syntax.jl")', "include"),
                    _call(entry, 'include("training.jl")', "include"),
                ],
                imports=[{"target": "Lux"}],
                exports=["VOCAB", "train!"],
            ),
        ),
        _record("src/syntax.jl", _syntax()),
        _record(
            "src/training.jl",
            _syntax(
                symbols=[_method("src/training.jl", "train!", training_source)],
                calls=[_call(training_source, "initialise()", "initialise")],
                scopes=[
                    {
                        "scope_id": "src/training.jl::scope:source",
                        "parent_scope_id": None,
                        "kind": "source_file",
                        "scope_class": "global",
                        "bindings": ["train!"],
                        "assignments": [],
                        "declarations": ["train!"],
                        "explicit_globals": [],
                        "explicit_locals": [],
                        "ambiguous_global_assignments": [],
                        "start_byte": 0,
                        "end_byte": len(training_source),
                        "start_line": 1,
                        "end_line": 2,
                    }
                ],
            ),
        ),
        _record(
            "experiment.jl",
            _syntax(
                calls=[
                    _call(experiment_source, "TinyModel()", "TinyModel"),
                    _call(experiment_source, "train!(model)", "train!"),
                ],
                imports=[{"target": "Demo"}],
            ),
        ),
    ]
    contents = {
        "Project.toml": 'name = "Demo"\n',
        "src/Demo.jl": entry,
        "src/syntax.jl": syntax_source,
        "src/training.jl": training_source,
        "experiment.jl": experiment_source,
    }

    compose_julia_snapshot(records, contents)
    by_path = {str(record["path"]): record for record in records}

    entry_syntax = by_path["src/Demo.jl"]["syntax"]
    assert entry_syntax["module_contexts"] == ["Demo"]
    assert {
        (item["target"], item["resolved_path"], item["module_context"])
        for item in entry_syntax["includes"]
    } == {
        ("syntax.jl", "src/syntax.jl", "Demo"),
        ("training.jl", "src/training.jl", "Demo"),
    }
    entry_initializer = next(
        symbol for symbol in entry_syntax["symbols"] if symbol["kind"] == "module_initializer"
    )
    assert entry_initializer["qualname"].startswith("Demo.__file_init__")
    assert len(entry_initializer["raw_calls"]) == 2

    syntax_symbols = by_path["src/syntax.jl"]["syntax"]["symbols"]
    vocab = next(symbol for symbol in syntax_symbols if symbol["name"] == "VOCAB")
    assert vocab["qualname"] == "Demo.VOCAB"
    assert vocab["kind"] == "constant"
    assert vocab["is_exported"] is True

    training_symbols = by_path["src/training.jl"]["syntax"]["symbols"]
    train = next(symbol for symbol in training_symbols if symbol["name"] == "train!")
    assert train["qualname"] == "Demo.train!"
    assert train["declaration_group_id"] == "julia:function:Demo.train!"
    assert train["is_exported"] is True
    assert train["language_details"]["declaring_module"] == "Demo"
    assert "Lux" in train["imports"]
    training_initializer = next(
        symbol for symbol in training_symbols if symbol["kind"] == "module_initializer"
    )
    assert training_initializer["raw_calls"][0]["callee"] == "initialise"

    experiment_symbols = by_path["experiment.jl"]["syntax"]["symbols"]
    entrypoint = next(
        symbol for symbol in experiment_symbols if symbol["kind"] == "script_entrypoint"
    )
    assert entrypoint["qualname"] == "experiment.__toplevel__"
    assert {call["callee"] for call in entrypoint["raw_calls"]} == {"TinyModel", "train!"}
    assert by_path["experiment.jl"]["syntax"]["package_context"]["name"] == "Demo"
