from __future__ import annotations

import hashlib
from itertools import islice
import re
from typing import Any, Iterable

from .diagnostics import error_code
from .structure_privacy import safe_reference, sanitize_syntax_fields

from .parsing import FUNCTION_LIKE_KINDS, language_for_path, language_label, parse_source
from .parsing.tree_sitter_parser import TreeSitterUnavailable, make_language
from .sql_extract import extract_sql_syntax
from .syntax_contract import empty_syntax

CSS_STRUCTURE_QUERY = """
(rule_set
  (selectors) @rule.selectors
  (block
    (declaration
      (property_name) @rule.property)*)) @rule
(media_statement) @media
(keyframes_statement
  (keyframes_name) @keyframes.name) @keyframes
(declaration
  (property_name) @property.name) @property.declaration
"""


MAX_AST_NODES = 250_000
MAX_SYMBOLS = 2_000
MAX_QUERY_MATCHES = 5_000
MAX_STYLE_RECORDS = 2_000
MAX_STYLE_IMPORTS = 1_000


class SyntaxTraversalLimit(RuntimeError):
    """Raised when syntax traversal exceeds the defensive node budget."""


SCRIPT_STYLE_IMPORT_QUERY = """
(import_statement
  source: (string
    (string_fragment) @style.path)) @style.import
(call_expression
  arguments: (arguments
    (string
      (string_fragment) @style.path))) @style.call
"""


def extract_syntax(path: str, content: str) -> dict[str, object]:
    """Return deterministic, interpretation-free syntax observations for one file."""
    if language_for_path(path) == "sql":
        return extract_sql_syntax(path, content)

    parsed = parse_source(path, content)
    if parsed is None:
        return {
            "language": None,
            "parse": {
                "status": "unsupported_language",
                "has_error_nodes": False,
                "error_node_count": 0,
                "missing_node_count": 0,
            },
            "syntax": _empty_syntax(),
        }

    root = parsed.tree.root_node
    source = parsed.content_bytes
    error_node_count, missing_node_count = _parse_problem_counts(root)
    parse_status = "parsed_with_errors" if error_node_count or missing_node_count else "parsed"

    imports = _imports_from_tree(root, source, parsed.language_name)
    includes = _cpp_includes_from_tree(root, source) if parsed.language_name == "cpp" else []
    symbols = _symbols_from_tree(root, source, parsed.language_name, path, imports)
    call_sites = _module_call_sites(root, source, parsed.language_name, symbols)
    scopes = _scopes_from_tree(root, source, parsed.language_name, path)
    exports: list[str] = []
    publics: list[str] = []
    if parsed.language_name == "julia":
        exported, public = _julia_visibility_names(root, source)
        exports = sorted(exported)
        publics = sorted(public)
    styles = _style_symbols(path, parsed.language_name, root, source)
    style_imports = _style_imports(path, parsed.language_name, root, source)

    return {
        "language": language_label(parsed.language_name) or parsed.language_name,
        "parse": {
            "status": parse_status,
            "has_error_nodes": bool(error_node_count or missing_node_count),
            "error_node_count": error_node_count,
            "missing_node_count": missing_node_count,
            "root_node_type": getattr(root, "type", None),
        },
        "syntax": {
            **empty_syntax(),
            "symbols": symbols,
            "imports": imports,
            "call_sites": call_sites,
            "includes": includes,
            "scopes": scopes,
            "exports": exports,
            "publics": publics,
            "styles": styles,
            "style_imports": style_imports,
        },
    }


def sanitize_syntax_for_structure_mode(syntax: object) -> None:
    """Remove verbatim source fragments while preserving structural facts in-place.

    Structure mode intentionally retains identifiers, qualified names, import targets,
    call targets, locations, and arity information. It must not retain arbitrary source
    expressions such as default argument values, full Julia declarations, or raw import
    statements.
    """
    if not isinstance(syntax, dict):
        return

    symbols = syntax.get("symbols")
    if isinstance(symbols, list):
        for raw_symbol in symbols:
            if not isinstance(raw_symbol, dict):
                continue
            kind = str(raw_symbol.get("kind") or "symbol")
            name = str(raw_symbol.get("name") or raw_symbol.get("qualname") or "<anonymous>")
            name = safe_reference(name)
            raw_symbol["name"] = name
            parameters_were_present = raw_symbol.get("parameters_text") is not None
            inputs = [
                str(value)
                for value in (raw_symbol.get("inputs") or [])
                if isinstance(value, str) and _is_parameter_name(value)
            ]
            raw_symbol["inputs"] = inputs
            details = raw_symbol.get("language_details")
            keyword_names: list[str] = []
            if isinstance(details, dict):
                keyword_names = [
                    str(value)
                    for value in (details.get("keyword_names") or [])
                    if isinstance(value, str) and _is_parameter_name(value)
                ]
                # Julia type expressions are source slices and may themselves contain
                # literal values (for example Val{:internal_name}). Arity and names remain.
                details.pop("positional_parameter_types", None)

            if parameters_were_present:
                positional = ", ".join(inputs)
                keywords = ", ".join(keyword_names)
                if positional and keywords:
                    parameter_shape = f"{positional}; {keywords}"
                else:
                    parameter_shape = positional or keywords
                raw_symbol["signature"] = f"{kind} {name}({parameter_shape})"
            else:
                raw_symbol["signature"] = f"{kind} {name}"
            raw_symbol["parameters_text"] = None
            raw_symbol["signature_fidelity"] = "canonical_structure"

    def remove_raw_text(value: object) -> None:
        if isinstance(value, dict):
            value.pop("raw_text", None)
            for nested in value.values():
                remove_raw_text(nested)
        elif isinstance(value, list):
            for nested in value:
                remove_raw_text(nested)

    remove_raw_text(syntax)
    sanitize_syntax_fields(syntax)


def parser_unavailable_result(path: str, exc: TreeSitterUnavailable) -> dict[str, object]:
    language = language_for_path(path)
    return {
        "language": language_label(language),
        "parse": {
            "status": "parser_unavailable",
            "has_error_nodes": False,
            "error_node_count": 0,
            "missing_node_count": 0,
            "error": error_code(exc),
        },
        "syntax": _empty_syntax(),
    }


def parse_failed_result(language: str | None, exc: Exception) -> dict[str, object]:
    return {
        "language": language_label(language),
        "parse": {
            "status": "parse_failed",
            "has_error_nodes": False,
            "error_node_count": 0,
            "missing_node_count": 0,
            "error": error_code(exc),
        },
        "syntax": _empty_syntax(),
    }


def _empty_syntax() -> dict[str, object]:
    return empty_syntax()


def _node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _field_text(node: Any, field_name: str, source: bytes) -> str | None:
    try:
        child = node.child_by_field_name(field_name)
    except Exception:
        child = None
    if child is None:
        return None
    return _node_text(child, source).strip()


def _children(node: Any) -> list[Any]:
    return list(getattr(node, "children", []) or [])


def _walk(node: Any, *, max_nodes: int = MAX_AST_NODES) -> Iterable[Any]:
    stack = [node]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > max_nodes:
            raise SyntaxTraversalLimit(f"syntax tree exceeded the {max_nodes} node traversal limit")
        yield current
        stack.extend(reversed(_children(current)))


def _line_start(node: Any) -> int | None:
    point = getattr(node, "start_point", None)
    return int(point[0]) + 1 if point is not None else None


def _line_end(node: Any) -> int | None:
    point = getattr(node, "end_point", None)
    return int(point[0]) + 1 if point is not None else None


def _location(node: Any) -> dict[str, int | None]:
    return {
        "start_line": _line_start(node),
        "end_line": _line_end(node),
        "start_byte": int(getattr(node, "start_byte", 0)),
        "end_byte": int(getattr(node, "end_byte", 0)),
    }


def _parse_problem_counts(root: Any) -> tuple[int, int]:
    errors = 0
    missing = 0
    for node in _walk(root):
        if getattr(node, "type", "") == "ERROR":
            errors += 1
        if bool(getattr(node, "is_missing", False)):
            missing += 1
    return errors, missing


def _first_named_child_of_type(node: Any, types: set[str]) -> Any | None:
    for child in _children(node):
        if getattr(child, "type", "") in types:
            return child
    return None


def _descendant_texts(node: Any, source: bytes, types: set[str], *, limit: int = 80) -> list[str]:
    values: list[str] = []
    for child in _walk(node):
        if getattr(child, "type", "") in types:
            text = _node_text(child, source).strip()
            if text and text not in values:
                values.append(text)
                if len(values) >= limit:
                    break
    return values


def _identifier_from_node(node: Any, source: bytes) -> str | None:
    text = _field_text(node, "name", source)
    if text:
        return text
    ident = _first_named_child_of_type(
        node, {"identifier", "property_identifier", "type_identifier"}
    )
    if ident is not None:
        return _node_text(ident, source).strip()
    return None


def _parameters_text(node: Any, source: bytes) -> str:
    params = _field_text(node, "parameters", source)
    if params is not None:
        return params
    for child in _children(node):
        if getattr(child, "type", "") in {
            "parameters",
            "formal_parameters",
            "parameter_list",
        }:
            return _node_text(child, source).strip()
    return "()"


def _inputs_from_params(params: str, language_name: str) -> list[str]:
    stripped = params.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    if not stripped:
        return []
    inputs: list[str] = []
    raw_parts = _split_top_level(stripped)
    for raw in raw_parts:
        part = raw.strip()
        if not part:
            continue
        part = part.split("=", 1)[0].strip()
        if ":" in part and language_name in {"python", "typescript", "tsx", "javascript"}:
            candidate = part.split(":", 1)[0].strip()
        else:
            pieces = [piece for piece in part.split() if piece]
            candidate = pieces[-1] if pieces else part
        candidate = candidate.strip().lstrip("*").rstrip("?")
        if _is_parameter_name(candidate):
            inputs.append(candidate)
    return inputs[:24]



def _cpp_normalize_qualified(value: str) -> str:
    """Return a compact C++ qualified name suitable for cross-file matching."""
    text = " ".join(value.strip().split())
    # Template arguments make call/definition names needlessly brittle. Remove the
    # balanced portions while preserving the surrounding qualified identifier.
    out: list[str] = []
    depth = 0
    for char in text:
        if char == "<":
            depth += 1
            continue
        if char == ">" and depth:
            depth -= 1
            continue
        if depth == 0:
            out.append(char)
    return "".join(out).replace("::", ".").replace("->", ".").replace(" ", "")


def _cpp_include_target(node: Any, source: bytes) -> str | None:
    try:
        path_node = node.child_by_field_name("path")
    except Exception:
        path_node = None
    raw = _node_text(path_node, source).strip() if path_node is not None else ""
    if not raw:
        raw = _node_text(node, source).strip()
        raw = re.sub(r"^\s*#\s*include\s*", "", raw).strip()
    if (raw.startswith("<") and raw.endswith(">")) or (
        raw.startswith('"') and raw.endswith('"')
    ):
        raw = raw[1:-1]
    return raw.strip() or None


def _cpp_includes_from_tree(root: Any, source: bytes) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[tuple[str, int | None]] = set()
    for node in _walk(root):
        if getattr(node, "type", "") != "preproc_include":
            continue
        target = _cpp_include_target(node, source)
        if not target:
            continue
        text = _node_text(node, source).strip()
        key = (target, _line_start(node))
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "target": target,
                "kind": "preproc_include",
                "system": "<" in text and ">" in text,
                "raw_text": text,
                **_location(node),
            }
        )
    return records[:160]


def _cpp_declarator_name(node: Any | None, source: bytes) -> str | None:
    if node is None:
        return None
    node_type = getattr(node, "type", "")
    if node_type in {
        "identifier",
        "field_identifier",
        "type_identifier",
        "operator_name",
        "destructor_name",
        "qualified_identifier",
        "template_function",
        "template_method",
    }:
        return _cpp_normalize_qualified(_node_text(node, source))
    try:
        declarator = node.child_by_field_name("declarator")
    except Exception:
        declarator = None
    if declarator is not None and declarator is not node:
        value = _cpp_declarator_name(declarator, source)
        if value:
            return value
    # The C++ grammar nests declarators heavily (pointer/reference/parenthesized).
    # Prefer the last name-shaped descendant, which is the declared entity rather
    # than a return/type identifier in the surrounding declaration.
    candidates: list[str] = []
    for child in _walk(node):
        if child is node:
            continue
        if getattr(child, "type", "") in {
            "identifier",
            "field_identifier",
            "operator_name",
            "destructor_name",
            "qualified_identifier",
            "template_function",
            "template_method",
        }:
            value = _cpp_normalize_qualified(_node_text(child, source))
            if value:
                candidates.append(value)
    return candidates[-1] if candidates else None


def _cpp_function_declarator(node: Any) -> Any | None:
    try:
        declarator = node.child_by_field_name("declarator")
    except Exception:
        declarator = None
    if declarator is None:
        return None
    if getattr(declarator, "type", "") == "function_declarator":
        return declarator
    for child in _walk(declarator):
        if getattr(child, "type", "") == "function_declarator":
            return child
    return None


def _cpp_function_parts(node: Any, source: bytes) -> tuple[str, str] | None:
    declarator = _cpp_function_declarator(node)
    if declarator is None:
        return None
    try:
        name_node = declarator.child_by_field_name("declarator")
    except Exception:
        name_node = None
    name = _cpp_declarator_name(name_node or declarator, source)
    if not name:
        return None
    params = _field_text(declarator, "parameters", source)
    if params is None:
        params = _parameters_text(declarator, source)
    return name, params


def _cpp_merge_parents(parents: list[str], declared_scope: list[str]) -> list[str]:
    if not declared_scope:
        return list(parents)
    for overlap in range(min(len(parents), len(declared_scope)), -1, -1):
        if parents[-overlap:] == declared_scope[:overlap] if overlap else True:
            return [*parents, *declared_scope[overlap:]]
    return [*parents, *declared_scope]


def _cpp_function_kind(name: str, parents: list[str], *, in_type: bool) -> str:
    leaf = name.split(".")[-1]
    bare = leaf.lstrip("~")
    declared_scope = name.split(".")[:-1]
    parent_leaf = parents[-1] if parents else ""
    if leaf.startswith("~"):
        return "destructor"
    if (in_type and parent_leaf and bare == parent_leaf) or (
        declared_scope and bare == declared_scope[-1]
    ):
        return "constructor"
    # A qualified out-of-class definition is not enough to distinguish a class
    # method from a namespace-qualified free function in a single file. Keep it
    # as a function unless we are lexically inside a type; Trace can reconcile it
    # with header declarations by declaration_group_id across the repository.
    return "method" if in_type else "function"


def _cpp_symbol_modifiers(node: Any, source: bytes) -> list[str]:
    header = _node_text(node, source).split("{", 1)[0].split(";", 1)[0]
    values: list[str] = []
    for token in (
        "static", "virtual", "inline", "constexpr", "consteval", "constinit",
        "explicit", "friend", "override", "final", "noexcept",
    ):
        if re.search(rf"\b{token}\b", header) and token not in values:
            values.append(token)
    return values


def _cpp_symbols_from_tree(
    root: Any,
    source: bytes,
    path: str,
    imports: list[dict[str, object]],
) -> list[dict[str, object]]:
    symbols: list[dict[str, object]] = []
    import_targets = [str(item["target"]) for item in imports]

    def add_symbol(
        node: Any,
        *,
        kind: str,
        name: str,
        parents: list[str],
        params: str | None = None,
        declaration_only: bool = False,
    ) -> None:
        leaf = name.split(".")[-1]
        declared_scope = name.split(".")[:-1]
        merged_parents = _cpp_merge_parents(parents, declared_scope)
        qualname = ".".join([*merged_parents, leaf]) if merged_parents else leaf
        function_like = kind in FUNCTION_LIKE_KINDS
        parameter_text = params if function_like else ""
        if function_like and parameter_text is None:
            parameter_text = "()"
        signature = (
            f"{kind} {leaf}{parameter_text}"
            if function_like
            else f"{kind} {leaf}"
        )
        raw_calls = [] if declaration_only else (
            _calls_in_node(node, source, "cpp") if function_like else []
        )
        declaration_group_id = None
        if kind in {"class", "struct", "union", "enum"}:
            declaration_group_id = f"cpp::type::{qualname}"
        elif function_like:
            declaration_group_id = f"cpp::function::{qualname}"
        symbol_id = f"{path}::{qualname}"
        if function_like:
            row_kind = "declaration" if declaration_only else "definition"
            parameter_id = hashlib.sha256(
                f"{path}:{qualname}:{node.start_byte}:{node.end_byte}".encode("utf-8")
            ).hexdigest()[:24]
            symbol_id = f"{path}::{qualname}::sig_{parameter_id}::{row_kind}"
        symbols.append(
            {
                "symbol_id": symbol_id,
                "kind": kind,
                "name": leaf,
                "qualname": qualname,
                "signature": signature,
                "parameters_text": parameter_text if function_like else None,
                "inputs": _inputs_from_params(parameter_text or "()", "cpp") if function_like else [],
                "imports": import_targets,
                "raw_calls": raw_calls,
                "modifiers": _cpp_symbol_modifiers(node, source),
                "declaration_group_id": declaration_group_id,
                "language_details": {
                    "declaration_only": declaration_only,
                    "qualified_declarator": name,
                },
                **_location(node),
            }
        )

    stack: list[tuple[Any, list[str], bool]] = [(root, [], False)]
    visited = 0
    while stack:
        node, parents, in_type = stack.pop()
        visited += 1
        if visited > MAX_AST_NODES:
            raise SyntaxTraversalLimit(
                f"syntax tree exceeded the {MAX_AST_NODES} node traversal limit"
            )
        node_type = getattr(node, "type", "")

        if node_type == "namespace_definition":
            namespace = _field_text(node, "name", source)
            if not namespace:
                candidate = _first_named_child_of_type(
                    node, {"namespace_identifier", "identifier", "nested_namespace_specifier"}
                )
                namespace = _node_text(candidate, source).strip() if candidate is not None else None
            scoped = [*parents, *_cpp_normalize_qualified(namespace).split(".")] if namespace else parents
            stack.extend((child, scoped, in_type) for child in reversed(_children(node)))
            continue

        container_kind = _class_or_container_kind(node_type)
        if container_kind:
            name = _field_text(node, "name", source)
            if not name:
                candidate = _first_named_child_of_type(node, {"type_identifier", "identifier"})
                name = _node_text(candidate, source).strip() if candidate is not None else None
            if name:
                name = _cpp_normalize_qualified(name)
                add_symbol(node, kind=container_kind, name=name, parents=parents)
                if len(symbols) >= MAX_SYMBOLS:
                    break
                stack.extend((child, [*parents, name.split(".")[-1]], True) for child in reversed(_children(node)))
                continue

        if node_type == "function_definition":
            parts = _cpp_function_parts(node, source)
            if parts:
                name, params = parts
                declared_scope = name.split(".")[:-1]
                merged = _cpp_merge_parents(parents, declared_scope)
                kind = _cpp_function_kind(name, merged, in_type=in_type)
                add_symbol(node, kind=kind, name=name, parents=parents, params=params)
            if len(symbols) >= MAX_SYMBOLS:
                break
            continue

        # Header declarations and pure-virtual methods matter for architecture even
        # when the implementation lives elsewhere. Restrict this to direct function
        # declarators to avoid mistaking function-pointer variables for functions.
        if node_type in {"declaration", "field_declaration"}:
            try:
                direct = node.child_by_field_name("declarator")
            except Exception:
                direct = None
            if direct is not None and getattr(direct, "type", "") == "function_declarator":
                parts = _cpp_function_parts(node, source)
                if parts:
                    name, params = parts
                    declared_scope = name.split(".")[:-1]
                    merged = _cpp_merge_parents(parents, declared_scope)
                    kind = _cpp_function_kind(name, merged, in_type=in_type)
                    add_symbol(
                        node,
                        kind=kind,
                        name=name,
                        parents=parents,
                        params=params,
                        declaration_only=True,
                    )
                    if len(symbols) >= MAX_SYMBOLS:
                        break
                    continue

        stack.extend((child, parents, in_type) for child in reversed(_children(node)))

    return symbols[:MAX_SYMBOLS]


def _imports_from_tree(root: Any, source: bytes, language_name: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[tuple[str, int | None]] = set()
    for node in _walk(root):
        node_type = getattr(node, "type", "")
        text = _node_text(node, source).strip()
        target: str | None = None
        if language_name == "python" and node_type in {
            "import_statement",
            "import_from_statement",
        }:
            target = text.replace("import ", "").replace("from ", "").split()[0] if text else None
        elif (
            language_name in {"javascript", "typescript", "tsx"} and node_type == "import_statement"
        ):
            strings = _descendant_texts(node, source, {"string", "string_fragment"}, limit=4)
            target = strings[-1].strip("'\"") if strings else text
        elif language_name == "java" and node_type == "import_declaration":
            target = text.replace("import", "").replace("static", "").replace(";", "").strip()
        elif language_name == "c_sharp" and node_type == "using_directive":
            target = text.replace("using", "").replace(";", "").strip()
        elif language_name == "cpp" and node_type == "preproc_include":
            target = _cpp_include_target(node, source)
        elif language_name == "julia" and node_type in {"import_statement", "using_statement"}:
            keyword = "import" if node_type == "import_statement" else "using"
            target = text[len(keyword) :].strip() if text.startswith(keyword) else text
        if not target:
            continue
        key = (target, _line_start(node))
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "target": target,
                "raw_text": text,
                "kind": node_type,
                **_location(node),
            }
        )
    return records[:160]


def _find_js_variable_function(node: Any, source: bytes) -> tuple[str, str, Any] | None:
    if getattr(node, "type", "") != "variable_declarator":
        return None
    name = _field_text(node, "name", source)
    value = node.child_by_field_name("value")
    if not name or value is None:
        return None
    if getattr(value, "type", "") in {"arrow_function", "function", "function_expression"}:
        kind = "arrow_function" if getattr(value, "type", "") == "arrow_function" else "function"
        return name.strip(), kind, value
    return None


def _class_or_container_kind(node_type: str) -> str | None:
    return {
        "class_definition": "class",
        "class_declaration": "class",
        "interface_declaration": "interface",
        "enum_declaration": "enum",
        "record_declaration": "record",
        "struct_declaration": "struct",
        "class_specifier": "class",
        "struct_specifier": "struct",
        "union_specifier": "union",
        "enum_specifier": "enum",
    }.get(node_type)


def _function_kind(node_type: str, parents: list[str]) -> str | None:
    if node_type in {"function_definition", "function_declaration", "function"}:
        return "method" if parents else "function"
    if node_type in {"method_definition", "method_declaration"}:
        return "method"
    if node_type == "constructor_declaration":
        return "constructor"
    if node_type == "arrow_function":
        return "arrow_function"
    return None


def _call_target(node: Any, source: bytes, *, _depth: int = 0) -> str | None:
    if _depth > 64:
        return "<dynamic>"
    node_type = getattr(node, "type", "")
    if node_type in {
        "identifier",
        "property_identifier",
        "type_identifier",
        "field_identifier",
        "macro_identifier",
        "operator_name",
        "destructor_name",
    }:
        return _node_text(node, source).strip()
    if node_type in {
        "attribute",
        "member_expression",
        "member_access_expression",
        "scoped_identifier",
        "qualified_name",
        "field_expression",
        "qualified_identifier",
        "template_function",
        "template_method",
    }:
        named = list(getattr(node, "named_children", ()) or ())
        parts = []
        for child in named:
            if getattr(child, "type", "") in {"template_argument_list", "type_argument_list"}:
                continue
            part = _call_target(child, source, _depth=_depth + 1)
            if part:
                parts.append(part)
        if parts:
            return ".".join(parts)
        # Tests/partial grammars may have no child fields. Accept only a plain
        # qualified identifier; never recover a call target from arbitrary text.
        text = _node_text(node, source).strip()
        if re.fullmatch(r"[\w~!]+(?:(?:\.|::)[\w~!]+)*", text):
            return _cpp_normalize_qualified(text)
        return "<dynamic>"
    if node_type in {
        "call",
        "call_expression",
        "broadcast_call_expression",
        "macrocall_expression",
        "invocation_expression",
        "method_invocation",
    }:
        target = node.child_by_field_name("function") or node.child_by_field_name("name")
        if target is None and _children(node):
            target = _children(node)[0]
        name = _call_target(target, source, _depth=_depth + 1) if target is not None else None
        if name:
            return name
        return "<dynamic>"
    if node_type == "object_creation_expression":
        target = node.child_by_field_name("type") or _first_named_child_of_type(
            node, {"type_identifier", "identifier", "generic_name"}
        )
        return _call_target(target, source, _depth=_depth + 1) if target is not None else "<dynamic>"
    if node_type == "new_expression":
        target = node.child_by_field_name("constructor") or node.child_by_field_name("type")
        return _call_target(target, source, _depth=_depth + 1) if target is not None else "<dynamic>"
    return None


def _call_types(language_name: str) -> set[str]:
    return {
        "python": {"call"},
        "javascript": {"call_expression", "new_expression"},
        "typescript": {"call_expression", "new_expression"},
        "tsx": {"call_expression", "new_expression"},
        "java": {"method_invocation", "object_creation_expression"},
        "c_sharp": {"invocation_expression", "object_creation_expression"},
        "cpp": {"call_expression", "new_expression"},
        "julia": {"call_expression", "broadcast_call_expression", "macrocall_expression"},
    }.get(language_name, set())


def _calls_in_node(
    node: Any,
    source: bytes,
    language_name: str,
    *,
    exclude_ranges: list[tuple[int, int]] | None = None,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[tuple[str, int | None, int]] = set()
    excluded = exclude_ranges or []
    for child in _walk(node):
        child_start = int(getattr(child, "start_byte", 0))
        child_end = int(getattr(child, "end_byte", 0))
        if any(start <= child_start and child_end <= end for start, end in excluded):
            continue
        if getattr(child, "type", "") not in _call_types(language_name):
            continue
        target = _call_target(child, source)
        if not target:
            continue
        if language_name == "cpp":
            target = _cpp_normalize_qualified(target)
        key = (target, _line_start(child), child_start)
        if key in seen:
            continue
        seen.add(key)
        record: dict[str, object] = {
            "callee": target,
            "kind": getattr(child, "type", ""),
            **_location(child),
        }
        if language_name == "julia":
            record.update(_julia_call_details(child, source))
        records.append(record)
        if len(records) >= 120:
            break
    return records



def _split_top_level(text: str, separator: str = ",") -> list[str]:
    """Split Julia argument-like text without breaking nested expressions."""
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == separator and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def _partition_top_level(text: str, separator: str) -> tuple[str, str | None]:
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == separator and depth == 0:
            return text[:index], text[index + 1 :]
    return text, None


def _has_top_level_default(value: str) -> bool:
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char != "=" or depth != 0:
            continue
        previous = value[index - 1] if index else ""
        following = value[index + 1] if index + 1 < len(value) else ""
        if previous not in {"=", "!", ">", "<", ":"} and following not in {"=", ">"}:
            return True
    return False


def _split_julia_positional_keywords(
    text: str, *, implicit_keywords: bool
) -> tuple[list[str], list[str]]:
    positional_text, keyword_text = _partition_top_level(text, ";")
    positional: list[str] = []
    keywords: list[str] = []
    for part in _split_top_level(positional_text):
        # At call sites Julia permits `f(x=1)` as keyword syntax. In a method
        # signature, a default before `;` remains an optional positional argument.
        if implicit_keywords and _has_top_level_default(part):
            keywords.append(part)
        else:
            positional.append(part)
    if keyword_text is not None:
        keywords.extend(_split_top_level(keyword_text))
    return positional, keywords


def _julia_name_from_signature(signature: str) -> tuple[str | None, str]:
    text = " ".join(signature.strip().split())
    if not text:
        return None, "()"
    depth = 0
    opening: int | None = None
    for index, char in enumerate(text):
        if char == "(" and depth == 0:
            opening = index
            break
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth = max(0, depth - 1)
    if opening is None:
        return text.split("::", 1)[0].strip() or None, "()"
    depth = 0
    closing: int | None = None
    for index in range(opening, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        closing = len(text) - 1
    name = text[:opening].strip()
    if name.startswith("(") and name.endswith(")"):
        name = name[1:-1].strip()
    return name or None, text[opening : closing + 1]


def _julia_parameter_details(parameters_text: str) -> dict[str, object]:
    inner = parameters_text.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]
    positional, keywords = _split_julia_positional_keywords(inner, implicit_keywords=False)
    min_positional = 0
    max_positional: int | None = 0
    positional_names: list[str] = []
    positional_types: list[str | None] = []
    for parameter in positional:
        has_default = _has_top_level_default(parameter)
        left = _partition_top_level(parameter, "=")[0].strip()
        variadic = left.endswith("...")
        left = left[:-3].strip() if variadic else left
        if "::" in left:
            raw_name, raw_type = left.split("::", 1)
            name = raw_name.strip() or left
            type_text: str | None = raw_type.strip() or None
        else:
            name = left.strip()
            type_text = None
        positional_names.append(name)
        positional_types.append(type_text)
        if not has_default and not variadic:
            min_positional += 1
        if max_positional is not None:
            max_positional += 1
        if variadic:
            max_positional = None
    keyword_names: list[str] = []
    required_keywords: list[str] = []
    has_keyword_splat = False
    for parameter in keywords:
        left = _partition_top_level(parameter, "=")[0].strip()
        variadic = left.endswith("...")
        if variadic:
            has_keyword_splat = True
            left = left[:-3].strip()
        name = left.split("::", 1)[0].strip()
        if name:
            keyword_names.append(name)
            if not _has_top_level_default(parameter) and not variadic:
                required_keywords.append(name)
    return {
        "min_positional_arity": min_positional,
        "max_positional_arity": max_positional,
        "positional_parameter_names": positional_names,
        "positional_parameter_types": positional_types,
        "keyword_names": keyword_names,
        "required_keyword_names": required_keywords,
        "accepts_keyword_splat": has_keyword_splat,
    }


def _julia_call_details(node: Any, source: bytes) -> dict[str, object]:
    node_type = getattr(node, "type", "")
    arguments = None
    try:
        arguments = node.child_by_field_name("arguments")
    except Exception:
        arguments = None
    if arguments is None:
        arguments = _first_named_child_of_type(node, {"argument_list"})
    argument_text = _node_text(arguments, source).strip() if arguments is not None else "()"
    inner = argument_text[1:-1] if argument_text.startswith("(") and argument_text.endswith(")") else argument_text
    positional, keywords = _split_julia_positional_keywords(inner, implicit_keywords=True)
    keyword_names: list[str] = []
    has_keyword_splat = False
    for argument in keywords:
        left = _partition_top_level(argument, "=")[0].strip()
        if left.endswith("..."):
            has_keyword_splat = True
            left = left[:-3].strip()
        name = left.split("::", 1)[0].strip()
        if name:
            keyword_names.append(name)
    return {
        "positional_argument_count": len(positional),
        "keyword_names": keyword_names,
        "has_positional_splat": any(item.rstrip().endswith("...") for item in positional),
        "has_keyword_splat": has_keyword_splat,
        "is_broadcast_call": node_type == "broadcast_call_expression",
        "is_macro_call": node_type == "macrocall_expression",
    }


def _julia_visibility_names(root: Any, source: bytes) -> tuple[set[str], set[str]]:
    exported: set[str] = set()
    public: set[str] = set()
    for node in _walk(root):
        node_type = getattr(node, "type", "")
        if node_type not in {"export_statement", "public_statement"}:
            continue
        text = _node_text(node, source).strip()
        keyword = "export" if node_type == "export_statement" else "public"
        names = _split_top_level(text[len(keyword) :].strip())
        target = exported if keyword == "export" else public
        target.update(name.strip() for name in names if name.strip())
    return exported, public


def _julia_definition_signature(node: Any, source: bytes) -> tuple[Any | None, str]:
    signature_node = None
    try:
        signature_node = node.child_by_field_name("signature")
    except Exception:
        signature_node = None
    if signature_node is None:
        signature_node = _first_named_child_of_type(
            node, {"signature", "call_expression", "where_expression", "typed_expression"}
        )
    return signature_node, _node_text(signature_node, source).strip() if signature_node else ""


def _julia_assignment_parts(node: Any) -> tuple[Any | None, Any | None]:
    left = right = None
    try:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
    except Exception:
        pass
    named = [child for child in _children(node) if bool(getattr(child, "is_named", True))]
    if left is None and named:
        left = named[0]
    if right is None and len(named) > 1:
        right = named[-1]
    return left, right


def _julia_short_method(node: Any, source: bytes) -> tuple[Any, Any | None, str] | None:
    if getattr(node, "type", "") != "assignment":
        return None
    left, right = _julia_assignment_parts(node)
    if left is None:
        return None
    left_type = getattr(left, "type", "")
    if left_type not in {"call_expression", "where_expression", "typed_expression"}:
        return None
    text = _node_text(left, source).strip()
    name, parameters = _julia_name_from_signature(text)
    if not name or parameters == "()":
        return None
    return left, right, text


def _julia_container_name(node: Any, source: bytes) -> str | None:
    name = _identifier_from_node(node, source)
    if name:
        return name
    head = _first_named_child_of_type(node, {"type_head"})
    if head is None:
        return None
    text = _node_text(head, source).strip()
    for separator in ("<:", "{"):
        text = text.split(separator, 1)[0].strip()
    return text or None


def _julia_definition_name(node: Any, source: bytes) -> str | None:
    node_type = getattr(node, "type", "")
    if node_type in {"function_definition", "macro_definition"}:
        _signature_node, signature_text = _julia_definition_signature(node, source)
        name, _parameters = _julia_name_from_signature(signature_text)
        if node_type == "macro_definition" and name and not name.startswith("@"):
            return f"@{name}"
        return name
    return _julia_container_name(node, source)


def _julia_symbols_from_tree(
    root: Any,
    source: bytes,
    path: str,
    imports: list[dict[str, object]],
) -> list[dict[str, object]]:
    symbols: list[dict[str, object]] = []
    import_targets = [str(item["target"]) for item in imports]
    exported, public = _julia_visibility_names(root, source)

    def add_symbol(
        node: Any,
        *,
        kind: str,
        name: str,
        parents: list[str],
        signature_node: Any | None = None,
        signature_text: str | None = None,
        body_node: Any | None = None,
    ) -> None:
        bare_name = name.split(".")[-1]
        if "." in name:
            qualified_name = name
        elif parents and name == parents[-1]:
            qualified_name = ".".join(parents)
        else:
            qualified_name = ".".join([*parents, name]) if parents else name
        is_callable = kind in {"method", "macro"}
        parameters_text = ""
        details: dict[str, object] = {"declaring_module": ".".join(parents) or None}
        if is_callable:
            parsed_name, parameters_text = _julia_name_from_signature(signature_text or name)
            if parsed_name:
                name = parsed_name
                bare_name = name.split(".")[-1]
                if "." in name:
                    qualified_name = name
                elif parents and name == parents[-1]:
                    qualified_name = ".".join(parents)
                else:
                    qualified_name = ".".join([*parents, name]) if parents else name
            details["explicitly_qualified_name"] = "." in name
            details.update(_julia_parameter_details(parameters_text))
            details["generic_function_name"] = qualified_name
            details["definition_signature_start_byte"] = int(
                getattr(signature_node or node, "start_byte", 0)
            )
            details["definition_signature_end_byte"] = int(
                getattr(signature_node or node, "end_byte", 0)
            )
        excluded = []
        if is_callable and signature_node is not None:
            excluded.append(
                (
                    int(getattr(signature_node, "start_byte", 0)),
                    int(getattr(signature_node, "end_byte", 0)),
                )
            )
        raw_calls = (
            _calls_in_node(
                body_node or node, source, "julia", exclude_ranges=excluded
            )
            if is_callable
            else []
        )
        line = _line_start(node) or 0
        symbol_id = f"{path}::{qualified_name}"
        declaration_group_id: str | None = None
        if kind in {"method", "macro"}:
            declaration_group_id = f"julia:{'macro' if kind == 'macro' else 'function'}:{qualified_name}"
            symbol_id = f"{symbol_id}@{line}:{int(getattr(node, 'start_byte', 0))}"
        symbol: dict[str, object] = {
            "symbol_id": symbol_id,
            "kind": kind,
            "name": bare_name,
            "qualname": qualified_name,
            "signature": (signature_text or f"{kind} {name}").strip(),
            "parameters_text": parameters_text if is_callable else None,
            "inputs": list(details.get("positional_parameter_names", [])) if is_callable else [],
            "imports": import_targets,
            "raw_calls": raw_calls,
            "declaration_group_id": declaration_group_id,
            "is_exported": bare_name in exported,
            "language_details": {
                **details,
                "is_public": bare_name in public or bare_name in exported,
            },
            **_location(node),
        }
        symbols.append(symbol)

    stack: list[tuple[Any, list[str], bool]] = [(root, [], True)]
    visited = 0
    container_kinds = {
        "module_definition": "module",
        "struct_definition": "mutable_struct",
        "abstract_definition": "abstract_type",
        "primitive_definition": "primitive_type",
    }
    while stack:
        node, parents, allow_binding = stack.pop()
        visited += 1
        if visited > MAX_AST_NODES:
            raise SyntaxTraversalLimit(
                f"syntax tree exceeded the {MAX_AST_NODES} node traversal limit"
            )
        node_type = getattr(node, "type", "")
        if node_type in container_kinds:
            name = _julia_container_name(node, source)
            if name:
                kind = container_kinds[node_type]
                if node_type == "struct_definition":
                    prefix = _node_text(node, source).lstrip()[:20]
                    kind = "mutable_struct" if prefix.startswith("mutable struct") else "struct"
                add_symbol(node, kind=kind, name=name, parents=parents)
                next_parents = (
                    [*parents, name]
                    if node_type in {"module_definition", "struct_definition"}
                    else parents
                )
                child_allow_binding = node_type == "module_definition"
                stack.extend(
                    (child, next_parents, child_allow_binding)
                    for child in reversed(_children(node))
                )
                if len(symbols) >= MAX_SYMBOLS:
                    break
                continue
        if node_type == "function_definition":
            signature_node, signature_text = _julia_definition_signature(node, source)
            name, _parameters = _julia_name_from_signature(signature_text)
            if name:
                add_symbol(
                    node,
                    kind="method",
                    name=name,
                    parents=parents,
                    signature_node=signature_node,
                    signature_text=signature_text,
                )
            if len(symbols) >= MAX_SYMBOLS:
                break
            continue
        if node_type == "macro_definition":
            signature_node, signature_text = _julia_definition_signature(node, source)
            name, _parameters = _julia_name_from_signature(signature_text)
            if name:
                name = name if name.startswith("@") else f"@{name}"
                add_symbol(
                    node,
                    kind="macro",
                    name=name,
                    parents=parents,
                    signature_node=signature_node,
                    signature_text=signature_text,
                )
            if len(symbols) >= MAX_SYMBOLS:
                break
            continue
        short_method = _julia_short_method(node, source)
        if short_method is not None:
            signature_node, body_node, signature_text = short_method
            name, _parameters = _julia_name_from_signature(signature_text)
            if name:
                add_symbol(
                    node,
                    kind="method",
                    name=name,
                    parents=parents,
                    signature_node=signature_node,
                    signature_text=signature_text,
                    body_node=body_node,
                )
            if len(symbols) >= MAX_SYMBOLS:
                break
            continue
        raw_text = _node_text(node, source).lstrip()
        is_global_constant = node_type in {"const_statement", "const_declaration"} or (
            node_type == "assignment" and raw_text.startswith("const ")
        )
        if allow_binding and is_global_constant:
            binding_node = node
            if node_type in {"const_statement", "const_declaration"}:
                nested_assignment = _first_named_child_of_type(node, {"assignment"})
                if nested_assignment is not None:
                    binding_node = nested_assignment
            names = _julia_assignment_names(binding_node, source)
            if not names and node_type in {"const_statement", "const_declaration"}:
                names = _descendant_texts(node, source, {"identifier"}, limit=24)
            for binding_name in names:
                if not binding_name:
                    continue
                add_symbol(
                    node,
                    kind="constant" if raw_text.startswith("const ") else "binding",
                    name=binding_name,
                    parents=parents,
                )
                if len(symbols) >= MAX_SYMBOLS:
                    break
            if len(symbols) >= MAX_SYMBOLS:
                break
            continue
        child_allow_binding = allow_binding and node_type not in {
            "let_statement",
            "comprehension_expression",
            "generator",
            "do_clause",
            "for_statement",
            "while_statement",
            "try_statement",
        }
        stack.extend(
            (child, parents, child_allow_binding)
            for child in reversed(_children(node))
        )
    return symbols[:MAX_SYMBOLS]


_JULIA_SCOPE_KINDS: dict[str, tuple[str, str]] = {
    "module_definition": ("module", "global"),
    "function_definition": ("function", "hard"),
    "macro_definition": ("macro", "hard"),
    "let_statement": ("let", "hard"),
    "struct_definition": ("struct", "hard"),
    "comprehension_expression": ("comprehension", "hard"),
    "generator": ("generator", "hard"),
    "do_clause": ("do", "hard"),
    "for_statement": ("for", "soft"),
    "while_statement": ("while", "soft"),
    "try_statement": ("try", "soft"),
}


def _julia_assignment_names(node: Any, source: bytes) -> list[str]:
    left, _right = _julia_assignment_parts(node)
    if left is None or getattr(left, "type", "") in {"call_expression", "where_expression"}:
        return []
    if getattr(left, "type", "") == "typed_expression":
        children = _children(left)
        left = children[0] if children else left
    if getattr(left, "type", "") == "identifier":
        text = _node_text(left, source).strip()
        return [text] if text else []
    return _descendant_texts(left, source, {"identifier"}, limit=24)


def _julia_explicit_scope_names(node: Any, source: bytes) -> list[str]:
    for child in _walk(node):
        if getattr(child, "type", "") in {"assignment", "compound_assignment_expression"}:
            names = _julia_assignment_names(child, source)
            if names:
                return names
    direct = [
        _node_text(child, source).strip()
        for child in _children(node)
        if getattr(child, "type", "") == "identifier"
    ]
    if direct:
        return direct
    return _descendant_texts(node, source, {"identifier"}, limit=24)


def _julia_direct_scope_facts(node: Any, source: bytes) -> tuple[list[str], list[str], list[str], list[str]]:
    assignments: list[str] = []
    declarations: list[str] = []
    explicit_globals: list[str] = []
    explicit_locals: list[str] = []
    stack = list(reversed(_children(node)))
    while stack:
        child = stack.pop()
        child_type = getattr(child, "type", "")
        if child_type in _JULIA_SCOPE_KINDS:
            name = _julia_definition_name(child, source)
            if name and child_type in {
                "module_definition",
                "function_definition",
                "macro_definition",
                "struct_definition",
            }:
                declarations.append(name.lstrip("@"))
            continue
        if child_type == "assignment":
            short_method = _julia_short_method(child, source)
            if short_method is not None:
                _signature_node, _body_node, signature_text = short_method
                method_name, _parameters = _julia_name_from_signature(signature_text)
                if method_name:
                    declarations.append(method_name.split(".")[-1])
            else:
                assignments.extend(_julia_assignment_names(child, source))
        elif child_type == "compound_assignment_expression":
            assignments.extend(_julia_assignment_names(child, source))
        elif child_type in {"global_statement", "local_statement"}:
            names = _julia_explicit_scope_names(child, source)
            (explicit_globals if child_type == "global_statement" else explicit_locals).extend(names)
        stack.extend(reversed(_children(child)))
    unique = lambda values: list(dict.fromkeys(value for value in values if value))
    return unique(assignments), unique(declarations), unique(explicit_globals), unique(explicit_locals)


def _scopes_from_tree(
    root: Any, source: bytes, language_name: str, path: str
) -> list[dict[str, object]]:
    if language_name != "julia":
        return []
    records: list[dict[str, object]] = []
    root_id = f"{path}::scope:source"
    assignments, declarations, explicit_globals, explicit_locals = _julia_direct_scope_facts(root, source)
    records.append(
        {
            "scope_id": root_id,
            "parent_scope_id": None,
            "kind": "source_file",
            "scope_class": "global",
            "name": path,
            "assignments": assignments,
            "declarations": declarations,
            "bindings": list(dict.fromkeys([*assignments, *declarations])),
            "explicit_globals": explicit_globals,
            "explicit_locals": explicit_locals,
            "ambiguous_global_assignments": [],
            **_location(root),
        }
    )
    stack: list[tuple[Any, str, str | None, str]] = [
        (child, root_id, None, root_id) for child in reversed(_children(root))
    ]
    while stack:
        node, parent_scope_id, enclosing_hard_scope_id, global_scope_id = stack.pop()
        node_type = getattr(node, "type", "")
        scope_spec = _JULIA_SCOPE_KINDS.get(node_type)
        next_parent = parent_scope_id
        next_hard = enclosing_hard_scope_id
        next_global = global_scope_id
        if scope_spec is not None:
            kind, scope_class = scope_spec
            scope_id = f"{path}::scope:{int(getattr(node, 'start_byte', 0))}"
            assignments, declarations, explicit_globals, explicit_locals = _julia_direct_scope_facts(
                node, source
            )
            name = _julia_definition_name(node, source)
            record: dict[str, object] = {
                "scope_id": scope_id,
                "parent_scope_id": parent_scope_id,
                "kind": kind,
                "scope_class": scope_class,
                "name": name,
                "assignments": assignments,
                "declarations": declarations,
                "bindings": list(dict.fromkeys([*assignments, *declarations])),
                "explicit_globals": explicit_globals,
                "explicit_locals": explicit_locals,
                "enclosing_hard_scope_id": enclosing_hard_scope_id,
                "global_scope_id": global_scope_id,
                "ambiguous_global_assignments": [],
                **_location(node),
            }
            records.append(record)
            next_parent = scope_id
            if scope_class == "hard":
                next_hard = scope_id
            elif scope_class == "global":
                next_hard = None
                next_global = scope_id
        stack.extend(
            (child, next_parent, next_hard, next_global)
            for child in reversed(_children(node))
        )
    by_id = {str(record["scope_id"]): record for record in records}
    for record in records:
        if record.get("scope_class") != "soft" or record.get("enclosing_hard_scope_id"):
            continue
        global_record = by_id.get(str(record.get("global_scope_id")))
        global_bindings = set(global_record.get("bindings", [])) if global_record else set()
        assignments = set(record.get("assignments", []))
        explicit = set(record.get("explicit_globals", [])) | set(record.get("explicit_locals", []))
        record["ambiguous_global_assignments"] = sorted((assignments & global_bindings) - explicit)
    return records


def _symbols_from_tree(
    root: Any,
    source: bytes,
    language_name: str,
    path: str,
    imports: list[dict[str, object]],
) -> list[dict[str, object]]:
    if language_name == "julia":
        return _julia_symbols_from_tree(root, source, path, imports)
    if language_name == "cpp":
        return _cpp_symbols_from_tree(root, source, path, imports)

    symbols: list[dict[str, object]] = []
    import_targets = [str(item["target"]) for item in imports]

    def add_symbol(
        node: Any, *, kind: str, name: str, parents: list[str], body_node: Any | None = None
    ) -> None:
        parameter_node = body_node if body_node is not None else node
        params = _parameters_text(parameter_node, source) if kind in FUNCTION_LIKE_KINDS else ""
        qualname = ".".join([*parents, name]) if parents else name
        signature = f"{kind} {name}{params}" if kind in FUNCTION_LIKE_KINDS else f"{kind} {name}"
        call_node = body_node or node
        raw_calls = (
            _calls_in_node(call_node, source, language_name) if kind in FUNCTION_LIKE_KINDS else []
        )
        symbols.append(
            {
                "symbol_id": f"{path}::{qualname}",
                "kind": kind,
                "name": name,
                "qualname": qualname,
                "signature": signature,
                "parameters_text": params if kind in FUNCTION_LIKE_KINDS else None,
                "inputs": _inputs_from_params(params, language_name)
                if kind in FUNCTION_LIKE_KINDS
                else [],
                "imports": import_targets,
                "raw_calls": raw_calls,
                **_location(node),
            }
        )

    stack: list[tuple[Any, list[str]]] = [(root, [])]
    visited = 0
    while stack:
        node, parents = stack.pop()
        visited += 1
        if visited > MAX_AST_NODES:
            raise SyntaxTraversalLimit(
                f"syntax tree exceeded the {MAX_AST_NODES} node traversal limit"
            )
        node_type = getattr(node, "type", "")
        container_kind = _class_or_container_kind(node_type)
        function_kind = _function_kind(node_type, parents)
        js_var_function = (
            _find_js_variable_function(node, source)
            if language_name in {"javascript", "typescript", "tsx"}
            else None
        )

        if container_kind:
            name = _identifier_from_node(node, source)
            if name:
                add_symbol(node, kind=container_kind, name=name, parents=parents)
                if len(symbols) >= MAX_SYMBOLS:
                    break
                stack.extend((child, [*parents, name]) for child in reversed(_children(node)))
                continue
        if function_kind:
            name = _identifier_from_node(node, source)
            if name:
                add_symbol(node, kind=function_kind, name=name, parents=parents)
            if len(symbols) >= MAX_SYMBOLS:
                break
            continue
        if js_var_function:
            name, kind, body_node = js_var_function
            add_symbol(node, kind=kind, name=name, parents=parents, body_node=body_node)
            if len(symbols) >= MAX_SYMBOLS:
                break
            continue
        stack.extend((child, parents) for child in reversed(_children(node)))

    return symbols[:MAX_SYMBOLS]


def _module_call_sites(
    root: Any,
    source: bytes,
    language_name: str,
    symbols: list[dict[str, object]],
) -> list[dict[str, object]]:
    excluded_ranges: list[tuple[int, int]] = []
    if language_name == "julia":
        for symbol in symbols:
            details = symbol.get("language_details")
            if not isinstance(details, dict):
                continue
            start = details.get("definition_signature_start_byte")
            end = details.get("definition_signature_end_byte")
            if isinstance(start, int) and isinstance(end, int):
                excluded_ranges.append((start, end))
    calls = _calls_in_node(
        root, source, language_name, exclude_ranges=excluded_ranges
    )
    ranges = [
        (
            int(symbol.get("start_byte") or 0),
            int(symbol.get("end_byte") or 0),
            str(symbol.get("qualname") or ""),
            str(symbol.get("symbol_id") or ""),
        )
        for symbol in symbols
        if symbol.get("kind") in FUNCTION_LIKE_KINDS
    ]
    for call in calls:
        start = int(call.get("start_byte") or 0)
        containing = [item for item in ranges if item[0] <= start <= item[1]]
        if containing:
            owner = min(containing, key=lambda item: item[1] - item[0])
            call["containing_symbol"] = owner[2]
            call["containing_symbol_id"] = owner[3]
        else:
            call["containing_symbol"] = None
            call["containing_symbol_id"] = None
    return calls


def _query_matches(
    language_name: str, query_text: str, root: Any
) -> list[tuple[int, dict[str, list[Any]]]]:
    try:
        from tree_sitter import Query, QueryCursor  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - dependency failure
        raise TreeSitterUnavailable("Install tree-sitter to enable syntax queries.") from exc
    language = make_language(language_name)
    try:
        query = Query(language, query_text)
        cursor = QueryCursor(query)
        return list(islice(cursor.matches(root), MAX_QUERY_MATCHES))
    except Exception as exc:
        raise TreeSitterUnavailable(f"Tree-sitter query failed for {language_name!r}.") from exc


def _capture_one(captures: dict[str, list[Any]], name: str) -> Any | None:
    values = captures.get(name) or []
    return values[0] if values else None


def _capture_many(captures: dict[str, list[Any]], name: str) -> list[Any]:
    return list(captures.get(name) or [])


def _style_symbols(
    path: str, language_name: str, root: Any, source: bytes
) -> list[dict[str, object]]:
    if language_name != "css":
        return []
    records: list[dict[str, object]] = []
    custom_properties: list[tuple[str, Any]] = []
    for _pattern_index, captures in _query_matches(language_name, CSS_STRUCTURE_QUERY, root):
        rule = _capture_one(captures, "rule")
        selectors = _capture_one(captures, "rule.selectors")
        if rule is not None and selectors is not None:
            properties: list[str] = []
            for property_node in _capture_many(captures, "rule.property"):
                value = _node_text(property_node, source).strip()
                if value and value not in properties:
                    properties.append(value)
            selector_text = _node_text(selectors, source).strip()
            for raw_selector in selector_text.split(","):
                selector = " ".join(raw_selector.split())
                if selector:
                    records.append(
                        {
                            "kind": "css_rule",
                            "name": selector,
                            "selector": selector,
                            "properties": properties[:80],
                            **_location(rule),
                        }
                    )
        media = _capture_one(captures, "media")
        if media is not None:
            text = _node_text(media, source).strip().split("{", 1)[0].strip()
            records.append(
                {
                    "kind": "media_query",
                    "name": " ".join(text.split()) or "@media",
                    **_location(media),
                }
            )
        keyframes = _capture_one(captures, "keyframes")
        keyframes_name = _capture_one(captures, "keyframes.name")
        if keyframes is not None and keyframes_name is not None:
            name = _node_text(keyframes_name, source).strip()
            if name:
                records.append({"kind": "keyframes", "name": name, **_location(keyframes)})
        property_node = _capture_one(captures, "property.name")
        if property_node is not None:
            name = _node_text(property_node, source).strip()
            if name.startswith("--"):
                custom_properties.append((name, property_node))
    for name, node in custom_properties:
        records.append(
            {
                "kind": "css_variable",
                "name": name,
                "properties": [name],
                **_location(node),
            }
        )
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[dict[str, object]] = []
    for record in records:
        key = (str(record.get("kind")), str(record.get("name")), record.get("start_line"))
        if key not in seen:
            seen.add(key)
            unique.append(record)
    return unique[:MAX_STYLE_RECORDS]


def _style_imports(
    path: str, language_name: str, root: Any, source: bytes
) -> list[dict[str, object]]:
    if language_name not in {"javascript", "typescript", "tsx"}:
        return []
    records: list[dict[str, object]] = []
    for _pattern_index, captures in _query_matches(language_name, SCRIPT_STYLE_IMPORT_QUERY, root):
        for node in _capture_many(captures, "style.path"):
            value = _node_text(node, source).strip()
            if value.lower().endswith((".css", ".scss", ".sass", ".less")):
                records.append({"path": value, **_location(node)})
    seen: set[tuple[str, int | None]] = set()
    unique: list[dict[str, object]] = []
    for record in records:
        key = (str(record["path"]), record.get("start_line"))
        if key not in seen:
            seen.add(key)
            unique.append(record)
    return unique[:MAX_STYLE_IMPORTS]


def _is_parameter_name(value: str) -> bool:
    return bool(re.fullmatch(r"[^\W\d]\w*[!?]?", value, re.UNICODE))
