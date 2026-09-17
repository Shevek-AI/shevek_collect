from __future__ import annotations

import json
from .diagnostics import error_code
import re
import tomllib
from collections import defaultdict
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any, Iterable

from .syntax_contract import empty_syntax


_LITERAL_INCLUDE_RE = re.compile(
    r"(?:\bBase\s*\.\s*)?\binclude\s*\(\s*(?:raw)?(?P<literal>\"(?:\\.|[^\"\\])*\")",
    re.DOTALL,
)
_TOP_LEVEL_CONST_RE = re.compile(
    r"^const\s+(?P<name>[A-Za-z_][A-Za-z0-9_!]*)\s*(?:::[^=]+)?=",
    re.MULTILINE,
)


CALLABLE_KINDS = {
    "function",
    "async_function",
    "method",
    "constructor",
    "arrow_function",
    "macro",
}


def extract_project_toml(path: str, content: str) -> dict[str, object]:
    """Extract deterministic Julia package metadata from a Project.toml file."""
    try:
        parsed = tomllib.loads(content)
    except Exception as exc:
        return {
            "language": "toml",
            "parse": {
                "status": "parse_failed",
                "has_error_nodes": False,
                "error_node_count": 0,
                "missing_node_count": 0,
                "error": error_code(exc),
            },
            "syntax": _empty_syntax(package={}),
        }

    package = {
        key: parsed.get(key)
        for key in ("name", "uuid", "version")
        if parsed.get(key) is not None
    }
    for key in ("deps", "weakdeps", "extensions", "compat", "extras", "targets"):
        value = parsed.get(key)
        if isinstance(value, dict):
            package[key] = _normalise_toml_mapping(value)
    package["project_path"] = path
    return {
        "language": "toml",
        "parse": {
            "status": "parsed",
            "has_error_nodes": False,
            "error_node_count": 0,
            "missing_node_count": 0,
            "root_node_type": "toml_document",
        },
        "syntax": _empty_syntax(package=package),
    }


def compose_julia_snapshot(
    file_records: list[dict[str, object]],
    contents_by_path: dict[str, str],
) -> None:
    """Join independently parsed Julia files into package/module composition contexts.

    Tree-sitter describes one file at a time, while Julia evaluates literal `include`
    targets in the caller's module. This pass resolves only literal includes, propagates
    module ownership, applies exports/public declarations across included files, and
    preserves top-level execution as synthetic initializer symbols.
    """
    julia_records = {
        str(record.get("path")): record
        for record in file_records
        if record.get("language") == "julia" and isinstance(record.get("syntax"), dict)
    }
    if not julia_records:
        return

    package_by_root, project_entry_paths = _package_projects(file_records)
    raw_includes: dict[str, list[dict[str, object]]] = {}
    all_targets: set[str] = set()
    available_paths = {str(record.get("path") or "") for record in file_records}
    for path, record in julia_records.items():
        content = contents_by_path.get(path, "")
        includes = _include_records(path, content, record)
        for include in includes:
            resolved = str(include.get("resolved_path") or "")
            if include.get("status") == "resolved" and resolved not in available_paths:
                include["status"] = "missing_target"
        raw_includes[path] = includes
        all_targets.update(
            str(item["resolved_path"])
            for item in includes
            if item.get("status") == "resolved" and item.get("resolved_path") in julia_records
        )

    roots = set(project_entry_paths)
    roots.update(
        path
        for path, record in julia_records.items()
        if _module_symbols(record) and path not in all_targets
    )

    contexts_by_path: dict[str, set[str | None]] = defaultdict(set)
    visited: set[tuple[str, str | None]] = set()

    def visit(path: str, inherited_context: str | None) -> None:
        key = (path, inherited_context)
        if key in visited or path not in julia_records:
            return
        if len(visited) >= 10_000 or len(inherited_context or "") > 512:
            raise ValueError("julia_composition_limit")
        visited.add(key)
        contexts_by_path[path].add(inherited_context)
        record = julia_records[path]
        for include in raw_includes.get(path, []):
            if include.get("status") != "resolved":
                continue
            target = str(include.get("resolved_path") or "")
            if target not in julia_records:
                continue
            call_context = _module_context_at(
                record,
                int(include.get("start_byte") or 0),
                inherited_context,
            )
            include["module_context"] = call_context
            visit(target, call_context)

    for root in sorted(roots):
        visit(root, None)
    for path in sorted(julia_records):
        if path not in contexts_by_path:
            contexts_by_path[path].add(None)

    # Project context is useful even for scripts that use the package rather
    # than being included by it.
    package_context_by_path: dict[str, dict[str, object]] = {}
    for path in julia_records:
        project = _nearest_project(path, package_by_root)
        if project:
            package_context_by_path[path] = project

    module_imports: dict[str, set[str]] = defaultdict(set)
    module_exports: dict[str, set[str]] = defaultdict(set)
    module_publics: dict[str, set[str]] = defaultdict(set)
    module_bindings: dict[str, set[str]] = defaultdict(set)

    for path, record in julia_records.items():
        syntax = _syntax(record)
        content = contents_by_path.get(path, "")
        fallback_exports, fallback_publics = _visibility_from_content(content)
        if not _string_rows(syntax.get("exports")) and fallback_exports:
            syntax["exports"] = fallback_exports
        if not _string_rows(syntax.get("publics")) and fallback_publics:
            syntax["publics"] = fallback_publics
        existing_names = {
            str(symbol.get("name") or "") for symbol in _dict_rows(syntax.get("symbols"))
        }
        fallback_bindings = [
            binding
            for binding in _top_level_constant_symbols(path, content)
            if str(binding.get("name") or "") not in existing_names
        ]
        if fallback_bindings:
            syntax["symbols"] = [*_dict_rows(syntax.get("symbols")), *fallback_bindings]
        contexts = contexts_by_path[path]
        for context in contexts:
            for import_record in _dict_rows(syntax.get("imports")):
                target = str(import_record.get("target") or "").strip()
                if target and context:
                    module_imports[context].add(target)
            if context:
                module_exports[context].update(_string_rows(syntax.get("exports")))
                module_publics[context].update(_string_rows(syntax.get("publics")))
                for symbol in _dict_rows(syntax.get("symbols")):
                    if _symbol_belongs_to_context(symbol, context):
                        module_bindings[context].add(str(symbol.get("name") or ""))
        # Export declarations inside a wrapper module belong to that module even
        # when the file context is None.
        for module in _module_symbols(record):
            context = str(module.get("qualname") or module.get("name") or "")
            if not context:
                continue
            module_exports[context].update(_string_rows(syntax.get("exports")))
            module_publics[context].update(_string_rows(syntax.get("publics")))
            for import_record in _dict_rows(syntax.get("imports")):
                target = str(import_record.get("target") or "").strip()
                if target:
                    module_imports[context].add(target)
            for symbol in _dict_rows(syntax.get("symbols")):
                if _symbol_belongs_to_context(symbol, context):
                    module_bindings[context].add(str(symbol.get("name") or ""))

    for path, record in julia_records.items():
        original_syntax = deepcopy(_syntax(record))
        contexts = sorted(contexts_by_path[path], key=lambda value: value or "")
        composed_symbols: list[dict[str, object]] = []
        composed_scopes: list[dict[str, object]] = []
        composed_calls: list[dict[str, object]] = []
        composed_includes: list[dict[str, object]] = []

        for context in contexts:
            symbols = [
                _rewrite_symbol(
                    path,
                    symbol,
                    context,
                    module_imports,
                    module_exports,
                    module_publics,
                )
                for symbol in _dict_rows(original_syntax.get("symbols"))
            ]
            symbol_id_map = {
                str(old.get("symbol_id") or ""): str(new.get("symbol_id") or "")
                for old, new in zip(
                    _dict_rows(original_syntax.get("symbols")),
                    symbols,
                    strict=False,
                )
            }
            qualname_map = {
                str(old.get("qualname") or ""): str(new.get("qualname") or "")
                for old, new in zip(
                    _dict_rows(original_syntax.get("symbols")),
                    symbols,
                    strict=False,
                )
            }

            include_by_span = {
                (
                    int(include.get("start_byte") or 0),
                    int(include.get("end_byte") or 0),
                ): include
                for include in raw_includes.get(path, [])
            }
            calls = []
            for call in _dict_rows(original_syntax.get("call_sites")):
                cloned = deepcopy(call)
                owner_id = str(cloned.get("containing_symbol_id") or "")
                owner_name = str(cloned.get("containing_symbol") or "")
                if owner_id in symbol_id_map:
                    cloned["containing_symbol_id"] = symbol_id_map[owner_id]
                if owner_name in qualname_map:
                    cloned["containing_symbol"] = qualname_map[owner_name]
                cloned["module_context"] = _module_context_at(
                    record, int(cloned.get("start_byte") or 0), context
                )
                include = include_by_span.get(
                    (
                        int(cloned.get("start_byte") or 0),
                        int(cloned.get("end_byte") or 0),
                    )
                )
                if include is not None:
                    cloned["include_status"] = include.get("status")
                    cloned["resolved_include_path"] = include.get("resolved_path")
                calls.append(cloned)

            top_level_groups: dict[str | None, list[dict[str, object]]] = defaultdict(list)
            for call in calls:
                if not call.get("containing_symbol_id"):
                    top_level_groups[
                        str(call.get("module_context")) if call.get("module_context") else None
                    ].append(call)
            initializer_contexts: set[str | None] = set()
            for call_context, top_level_calls in top_level_groups.items():
                initializer = _initializer_symbol(
                    path=path,
                    context=call_context,
                    calls=top_level_calls,
                    imports=(
                        sorted(module_imports.get(call_context, set())) if call_context else []
                    ),
                    original_symbols=symbols,
                    content=contents_by_path.get(path, ""),
                )
                symbols.append(initializer)
                initializer_contexts.add(call_context)
                for call in top_level_calls:
                    call["containing_symbol"] = initializer["qualname"]
                    call["containing_symbol_id"] = initializer["symbol_id"]
            if context and context not in initializer_contexts:
                symbols.append(
                    _initializer_symbol(
                        path=path,
                        context=context,
                        calls=[],
                        imports=sorted(module_imports.get(context, set())),
                        original_symbols=symbols,
                        content=contents_by_path.get(path, ""),
                    )
                )

            scopes = [
                _rewrite_scope(path, scope, context, module_bindings)
                for scope in _dict_rows(original_syntax.get("scopes"))
            ]
            composed_symbols.extend(symbols)
            composed_calls.extend(calls)
            composed_scopes.extend(scopes)
            for include in raw_includes.get(path, []):
                cloned_include = deepcopy(include)
                cloned_include["module_context"] = _module_context_at(
                    record, int(cloned_include.get("start_byte") or 0), context
                )
                if cloned_include not in composed_includes:
                    composed_includes.append(cloned_include)

        syntax = _syntax(record)
        syntax["symbols"] = _dedupe_dicts(composed_symbols, ("symbol_id",))
        syntax["call_sites"] = _dedupe_dicts(
            composed_calls, ("start_byte", "end_byte", "callee", "containing_symbol_id")
        )
        syntax["scopes"] = _dedupe_dicts(composed_scopes, ("scope_id", "module_context"))
        syntax["includes"] = composed_includes
        wrapper_modules = {
            str(symbol.get("qualname") or symbol.get("name") or "")
            for symbol in _module_symbols(record)
            if str(symbol.get("qualname") or symbol.get("name") or "")
        }
        syntax["module_contexts"] = sorted(
            {value for value in contexts if value} | wrapper_modules
        )
        package = package_context_by_path.get(path)
        if package:
            syntax["package_context"] = dict(package)


def _normalise_toml_mapping(value: dict[str, Any]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(item, dict):
            result[str(key)] = _normalise_toml_mapping(item)
        elif isinstance(item, list):
            result[str(key)] = [str(part) for part in item]
        elif isinstance(item, (str, int, float, bool)) or item is None:
            result[str(key)] = item
        else:
            result[str(key)] = str(item)
    return result


def _visibility_from_content(content: str) -> tuple[list[str], list[str]]:
    """Fallback for older bundles and parser grammar differences."""
    exported: set[str] = set()
    public: set[str] = set()
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("export "):
            exported.update(part.strip() for part in line[7:].split(",") if part.strip())
        elif line.startswith("public "):
            public.update(part.strip() for part in line[7:].split(",") if part.strip())
    return sorted(exported), sorted(public)


def _top_level_constant_symbols(path: str, content: str) -> list[dict[str, object]]:
    symbols: list[dict[str, object]] = []
    for match in _TOP_LEVEL_CONST_RE.finditer(content):
        name = match.group("name")
        start = match.start()
        line = content[:start].count("\n") + 1
        line_end = content.find("\n", start)
        end = len(content) if line_end < 0 else line_end
        symbols.append(
            {
                "symbol_id": f"{path}::{name}",
                "kind": "constant",
                "name": name,
                "qualname": name,
                "signature": content[start:end].strip(),
                "parameters_text": None,
                "inputs": [],
                "imports": [],
                "raw_calls": [],
                "declaration_group_id": None,
                "is_exported": False,
                "language_details": {
                    "declaring_module": None,
                    "is_public": False,
                    "fallback_extraction": "top_level_const",
                },
                "start_byte": len(content[:start].encode("utf-8")),
                "end_byte": len(content[:end].encode("utf-8")),
                "start_line": line,
                "end_line": line,
            }
        )
    return symbols


def _empty_syntax(*, package: dict[str, object]) -> dict[str, object]:
    return empty_syntax(package=package)


def _syntax(record: dict[str, object]) -> dict[str, object]:
    value = record.get("syntax")
    if not isinstance(value, dict):
        value = {}
        record["syntax"] = value
    return value


def _dict_rows(value: object) -> list[dict[str, object]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _string_rows(value: object) -> list[str]:
    return [str(item) for item in value if str(item)] if isinstance(value, list) else []


def _module_symbols(record: dict[str, object]) -> list[dict[str, object]]:
    return [
        item
        for item in _dict_rows(_syntax(record).get("symbols"))
        if item.get("kind") == "module"
    ]


def _package_projects(
    file_records: list[dict[str, object]],
) -> tuple[dict[str, dict[str, object]], set[str]]:
    projects: dict[str, dict[str, object]] = {}
    entries: set[str] = set()
    available_paths = {str(record.get("path")) for record in file_records}
    for record in file_records:
        path = str(record.get("path") or "")
        if PurePosixPath(path).name != "Project.toml":
            continue
        package = _syntax(record).get("package")
        if not isinstance(package, dict):
            continue
        root = str(PurePosixPath(path).parent)
        root = "" if root == "." else root
        project = dict(package)
        project["project_root"] = root
        projects[root] = project
        name = str(package.get("name") or "").strip()
        if name:
            entry = str(PurePosixPath(root) / "src" / f"{name}.jl") if root else f"src/{name}.jl"
            if entry in available_paths:
                entries.add(entry)
    return projects, entries


def _nearest_project(path: str, projects: dict[str, dict[str, object]]) -> dict[str, object] | None:
    candidates = [
        (root, project)
        for root, project in projects.items()
        if not root or path == root or path.startswith(f"{root}/")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: len(item[0]))[1]


def _include_records(
    path: str,
    content: str,
    record: dict[str, object],
) -> list[dict[str, object]]:
    includes: list[dict[str, object]] = []
    for call in _dict_rows(_syntax(record).get("call_sites")):
        if str(call.get("callee") or "").split(".")[-1] != "include":
            continue
        start = int(call.get("start_byte") or 0)
        end = int(call.get("end_byte") or start)
        snippet = content[start:end]
        match = _LITERAL_INCLUDE_RE.search(snippet)
        target: str | None = None
        if match:
            try:
                target = json.loads(match.group("literal"))
            except Exception:
                target = None
        resolved = _resolve_relative(path, target) if target else None
        includes.append(
            {
                "kind": "julia_include",
                "target": target,
                "raw_text": snippet,
                "resolved_path": resolved,
                "status": "resolved" if resolved else "dynamic_or_nonliteral",
                "start_byte": start,
                "end_byte": end,
                "start_line": call.get("start_line"),
                "end_line": call.get("end_line"),
            }
        )
    return includes


def _resolve_relative(source_path: str, target: str) -> str:
    parent = PurePosixPath(source_path).parent
    parts: list[str] = []
    for part in (parent / target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _module_context_at(
    record: dict[str, object],
    byte_offset: int,
    inherited_context: str | None,
) -> str | None:
    containing = [
        module
        for module in _module_symbols(record)
        if int(module.get("start_byte") or 0) <= byte_offset <= int(module.get("end_byte") or 0)
    ]
    if not containing:
        return inherited_context
    module = min(
        containing,
        key=lambda item: int(item.get("end_byte") or 0) - int(item.get("start_byte") or 0),
    )
    raw = str(module.get("qualname") or module.get("name") or "").strip()
    if not raw:
        return inherited_context
    if (
        inherited_context
        and not raw.startswith(f"{inherited_context}.")
        and raw != inherited_context
    ):
        return f"{inherited_context}.{raw}"
    return raw


def _rewrite_symbol(
    path: str,
    raw_symbol: dict[str, object],
    context: str | None,
    module_imports: dict[str, set[str]],
    module_exports: dict[str, set[str]],
    module_publics: dict[str, set[str]],
) -> dict[str, object]:
    symbol = deepcopy(raw_symbol)
    details = (
        dict(symbol.get("language_details"))
        if isinstance(symbol.get("language_details"), dict)
        else {}
    )
    old_qualname = str(symbol.get("qualname") or symbol.get("name") or "")
    explicit = bool(details.get("explicitly_qualified_name"))
    kind = str(symbol.get("kind") or "")

    if context and old_qualname:
        if explicit and kind in CALLABLE_KINDS:
            new_qualname = old_qualname
        elif old_qualname == context or old_qualname.startswith(f"{context}."):
            new_qualname = old_qualname
        else:
            new_qualname = f"{context}.{old_qualname}"
    else:
        new_qualname = old_qualname

    symbol["qualname"] = new_qualname
    line = int(symbol.get("start_line") or 0)
    start = int(symbol.get("start_byte") or 0)
    if kind in {"method", "macro"}:
        symbol["symbol_id"] = f"{path}::{new_qualname}@{line}:{start}"
    else:
        symbol["symbol_id"] = f"{path}::{new_qualname}"

    declaring_module = context
    if kind == "module":
        declaring_module = new_qualname.rsplit(".", 1)[0] if "." in new_qualname else None
    details["declaring_module"] = declaring_module
    details["module_context"] = context
    if kind in {"method", "macro"}:
        generic_name = old_qualname if explicit else new_qualname
        details["generic_function_name"] = generic_name
        symbol["declaration_group_id"] = (
            f"julia:{'macro' if kind == 'macro' else 'function'}:{generic_name}"
        )

    name = str(symbol.get("name") or "")
    exports = module_exports.get(context or "", set())
    publics = module_publics.get(context or "", set())
    symbol["is_exported"] = bool(symbol.get("is_exported")) or name in exports
    details["is_public"] = bool(details.get("is_public")) or name in publics or name in exports
    symbol["language_details"] = details

    imports = (
        {str(item) for item in symbol.get("imports", []) if str(item)}
        if isinstance(symbol.get("imports"), list)
        else set()
    )
    if context:
        imports.update(module_imports.get(context, set()))
    symbol["imports"] = sorted(imports)

    # Raw call ownership is rewritten here so Trace can preserve correct locations.
    raw_calls = []
    for call in _dict_rows(symbol.get("raw_calls")):
        cloned = deepcopy(call)
        cloned["containing_symbol"] = new_qualname
        cloned["containing_symbol_id"] = symbol["symbol_id"]
        cloned["module_context"] = context
        raw_calls.append(cloned)
    symbol["raw_calls"] = raw_calls
    return symbol


def _symbol_belongs_to_context(symbol: dict[str, object], context: str) -> bool:
    details = symbol.get("language_details")
    declaring = str(details.get("declaring_module") or "") if isinstance(details, dict) else ""
    return not declaring or declaring == context


def _initializer_symbol(
    *,
    path: str,
    context: str | None,
    calls: list[dict[str, object]],
    imports: list[str],
    original_symbols: list[dict[str, object]],
    content: str,
) -> dict[str, object]:
    stem = str(PurePosixPath(path).with_suffix(""))
    stem = re.sub(r"[^A-Za-z0-9_]+", "__", stem).strip("_") or "file"
    if context:
        kind = "module_initializer"
        name = f"__file_init__{stem}"
        qualname = f"{context}.{name}"
        signature = f"module initializer {path}"
    else:
        kind = "script_entrypoint"
        name = "__toplevel__"
        qualname = f"{stem}.{name}"
        signature = f"script entrypoint {path}"
    symbol_id = f"{path}::{qualname}@synthetic"
    owned_calls = []
    for call in calls:
        cloned = deepcopy(call)
        cloned["containing_symbol"] = qualname
        cloned["containing_symbol_id"] = symbol_id
        owned_calls.append(cloned)
    end_line = max(1, content.count("\n") + 1)
    return {
        "symbol_id": symbol_id,
        "kind": kind,
        "name": name,
        "qualname": qualname,
        "signature": signature,
        "parameters_text": None,
        "inputs": [],
        "imports": imports,
        "raw_calls": owned_calls,
        "declaration_group_id": None,
        "is_exported": False,
        "language_details": {
            "declaring_module": context,
            "module_context": context,
            "synthetic": True,
            "top_level_execution": True,
            "declared_symbol_count": len(original_symbols),
        },
        "start_byte": 0,
        "end_byte": len(content.encode("utf-8")),
        "start_line": 1,
        "end_line": end_line,
    }


def _rewrite_scope(
    path: str,
    raw_scope: dict[str, object],
    context: str | None,
    module_bindings: dict[str, set[str]],
) -> dict[str, object]:
    scope = deepcopy(raw_scope)
    scope["module_context"] = context
    scope_id = str(scope.get("scope_id") or "")
    if context:
        scope["scope_id"] = f"{scope_id}::module:{context}"
        parent = scope.get("parent_scope_id")
        if parent:
            scope["parent_scope_id"] = f"{parent}::module:{context}"
        hard = scope.get("enclosing_hard_scope_id")
        if hard:
            scope["enclosing_hard_scope_id"] = f"{hard}::module:{context}"
        global_id = scope.get("global_scope_id")
        if global_id:
            scope["global_scope_id"] = f"{global_id}::module:{context}"
        if scope.get("kind") == "source_file":
            scope["name"] = context

    if (
        context
        and scope.get("scope_class") == "soft"
        and not scope.get("enclosing_hard_scope_id")
    ):
        assignments = (
            {str(item) for item in scope.get("assignments", []) if str(item)}
            if isinstance(scope.get("assignments"), list)
            else set()
        )
        explicit = {
            str(item)
            for key in ("explicit_globals", "explicit_locals")
            for item in (scope.get(key, []) if isinstance(scope.get(key), list) else [])
            if str(item)
        }
        existing = (
            {
                str(item)
                for item in scope.get("ambiguous_global_assignments", [])
                if str(item)
            }
            if isinstance(scope.get("ambiguous_global_assignments"), list)
            else set()
        )
        scope["ambiguous_global_assignments"] = sorted(
            existing | ((assignments & module_bindings.get(context, set())) - explicit)
        )
    return scope


def _dedupe_dicts(
    rows: Iterable[dict[str, object]], keys: tuple[str, ...]
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for row in rows:
        key = tuple(row.get(item) for item in keys)
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result
