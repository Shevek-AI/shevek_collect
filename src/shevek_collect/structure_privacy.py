"""Positive export policy for operational structure, independent of raw parsing.

Names and paths are intentionally disclosed. Arbitrary literal values are not.
New parser fields are omitted until this policy explicitly handles them.
"""
from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit, urlunsplit

OMITTED = "<omitted-literal>"
_NAME = re.compile(r"^[\w@./:+${}!?*<>~-]{1,512}$", re.UNICODE)
_OPTION = re.compile(r"^--?[A-Za-z][A-Za-z0-9_-]*$")


def safe_reference(value: object) -> str:
    if not isinstance(value, str):
        return OMITTED
    if "://" in value:
        return strip_url_credentials(value)
    return value if _NAME.fullmatch(value) else OMITTED


def strip_url_credentials(value: str) -> str:
    """Preserve locator identity, excluding authentication, query and fragment."""
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            return OMITTED
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        if parsed.port is not None:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        return OMITTED


def _arguments(value: object, *, executable: bool = False) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for index, item in enumerate(value[:256]):
        token = str(item)
        if index == 0 and executable:
            result.append(safe_reference(token))
        elif _OPTION.fullmatch(token):
            result.append(token)
        elif token.startswith("-") and "=" in token and _OPTION.fullmatch(token.split("=", 1)[0]):
            result.append(token.split("=", 1)[0] + "=" + OMITTED)
        else:
            result.append(OMITTED)
    return result


_IDENTITIES = frozenset({
    "kind", "name", "stage", "service", "resource", "resource_kind", "container",
    "container_group", "instruction", "form", "manager", "source_kind", "format",
    "source_context", "workflow_job", "workflow_step", "job", "step", "shell",
    "executable", "base_image", "platform", "from_stage", "destination", "context",
    "dockerfile", "target", "api_version", "version", "backend", "group", "probe",
    "assignment_value_kind", "assignment_operator",
})
_LISTS = frozenset({"sources", "platforms", "top_level_keys", "requires", "lock_enforcement_flags"})
_NUMBERS = frozenset({
    "start_line", "end_line", "start_byte", "end_byte", "document_index", "wheel_count",
    "has_default", "immutable_revision", "digest_pinned", "tag_reference", "lock_enforced",
    "manifest_install", "platform_specific_wheel", "lock_revision", "lock_version",
})
_REFERENCE_VALUES = frozenset({
    "base_image", "build_input", "container_stage_reference", "container_image",
    "service_dependency", "workflow_job_dependency", "workflow_action", "external_download",
    "script_source", "script_execution", "dependency_manifest", "dependency_lock",
})


def sanitize_operational_structure(structure: dict[str, object]) -> dict[str, object]:
    result = {key: structure.get(key) for key in ("schema_version", "artifact_kind", "format")}
    parse = structure.get("parse")
    result["parse"] = {
        key: value for key, value in (parse.items() if isinstance(parse, dict) else [])
        if isinstance(value, (bool, int)) or key in {"status", "error"}
    }
    result["literal_values_omitted"] = True
    for category in ("entities", "operations", "references", "controls"):
        rows = structure.get(category)
        output = []
        for row in rows[:5000] if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            cleaned: dict[str, object] = {}
            for key, value in row.items():
                if key in _IDENTITIES:
                    cleaned[key] = safe_reference(value) if value is not None else None
                elif key in _NUMBERS and isinstance(value, (int, bool)):
                    cleaned[key] = value
                elif key in _LISTS and isinstance(value, list):
                    cleaned[key] = [safe_reference(item) for item in value[:256]]
                elif key in {"argv", "args", "flags"}:
                    # Docker/Compose argv contain the executable; shell argv
                    # and Kubernetes args do not.
                    has_executable = key == "argv" and "executable" not in row
                    cleaned[key] = _arguments(value, executable=has_executable)
                elif key == "command":
                    if isinstance(value, list):
                        cleaned[key] = _arguments(value, executable=True)
                    elif isinstance(value, str):
                        try:
                            cleaned[key] = shlex.join(_arguments(shlex.split(value), executable=True))
                        except ValueError:
                            cleaned[key] = OMITTED
                    else:
                        cleaned[key] = None
                elif key == "value":
                    cleaned[key] = (
                        safe_reference(value) if row.get("kind") in _REFERENCE_VALUES else OMITTED
                    )
                elif key in {"argument", "constraint", "requires_runtime", "requires_python"}:
                    cleaned[key] = OMITTED if value is not None else None
                # raw, defaults, and unrecognised fields have no export path.
            output.append(cleaned)
        result[category] = output
    return result


_SYNTAX_FIELDS = frozenset("""
schema_version symbols imports call_sites references scopes exports publics includes styles style_imports
kind name qualname symbol_id declaration_group_id signature parameters_text signature_fidelity inputs
raw_calls start_line end_line start_byte end_byte language_details modifiers declaration_only
qualified_declarator containing_symbol containing_symbol_id callee target target_kind target_form reference_id
system path resolved_path resolved_include_path include_status module_context module_contexts
scope_id parent_scope_id global_scope_id enclosing_hard_scope_id scope_class bindings assignments
explicit_globals explicit_locals ambiguous_global_assignments declaring_module is_exported is_public
generic_function_name explicitly_qualified_name positional_parameter_names keyword_names required_keyword_names
min_positional_arity max_positional_arity accepts_keyword_splat has_keyword_splat has_positional_splat
positional_argument_count is_broadcast_call is_macro_call definition_signature_start_byte definition_signature_end_byte
status fallback_extraction declared_symbol_count top_level_execution synthetic selector properties declarations
package package_context root project_path entry_path source_root dialect scanner parser validation_level
""".split())


def sanitize_syntax_fields(syntax: dict[str, object]) -> None:
    """New fields require explicit review; derived text is never a raw-source channel."""
    budget = 100_000

    def clean(value: object, key: str = "", depth: int = 0) -> object:
        nonlocal budget
        budget -= 1
        if budget < 0 or depth > 64:
            raise ValueError("structure_export_limit")
        if isinstance(value, dict):
            if key in {"package", "package_context"}:
                # Package metadata has caller-defined dependency keys. Keep only
                # the package identity; arbitrary nested TOML values are omitted.
                return {k: safe_reference(v) for k, v in value.items()
                        if k in {"name", "uuid", "version", "project_path", "root"} and isinstance(v, str)}
            return {k: clean(v, k, depth + 1) for k, v in value.items() if k in _SYNTAX_FIELDS}
        if isinstance(value, list):
            return [clean(item, key, depth + 1) for item in value]
        if isinstance(value, str):
            if key == "signature":
                # Generated by sanitize_syntax_for_structure_mode from validated names.
                return value
            if key == "selector":
                # CSS selector identity is useful; literal attribute values are not.
                value = re.sub(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' ''',
                               "<literal>", value, flags=re.X)
                return re.sub(r"(\[[^\]]*?=)[^\]]*(\])", r"\1<literal>\2", value)[:2048]
            return safe_reference(value)
        return value if value is None or isinstance(value, (bool, int, float)) else None

    cleaned = clean(syntax)
    assert isinstance(cleaned, dict)
    syntax.clear()
    syntax.update(cleaned)
