from __future__ import annotations

from pathlib import Path

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".cs": "c_sharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c++": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".h++": "cpp",
    ".h": "cpp",
    ".css": "css",
    ".jl": "julia",
    ".sql": "sql",
}

LANGUAGE_LABELS: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "tsx": "typescript",
    "java": "java",
    "c_sharp": "csharp",
    "cpp": "cpp",
    "css": "css",
    "julia": "julia",
    "sql": "sql",
}

SOURCE_SUFFIXES = set(LANGUAGE_BY_SUFFIX)

FUNCTION_LIKE_KINDS = {
    "function",
    "async_function",
    "method",
    "constructor",
    "destructor",
    "arrow_function",
    "macro",
    "module_initializer",
    "script_entrypoint",
}


def language_for_path(path: str | Path) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(Path(str(path)).suffix.lower())


def language_label(language_name: str | None) -> str | None:
    if language_name is None:
        return None
    return LANGUAGE_LABELS.get(language_name, language_name)


def is_source_path(path: str | Path) -> bool:
    return language_for_path(path) is not None
