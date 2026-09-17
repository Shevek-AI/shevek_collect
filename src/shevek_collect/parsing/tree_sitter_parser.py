from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable

from .languages import language_for_path


class TreeSitterUnavailable(RuntimeError):
    """Raised when Tree-sitter or a configured grammar package is unavailable."""


@dataclass(frozen=True)
class ParsedSource:
    path: str
    language_name: str
    content: str
    content_bytes: bytes
    tree: Any


GrammarFactory = Callable[[], Any]


def _bash_language() -> Any:
    return importlib.import_module("tree_sitter_bash").language()


def _python_language() -> Any:
    return importlib.import_module("tree_sitter_python").language()


def _javascript_language() -> Any:
    return importlib.import_module("tree_sitter_javascript").language()


def _typescript_language() -> Any:
    return importlib.import_module("tree_sitter_typescript").language_typescript()


def _tsx_language() -> Any:
    return importlib.import_module("tree_sitter_typescript").language_tsx()


def _java_language() -> Any:
    return importlib.import_module("tree_sitter_java").language()


def _c_sharp_language() -> Any:
    return importlib.import_module("tree_sitter_c_sharp").language()


def _cpp_language() -> Any:
    return importlib.import_module("tree_sitter_cpp").language()


def _css_language() -> Any:
    return importlib.import_module("tree_sitter_css").language()


def _julia_language() -> Any:
    return importlib.import_module("tree_sitter_julia").language()


LANGUAGE_FACTORIES: dict[str, GrammarFactory] = {
    "bash": _bash_language,
    "python": _python_language,
    "javascript": _javascript_language,
    "typescript": _typescript_language,
    "tsx": _tsx_language,
    "java": _java_language,
    "c_sharp": _c_sharp_language,
    "cpp": _cpp_language,
    "css": _css_language,
    "julia": _julia_language,
}


def make_language(language_name: str) -> Any:
    try:
        from tree_sitter import Language  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - dependency failure
        raise TreeSitterUnavailable("Install tree-sitter to enable source parsing.") from exc
    factory = LANGUAGE_FACTORIES.get(language_name)
    if factory is None:
        raise TreeSitterUnavailable(f"Tree-sitter grammar is not configured for {language_name!r}.")
    try:
        capsule_or_language = factory()
        if isinstance(capsule_or_language, Language):
            return capsule_or_language
        return Language(capsule_or_language)
    except Exception as exc:  # pragma: no cover - dependency failure
        raise TreeSitterUnavailable(
            f"Tree-sitter grammar is not available for {language_name!r}."
        ) from exc


def make_parser(language_name: str) -> Any:
    try:
        from tree_sitter import Parser  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - dependency failure
        raise TreeSitterUnavailable("Install tree-sitter to enable source parsing.") from exc
    language = make_language(language_name)
    try:
        return Parser(language)
    except TypeError:
        parser = Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language
        return parser


def parse_source(path: str, content: str) -> ParsedSource | None:
    language_name = language_for_path(path)
    if language_name is None:
        return None
    parser = make_parser(language_name)
    content_bytes = content.encode("utf-8", errors="replace")
    tree = parser.parse(content_bytes)
    return ParsedSource(
        path=path,
        language_name=language_name,
        content=content,
        content_bytes=content_bytes,
        tree=tree,
    )
