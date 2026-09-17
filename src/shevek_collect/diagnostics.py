"""Exportable diagnostics never contain parser source excerpts or OS paths."""
from __future__ import annotations

import re


def error_code(exc: BaseException) -> str:
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", name) else "Error"


def parse_diagnostic(exc: BaseException) -> dict[str, object]:
    result: dict[str, object] = {"error": error_code(exc)}
    mark = getattr(exc, "problem_mark", None)
    for output, attribute in (("error_line", "line"), ("error_column", "column")):
        value = getattr(mark, attribute, None)
        if isinstance(value, int) and 0 <= value < 10_000_000:
            result[output] = value + 1
    return result
