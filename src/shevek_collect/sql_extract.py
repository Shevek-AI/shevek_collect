from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .syntax_contract import empty_syntax

SQL_STRUCTURE_SCANNER_VERSION = "shevek_collect_sql_structure.v1"
MAX_SQL_TOKENS = 250_000
MAX_SQL_SYMBOLS = 2_000
MAX_SQL_REFERENCES = 10_000

_DECLARATION_KINDS = {
    "TABLE": "table",
    "VIEW": "view",
    "PROCEDURE": "procedure",
    "PROC": "procedure",
    "FUNCTION": "function",
    "TRIGGER": "trigger",
}
_PSEUDO_RELATIONS = {"inserted", "deleted"}
_CLAUSE_BOUNDARIES = {
    "WHERE",
    "GROUP",
    "ORDER",
    "HAVING",
    "OPTION",
    "WHEN",
    "SET",
    "VALUES",
    "OUTPUT",
    "RETURN",
    "UNION",
    "EXCEPT",
    "INTERSECT",
}
_ALIAS_STOP_WORDS = _CLAUSE_BOUNDARIES | {
    "JOIN",
    "LEFT",
    "RIGHT",
    "FULL",
    "INNER",
    "OUTER",
    "CROSS",
    "ON",
    "USING",
    "WITH",
    "AS",
}
_NON_OBJECT_KEYWORDS = _ALIAS_STOP_WORDS | {
    "AFTER",
    "BEFORE",
    "BEGIN",
    "BY",
    "CALL",
    "CREATE",
    "DELETE",
    "END",
    "EXEC",
    "EXECUTE",
    "FETCH",
    "FROM",
    "GO",
    "INSERT",
    "INTO",
    "MATCHED",
    "MERGE",
    "NEXT",
    "NOT",
    "SELECT",
    "TABLE",
    "THEN",
    "TOP",
    "TRIGGER",
    "TRUNCATE",
    "UPDATE",
    "VIEW",
}


@dataclass(frozen=True)
class SqlToken:
    text: str
    kind: str
    start_char: int
    end_char: int
    start_byte: int
    end_byte: int
    line: int
    end_line: int

    @property
    def upper(self) -> str:
        return self.text.upper()


@dataclass(frozen=True)
class SqlDeclaration:
    kind: str
    qualname: str
    start_index: int
    body_start_index: int
    end_index: int


def extract_sql_syntax(path: str, content: str) -> dict[str, object]:
    """Extract conservative SQL structural observations without executing SQL.

    This is intentionally a dialect-neutral structural scanner rather than a validating
    grammar. It recognises common SQL forms plus a bounded set of widespread dialect
    extensions. Ambiguous or dynamic forms are retained as such instead of being guessed.
    """

    try:
        tokens = _tokenize(content)
        if len(tokens) > MAX_SQL_TOKENS:
            raise ValueError(f"SQL token stream exceeded {MAX_SQL_TOKENS} tokens")
        declarations = _declarations(tokens)
        symbols = _symbols(path, tokens, declarations)
        references = _references(path, tokens, declarations, symbols)
        syntax = empty_syntax()
        syntax["symbols"] = symbols
        syntax["references"] = references
        return {
            "language": "sql",
            "parse": {
                "status": "parsed",
                "has_error_nodes": False,
                "error_node_count": 0,
                "missing_node_count": 0,
                "parser": SQL_STRUCTURE_SCANNER_VERSION,
                "validation_level": "structural_scan",
                "dialect": "unknown",
            },
            "syntax": syntax,
        }
    except Exception as exc:
        return {
            "language": "sql",
            "parse": {
                "status": "parse_failed",
                "has_error_nodes": False,
                "error_node_count": 0,
                "missing_node_count": 0,
                "parser": SQL_STRUCTURE_SCANNER_VERSION,
                "validation_level": "structural_scan",
                "dialect": "unknown",
                "error": type(exc).__name__,
            },
            "syntax": empty_syntax(),
        }


def _byte_offsets(text: str) -> list[int]:
    offsets = [0] * (len(text) + 1)
    total = 0
    for index, char in enumerate(text):
        offsets[index] = total
        total += len(char.encode("utf-8", errors="replace"))
    offsets[len(text)] = total
    return offsets


def _tokenize(text: str) -> list[SqlToken]:
    byte_offsets = _byte_offsets(text)
    tokens: list[SqlToken] = []
    i = 0
    line = 1
    length = len(text)

    def emit(start: int, end: int, kind: str, start_line: int, end_line: int | None = None) -> None:
        tokens.append(
            SqlToken(
                text=text[start:end],
                kind=kind,
                start_char=start,
                end_char=end,
                start_byte=byte_offsets[start],
                end_byte=byte_offsets[end],
                line=start_line,
                end_line=end_line if end_line is not None else start_line,
            )
        )

    while i < length:
        char = text[i]
        if char.isspace():
            if char == "\n":
                line += 1
            i += 1
            continue
        if text.startswith("--", i):
            newline = text.find("\n", i + 2)
            if newline < 0:
                break
            i = newline
            continue
        if text.startswith("/*", i):
            depth = 1
            i += 2
            while i < length and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if text[i] == "\n":
                        line += 1
                    i += 1
            continue
        if char in {"N", "n"} and i + 1 < length and text[i + 1] == "'":
            start = i
            start_line = line
            i += 1
            char = "'"
        else:
            start = i
            start_line = line
        if char == "'":
            i += 1
            while i < length:
                if text[i] == "\n":
                    line += 1
                if text[i] == "'":
                    if i + 1 < length and text[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            emit(start, i, "string", start_line, line)
            continue
        if char == "[":
            i += 1
            while i < length:
                if text[i] == "]":
                    if i + 1 < length and text[i + 1] == "]":
                        i += 2
                        continue
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            emit(start, i, "identifier", start_line, line)
            continue
        if char == '"':
            i += 1
            while i < length:
                if text[i] == '"':
                    if i + 1 < length and text[i + 1] == '"':
                        i += 2
                        continue
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            emit(start, i, "identifier", start_line, line)
            continue
        if char == "`":
            i += 1
            while i < length:
                if text[i] == "`":
                    if i + 1 < length and text[i + 1] == "`":
                        i += 2
                        continue
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            emit(start, i, "identifier", start_line, line)
            continue
        if char == "@":
            i += 1
            while i < length and (text[i].isalnum() or text[i] in {"_", "$", "#"}):
                i += 1
            emit(start, i, "variable", start_line)
            continue
        if char.isalpha() or char in {"_", "#"}:
            i += 1
            while i < length and (text[i].isalnum() or text[i] in {"_", "$", "#"}):
                i += 1
            emit(start, i, "word", start_line)
            continue
        if char.isdigit():
            i += 1
            while i < length and (text[i].isalnum() or text[i] in {".", "_"}):
                i += 1
            emit(start, i, "number", start_line)
            continue
        emit(start, i + 1, "punct", start_line)
        i += 1
    return tokens


def _identifier_text(token: SqlToken) -> str:
    text = token.text
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1].replace("]]", "]")
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1].replace('""', '"')
    if text.startswith("`") and text.endswith("`"):
        return text[1:-1].replace("``", "`")
    return text


def _name_at(tokens: list[SqlToken], index: int) -> tuple[str | None, int, str]:
    if index >= len(tokens):
        return None, index, "identifier"
    first = tokens[index]
    if first.kind == "variable":
        return None, index + 1, "dynamic"
    if first.text == "(" or first.kind not in {"word", "identifier"}:
        return None, index + 1, "dynamic"
    if first.kind == "word" and first.upper in _NON_OBJECT_KEYWORDS:
        return None, index + 1, "dynamic"
    parts = [_identifier_text(first)]
    end = index + 1
    while end + 1 < len(tokens) and tokens[end].text == ".":
        candidate = tokens[end + 1]
        if candidate.kind not in {"word", "identifier"}:
            break
        parts.append(_identifier_text(candidate))
        end += 2
    name = ".".join(parts)
    form = "temporary" if parts[-1].startswith("#") else "identifier"
    return name, end, form




def _skip_top_clause(tokens: list[SqlToken], index: int) -> int:
    """Skip the T-SQL TOP modifier before a DML target."""
    if index >= len(tokens) or tokens[index].upper != "TOP":
        return index
    index += 1
    if index < len(tokens) and tokens[index].text == "(":
        depth = 1
        index += 1
        while index < len(tokens) and depth:
            if tokens[index].text == "(":
                depth += 1
            elif tokens[index].text == ")":
                depth -= 1
            index += 1
    elif index < len(tokens):
        index += 1
    if index < len(tokens) and tokens[index].upper == "PERCENT":
        index += 1
    return index


def _declarations(tokens: list[SqlToken]) -> list[SqlDeclaration]:
    starts: list[tuple[str, str, int, int]] = []
    index = 0
    while index < len(tokens):
        if tokens[index].upper != "CREATE":
            index += 1
            continue
        cursor = index + 1
        if (
            cursor + 1 < len(tokens)
            and tokens[cursor].upper == "OR"
            and tokens[cursor + 1].upper in {"ALTER", "REPLACE"}
        ):
            cursor += 2
        if cursor >= len(tokens):
            break
        kind = _DECLARATION_KINDS.get(tokens[cursor].upper)
        if kind is None:
            index += 1
            continue
        name, after_name, _ = _name_at(tokens, cursor + 1)
        if not name:
            index += 1
            continue
        starts.append((kind, name, index, after_name))
        index = after_name

    declarations: list[SqlDeclaration] = []
    for offset, (kind, name, start_index, body_start) in enumerate(starts):
        next_start = starts[offset + 1][2] if offset + 1 < len(starts) else len(tokens)
        end_index = next_start
        for cursor in range(body_start, next_start):
            token = tokens[cursor]
            if token.upper == "GO" and (cursor == 0 or tokens[cursor - 1].line < token.line):
                end_index = cursor
                break
        declarations.append(
            SqlDeclaration(
                kind=kind,
                qualname=name,
                start_index=start_index,
                body_start_index=body_start,
                end_index=end_index,
            )
        )
    return declarations[:MAX_SQL_SYMBOLS]


def _location(start: SqlToken, end: SqlToken) -> dict[str, int]:
    return {
        "start_line": start.line,
        "end_line": end.end_line,
        "start_byte": start.start_byte,
        "end_byte": end.end_byte,
    }


def _symbols(
    path: str,
    tokens: list[SqlToken],
    declarations: list[SqlDeclaration],
) -> list[dict[str, object]]:
    symbols: list[dict[str, object]] = []
    for declaration in declarations:
        if declaration.start_index >= len(tokens):
            continue
        start = tokens[declaration.start_index]
        end_index = max(declaration.start_index, min(declaration.end_index - 1, len(tokens) - 1))
        end = tokens[end_index]
        name = declaration.qualname.rsplit(".", 1)[-1]
        symbols.append(
            {
                "symbol_id": f"{path}::{declaration.qualname}",
                "kind": declaration.kind,
                "name": name,
                "qualname": declaration.qualname,
                "signature": f"{declaration.kind} {declaration.qualname}",
                "parameters_text": None,
                "inputs": [],
                "imports": [],
                "raw_calls": [],
                "language_details": {
                    "dialect": "unknown",
                    "scanner": SQL_STRUCTURE_SCANNER_VERSION,
                },
                **_location(start, end),
            }
        )
    return symbols


def _owner_for_index(
    path: str,
    index: int,
    declarations: list[SqlDeclaration],
) -> tuple[str | None, str | None]:
    candidates = [
        declaration
        for declaration in declarations
        if declaration.start_index <= index < declaration.end_index
    ]
    if not candidates:
        return None, None
    owner = max(candidates, key=lambda item: item.start_index)
    return owner.qualname, f"{path}::{owner.qualname}"


def _statement_range(tokens: list[SqlToken], index: int) -> tuple[int, int]:
    start = index
    while start > 0:
        previous = tokens[start - 1]
        if previous.text == ";" or previous.upper == "GO":
            break
        start -= 1
    end = index + 1
    while end < len(tokens):
        current = tokens[end]
        if current.text == ";" or current.upper == "GO":
            break
        end += 1
    return start, end


def _local_ctes(tokens: list[SqlToken], start: int, end: int) -> set[str]:
    names: set[str] = set()
    index = start
    if index < end and tokens[index].upper == "WITH":
        index += 1
        while index < end:
            name, after_name, _ = _name_at(tokens, index)
            if not name or after_name >= end or tokens[after_name].upper != "AS":
                break
            if after_name + 1 >= end or tokens[after_name + 1].text != "(":
                break
            names.add(name.lower())
            depth = 1
            cursor = after_name + 2
            while cursor < end and depth:
                if tokens[cursor].text == "(":
                    depth += 1
                elif tokens[cursor].text == ")":
                    depth -= 1
                cursor += 1
            if cursor < end and tokens[cursor].text == ",":
                index = cursor + 1
                continue
            break
    return names


def _aliases(tokens: list[SqlToken], start: int, end: int) -> dict[str, str]:
    aliases: dict[str, str] = {}
    cursor = start
    while cursor < end:
        if tokens[cursor].upper not in {"FROM", "JOIN", "APPLY"}:
            cursor += 1
            continue
        name, after_name, form = _name_at(tokens, cursor + 1)
        if not name or form != "identifier":
            cursor += 1
            continue
        alias_index = after_name
        if alias_index < end and tokens[alias_index].upper == "AS":
            alias_index += 1
        if alias_index < end:
            alias = tokens[alias_index]
            if alias.kind in {"word", "identifier"} and alias.upper not in _ALIAS_STOP_WORDS:
                aliases[_identifier_text(alias).lower()] = name
        cursor = max(cursor + 1, after_name)
    return aliases


def _reference_record(
    *,
    path: str,
    kind: str,
    target: str | None,
    target_kind: str,
    target_form: str,
    token: SqlToken,
    end_token: SqlToken,
    declarations: list[SqlDeclaration],
    index: int,
) -> dict[str, object]:
    owner, owner_id = _owner_for_index(path, index, declarations)
    return {
        "reference_id": f"{path}::{token.start_byte}:{kind}:{target or '<dynamic>'}",
        "kind": kind,
        "target": target,
        "target_kind": target_kind,
        "target_form": target_form,
        "containing_symbol": owner,
        "containing_symbol_id": owner_id,
        "language_details": {"dialect": "unknown"},
        **_location(token, end_token),
    }


def _references(
    path: str,
    tokens: list[SqlToken],
    declarations: list[SqlDeclaration],
    symbols: list[dict[str, object]],
) -> list[dict[str, object]]:
    references: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()

    def add(
        index: int,
        kind: str,
        target: str | None,
        target_kind: str,
        form: str,
        end_index: int,
    ) -> None:
        if len(references) >= MAX_SQL_REFERENCES:
            return
        if target and target.lower() in _PSEUDO_RELATIONS:
            return
        key = (index, kind, target, target_kind, form)
        if key in seen:
            return
        seen.add(key)
        references.append(
            _reference_record(
                path=path,
                kind=kind,
                target=target,
                target_kind=target_kind,
                target_form=form,
                token=tokens[index],
                end_token=tokens[max(index, min(end_index - 1, len(tokens) - 1))],
                declarations=declarations,
                index=index,
            )
        )

    # Trigger attachment is a definition relationship, not a read.
    for declaration in declarations:
        if declaration.kind != "trigger":
            continue
        cursor = declaration.body_start_index
        while cursor < declaration.end_index:
            if tokens[cursor].upper == "ON":
                target, after, form = _name_at(tokens, cursor + 1)
                if target:
                    add(cursor, "defined_on", target, "relation", form, after)
                break
            cursor += 1

    index = 0
    while index < len(tokens):
        upper = tokens[index].upper
        statement_start, statement_end = _statement_range(tokens, index)
        ctes = _local_ctes(tokens, statement_start, statement_end)
        aliases = _aliases(tokens, statement_start, statement_end)

        if upper in {"FROM", "JOIN", "APPLY"}:
            if (
                upper == "FROM"
                and index >= 2
                and tokens[index - 2].upper == "FETCH"
                and tokens[index - 1].upper
                in {"NEXT", "PRIOR", "FIRST", "LAST", "ABSOLUTE", "RELATIVE"}
            ):
                index += 1
                continue
            target, after, form = _name_at(tokens, index + 1)
            if target and target.lower() not in ctes:
                target_kind = (
                    "routine"
                    if after < len(tokens) and tokens[after].text == "("
                    else "relation"
                )
                add(index, "read", target, target_kind, form, after)
                index = max(index + 1, after)
                continue

        if upper == "USING" and any(
            token.upper == "MERGE" for token in tokens[statement_start:index]
        ):
            target, after, form = _name_at(tokens, index + 1)
            if target and target.lower() not in ctes:
                target_kind = (
                    "routine"
                    if after < len(tokens) and tokens[after].text == "("
                    else "relation"
                )
                add(index, "read", target, target_kind, form, after)
                index = max(index + 1, after)
                continue

        if upper == "UPDATE":
            cursor = _skip_top_clause(tokens, index + 1)
            target, after, form = _name_at(tokens, cursor)
            if target:
                resolved = aliases.get(target.lower(), target)
                add(index, "write", resolved, "relation", form, after)
                index = max(index + 1, after)
                continue

        if upper == "INSERT":
            cursor = _skip_top_clause(tokens, index + 1)
            if cursor < len(tokens) and tokens[cursor].upper == "INTO":
                cursor += 1
            target, after, form = _name_at(tokens, cursor)
            if target:
                add(index, "write", target, "relation", form, after)
                index = max(index + 1, after)
                continue

        if upper == "DELETE":
            cursor = _skip_top_clause(tokens, index + 1)
            if cursor < len(tokens) and tokens[cursor].upper == "FROM":
                cursor += 1
            target, after, form = _name_at(tokens, cursor)
            if target:
                resolved = aliases.get(target.lower(), target)
                add(index, "write", resolved, "relation", form, after)
                index = max(index + 1, after)
                continue

        if upper == "MERGE":
            cursor = index + 1
            if cursor < len(tokens) and tokens[cursor].upper == "INTO":
                cursor += 1
            target, after, form = _name_at(tokens, cursor)
            if target:
                add(index, "write", target, "relation", form, after)
                index = max(index + 1, after)
                continue

        if upper == "TRUNCATE" and index + 1 < len(tokens) and tokens[index + 1].upper == "TABLE":
            target, after, form = _name_at(tokens, index + 2)
            if target:
                add(index, "write", target, "relation", form, after)
                index = max(index + 1, after)
                continue

        if upper == "INTO" and index > 0 and any(
            token.upper == "SELECT" for token in tokens[statement_start:index]
        ):
            target, after, form = _name_at(tokens, index + 1)
            if target:
                add(index, "write", target, "relation", form, after)
                index = max(index + 1, after)
                continue

        if upper in {"EXEC", "EXECUTE", "CALL"}:
            cursor = index + 1
            if cursor < len(tokens) and tokens[cursor].text == "(":
                add(index, "execute", None, "routine", "dynamic", cursor + 1)
                index += 1
                continue
            target, after, form = _name_at(tokens, cursor)
            if target:
                add(index, "execute", target, "routine", form, after)
                if target.lower().endswith("sp_executesql"):
                    add(index, "execute", None, "routine", "dynamic", after)
                index = max(index + 1, after)
                continue
            if form == "dynamic":
                add(index, "execute", None, "routine", "dynamic", after)

        if upper == "REFERENCES":
            target, after, form = _name_at(tokens, index + 1)
            if target:
                add(index, "reference", target, "relation", form, after)
                index = max(index + 1, after)
                continue

        index += 1

    references.sort(
        key=lambda item: (
            int(item.get("start_byte") or 0),
            str(item.get("kind") or ""),
            str(item.get("target") or ""),
        )
    )
    return references[:MAX_SQL_REFERENCES]
