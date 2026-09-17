"""Bound repository parsing in a disposable process. Never evaluate source code.

This is resource containment, not an OS security sandbox. Native grammars and
the installed Python environment must still be trusted and kept up to date.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

PARSER_TIMEOUT_SECONDS = 10
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_RESULT_BYTES = 32 * 1024 * 1024
PARSER_MEMORY_BYTES = 768 * 1024 * 1024


class ParserBudgetExceeded(RuntimeError):
    pass


class ParserWorkerFailed(RuntimeError):
    pass


def run_parser(operation: str, payload: dict) -> dict:
    request = json.dumps({"operation": operation, "payload": payload}, ensure_ascii=False).encode()
    if len(request) > MAX_REQUEST_BYTES:
        raise ParserBudgetExceeded("Parser input limit")
    # -I ignores PYTHONPATH, the current directory, and user site packages. Use
    # this installed package's trusted location, including editable installs.
    package_root = str(Path(__file__).resolve().parent.parent)
    bootstrap = (
        f"import sys; sys.path.insert(0, {package_root!r}); "
        "from shevek_collect.parser_worker import _main; _main()"
    )
    permitted = {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR", "LANG"}
    env = {key: value for key, value in os.environ.items() if key.upper() in permitted}
    try:
        process = subprocess.run(
            [sys.executable, "-I", "-c", bootstrap], input=request,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=PARSER_TIMEOUT_SECONDS, env=env,
        )
    except subprocess.TimeoutExpired:
        raise ParserBudgetExceeded("Parser time limit") from None
    if process.returncode != 0:
        raise ParserWorkerFailed("Parser terminated")
    if len(process.stdout) > MAX_RESULT_BYTES:
        raise ParserBudgetExceeded("Parser output limit")
    try:
        result = json.loads(process.stdout)
    except (ValueError, UnicodeError):
        raise ParserWorkerFailed("Invalid parser response") from None
    if not isinstance(result, dict) or result.get("worker_error"):
        raise ParserWorkerFailed("Parser could not complete")
    return result


def _main() -> None:
    if os.name == "posix":
        import resource
        for kind, limits in (
            (resource.RLIMIT_AS, (PARSER_MEMORY_BYTES, PARSER_MEMORY_BYTES)),
            (resource.RLIMIT_CPU, (PARSER_TIMEOUT_SECONDS, PARSER_TIMEOUT_SECONDS)),
            (resource.RLIMIT_CORE, (0, 0)),
        ):
            soft, hard = resource.getrlimit(kind)
            cap = limits[1] if hard == resource.RLIM_INFINITY else min(hard, limits[1])
            resource.setrlimit(kind, (min(limits[0], cap), cap))
    try:
        data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(data) > MAX_REQUEST_BYTES:
            raise ParserBudgetExceeded("Parser input limit")
        request = json.loads(data)
        payload = request["payload"]
        if request["operation"] == "file":
            from .julia_package import extract_project_toml
            from .operational_extract import extract_operational_structure
            from .parsing import TreeSitterUnavailable, language_for_path
            from .syntax_extract import extract_syntax, parse_failed_result, parser_unavailable_result
            path, content = payload["path"], payload["content"]
            try:
                syntax = (extract_project_toml(path, content) if Path(path).name == "Project.toml"
                          else extract_syntax(path, content))
            except TreeSitterUnavailable as exc:
                syntax = parser_unavailable_result(path, exc)
            except Exception as exc:
                syntax = parse_failed_result(language_for_path(path), exc)
            result = {"extracted": syntax, "operational": extract_operational_structure(path, content)}
        elif request["operation"] == "julia_composition":
            from .julia_package import compose_julia_snapshot
            records = payload["records"]
            compose_julia_snapshot(records, payload["contents"])
            result = {"records": records}
        else:
            raise ValueError("Unknown parser operation")
        encoded = json.dumps(result, ensure_ascii=False).encode()
        if len(encoded) > MAX_RESULT_BYTES:
            raise ParserBudgetExceeded("Parser output limit")
    except Exception:
        encoded = b'{"worker_error":true}'
    sys.stdout.buffer.write(encoded)
