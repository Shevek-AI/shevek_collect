"""Finite, non-interactive Git observations without local execution callbacks."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

GIT_TIMEOUT_SECONDS = 60
FETCH_TIMEOUT_SECONDS = 120


def observation_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    # Do not give Git the collector's provider tokens, privacy key, or ambient
    # GIT_CONFIG_COUNT / GIT_DIR / GIT_EXTERNAL_DIFF overrides.
    permitted = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TMP", "TEMP", "TMPDIR",
                 "LANG", "LC_ALL", "LC_CTYPE"}
    env = {key: value for key, value in os.environ.items() if key.upper() in permitted}
    if extra:
        allowed_extra = {"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"}
        if set(extra) - allowed_extra:
            raise ValueError("Unsupported Git observation environment override")
        env.update(extra)
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "", "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat", "GIT_ATTR_NOSYSTEM": "1",
    })
    return env


def safe_git_command(repo: Path, args: Sequence[str]) -> list[str]:
    command = list(args)
    if command and command[0] in {"show", "log", "diff"}:
        command[1:1] = ["--no-ext-diff", "--no-textconv"]
    return ["git", "--no-pager", "-c", "core.fsmonitor=false",
            "-c", f"core.hooksPath={os.devnull}", "-c", "core.untrackedCache=false",
            "-c", "gc.auto=0", "-c", "maintenance.auto=false",
            "-C", repo.as_posix(), *command]


def run_git(repo: Path, args: Sequence[str], *, text: bool = True,
            env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess:
    kwargs = {"encoding": "utf-8", "errors": "replace"} if text else {}
    try:
        return subprocess.run(
            safe_git_command(repo, args), check=False, text=text,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS, env=observation_environment(env), **kwargs,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Git observation exceeded its time limit") from None
