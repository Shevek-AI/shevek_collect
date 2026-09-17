from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable, TextIO

ProgressCallback = Callable[[str], None]


@dataclass
class ProgressReporter:
    """Small line-oriented progress reporter intended for interactive CLI use."""

    stream: TextIO = field(default_factory=lambda: sys.stderr)
    prefix: str = "[collect]"

    def __call__(self, message: str) -> None:
        print(f"{self.prefix} {message}", file=self.stream, flush=True)


def emit_progress(progress: ProgressCallback | None, message: str) -> None:
    if progress is not None:
        progress(message)


def progress_checkpoint(current: int, total: int, *, every: int) -> bool:
    """Return true for bounded periodic progress on meaningfully large runs."""
    if total < every or current <= 0:
        return False
    return current == total or current % every == 0


def retry_progress_message(
    *,
    operation: str,
    delay_seconds: float,
    next_attempt: int,
    max_attempts: int,
    error: str,
) -> str:
    detail = " ".join(error.split())
    if len(detail) > 240:
        detail = f"{detail[:237]}..."
    return (
        f"Retrying {operation} in {delay_seconds:.1f}s "
        f"(attempt {next_attempt}/{max_attempts}): {detail}"
    )
