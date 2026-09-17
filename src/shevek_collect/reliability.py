from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Callable, Literal, Mapping, TypeVar

CollectionStatus = Literal["complete", "partial", "failed"]
T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry policy for transient provider requests."""

    max_attempts: int = 5
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    max_retry_after_seconds: float = 300.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("retry max_attempts must be at least 1")
        if self.initial_delay_seconds < 0:
            raise ValueError("retry initial_delay_seconds must be non-negative")
        if self.max_delay_seconds < 0:
            raise ValueError("retry max_delay_seconds must be non-negative")
        if self.max_retry_after_seconds < 0:
            raise ValueError("retry max_retry_after_seconds must be non-negative")

    def manifest_metadata(self) -> dict[str, object]:
        return {
            "max_attempts": self.max_attempts,
            "initial_delay_seconds": self.initial_delay_seconds,
            "max_delay_seconds": self.max_delay_seconds,
            "max_retry_after_seconds": self.max_retry_after_seconds,
            "backoff": "exponential_full_jitter",
            "retry_after": "honoured_with_safety_cap",
        }


@dataclass(frozen=True)
class RetrySnapshot:
    requests: int = 0
    attempts: int = 0
    requests_retried: int = 0
    retry_attempts: int = 0
    exhausted_requests: int = 0

    def __sub__(self, other: RetrySnapshot) -> RetrySnapshot:
        return RetrySnapshot(
            requests=self.requests - other.requests,
            attempts=self.attempts - other.attempts,
            requests_retried=self.requests_retried - other.requests_retried,
            retry_attempts=self.retry_attempts - other.retry_attempts,
            exhausted_requests=self.exhausted_requests - other.exhausted_requests,
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "requests": self.requests,
            "attempts": self.attempts,
            "requests_retried": self.requests_retried,
            "retry_attempts": self.retry_attempts,
            "exhausted_requests": self.exhausted_requests,
        }


@dataclass(frozen=True)
class RetryNotice:
    operation: str
    failed_attempt: int
    next_attempt: int
    max_attempts: int
    delay_seconds: float
    error: str


class RetryExecutor:
    """Execute logical requests while recording deterministic retry accounting."""

    def __init__(
        self,
        policy: RetryPolicy,
        *,
        sleep: Callable[[float], None] | None = None,
        random_source: Callable[[], float] | None = None,
        on_retry: Callable[[RetryNotice], None] | None = None,
    ) -> None:
        self.policy = policy
        self._sleep = sleep or time.sleep
        self._random_source = random_source or random.random
        self._on_retry = on_retry
        self._requests = 0
        self._attempts = 0
        self._requests_retried = 0
        self._retry_attempts = 0
        self._exhausted_requests = 0

    def snapshot(self) -> RetrySnapshot:
        return RetrySnapshot(
            requests=self._requests,
            attempts=self._attempts,
            requests_retried=self._requests_retried,
            retry_attempts=self._retry_attempts,
            exhausted_requests=self._exhausted_requests,
        )

    def run(
        self,
        operation: Callable[[], T],
        *,
        should_retry: Callable[[Exception], bool],
        retry_after: Callable[[Exception], float | None] | None = None,
        operation_name: str = "provider request",
    ) -> T:
        self._requests += 1
        retried = False
        for attempt in range(1, self.policy.max_attempts + 1):
            self._attempts += 1
            try:
                return operation()
            except Exception as exc:
                retryable = should_retry(exc)
                if not retryable or attempt >= self.policy.max_attempts:
                    if retryable and attempt >= self.policy.max_attempts:
                        self._exhausted_requests += 1
                    raise
                if not retried:
                    self._requests_retried += 1
                    retried = True
                self._retry_attempts += 1
                explicit_delay = retry_after(exc) if retry_after is not None else None
                delay = self._delay(attempt=attempt, retry_after=explicit_delay)
                if self._on_retry is not None:
                    self._on_retry(
                        RetryNotice(
                            operation=operation_name,
                            failed_attempt=attempt,
                            next_attempt=attempt + 1,
                            max_attempts=self.policy.max_attempts,
                            delay_seconds=delay,
                            error=str(exc),
                        )
                    )
                self._sleep(delay)
        raise AssertionError("retry loop exhausted without returning or raising")

    def _delay(self, *, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0.0), self.policy.max_retry_after_seconds)
        ceiling = min(
            self.policy.max_delay_seconds,
            self.policy.initial_delay_seconds * (2 ** (attempt - 1)),
        )
        return ceiling * min(max(self._random_source(), 0.0), 1.0)


def collection_status(
    *,
    repos_requested: int,
    repos_collected: int,
    errors: list[str],
) -> CollectionStatus:
    if not errors and repos_collected == repos_requested:
        return "complete"
    if repos_collected > 0:
        return "partial"
    return "failed"


def retry_after_seconds(
    headers: Mapping[str, str] | None = None,
    *,
    message: str = "",
    now: datetime | None = None,
) -> float | None:
    normalized = {str(key).casefold(): str(value).strip() for key, value in (headers or {}).items()}
    milliseconds = _float(normalized.get("x-ms-retry-after-ms"))
    if milliseconds is not None:
        return max(milliseconds / 1000.0, 0.0)

    raw_retry_after = normalized.get("retry-after")
    if raw_retry_after:
        seconds = _float(raw_retry_after)
        if seconds is not None:
            return max(seconds, 0.0)
        try:
            target = parsedate_to_datetime(raw_retry_after)
            if target.tzinfo is None:
                target = target.replace(tzinfo=UTC)
            current = now or datetime.now(UTC)
            return max((target - current).total_seconds(), 0.0)
        except (TypeError, ValueError, OverflowError):
            pass

    patterns = (
        r"retry[- ]after\s*[:=]?\s*(\d+(?:\.\d+)?)",
        r"retry\s+after\s+(\d+(?:\.\d+)?)\s+seconds?",
    )
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return float(match.group(1))
    return None


def transient_network_message(message: str) -> bool:
    lowered = message.casefold()
    return any(
        marker in lowered
        for marker in (
            "connection reset",
            "connection refused",
            "connection aborted",
            "failed to connect",
            "could not resolve host",
            "remote end closed",
            "temporary failure",
            "temporarily unavailable",
            "timed out",
            "timeout",
            "tls handshake timeout",
            "unexpected eof",
            "network is unreachable",
            "name or service not known",
        )
    )


def rate_limit_message(message: str) -> bool:
    lowered = message.casefold()
    return any(
        marker in lowered
        for marker in (
            "rate limit",
            "rate-limit",
            "too many requests",
            "secondary rate",
            "abuse detection",
            "throttl",
        )
    )


def _float(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
