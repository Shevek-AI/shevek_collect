from __future__ import annotations

from datetime import UTC, datetime

import pytest

from shevek_collect.reliability import RetryExecutor, RetryPolicy, retry_after_seconds


class _TransientError(RuntimeError):
    pass


def test_retry_executor_uses_exponential_full_jitter_and_accounts_attempts() -> None:
    delays: list[float] = []
    calls = 0
    executor = RetryExecutor(
        RetryPolicy(max_attempts=4, initial_delay_seconds=2, max_delay_seconds=10),
        sleep=delays.append,
        random_source=lambda: 0.5,
    )

    def operation() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise _TransientError("try again")
        return "ok"

    assert (
        executor.run(operation, should_retry=lambda exc: isinstance(exc, _TransientError)) == "ok"
    )
    assert delays == [1.0, 2.0]
    assert executor.snapshot().as_dict() == {
        "requests": 1,
        "attempts": 3,
        "requests_retried": 1,
        "retry_attempts": 2,
        "exhausted_requests": 0,
    }


def test_retry_executor_records_exhaustion() -> None:
    executor = RetryExecutor(
        RetryPolicy(max_attempts=2, initial_delay_seconds=0),
        sleep=lambda _seconds: None,
    )

    with pytest.raises(_TransientError):
        executor.run(
            lambda: (_ for _ in ()).throw(_TransientError("still down")),
            should_retry=lambda _exc: True,
        )

    assert executor.snapshot().as_dict() == {
        "requests": 1,
        "attempts": 2,
        "requests_retried": 1,
        "retry_attempts": 1,
        "exhausted_requests": 1,
    }


def test_retry_after_supports_seconds_milliseconds_and_http_dates() -> None:
    assert retry_after_seconds({"Retry-After": "12"}) == 12
    assert retry_after_seconds({"x-ms-retry-after-ms": "2500"}) == 2.5
    assert retry_after_seconds(message="rate limited; Retry-After: 7") == 7
    now = datetime(2026, 7, 17, 0, 0, 0, tzinfo=UTC)
    assert retry_after_seconds({"Retry-After": "Fri, 17 Jul 2026 00:00:09 GMT"}, now=now) == 9
