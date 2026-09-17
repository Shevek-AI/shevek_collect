from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import shevek_collect.cli as cli
from shevek_collect.github_collect import GitHubCollectOptions
from shevek_collect.progress import (
    ProgressReporter,
    progress_checkpoint,
    retry_progress_message,
)
from shevek_collect.reliability import RetryExecutor, RetryPolicy
from shevek_collect.run_collect import RunCollectOptions, collect_from_config


def _result(out: Path) -> dict[str, object]:
    return {
        "out": out.resolve().as_posix(),
        "repos_requested": 1,
        "repos_collected": 1,
        "events": 0,
        "artifacts": 0,
        "errors": [],
        "outputs": {},
    }


def test_cli_progress_uses_stderr_and_preserves_json_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_collect(options: GitHubCollectOptions) -> dict[str, object]:
        assert options.progress is not None
        options.progress("GitHub repository 1/1: acme/demo")
        return _result(options.out)

    monkeypatch.setattr(cli, "collect_github", fake_collect)
    out = tmp_path / "bundle"

    assert cli.main(["github", "scan", "--repo", "acme/demo", "--out", str(out), "--json"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["out"] == out.resolve().as_posix()
    assert "[collect] GitHub repository 1/1: acme/demo" in captured.err


def test_quiet_suppresses_cli_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_collect(options: GitHubCollectOptions) -> dict[str, object]:
        assert options.progress is None
        return _result(options.out)

    monkeypatch.setattr(cli, "collect_github", fake_collect)

    assert (
        cli.main(
            [
                "github",
                "scan",
                "--repo",
                "acme/demo",
                "--out",
                str(tmp_path / "bundle"),
                "--quiet",
                "--json",
            ]
        )
        == 0
    )

    assert capsys.readouterr().err == ""


def test_configured_run_threads_progress_through_sources_and_snapshots(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "app.py").write_text("def hello():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)

    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
activity_sources:
  git:
    repos:
      - {repo.as_posix()}
repository_snapshots:
  git:
    repos:
      - {repo.as_posix()}
    capture:
      content_mode: structure
""".lstrip(),
        encoding="utf-8",
    )
    messages: list[str] = []

    result = collect_from_config(
        RunCollectOptions(
            config=config,
            out=tmp_path / "bundle",
            progress=messages.append,
        )
    )

    assert result["collection_status"] == "complete"
    assert any(message.startswith("Starting configured collection") for message in messages)
    assert "Activity source 1/1: git" in messages
    assert any(message.startswith("Git repository 1/1:") for message in messages)
    assert any(message.startswith("Snapshot repository 1/1:") for message in messages)
    assert any(message.startswith("Configured collection complete:") for message in messages)


def test_retry_executor_reports_retry_before_sleep() -> None:
    notices = []
    sleeps: list[float] = []
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("temporary timeout")
        return "ok"

    executor = RetryExecutor(
        RetryPolicy(max_attempts=3, initial_delay_seconds=2, max_delay_seconds=10),
        sleep=sleeps.append,
        random_source=lambda: 0.5,
        on_retry=notices.append,
    )

    assert (
        executor.run(
            operation,
            should_retry=lambda exc: isinstance(exc, TimeoutError),
            operation_name="GitHub API request",
        )
        == "ok"
    )
    assert sleeps == [1.0]
    assert len(notices) == 1
    assert notices[0].operation == "GitHub API request"
    assert notices[0].next_attempt == 2
    assert notices[0].delay_seconds == 1.0


def test_progress_checkpoint_is_bounded_and_includes_final_item() -> None:
    emitted = [index for index in range(1, 101) if progress_checkpoint(index, 100, every=25)]

    assert emitted == [25, 50, 75, 100]
    assert not any(progress_checkpoint(index, 10, every=25) for index in range(1, 11))


def test_retry_progress_is_single_line_and_bounded() -> None:
    message = retry_progress_message(
        operation="GitHub API request",
        delay_seconds=2.5,
        next_attempt=2,
        max_attempts=5,
        error="HTTP 429\n" + ("rate limited " * 40),
    )

    assert "\n" not in message
    assert len(message) < 340
    assert message.startswith("Retrying GitHub API request in 2.5s (attempt 2/5):")


def test_progress_reporter_flushes_line(capsys: pytest.CaptureFixture[str]) -> None:
    ProgressReporter()("hello")

    assert capsys.readouterr().err == "[collect] hello\n"
