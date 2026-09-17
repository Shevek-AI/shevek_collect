import json
import subprocess
from pathlib import Path

import pytest

import shevek_collect.git_collect as git_collect_module
from shevek_collect.cli import main
from shevek_collect.git_collect import GitCollectOptions, collect_git, discover_git_repos


def test_collect_git_writes_source_bundle(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "demo_repo")
    out = tmp_path / "bundle"

    result = collect_git(GitCollectOptions(repos=(repo,), out=out))

    assert result["errors"] == []
    assert result["repos_collected"] == 1
    assert result["events"] == 2
    assert (out / "source_events.jsonl").exists()
    assert (out / "source_artifacts.jsonl").exists()
    assert (out / "collect_manifest.json").exists()
    assert (out / "privacy_report.md").exists()

    events = [json.loads(line) for line in (out / "source_events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [event["event_type"] for event in events] == ["git.commit", "git.commit"]
    assert {event["payload"]["subject"] for event in events} == {"initial docs", "add app code"}
    assert all("body" not in event["payload"] for event in events)
    assert all("author_email" not in event["actor"] for event in events)
    assert any(
        changed_path["path"] == "src/app.py"
        for event in events
        for changed_path in event["payload"]["changed_paths"]
    )

    artifacts = [
        json.loads(line) for line in (out / "source_artifacts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(artifact["artifact_type"] == "git.repository" for artifact in artifacts)
    assert any(
        artifact["artifact_type"] == "git.changed_path"
        and artifact["payload"]["path"] == "src/app.py"
        for artifact in artifacts
    )

    manifest = json.loads((out / "collect_manifest.json").read_text(encoding="utf-8"))
    assert manifest["settings"]["include_file_content"] is False
    assert manifest["privacy"]["contains_file_content"] is False
    assert manifest["privacy"]["contains_raw_emails"] is False


def test_collect_git_message_modes_and_raw_email_opt_in(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "demo_repo")
    out = tmp_path / "bundle"

    collect_git(
        GitCollectOptions(
            repos=(repo,),
            out=out,
            message_mode="full",
            include_raw_emails=True,
        )
    )

    events = [json.loads(line) for line in (out / "source_events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all("body" in event["payload"] for event in events)
    assert all("author_email" in event["actor"] for event in events)


def test_git_scan_cli_writes_bundle(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "demo_repo")
    out = tmp_path / "bundle"

    exit_code = main(["git", "scan", "--repo", str(repo), "--out", str(out), "--json"])

    assert exit_code == 0
    assert (out / "source_events.jsonl").exists()
    assert (out / "collect_manifest.json").exists()


def test_git_failure_manifest_redacts_unvalidated_repository_path(tmp_path: Path) -> None:
    repo = tmp_path / "classified_repository_name"
    out = tmp_path / "bundle"

    result = collect_git(GitCollectOptions(repos=(repo,), out=out))

    manifest_text = (out / "collect_manifest.json").read_text(encoding="utf-8")
    report_text = (out / "privacy_report.md").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)

    assert result["complete"] is False
    assert repo.name not in manifest_text
    assert repo.as_posix() not in manifest_text
    assert repo.name not in report_text
    assert repo.as_posix() not in report_text
    assert manifest["repository_results"] == [
        {
            "repo_id": manifest["repository_results"][0]["repo_id"],
            "status": "failed",
            "error": "repository_not_found",
        }
    ]
    assert manifest["repository_results"][0]["repo_id"].startswith("local_repo_v2_")
    assert "repo_hint" not in manifest["repository_results"][0]
    assert manifest["errors"] == [
        f"{manifest['repository_results'][0]['repo_id']}: repository_not_found"
    ]


def test_git_late_failure_removes_plaintext_repo_hint_from_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _make_git_repo(tmp_path / "classified_repository_name")
    out = tmp_path / "bundle"

    def fail_after_repo_summary(*_args: object, **_kwargs: object) -> list[str]:
        raise RuntimeError(f"synthetic failure while reading {repo}")

    monkeypatch.setattr(git_collect_module, "_commit_ids", fail_after_repo_summary)

    collect_git(GitCollectOptions(repos=(repo,), out=out))

    manifest_text = (out / "collect_manifest.json").read_text(encoding="utf-8")
    report_text = (out / "privacy_report.md").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    repository_result = manifest["repository_results"][0]

    assert repo.name not in manifest_text
    assert repo.as_posix() not in manifest_text
    assert repo.name not in report_text
    assert repo.as_posix() not in report_text
    assert repository_result["status"] == "failed"
    assert repository_result["error"] == "git_command_failed"
    assert "repo_hint" not in repository_result
    assert manifest["errors"] == [f"{repository_result['repo_id']}: git_command_failed"]


def test_discover_git_repos(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "src" / "demo_repo")
    (tmp_path / "src" / "not_repo").mkdir()

    repos = discover_git_repos(tmp_path / "src")

    assert repos == [repo.resolve()]


def _make_git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test User")

    (path / "README.md").write_text("# Demo\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial docs")

    (path / "src").mkdir()
    (path / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    _git(path, "add", "src/app.py")
    _git(path, "commit", "-m", "add app code", "-m", "With a body")
    return path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
