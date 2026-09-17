import json
import subprocess
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import unquote, urlsplit

from shevek_collect.cli import main
from shevek_collect.run_collect import RunCollectOptions, collect_from_config, plan_collect


def test_collect_run_merges_git_github_and_azure_devops_sources(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "local_repo")
    config = tmp_path / "shevek_collect.yaml"
    config.write_text(
        f"""
version: 1
defaults:
  since: 2026-01-01
activity_sources:
  git:
    repos:
      - path: {repo.as_posix()}
    message_mode: subject
  github:
    repos:
      - acme/demo
    skip_auth_check: true
    body_mode: title
    comment_mode: metadata
  azure_devops:
    organization: Acme
    repos:
      - project: Platform
        repo: Backend
    comment_mode: metadata
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    result = collect_from_config(
        RunCollectOptions(
            config=config,
            out=out,
            gh_runner=_fake_gh_runner(),
            azdo_requester=_fake_azdo_requester(),
        )
    )

    assert result["errors"] == []
    assert result["source_runs"] == 3
    assert result["repos_collected"] == 3
    assert (out / "source_events.jsonl").exists()
    assert (out / "source_artifacts.jsonl").exists()
    assert (out / "collect_manifest.json").exists()
    assert (out / "privacy_report.md").exists()

    events = [
        json.loads(line)
        for line in (out / "source_events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {event["event_type"] for event in events} == {
        "git.commit",
        "github.pull_request",
        "github.pull_request_commit",
        "github.issue_comment",
        "azure_devops.pull_request",
        "azure_devops.pull_request_commit",
        "azure_devops.pull_request_comment",
    }

    manifest_text = (out / "collect_manifest.json").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    assert repo.as_posix() not in manifest_text
    assert manifest["command"] == "run"
    assert manifest["source_kinds"] == ["azure_devops", "git", "github"]
    assert manifest["counts"]["source_runs"] == 3
    assert manifest["counts"]["event:git.commit"] == 2
    assert manifest["counts"]["event:github.pull_request"] == 1
    assert manifest["counts"]["event:azure_devops.pull_request"] == 1
    assert manifest["privacy"]["contains_file_content"] is False
    assert manifest["privacy"]["contains_paths"] is True


def test_run_dry_run_plans_without_writing_bundle(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "local_repo")
    config = tmp_path / "shevek_collect.yaml"
    config.write_text(
        f"""
version: 1
activity_sources:
  git:
    repos:
      - {repo.as_posix()}
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    plan = plan_collect(RunCollectOptions(config=config, out=out, dry_run=True))

    assert plan["dry_run"] is True
    assert plan["source_runs"] == 1
    assert plan["sources"][0]["source_kind"] == "git"
    assert plan["sources"][0]["repo_count"] == 1
    assert not out.exists()


def test_run_cli_dry_run(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "local_repo")
    config = tmp_path / "shevek_collect.yaml"
    config.write_text(
        f"""
version: 1
activity_sources:
  git:
    repos:
      - {repo.as_posix()}
""".lstrip(),
        encoding="utf-8",
    )

    exit_code = main(
        ["run", "--config", str(config), "--out", str(tmp_path / "bundle"), "--dry-run", "--json"]
    )

    assert exit_code == 0


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
    _git(path, "commit", "-m", "add app code")
    return path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def _fake_gh_runner():
    def run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if list(cmd[:2]) == ["gh", "--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="gh version 2.0.0\n", stderr="")
        endpoint = _endpoint(cmd)
        if endpoint == "/repos/acme/demo/pulls?state=all&per_page=100":
            return _jsonl(cmd, [{"number": 1, "updated_at": "2026-06-20T10:00:00Z"}])
        if endpoint == "/repos/acme/demo/pulls/1":
            return _json(cmd, _pull_detail())
        if endpoint == "/repos/acme/demo/pulls/1/commits?per_page=100":
            return _jsonl(cmd, [_commit()])
        if endpoint == "/repos/acme/demo/pulls/1/files?per_page=100":
            return _jsonl(cmd, [_file_record()])
        if endpoint == "/repos/acme/demo/issues/1/comments?per_page=100":
            return _jsonl(cmd, [_comment()])
        return subprocess.CompletedProcess(
            cmd, 1, stdout="", stderr=f"unexpected command: {' '.join(cmd)}"
        )

    return run


def _endpoint(cmd: Sequence[str]) -> str:
    for part in cmd:
        if part.startswith("/repos/"):
            return part
    return ""


def _json(cmd: Sequence[str], value: dict[str, object]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(value), stderr="")


def _jsonl(cmd: Sequence[str], values: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        cmd,
        0,
        stdout="".join(json.dumps(value) + "\n" for value in values),
        stderr="",
    )


def _user(login: str) -> dict[str, object]:
    return {"login": login, "type": "User"}


def _pull_detail() -> dict[str, object]:
    return {
        "number": 1,
        "id": 1001,
        "node_id": "PR_1",
        "state": "closed",
        "draft": False,
        "locked": False,
        "created_at": "2026-06-18T10:00:00Z",
        "updated_at": "2026-06-20T10:00:00Z",
        "closed_at": "2026-06-21T10:00:00Z",
        "merged_at": "2026-06-21T10:00:00Z",
        "merged": True,
        "merge_commit_sha": "def456",
        "additions": 12,
        "deletions": 3,
        "changed_files": 1,
        "commits": 1,
        "title": "Add catalogue import",
        "body": "Not included by default.",
        "user": _user("alice"),
        "base": {
            "ref": "main",
            "sha": "base123",
            "repo": {"full_name": "acme/demo", "private": True, "owner": _user("acme")},
        },
        "head": {
            "ref": "collect",
            "sha": "head123",
            "repo": {"full_name": "alice/demo", "private": True, "owner": _user("alice")},
        },
    }


def _commit() -> dict[str, object]:
    return {
        "sha": "abc123",
        "author": _user("alice"),
        "parents": [{"sha": "parent123"}],
        "commit": {
            "message": "add import path\n\nBody text",
            "author": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-06-18T10:05:00Z",
            },
            "committer": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-06-18T10:06:00Z",
            },
        },
    }


def _file_record() -> dict[str, object]:
    return {
        "filename": "src/importer.py",
        "status": "modified",
        "sha": "file123",
        "additions": 12,
        "deletions": 3,
        "changes": 15,
    }


def _comment() -> dict[str, object]:
    return {
        "id": 9001,
        "node_id": "IC_9001",
        "created_at": "2026-06-20T10:20:00Z",
        "updated_at": "2026-06-20T10:20:00Z",
        "author_association": "MEMBER",
        "body": "Looks good.",
        "user": _user("bob"),
    }


def _fake_azdo_requester():
    def request(url: str, _headers: Mapping[str, str]):
        path = unquote(urlsplit(url).path)
        suffix = path.split("/_apis/", 1)[-1]
        if suffix == "git/repositories/Backend":
            return {
                "id": "backend-guid",
                "name": "Backend",
                "defaultBranch": "refs/heads/main",
                "project": {"id": "platform-guid", "name": "Platform"},
            }
        if suffix == "git/repositories/Backend/pullrequests":
            return {
                "value": [
                    {
                        "pullRequestId": 2,
                        "status": "active",
                        "creationDate": "2026-06-20T09:00:00Z",
                    }
                ]
            }
        if suffix == "git/repositories/Backend/pullrequests/2":
            return {
                "pullRequestId": 2,
                "status": "active",
                "creationDate": "2026-06-20T09:00:00Z",
                "title": "Azure adapter",
                "sourceRefName": "refs/heads/feature/azure",
                "targetRefName": "refs/heads/main",
                "lastMergeSourceCommit": {"commitId": "az-head"},
                "lastMergeTargetCommit": {"commitId": "az-base"},
                "createdBy": {"displayName": "Alice"},
            }
        if suffix == "git/repositories/Backend/pullrequests/2/commits":
            return {
                "value": [
                    {
                        "commitId": "az-commit",
                        "comment": "azure activity",
                        "author": {"name": "Alice", "date": "2026-06-20T09:05:00Z"},
                        "committer": {"name": "Alice", "date": "2026-06-20T09:06:00Z"},
                    }
                ]
            }
        if suffix == "git/repositories/Backend/pullrequests/2/iterations":
            return {"value": [{"id": 1}]}
        if suffix == "git/repositories/Backend/pullrequests/2/iterations/1/changes":
            return {
                "changeEntries": [
                    {"changeId": 1, "changeType": "edit", "item": {"path": "/src/azure.py"}}
                ],
                "nextSkip": 0,
                "nextTop": 0,
            }
        if suffix == "git/repositories/Backend/pullrequests/2/threads":
            return {
                "value": [
                    {
                        "id": 3,
                        "comments": [
                            {
                                "id": 4,
                                "commentType": "text",
                                "publishedDate": "2026-06-20T09:10:00Z",
                                "author": {"displayName": "Bob"},
                            }
                        ],
                    }
                ]
            }
        raise AssertionError(f"unexpected Azure DevOps URL: {url}")

    return request


def test_collect_run_marks_partial_and_excludes_failed_repository_records(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "local_repo")
    config = tmp_path / "shevek_collect.yaml"
    config.write_text(
        f"""
version: 1
activity_sources:
  git:
    repos:
      - {repo.as_posix()}
    max_count: 1
  github:
    repos:
      - acme/demo
    skip_auth_check: true
    retry:
      max_attempts: 2
      initial_delay_seconds: 0
""".lstrip(),
        encoding="utf-8",
    )
    base = _fake_gh_runner()

    def failing_runner(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        endpoint = next((part for part in cmd if part.startswith("/repos/")), "")
        if endpoint == "/repos/acme/demo/issues/1/comments?per_page=100":
            return subprocess.CompletedProcess(
                cmd,
                1,
                stdout="",
                stderr="gh: Resource not accessible by integration (HTTP 403)",
            )
        return base(cmd)

    out = tmp_path / "bundle"
    result = collect_from_config(
        RunCollectOptions(
            config=config,
            out=out,
            gh_runner=failing_runner,
            retry_sleep=lambda _seconds: None,
        )
    )

    assert result["collection_status"] == "partial"
    assert result["complete"] is False
    assert result["repos_requested"] == 2
    assert result["repos_collected"] == 1
    events = [json.loads(line) for line in (out / "source_events.jsonl").read_text().splitlines()]
    assert {event["event_type"] for event in events} == {"git.commit"}
    artifacts = [
        json.loads(line) for line in (out / "source_artifacts.jsonl").read_text().splitlines()
    ]
    assert all(not str(item["artifact_type"]).startswith("github.") for item in artifacts)

    manifest = json.loads((out / "collect_manifest.json").read_text())
    assert manifest["collection_status"] == "partial"
    assert manifest["complete"] is False
    assert manifest["counts"]["repos_failed"] == 1
    statuses = {(item["source_kind"], item["status"]) for item in manifest["repository_results"]}
    assert statuses == {("git", "complete"), ("github", "failed")}
