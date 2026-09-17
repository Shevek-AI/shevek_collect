import json
import subprocess
from pathlib import Path
from typing import Sequence

from shevek_collect.github_collect import GitHubCollectOptions, collect_github, read_repo_file
from shevek_collect.repo_identity import github_repository_identity

def test_collect_github_writes_source_bundle(tmp_path: Path) -> None:
    out = tmp_path / "bundle"

    result = collect_github(
        GitHubCollectOptions(
            repos=("acme/demo",),
            out=out,
            skip_auth_check=False,
            gh_runner=_fake_gh_runner(),
        )
    )

    assert result["errors"] == []
    assert result["repos_collected"] == 1
    assert result["events"] == 3
    assert (out / "source_events.jsonl").exists()
    assert (out / "source_artifacts.jsonl").exists()
    assert (out / "collect_manifest.json").exists()
    assert (out / "privacy_report.md").exists()

    events = [
        json.loads(line)
        for line in (out / "source_events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event_type"] for event in events] == [
        "github.pull_request",
        "github.pull_request_commit",
        "github.issue_comment",
    ]

    pr_event = events[0]
    assert pr_event["payload"]["number"] == 1
    assert pr_event["payload"]["title"] == "Add catalogue import"
    assert "body" not in pr_event["payload"]
    assert pr_event["actor"]["login"] == "alice"

    commit_event = events[1]
    assert commit_event["payload"]["subject"] == "add import path"
    assert "message" not in commit_event["payload"]
    assert commit_event["actor"]["author_email_hash"].startswith("hmac-sha256:v1:")
    assert "author_email" not in commit_event["actor"]

    comment_event = events[2]
    assert comment_event["payload"]["id"] == 9001
    assert "body" not in comment_event["payload"]

    artifacts = [
        json.loads(line)
        for line in (out / "source_artifacts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(artifact["artifact_type"] == "github.repository" for artifact in artifacts)
    assert any(
        artifact["artifact_type"] == "github.pull_request_file"
        and artifact["payload"]["path"] == "src/importer.py"
        for artifact in artifacts
    )
    assert any(
        artifact["artifact_type"] == "github.changed_path"
        and artifact["payload"]["path"] == "src/importer.py"
        for artifact in artifacts
    )
    assert all("patch" not in artifact.get("payload", {}) for artifact in artifacts)

    manifest = json.loads((out / "collect_manifest.json").read_text(encoding="utf-8"))
    assert manifest["command"] == "github scan"
    assert manifest["privacy"]["contains_pr_bodies"] is False
    assert manifest["privacy"]["contains_comment_bodies"] is False
    assert manifest["privacy"]["contains_raw_emails"] is False
    assert manifest["privacy"]["contains_patches"] is False
    assert manifest["repository_results"][0]["repo_full_name"] == "acme/demo"

def test_collect_github_full_text_and_patch_opt_ins(tmp_path: Path) -> None:
    out = tmp_path / "bundle"

    collect_github(
        GitHubCollectOptions(
            repos=("acme/demo",),
            out=out,
            body_mode="full",
            comment_mode="full",
            commit_message_mode="full",
            include_raw_emails=True,
            include_urls=True,
            include_file_patches=True,
            skip_auth_check=True,
            gh_runner=_fake_gh_runner(),
        )
    )

    events = [
        json.loads(line)
        for line in (out / "source_events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events[0]["payload"]["body"] == "Wire collect output into catalogue."
    assert events[1]["payload"]["message"] == "add import path\n\nBody text"
    assert events[1]["actor"]["author_email"] == "alice@example.com"
    assert events[2]["payload"]["body"] == "Looks good."

    artifacts = [
        json.loads(line)
        for line in (out / "source_artifacts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    pr_file = next(
        artifact
        for artifact in artifacts
        if artifact["artifact_type"] == "github.pull_request_file"
    )
    assert pr_file["payload"]["patch"] == "@@ demo patch @@"
    assert pr_file["payload"]["blob_url"] == "https://github.com/acme/demo/blob/abc/src/importer.py"

    manifest = json.loads((out / "collect_manifest.json").read_text(encoding="utf-8"))
    assert manifest["privacy"]["contains_pr_bodies"] is True
    assert manifest["privacy"]["contains_comment_bodies"] is True
    assert manifest["privacy"]["contains_raw_emails"] is True
    assert manifest["privacy"]["contains_patches"] is True

def test_collect_github_since_and_max_prs_filter(tmp_path: Path) -> None:
    out = tmp_path / "bundle"

    collect_github(
        GitHubCollectOptions(
            repos=("acme/demo",),
            out=out,
            since="2026-06-01",
            max_prs=1,
            skip_auth_check=True,
            gh_runner=_fake_gh_runner(include_old_pr=True),
        )
    )

    events = [
        json.loads(line)
        for line in (out / "source_events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {
        event["payload"].get("number")
        for event in events
        if event["event_type"] == "github.pull_request"
    } == {1}


def test_read_repo_file_ignores_comments_and_blanks(tmp_path: Path) -> None:
    repo_file = tmp_path / "repos.txt"
    repo_file.write_text("\n# comment\nacme/demo\n other/repo \n", encoding="utf-8")

    assert read_repo_file(repo_file) == ["acme/demo", "other/repo"]


def _fake_gh_runner(*, include_old_pr: bool = False):
    def run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if list(cmd[:2]) == ["gh", "--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="gh version 2.0.0\n", stderr="")
        if list(cmd[:3]) == ["gh", "auth", "status"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="Logged in\n", stderr="")
        endpoint = _endpoint(cmd)
        if endpoint == "/repos/acme/demo/pulls?state=all&per_page=100":
            pulls = [_pull_summary(1)]
            if include_old_pr:
                pulls.append(_pull_summary(2, updated_at="2026-01-01T00:00:00Z"))
            return _jsonl(cmd, pulls)
        if endpoint == "/repos/acme/demo/pulls/1":
            return _json(cmd, _pull_detail(1))
        if endpoint == "/repos/acme/demo/pulls/1/commits?per_page=100":
            return _jsonl(cmd, [_commit()])
        if endpoint == "/repos/acme/demo/pulls/1/files?per_page=100":
            return _jsonl(cmd, [_file_record()])
        if endpoint == "/repos/acme/demo/issues/1/comments?per_page=100":
            return _jsonl(cmd, [_comment()])
        if endpoint == "/repos/acme/demo/pulls/2":
            return _json(cmd, _pull_detail(2, title="Old PR", updated_at="2026-01-01T00:00:00Z"))
        if endpoint == "/repos/acme/demo/pulls/2/commits?per_page=100":
            return _jsonl(cmd, [])
        if endpoint == "/repos/acme/demo/pulls/2/files?per_page=100":
            return _jsonl(cmd, [])
        if endpoint == "/repos/acme/demo/issues/2/comments?per_page=100":
            return _jsonl(cmd, [])
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


def _pull_summary(number: int, *, updated_at: str = "2026-06-20T10:00:00Z") -> dict[str, object]:
    return {"number": number, "updated_at": updated_at, "created_at": updated_at}


def _pull_detail(
    number: int, *, title: str = "Add catalogue import", updated_at: str = "2026-06-20T10:00:00Z"
) -> dict[str, object]:
    return {
        "number": number,
        "id": 1000 + number,
        "node_id": f"PR_{number}",
        "state": "closed",
        "draft": False,
        "locked": False,
        "created_at": "2026-06-18T10:00:00Z",
        "updated_at": updated_at,
        "closed_at": "2026-06-21T10:00:00Z",
        "merged_at": "2026-06-21T10:00:00Z",
        "merged": True,
        "merge_commit_sha": "def456",
        "additions": 12,
        "deletions": 3,
        "changed_files": 1,
        "commits": 1,
        "title": title,
        "body": "Wire collect output into catalogue.",
        "user": _user("alice"),
        "labels": [{"name": "enhancement", "color": "abc123"}],
        "milestone": {
            "number": 1,
            "title": "v0",
            "state": "open",
            "created_at": "2026-06-01T00:00:00Z",
            "due_on": None,
        },
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
        "url": "https://api.github.com/repos/acme/demo/pulls/1",
        "html_url": "https://github.com/acme/demo/pull/1",
        "diff_url": "https://github.com/acme/demo/pull/1.diff",
        "patch_url": "https://github.com/acme/demo/pull/1.patch",
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
        "url": "https://api.github.com/repos/acme/demo/commits/abc123",
        "html_url": "https://github.com/acme/demo/commit/abc123",
    }


def _file_record() -> dict[str, object]:
    return {
        "filename": "src/importer.py",
        "status": "modified",
        "sha": "file123",
        "additions": 12,
        "deletions": 3,
        "changes": 15,
        "patch": "@@ demo patch @@",
        "blob_url": "https://github.com/acme/demo/blob/abc/src/importer.py",
        "raw_url": "https://github.com/acme/demo/raw/abc/src/importer.py",
        "contents_url": "https://api.github.com/repos/acme/demo/contents/src/importer.py",
    }


def _comment() -> dict[str, object]:
    return {
        "id": 9001,
        "node_id": "IC_9001",
        "created_at": "2026-06-19T10:00:00Z",
        "updated_at": "2026-06-19T10:01:00Z",
        "body": "Looks good.",
        "author_association": "MEMBER",
        "user": _user("bob"),
        "url": "https://api.github.com/repos/acme/demo/issues/comments/9001",
        "html_url": "https://github.com/acme/demo/pull/1#issuecomment-9001",
        "issue_url": "https://api.github.com/repos/acme/demo/issues/1",
    }

def test_collect_github_retries_rate_limit_and_records_accounting(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    base = _fake_gh_runner()
    attempts = 0
    delays: list[float] = []

    def run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        nonlocal attempts
        if _endpoint(cmd) == "/repos/acme/demo/pulls/1/commits?per_page=100":
            attempts += 1
            if attempts == 1:
                return subprocess.CompletedProcess(
                    cmd,
                    1,
                    stdout="",
                    stderr="gh: API rate limit exceeded; Retry-After: 0 (HTTP 403)",
                )
        return base(cmd)

    result = collect_github(
        GitHubCollectOptions(
            repos=("acme/demo",),
            out=out,
            gh_runner=run,
            retry_sleep=delays.append,
            retry_random=lambda: 1.0,
        )
    )

    assert result["complete"] is True
    assert result["retry"]["requests_retried"] == 1
    assert result["retry"]["retry_attempts"] == 1
    assert delays == [0.0]
    manifest = json.loads((out / "collect_manifest.json").read_text())
    assert manifest["collection_status"] == "complete"
    assert manifest["reliability"]["retry_metrics"]["attempts"] == 6
    assert manifest["repository_results"][0]["retry"]["retry_attempts"] == 1


def test_collect_github_setup_failure_does_not_persist_raw_details(tmp_path: Path) -> None:
    out = tmp_path / "bundle"

    def run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if list(cmd[:2]) == ["gh", "--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="gh version 2.0.0\n", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout="",
            stderr="authentication failed for acme/demo using sensitive detail",
        )

    result = collect_github(
        GitHubCollectOptions(
            repos=("acme/demo",),
            out=out,
            gh_runner=run,
        )
    )

    expected_id = github_repository_identity(
        hostname="github.com",
        owner="acme",
        repo="demo",
    ).fingerprint
    manifest = json.loads((out / "collect_manifest.json").read_text())
    manifest_text = json.dumps(manifest, sort_keys=True)

    assert result["errors"] == ["github_setup: provider_setup_failed"]
    assert manifest["repository_results"] == [
        {
            "repo_id": expected_id,
            "status": "failed",
            "error": "provider_setup_failed",
            "retry": {
                "requests": 0,
                "attempts": 0,
                "requests_retried": 0,
                "retry_attempts": 0,
                "exhausted_requests": 0,
            },
        }
    ]
    assert "acme/demo" not in manifest_text
    assert "sensitive detail" not in manifest_text

def test_collect_github_discards_repository_records_after_late_failure(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    base = _fake_gh_runner()
    calls = 0

    def run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        if _endpoint(cmd) == "/repos/acme/demo/issues/1/comments?per_page=100":
            calls += 1
            return subprocess.CompletedProcess(
                cmd,
                1,
                stdout="",
                stderr="gh: Resource not accessible by integration (HTTP 403)",
            )
        return base(cmd)

    result = collect_github(
        GitHubCollectOptions(
            repos=("acme/demo",),
            out=out,
            gh_runner=run,
            retry_sleep=lambda _seconds: None,
        )
    )

    assert calls == 1  # ordinary permission failures are not retried
    assert result["collection_status"] == "failed"
    assert result["repos_collected"] == 0
    assert result["events"] == 0
    assert result["artifacts"] == 0
    assert (out / "source_events.jsonl").read_text() == ""
    assert (out / "source_artifacts.jsonl").read_text() == ""
    manifest = json.loads((out / "collect_manifest.json").read_text())
    expected_id = github_repository_identity(
        hostname="github.com",
        owner="acme",
        repo="demo",
    ).fingerprint
    manifest_text = json.dumps(manifest, sort_keys=True)

    assert manifest["complete"] is False
    assert manifest["repository_results"][0]["status"] == "failed"
    assert manifest["repository_results"][0]["repo_id"] == expected_id
    assert manifest["repository_results"][0]["error"] == "permission_denied"
    assert "repo_full_name" not in manifest["repository_results"][0]
    assert manifest["errors"] == [f"{expected_id}: permission_denied"]
    assert manifest["privacy"]["contains_raw_error_text"] is False
    assert manifest["privacy"]["contains_failed_repository_names"] is False
    assert "acme/demo" not in manifest_text
    assert "Resource not accessible by integration" not in manifest_text
    assert manifest["reliability"]["repository_transaction"] == "all_or_nothing"
