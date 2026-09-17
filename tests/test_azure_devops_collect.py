import json
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qs, unquote, urlsplit

from shevek_collect.azure_devops_collect import (
    AzureDevOpsCollectOptions,
    AzureRepoRef,
    collect_azure_devops,
    parse_azure_repo,
)
from shevek_collect.repo_identity import azure_devops_repository_identity

def test_collect_azure_devops_writes_source_bundle(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    result = collect_azure_devops(
        AzureDevOpsCollectOptions(
            organization="Acme",
            repos=(AzureRepoRef(project="Platform", repo="Backend"),),
            out=out,
            requester=_fake_requester(),
        )
    )

    assert result["errors"] == []
    assert result["repos_collected"] == 1
    assert result["events"] == 3

    events = [json.loads(line) for line in (out / "source_events.jsonl").read_text().splitlines()]
    assert [event["event_type"] for event in events] == [
        "azure_devops.pull_request",
        "azure_devops.pull_request_commit",
        "azure_devops.pull_request_comment",
    ]
    assert {event["semantic_type"] for event in events} == {
        "code_review.pull_request",
        "code_review.pull_request_commit",
        "code_review.comment",
    }
    expected_id = azure_devops_repository_identity(
        organization="Acme", project="Platform", repo="Backend"
    ).fingerprint
    assert {event["source"]["repo_id"] for event in events} == {expected_id}

    pr = events[0]
    assert pr["payload"]["number"] == 42
    assert pr["payload"]["title"] == "Add activity bundle adapter"
    assert "body" not in pr["payload"]
    assert pr["payload"]["base"]["sha"] == "base123"
    assert pr["payload"]["head"]["sha"] == "head123"
    assert pr["payload"]["completion_options"]["merge_strategy"] == "squash"

    commit = events[1]
    assert commit["payload"]["sha"] == "abc123"
    assert commit["payload"]["subject"] == "add adapter"
    assert "author_email" not in commit["actor"]

    comment = events[2]
    assert comment["payload"]["thread_id"] == 7
    assert comment["payload"]["path"] == "/src/importer.py"
    assert "body" not in comment["payload"]

    artifacts = [
        json.loads(line) for line in (out / "source_artifacts.jsonl").read_text().splitlines()
    ]
    file_artifact = next(
        artifact
        for artifact in artifacts
        if artifact["semantic_type"] == "code_review.pull_request_file"
    )
    assert file_artifact["payload"]["path"] == "/src/importer.py"
    assert any(artifact["semantic_type"] == "code_review.changed_path" for artifact in artifacts)

    manifest = json.loads((out / "collect_manifest.json").read_text())
    assert manifest["source_kinds"] == ["azure_devops"]
    assert manifest["settings"]["token_env"] == "AZURE_DEVOPS_EXT_PAT"
    assert manifest["privacy"]["contains_pr_bodies"] is False
    assert manifest["privacy"]["contains_comment_bodies"] is False
    assert manifest["repository_results"][0]["repo_full_name"] == "Platform/Backend"

def test_collect_azure_devops_full_text_opt_ins(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    collect_azure_devops(
        AzureDevOpsCollectOptions(
            organization="Acme",
            repos=(AzureRepoRef(project="Platform", repo="Backend"),),
            out=out,
            body_mode="full",
            comment_mode="full",
            commit_message_mode="full",
            include_raw_emails=True,
            include_urls=True,
            requester=_fake_requester(),
        )
    )
    events = [json.loads(line) for line in (out / "source_events.jsonl").read_text().splitlines()]
    assert events[0]["payload"]["body"] == "Wire Azure activity into Catalogue."
    assert events[1]["payload"]["message"] == "add adapter\n\nBody text"
    assert events[1]["actor"]["author_email"] == "alice@example.com"
    assert events[2]["payload"]["body"] == "Looks good."


def test_parse_azure_repo() -> None:
    assert parse_azure_repo("Platform/Backend") == AzureRepoRef(project="Platform", repo="Backend")


def _fake_requester():
    def request(url: str, _headers: Mapping[str, str]):
        parsed = urlsplit(url)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)
        suffix = path.split("/_apis/", 1)[-1]

        if suffix == "git/repositories/Backend":
            return {
                "id": "repo-guid",
                "name": "Backend",
                "defaultBranch": "refs/heads/main",
                "project": {"id": "project-guid", "name": "Platform"},
                "remoteUrl": "https://dev.azure.com/Acme/Platform/_git/Backend",
            }
        if suffix == "git/repositories/Backend/pullrequests":
            assert query["searchCriteria.status"] == ["all"]
            return {
                "count": 1,
                "value": [
                    {
                        "pullRequestId": 42,
                        "status": "completed",
                        "creationDate": "2026-06-18T10:00:00Z",
                        "closedDate": "2026-06-21T10:00:00Z",
                    }
                ],
            }
        if suffix == "git/repositories/Backend/pullrequests/42":
            return _pull_request()
        if suffix == "git/repositories/Backend/pullrequests/42/commits":
            return {"count": 1, "value": [_commit()]}
        if suffix == "git/repositories/Backend/pullrequests/42/iterations":
            return {"count": 2, "value": [{"id": 1}, {"id": 2}]}
        if suffix == "git/repositories/Backend/pullrequests/42/iterations/2/changes":
            return {
                "changeEntries": [
                    {
                        "changeId": 1,
                        "changeType": "edit",
                        "item": {
                            "path": "/src/importer.py",
                            "objectId": "file-sha",
                            "url": "https://dev.azure.com/example/file",
                        },
                    }
                ],
                "nextSkip": 0,
                "nextTop": 0,
            }
        if suffix == "git/repositories/Backend/pullrequests/42/threads":
            return {
                "count": 1,
                "value": [
                    {
                        "id": 7,
                        "status": "fixed",
                        "threadContext": {"filePath": "/src/importer.py"},
                        "comments": [
                            {
                                "id": 9,
                                "parentCommentId": 0,
                                "commentType": "text",
                                "content": "Looks good.",
                                "publishedDate": "2026-06-20T10:20:00Z",
                                "lastUpdatedDate": "2026-06-20T10:21:00Z",
                                "author": {
                                    "id": "bob-id",
                                    "displayName": "Bob Reviewer",
                                },
                            }
                        ],
                    }
                ],
            }
        raise AssertionError(f"Unexpected Azure DevOps URL: {url}")

    return request


def _pull_request() -> dict[str, object]:
    return {
        "pullRequestId": 42,
        "codeReviewId": 42,
        "status": "completed",
        "isDraft": False,
        "creationDate": "2026-06-18T10:00:00Z",
        "closedDate": "2026-06-21T10:00:00Z",
        "title": "Add activity bundle adapter",
        "description": "Wire Azure activity into Catalogue.",
        "sourceRefName": "refs/heads/collect",
        "targetRefName": "refs/heads/main",
        "mergeStatus": "succeeded",
        "lastMergeSourceCommit": {"commitId": "head123"},
        "lastMergeTargetCommit": {"commitId": "base123"},
        "lastMergeCommit": {"commitId": "merge123"},
        "supportsIterations": True,
        "createdBy": {"id": "alice-id", "displayName": "Alice Author"},
        "reviewers": [{"id": "bob-id", "displayName": "Bob Reviewer", "vote": 10}],
        "labels": [{"id": "label-id", "name": "feature", "active": True}],
        "workItemRefs": [{"id": "1001", "url": "https://dev.azure.com/work/1001"}],
        "completionOptions": {"mergeStrategy": "squash", "deleteSourceBranch": True},
        "url": "https://dev.azure.com/api/pr/42",
        "remoteUrl": "https://dev.azure.com/Acme/Platform/_git/Backend/pullrequest/42",
    }


def _commit() -> dict[str, object]:
    return {
        "commitId": "abc123",
        "comment": "add adapter\n\nBody text",
        "parents": ["parent123"],
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
        "url": "https://dev.azure.com/api/commit/abc123",
        "remoteUrl": "https://dev.azure.com/commit/abc123",
    }


def test_local_git_and_azure_devops_share_repository_id(tmp_path: Path) -> None:
    import subprocess

    from shevek_collect.git_collect import GitCollectOptions, collect_git

    repo = tmp_path / "Backend"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
    )
    (repo / "README.md").write_text("# Backend\n")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "initial"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "remote",
            "add",
            "origin",
            "git@ssh.dev.azure.com:v3/Acme/Platform/Backend",
        ],
        check=True,
    )

    git_out = tmp_path / "git_bundle"
    azure_out = tmp_path / "azure_bundle"
    collect_git(GitCollectOptions(repos=(repo,), out=git_out))
    collect_azure_devops(
        AzureDevOpsCollectOptions(
            organization="Acme",
            repos=(AzureRepoRef(project="Platform", repo="Backend"),),
            out=azure_out,
            requester=_fake_requester(),
        )
    )

    git_event = json.loads((git_out / "source_events.jsonl").read_text().splitlines()[0])
    azure_event = json.loads((azure_out / "source_events.jsonl").read_text().splitlines()[0])
    assert git_event["source"]["repo_id"] == azure_event["source"]["repo_id"]

def test_collect_azure_devops_retries_429_and_honours_retry_after(tmp_path: Path) -> None:
    from io import BytesIO
    from urllib.error import HTTPError

    out = tmp_path / "bundle"
    base = _fake_requester()
    attempts = 0
    delays: list[float] = []

    def request(url: str, headers: Mapping[str, str]):
        nonlocal attempts
        if "/pullrequests/42/commits" in url:
            attempts += 1
            if attempts == 1:
                raise HTTPError(
                    url,
                    429,
                    "Too Many Requests",
                    {"Retry-After": "0"},
                    BytesIO(b"throttled"),
                )
        return base(url, headers)

    result = collect_azure_devops(
        AzureDevOpsCollectOptions(
            organization="Acme",
            repos=(AzureRepoRef(project="Platform", repo="Backend"),),
            out=out,
            requester=request,
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
    assert manifest["repository_results"][0]["retry"]["retry_attempts"] == 1


def test_collect_azure_devops_setup_failure_does_not_persist_raw_details(
    tmp_path: Path,
    monkeypatch,
) -> None:
    out = tmp_path / "bundle"
    monkeypatch.delenv("AZURE_DEVOPS_EXT_PAT", raising=False)

    result = collect_azure_devops(
        AzureDevOpsCollectOptions(
            organization="Acme",
            repos=(AzureRepoRef(project="Platform", repo="Backend"),),
            out=out,
        )
    )

    expected_id = azure_devops_repository_identity(
        organization="Acme",
        project="Platform",
        repo="Backend",
    ).fingerprint
    manifest = json.loads((out / "collect_manifest.json").read_text())
    manifest_text = json.dumps(manifest, sort_keys=True)

    assert result["errors"] == ["azure_devops_setup: provider_setup_failed"]
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
    assert "Platform/Backend" not in manifest_text
    assert "is not set" not in manifest_text

def test_collect_azure_devops_discards_repository_records_after_late_failure(
    tmp_path: Path,
) -> None:
    from io import BytesIO
    from urllib.error import HTTPError

    out = tmp_path / "bundle"
    base = _fake_requester()
    calls = 0

    def request(url: str, headers: Mapping[str, str]):
        nonlocal calls
        if "/pullrequests/42/threads" in url:
            calls += 1
            raise HTTPError(
                url,
                401,
                "Unauthorized",
                {},
                BytesIO(b"bad token"),
            )
        return base(url, headers)

    result = collect_azure_devops(
        AzureDevOpsCollectOptions(
            organization="Acme",
            repos=(AzureRepoRef(project="Platform", repo="Backend"),),
            out=out,
            requester=request,
            retry_sleep=lambda _seconds: None,
        )
    )

    assert calls == 1
    assert result["collection_status"] == "failed"
    assert result["repos_collected"] == 0
    assert result["events"] == 0
    assert result["artifacts"] == 0
    assert (out / "source_events.jsonl").read_text() == ""
    assert (out / "source_artifacts.jsonl").read_text() == ""
    manifest = json.loads((out / "collect_manifest.json").read_text())
    expected_id = azure_devops_repository_identity(
        organization="Acme",
        project="Platform",
        repo="Backend",
    ).fingerprint
    manifest_text = json.dumps(manifest, sort_keys=True)

    assert manifest["repository_results"][0]["status"] == "failed"
    assert manifest["repository_results"][0]["repo_id"] == expected_id
    assert manifest["repository_results"][0]["error"] == "authentication_failed"
    assert "repo_full_name" not in manifest["repository_results"][0]
    assert manifest["errors"] == [f"{expected_id}: authentication_failed"]
    assert manifest["privacy"]["contains_raw_error_text"] is False
    assert manifest["privacy"]["contains_failed_repository_names"] is False
    assert "Platform/Backend" not in manifest_text
    assert "bad token" not in manifest_text
    assert manifest["reliability"]["repository_transaction"] == "all_or_nothing"
