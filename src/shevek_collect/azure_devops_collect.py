from __future__ import annotations

import base64
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterable, Literal, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request
from .http_security import secure_urlopen, read_response

from . import __version__
from .io_utils import atomic_bundle_directory, write_json, write_jsonl, write_text
from .privacy import PrivacyHasher, resolve_privacy_hasher
from .progress import (
    ProgressCallback,
    emit_progress,
    progress_checkpoint,
    retry_progress_message,
)
from .reliability import (
    RetryExecutor,
    RetryPolicy,
    RetrySnapshot,
    collection_status,
    rate_limit_message,
    retry_after_seconds,
    transient_network_message,
)
from .repo_identity import azure_devops_repository_identity

BodyMode = Literal["none", "title", "full"]
CommentMode = Literal["none", "metadata", "full"]
ActorMode = Literal["login", "hash", "none"]
CommitMessageMode = Literal["none", "subject", "full"]

SOURCE_EVENT_SCHEMA_VERSION = "shevek.source_event.v1"
SOURCE_ARTIFACT_SCHEMA_VERSION = "shevek.source_artifact.v1"
COLLECT_MANIFEST_SCHEMA_VERSION = "shevek.collect_manifest.v1"

# A requester receives the fully constructed URL and request headers. Tests can
# return either a JSON mapping or ``(mapping, headers)``.
AzdoRequester = Callable[[str, Mapping[str, str]], object]


@dataclass(frozen=True)
class AzureRepoRef:
    project: str
    repo: str

    @property
    def display_name(self) -> str:
        return f"{self.project}/{self.repo}"


@dataclass(frozen=True)
class AzureDevOpsCollectOptions:
    organization: str
    repos: tuple[AzureRepoRef, ...]
    out: Path
    overwrite: bool = False
    force_overwrite: bool = False
    since: str | None = None
    max_prs: int | None = None
    body_mode: BodyMode = "title"
    comment_mode: CommentMode = "metadata"
    actor_mode: ActorMode = "login"
    commit_message_mode: CommitMessageMode = "subject"
    include_raw_emails: bool = False
    include_urls: bool = False
    token_env: str = "AZURE_DEVOPS_EXT_PAT"
    api_version: str = "7.1"
    requester: AzdoRequester | None = field(default=None, repr=False, compare=False)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    retry_sleep: Callable[[float], None] | None = field(default=None, repr=False, compare=False)
    retry_random: Callable[[], float] | None = field(default=None, repr=False, compare=False)
    privacy_hasher: PrivacyHasher | None = field(default=None, repr=False, compare=False)
    progress: ProgressCallback | None = field(default=None, repr=False, compare=False)


class AzureDevOpsRequestError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.headers = {str(key).casefold(): str(value) for key, value in (headers or {}).items()}


class AzureDevOpsClient:
    def __init__(
        self,
        *,
        organization: str,
        token_env: str,
        api_version: str = "7.1",
        requester: AzdoRequester | None = None,
        retry_policy: RetryPolicy | None = None,
        retry_sleep: Callable[[float], None] | None = None,
        retry_random: Callable[[], float] | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.organization = organization
        self.token_env = token_env
        self.api_version = api_version
        self._requester = requester
        self._retry = RetryExecutor(
            retry_policy or RetryPolicy(),
            sleep=retry_sleep,
            random_source=retry_random,
            on_retry=(
                None
                if progress is None
                else lambda notice: emit_progress(
                    progress,
                    retry_progress_message(
                        operation=notice.operation,
                        delay_seconds=notice.delay_seconds,
                        next_attempt=notice.next_attempt,
                        max_attempts=notice.max_attempts,
                        error=notice.error,
                    ),
                )
            ),
        )

    @property
    def retry_policy(self) -> RetryPolicy:
        return self._retry.policy

    def retry_snapshot(self) -> RetrySnapshot:
        return self._retry.snapshot()

    def check_auth(self) -> None:
        if self._requester is not None:
            return
        if not os.environ.get(self.token_env):
            raise RuntimeError(
                f"Azure DevOps PAT environment variable {self.token_env!r} is not set"
            )

    def get(
        self,
        *,
        project: str,
        path: str,
        params: Mapping[str, object] | None = None,
    ) -> tuple[dict[str, object], dict[str, str]]:
        query: dict[str, object] = {"api-version": self.api_version}
        if params:
            query.update({key: value for key, value in params.items() if value is not None})
        base = (
            f"https://dev.azure.com/{quote(self.organization, safe='')}/"
            f"{quote(project, safe='')}/_apis/{path.lstrip('/')}"
        )
        url = f"{base}?{urlencode(query)}"
        headers = {"Accept": "application/json"}
        token = os.environ.get(self.token_env)
        if token:
            encoded = base64.b64encode(f":{token}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"

        return self._retry.run(
            lambda: self._get_once(url, headers),
            should_retry=_azure_should_retry,
            retry_after=_azure_retry_after,
            operation_name="Azure DevOps API request",
        )

    def _get_once(
        self,
        url: str,
        headers: Mapping[str, str],
    ) -> tuple[dict[str, object], dict[str, str]]:
        if self._requester is not None:
            try:
                raw = self._requester(url, headers)
            except HTTPError as exc:
                body = exc.read(64 * 1024).decode("utf-8", errors="replace")
                detail = body.strip() or str(exc.reason)
                raise AzureDevOpsRequestError(
                    f"Azure DevOps GET failed ({exc.code}): {detail}",
                    status_code=exc.code,
                    headers=dict(exc.headers or {}),
                ) from exc
            except URLError as exc:
                raise AzureDevOpsRequestError(f"Azure DevOps GET failed: {exc.reason}") from exc
            if isinstance(raw, tuple) and len(raw) == 2:
                payload, response_headers = raw
            else:
                payload, response_headers = raw, {}
            if not isinstance(payload, dict):
                raise RuntimeError(
                    f"Azure DevOps requester returned {type(payload).__name__}, expected mapping"
                )
            return dict(payload), {
                str(key).casefold(): str(value) for key, value in dict(response_headers).items()
            }

        request = Request(url, headers=dict(headers), method="GET")
        try:
            with secure_urlopen(request, timeout=60) as response:  # noqa: S310 - fixed HTTPS host
                text = read_response(response).decode("utf-8", errors="replace")
                payload = json.loads(text) if text.strip() else {}
                if not isinstance(payload, dict):
                    raise RuntimeError(
                        f"Azure DevOps returned {type(payload).__name__}, expected JSON object"
                    )
                return payload, {
                    str(key).casefold(): str(value) for key, value in response.headers.items()
                }
        except HTTPError as exc:
            body = exc.read(64 * 1024).decode("utf-8", errors="replace")
            detail = body.strip() or str(exc.reason)
            raise AzureDevOpsRequestError(
                f"Azure DevOps GET failed ({exc.code}): {detail}",
                status_code=exc.code,
                headers=dict(exc.headers or {}),
            ) from exc
        except URLError as exc:
            raise AzureDevOpsRequestError(f"Azure DevOps GET failed: {exc.reason}") from exc

    def repository(self, repo: AzureRepoRef) -> dict[str, object]:
        payload, _ = self.get(
            project=repo.project,
            path=f"git/repositories/{quote(repo.repo, safe='')}",
        )
        return payload

    def pull_requests(self, repo: AzureRepoRef) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        skip = 0
        page_size = 100
        while True:
            payload, _ = self.get(
                project=repo.project,
                path=f"git/repositories/{quote(repo.repo, safe='')}/pullrequests",
                params={
                    "searchCriteria.status": "all",
                    "$top": page_size,
                    "$skip": skip,
                },
            )
            page = _value_list(payload)
            records.extend(page)
            if len(page) < page_size:
                break
            skip += len(page)
        return records

    def pull_request(self, repo: AzureRepoRef, number: int) -> dict[str, object]:
        payload, _ = self.get(
            project=repo.project,
            path=(f"git/repositories/{quote(repo.repo, safe='')}/pullrequests/{number}"),
            params={"includeWorkItemRefs": "true"},
        )
        return payload

    def pull_request_commits(self, repo: AzureRepoRef, number: int) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        continuation: str | None = None
        while True:
            payload, headers = self.get(
                project=repo.project,
                path=(
                    f"git/repositories/{quote(repo.repo, safe='')}/pullrequests/{number}/commits"
                ),
                params={"$top": 100, "continuationToken": continuation},
            )
            records.extend(_value_list(payload))
            next_token = headers.get("x-ms-continuationtoken") or payload.get("continuationToken")
            if next_token is None or str(next_token) == continuation:
                break
            continuation = str(next_token)
        return records

    def latest_iteration(self, repo: AzureRepoRef, number: int) -> int | None:
        payload, _ = self.get(
            project=repo.project,
            path=(f"git/repositories/{quote(repo.repo, safe='')}/pullrequests/{number}/iterations"),
        )
        ids = [
            _int(row.get("id"), default=0)
            for row in _value_list(payload)
            if _int(row.get("id"), default=0) > 0
        ]
        return max(ids) if ids else None

    def iteration_changes(
        self,
        repo: AzureRepoRef,
        number: int,
        iteration_id: int,
    ) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        skip = 0
        top = 2000
        while True:
            payload, _ = self.get(
                project=repo.project,
                path=(
                    f"git/repositories/{quote(repo.repo, safe='')}/pullrequests/"
                    f"{number}/iterations/{iteration_id}/changes"
                ),
                params={"$top": top, "$skip": skip},
            )
            page = payload.get("changeEntries")
            if isinstance(page, list):
                records.extend(row for row in page if isinstance(row, dict))
            next_skip = _int(payload.get("nextSkip"), default=0)
            next_top = _int(payload.get("nextTop"), default=0)
            if next_skip <= 0 or next_top <= 0 or next_skip == skip:
                break
            skip, top = next_skip, next_top
        return records

    def threads(self, repo: AzureRepoRef, number: int) -> list[dict[str, object]]:
        payload, _ = self.get(
            project=repo.project,
            path=(f"git/repositories/{quote(repo.repo, safe='')}/pullrequests/{number}/threads"),
        )
        return _value_list(payload)


def _azure_should_retry(exc: Exception) -> bool:
    if isinstance(exc, AzureDevOpsRequestError):
        status = exc.status_code
        message = str(exc)
        if status in {408, 429}:
            return True
        if status is not None and 500 <= status <= 599:
            return True
        if status == 403:
            return rate_limit_message(message) or any(
                key in exc.headers for key in ("retry-after", "x-ms-retry-after-ms")
            )
        return status is None and transient_network_message(message)
    return isinstance(exc, (ConnectionError, TimeoutError, OSError)) and not isinstance(
        exc, FileNotFoundError
    )


def _azure_retry_after(exc: Exception) -> float | None:
    if isinstance(exc, AzureDevOpsRequestError):
        return retry_after_seconds(exc.headers, message=str(exc))
    return retry_after_seconds(message=str(exc))


def collect_azure_devops(options: AzureDevOpsCollectOptions) -> dict[str, object]:
    """Collect Azure DevOps pull-request activity and atomically publish the bundle."""
    options = replace(
        options,
        privacy_hasher=resolve_privacy_hasher(options.privacy_hasher),
    )
    public_out = options.out.expanduser().resolve()
    with atomic_bundle_directory(
        options.out,
        overwrite=options.overwrite,
        force_overwrite=options.force_overwrite,
    ) as stage:
        return _collect_azure_devops_into(options, out=stage, public_out=public_out)


def _collect_azure_devops_into(
    options: AzureDevOpsCollectOptions,
    *,
    out: Path,
    public_out: Path,
) -> dict[str, object]:
    observed_at = _now_iso()
    privacy_hasher = options.privacy_hasher
    assert privacy_hasher is not None
    client = AzureDevOpsClient(
        organization=options.organization,
        token_env=options.token_env,
        api_version=options.api_version,
        requester=options.requester,
        retry_policy=options.retry_policy,
        retry_sleep=options.retry_sleep,
        retry_random=options.retry_random,
        progress=options.progress,
    )
    events: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    changed_path_stats: dict[tuple[str, str], dict[str, object]] = {}
    errors: list[str] = []
    collected_repos: list[dict[str, object]] = []
    repository_results: list[dict[str, object]] = []

    emit_progress(
        options.progress,
        f"Starting Azure DevOps collection for {len(options.repos)} repositories",
    )
    try:
        client.check_auth()
    except Exception as exc:
        errors.append("azure_devops_setup: provider_setup_failed")
        emit_progress(options.progress, f"Azure DevOps setup failed: {exc}")
        repository_results.extend(
            {
                "repo_id": _input_repo_id(
                    organization=options.organization,
                    repo_ref=repo,
                    privacy_hasher=privacy_hasher,
                ),
                "status": "failed",
                "error": "provider_setup_failed",
                "retry": RetrySnapshot().as_dict(),
            }
            for repo in options.repos
        )
        return _write_outputs(
            out=out,
            public_out=public_out,
            observed_at=observed_at,
            options=options,
            collected_repos=collected_repos,
            repository_results=repository_results,
            retry_metrics=client.retry_snapshot(),
            events=events,
            artifacts=artifacts,
            errors=errors,
        )

    since_dt = _parse_since(options.since)
    for repo_index, repo_ref in enumerate(options.repos, start=1):
        emit_progress(
            options.progress,
            f"Azure DevOps repository {repo_index}/{len(options.repos)}: {repo_ref.display_name}",
        )
        retry_before = client.retry_snapshot()
        repo_events: list[dict[str, object]] = []
        repo_artifacts: list[dict[str, object]] = []
        repo_path_stats: dict[tuple[str, str], dict[str, object]] = {}
        repo_id = _input_repo_id(
            organization=options.organization,
            repo_ref=repo_ref,
            privacy_hasher=privacy_hasher,
        )
        repo_result: dict[str, object] = {
            "repo_id": repo_id,
            "status": "failed",
        }
        try:
            repository = client.repository(repo_ref)
            repo_summary = _repo_summary(
                organization=options.organization,
                repo_ref=repo_ref,
                repository=repository,
                privacy_hasher=privacy_hasher,
            )
            repo_id = str(repo_summary["repo_id"])
            repo_result.update(
                {
                    "repo_id": repo_id,
                    "repo_full_name": repo_ref.display_name,
                }
            )
            pull_summaries = _filter_pulls(
                client.pull_requests(repo_ref),
                since=since_dt,
                max_prs=options.max_prs,
            )
            emit_progress(options.progress, f"  found {len(pull_summaries)} pull requests")
            repo_artifacts.append(
                _repo_artifact(
                    repo_summary,
                    observed_at=observed_at,
                    pull_request_count=len(pull_summaries),
                )
            )
            counts = {
                "pull_requests": 0,
                "pr_commits": 0,
                "pr_files": 0,
                "comments": 0,
            }

            for pull_index, summary in enumerate(pull_summaries, start=1):
                number = _int(summary.get("pullRequestId"), default=0)
                if number <= 0:
                    continue
                pr = client.pull_request(repo_ref, number)
                commits = client.pull_request_commits(repo_ref, number)
                iteration_id = client.latest_iteration(repo_ref, number)
                changes = (
                    client.iteration_changes(repo_ref, number, iteration_id)
                    if iteration_id is not None
                    else []
                )
                threads = client.threads(repo_ref, number) if options.comment_mode != "none" else []

                repo_events.append(
                    _pull_request_event(
                        pr,
                        repo_summary,
                        observed_at=observed_at,
                        body_mode=options.body_mode,
                        actor_mode=options.actor_mode,
                        include_urls=options.include_urls,
                        privacy_hasher=privacy_hasher,
                    )
                )
                counts["pull_requests"] += 1

                for commit in commits:
                    repo_events.append(
                        _pr_commit_event(
                            commit,
                            repo_summary,
                            pr_number=number,
                            observed_at=observed_at,
                            actor_mode=options.actor_mode,
                            commit_message_mode=options.commit_message_mode,
                            include_raw_emails=options.include_raw_emails,
                            include_urls=options.include_urls,
                            privacy_hasher=privacy_hasher,
                        )
                    )
                    counts["pr_commits"] += 1

                for change in changes:
                    artifact = _pr_file_artifact(
                        change,
                        repo_summary,
                        pr_number=number,
                        iteration_id=iteration_id,
                        observed_at=observed_at,
                        include_urls=options.include_urls,
                        privacy_hasher=privacy_hasher,
                    )
                    if artifact is None:
                        continue
                    repo_artifacts.append(artifact)
                    _update_changed_path_stats(
                        repo_path_stats,
                        repo_id=repo_id,
                        pr=pr,
                        change=change,
                        privacy_hasher=privacy_hasher,
                    )
                    counts["pr_files"] += 1

                for thread in threads:
                    for comment in _thread_comments(thread):
                        repo_events.append(
                            _comment_event(
                                comment,
                                thread,
                                repo_summary,
                                pr_number=number,
                                observed_at=observed_at,
                                comment_mode=options.comment_mode,
                                actor_mode=options.actor_mode,
                                include_urls=options.include_urls,
                                privacy_hasher=privacy_hasher,
                            )
                        )
                        counts["comments"] += 1

                if progress_checkpoint(pull_index, len(pull_summaries), every=25):
                    emit_progress(
                        options.progress,
                        f"  processed {pull_index}/{len(pull_summaries)} pull requests",
                    )

            # Commit repository observations only after every request and transform succeeds.
            events.extend(repo_events)
            artifacts.extend(repo_artifacts)
            changed_path_stats.update(repo_path_stats)
            collected_repos.append(
                {
                    "repo_id": repo_id,
                    "repository_fingerprint": repo_id,
                    "organization": options.organization,
                    "project": repo_summary["project"],
                    "repo": repo_summary["repo"],
                    "repo_full_name": repo_summary["repo_full_name"],
                    **counts,
                }
            )
            repo_result.update({"status": "complete", "counts": counts})
            emit_progress(
                options.progress,
                f"  complete: {counts['pull_requests']} pull requests",
            )
        except Exception as exc:
            error_code = _bundle_safe_azure_devops_error(exc)
            repo_result.pop("repo_full_name", None)
            repo_result["error"] = error_code
            errors.append(f"{repo_id}: {error_code}")
            emit_progress(options.progress, f"  failed: {exc}")
        finally:
            repo_result["retry"] = (client.retry_snapshot() - retry_before).as_dict()
            repository_results.append(repo_result)

    artifacts.extend(
        _changed_path_artifacts(
            changed_path_stats,
            observed_at=observed_at,
            privacy_hasher=privacy_hasher,
        )
    )
    return _write_outputs(
        out=out,
        public_out=public_out,
        observed_at=observed_at,
        options=options,
        collected_repos=collected_repos,
        repository_results=repository_results,
        retry_metrics=client.retry_snapshot(),
        events=events,
        artifacts=artifacts,
        errors=errors,
    )


def _input_repo_id(
    *,
    organization: str,
    repo_ref: AzureRepoRef,
    privacy_hasher: PrivacyHasher,
) -> str:
    return azure_devops_repository_identity(
        organization=organization,
        project=repo_ref.project,
        repo=repo_ref.repo,
        privacy_hasher=privacy_hasher,
    ).fingerprint


def _bundle_safe_azure_devops_error(exc: Exception) -> str:
    """Return a stable bundle error code without provider text or repository names."""
    if isinstance(exc, TimeoutError):
        return "provider_timeout"
    if isinstance(exc, json.JSONDecodeError):
        return "provider_response_parse_failed"
    if isinstance(exc, AzureDevOpsRequestError):
        status = exc.status_code
        if status == 401:
            return "authentication_failed"
        if status == 403:
            return "permission_denied"
        if status == 404:
            return "repository_not_found"
        if status == 408:
            return "provider_timeout"
        if status == 429:
            return "rate_limited"
        if status is not None and 500 <= status <= 599:
            return "provider_unavailable"
        return "provider_request_failed"
    return f"collector_error:{type(exc).__name__}"

def parse_azure_repo(value: str) -> AzureRepoRef:
    parts = [part.strip() for part in value.strip().split("/", 1)]
    if len(parts) != 2 or not all(parts):
        raise ValueError(f"Expected Azure DevOps repository as project/repo, got {value!r}")
    return AzureRepoRef(project=parts[0], repo=parts[1])


def _write_outputs(
    *,
    out: Path,
    public_out: Path,
    observed_at: str,
    options: AzureDevOpsCollectOptions,
    collected_repos: list[dict[str, object]],
    repository_results: list[dict[str, object]],
    retry_metrics: RetrySnapshot,
    events: list[dict[str, object]],
    artifacts: list[dict[str, object]],
    errors: list[str],
) -> dict[str, object]:
    outputs = {
        "source_events": "source_events.jsonl",
        "source_artifacts": "source_artifacts.jsonl",
        "collect_manifest": "collect_manifest.json",
        "privacy_report": "privacy_report.md",
    }
    manifest = _manifest(
        out=public_out,
        observed_at=observed_at,
        options=options,
        collected_repos=collected_repos,
        repository_results=repository_results,
        retry_metrics=retry_metrics,
        events=events,
        artifacts=artifacts,
        errors=errors,
        outputs=outputs,
    )
    write_jsonl(out / outputs["source_events"], events)
    write_jsonl(out / outputs["source_artifacts"], artifacts)
    write_json(out / outputs["collect_manifest"], manifest)
    write_text(out / outputs["privacy_report"], _privacy_report(manifest, options=options))
    status = collection_status(
        repos_requested=len(options.repos),
        repos_collected=len(collected_repos),
        errors=errors,
    )
    emit_progress(
        options.progress,
        f"Azure DevOps collection {status}: {len(collected_repos)}/{len(options.repos)} repositories",
    )
    return {
        "out": public_out.as_posix(),
        "collection_status": status,
        "complete": status == "complete",
        "repos_requested": len(options.repos),
        "repos_collected": len(collected_repos),
        "events": len(events),
        "artifacts": len(artifacts),
        "repository_results": repository_results,
        "retry": retry_metrics.as_dict(),
        "errors": errors,
        "outputs": outputs,
    }


def _manifest(
    *,
    out: Path,
    observed_at: str,
    options: AzureDevOpsCollectOptions,
    collected_repos: list[dict[str, object]],
    repository_results: list[dict[str, object]],
    retry_metrics: RetrySnapshot,
    events: list[dict[str, object]],
    artifacts: list[dict[str, object]],
    errors: list[str],
    outputs: dict[str, str],
) -> dict[str, object]:
    event_counts: dict[str, int] = defaultdict(int)
    artifact_counts: dict[str, int] = defaultdict(int)
    for event in events:
        event_counts[str(event.get("event_type") or "unknown")] += 1
    for artifact in artifacts:
        artifact_counts[str(artifact.get("artifact_type") or "unknown")] += 1
    status = collection_status(
        repos_requested=len(options.repos),
        repos_collected=len(collected_repos),
        errors=errors,
    )
    return {
        "schema_version": COLLECT_MANIFEST_SCHEMA_VERSION,
        "collector": {"name": "shevek_collect", "version": __version__},
        "created_at": observed_at,
        "bundle_kind": "source_evidence",
        "bundle_version": "0.1",
        "out": out.name,
        "out_path_hash": _privacy_hasher(options).local_path(out.as_posix()),
        "command": "azure-devops scan",
        "source_kinds": ["azure_devops"],
        "collection_status": status,
        "complete": status == "complete",
        "settings": {
            "organization": options.organization,
            "since": options.since,
            "max_prs": options.max_prs,
            "body_mode": options.body_mode,
            "comment_mode": options.comment_mode,
            "actor_mode": options.actor_mode,
            "commit_message_mode": options.commit_message_mode,
            "include_raw_emails": options.include_raw_emails,
            "include_urls": options.include_urls,
            "include_file_content": False,
            "include_patches": False,
            "token_env": options.token_env,
            "api_version": options.api_version,
        },
        "counts": {
            "repos_requested": len(options.repos),
            "repos_collected": len(collected_repos),
            "repos_failed": len(options.repos) - len(collected_repos),
            "events": len(events),
            "source_events": len(events),
            "source_artifacts": len(artifacts),
            **dict(sorted(event_counts.items())),
            **{f"artifact:{key}": value for key, value in sorted(artifact_counts.items())},
        },
        "repos": collected_repos,
        "repository_results": repository_results,
        "reliability": {
            "repository_transaction": "all_or_nothing",
            "retry_policy": options.retry_policy.manifest_metadata(),
            "retry_metrics": retry_metrics.as_dict(),
        },
        "outputs": outputs,
        "privacy": {
            "contains_file_content": False,
            "contains_patches": False,
            "contains_paths": True,
            "contains_pr_titles": options.body_mode in {"title", "full"},
            "contains_pr_bodies": options.body_mode == "full",
            "contains_comment_bodies": options.comment_mode == "full",
            "contains_commit_messages": options.commit_message_mode != "none",
            "contains_full_commit_bodies": options.commit_message_mode == "full",
            "contains_actor_logins": options.actor_mode == "login",
            "contains_actor_hashes": options.actor_mode == "hash",
            "contains_raw_emails": options.include_raw_emails,
            "contains_urls": options.include_urls,
            "contains_raw_error_text": False,
            "contains_failed_repository_names": False,
            "secret_scanning": "not_performed",
        },
        "identity": _privacy_hasher(options).manifest_metadata(),
        "errors": errors,
    }


def _privacy_report(manifest: dict[str, object], *, options: AzureDevOpsCollectOptions) -> str:
    counts = manifest.get("counts", {})
    privacy = manifest.get("privacy", {})
    identity = manifest.get("identity", {})
    reliability = manifest.get("reliability", {})
    assert isinstance(counts, dict)
    assert isinstance(privacy, dict)
    assert isinstance(identity, dict)
    assert isinstance(reliability, dict)
    retry_metrics = reliability.get("retry_metrics", {})
    assert isinstance(retry_metrics, dict)
    lines = [
        "# Shevek Collect Privacy Report",
        "",
        f"Created at: `{manifest.get('created_at')}`",
        f"Bundle: `{manifest.get('out')}`",
        f"Collection status: `{manifest.get('collection_status')}`",
        "",
        "## Summary",
        "",
        f"- Repositories requested: {counts.get('repos_requested', 0)}",
        f"- Repositories collected: {counts.get('repos_collected', 0)}",
        f"- Repositories failed: {counts.get('repos_failed', 0)}",
        f"- Source events: {counts.get('source_events', 0)}",
        f"- Source artifacts: {counts.get('source_artifacts', 0)}",
        f"- Provider requests: {retry_metrics.get('requests', 0)}",
        f"- Retry attempts: {retry_metrics.get('retry_attempts', 0)}",
        f"- Exhausted requests: {retry_metrics.get('exhausted_requests', 0)}",
        "",
        "## Reliability",
        "",
        "- Repository publication is all-or-nothing within this bundle.",
        "- Transient provider failures are retried with exponential full-jitter backoff.",
        "- Ordinary authentication and permission failures are not retried.",
        "",
        "## Pseudonymous identifiers",
        "",
        f"- Scheme: `{identity.get('schema')}`",
        f"- Algorithm: `{identity.get('algorithm')}` with domain separation.",
        f"- Pseudonymisation namespace (public ID): `{identity.get('key_id')}`",
        "- The secret key is not included in the bundle.",
        "",
        "## Included by this Azure DevOps scan",
        "",
        "- Pull request metadata, source/target refs, merge state, reviewers, commits, and changed paths.",
        "- Repository and project identity needed to join hosted activity to local Git evidence.",
    ]
    if options.body_mode == "none":
        lines.append("- Pull request titles and descriptions were not included.")
    elif options.body_mode == "title":
        lines.append("- Pull request titles were included; descriptions were not included.")
    else:
        lines.append("- Pull request titles and descriptions were included.")
    if options.comment_mode == "none":
        lines.append("- Pull request threads were not collected.")
    elif options.comment_mode == "metadata":
        lines.append("- Pull request thread/comment metadata was included without comment bodies.")
    else:
        lines.append("- Pull request comment bodies were included.")
    lines.extend(
        [
            "",
            "## Not included by default",
            "",
            "- Source file contents.",
            "- Patch or diff hunk contents.",
            "- Raw commit email addresses unless `include_raw_emails` is enabled.",
            "- Azure DevOps URLs unless `include_urls` is enabled.",
            "- The PAT value; only the environment-variable name is recorded.",
            "",
            "## Privacy flags",
            "",
        ]
    )
    for key, value in sorted(privacy.items()):
        lines.append(f"- `{key}`: `{value}`")
    errors = manifest.get("errors") or []
    if errors:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in errors)
    return "\n".join(lines) + "\n"


def _repo_summary(
    *,
    organization: str,
    repo_ref: AzureRepoRef,
    repository: Mapping[str, object],
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    project_block = repository.get("project") if isinstance(repository.get("project"), dict) else {}
    assert isinstance(project_block, dict)
    project = str(project_block.get("name") or repo_ref.project)
    repo_name = str(repository.get("name") or repo_ref.repo)
    identity = azure_devops_repository_identity(
        organization=organization,
        project=project,
        repo=repo_name,
        privacy_hasher=privacy_hasher,
    )
    return {
        "kind": "azure_devops",
        "provider": "azure_devops",
        "repo_id": identity.fingerprint,
        "repository_fingerprint": identity.fingerprint,
        "organization": organization,
        "project": project,
        "project_id": project_block.get("id"),
        "repo": repo_name,
        "repository_id": repository.get("id"),
        "repo_full_name": f"{project}/{repo_name}",
        "default_branch": repository.get("defaultBranch"),
        "is_disabled": repository.get("isDisabled"),
        "is_fork": repository.get("isFork"),
        "size": repository.get("size"),
    }


def _repo_artifact(
    repo_summary: Mapping[str, object], *, observed_at: str, pull_request_count: int
) -> dict[str, object]:
    repo_id = str(repo_summary["repo_id"])
    return {
        "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
        "artifact_id": f"azure_devops.repo:{repo_id}",
        "artifact_type": "azure_devops.repository",
        "semantic_type": "code_host.repository",
        "source": _source_block(repo_summary),
        "observed_at": observed_at,
        "payload": _drop_none(
            {
                "repo_full_name": repo_summary.get("repo_full_name"),
                "organization": repo_summary.get("organization"),
                "project": repo_summary.get("project"),
                "project_id": repo_summary.get("project_id"),
                "repository_id": repo_summary.get("repository_id"),
                "default_branch": repo_summary.get("default_branch"),
                "is_disabled": repo_summary.get("is_disabled"),
                "is_fork": repo_summary.get("is_fork"),
                "size": repo_summary.get("size"),
                "pull_request_count": pull_request_count,
            }
        ),
        "privacy": {"contains_content": False, "contains_paths": False},
        "provenance": _provenance(),
    }


def _pull_request_event(
    pr: Mapping[str, object],
    repo_summary: Mapping[str, object],
    *,
    observed_at: str,
    body_mode: BodyMode,
    actor_mode: ActorMode,
    include_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    number = _int(pr.get("pullRequestId"), default=0)
    status = str(pr.get("status") or "")
    source_commit = _commit_ref(pr.get("lastMergeSourceCommit"))
    target_commit = _commit_ref(pr.get("lastMergeTargetCommit"))
    merge_commit = _commit_ref(pr.get("lastMergeCommit"))
    payload: dict[str, object] = {
        "number": number,
        "id": pr.get("pullRequestId"),
        "code_review_id": pr.get("codeReviewId"),
        "state": status,
        "draft": pr.get("isDraft"),
        "created_at": pr.get("creationDate"),
        "closed_at": pr.get("closedDate"),
        "merged_at": pr.get("closedDate") if status == "completed" else None,
        "merged": status == "completed",
        "merge_commit_sha": merge_commit.get("sha") if merge_commit else None,
        "merge_status": pr.get("mergeStatus"),
        "merge_failure_type": pr.get("mergeFailureType"),
        "merge_failure_message": pr.get("mergeFailureMessage"),
        "has_multiple_merge_bases": pr.get("hasMultipleMergeBases"),
        "supports_iterations": pr.get("supportsIterations"),
        "labels": _labels(pr.get("labels")),
        "reviewers": _reviewers(
            pr.get("reviewers"), actor_mode=actor_mode, privacy_hasher=privacy_hasher
        ),
        "work_item_refs": _resource_refs(pr.get("workItemRefs"), include_urls=include_urls),
        "completion_options": _completion_options(pr.get("completionOptions")),
        "base": _drop_none(
            {
                "ref": pr.get("targetRefName"),
                "sha": target_commit.get("sha") if target_commit else None,
                "repo_full_name": repo_summary.get("repo_full_name"),
                "repository_fingerprint": repo_summary.get("repository_fingerprint"),
            }
        ),
        "head": _drop_none(
            {
                "ref": pr.get("sourceRefName"),
                "sha": source_commit.get("sha") if source_commit else None,
                "repo_full_name": repo_summary.get("repo_full_name"),
                "repository_fingerprint": repo_summary.get("repository_fingerprint"),
            }
        ),
    }
    if body_mode in {"title", "full"}:
        payload["title"] = pr.get("title")
    if body_mode == "full":
        payload["body"] = pr.get("description")
    if include_urls:
        payload["url"] = pr.get("url")
        payload["remote_url"] = pr.get("remoteUrl")

    return {
        "schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "event_id": f"azure_devops.pull_request:{repo_summary['repo_id']}:{number}",
        "event_type": "azure_devops.pull_request",
        "semantic_type": "code_review.pull_request",
        "source": _source_block(repo_summary),
        "occurred_at": str(pr.get("creationDate") or pr.get("closedDate") or observed_at),
        "observed_at": observed_at,
        "actor": _actor(pr.get("createdBy"), actor_mode=actor_mode, privacy_hasher=privacy_hasher),
        "payload": _drop_none(payload),
        "privacy": {
            "contains_content": body_mode == "full",
            "contains_paths": True,
            "contains_pr_title": body_mode in {"title", "full"},
            "contains_pr_body": body_mode == "full",
            "contains_urls": include_urls,
        },
        "provenance": _provenance(),
    }


def _pr_commit_event(
    commit: Mapping[str, object],
    repo_summary: Mapping[str, object],
    *,
    pr_number: int,
    observed_at: str,
    actor_mode: ActorMode,
    commit_message_mode: CommitMessageMode,
    include_raw_emails: bool,
    include_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    sha = str(commit.get("commitId") or "")
    author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
    committer = commit.get("committer") if isinstance(commit.get("committer"), dict) else {}
    assert isinstance(author, dict)
    assert isinstance(committer, dict)
    message = str(commit.get("comment") or "")
    payload: dict[str, object] = {
        "pull_request_number": pr_number,
        "sha": sha,
        "author_date": author.get("date"),
        "committer_date": committer.get("date"),
        "parents": [str(value) for value in commit.get("parents") or []],
        "comment_truncated": commit.get("commentTruncated"),
    }
    if commit_message_mode == "subject":
        payload["subject"] = message.splitlines()[0] if message else ""
    elif commit_message_mode == "full":
        payload["message"] = message
    if include_urls:
        payload["url"] = commit.get("url")
        payload["remote_url"] = commit.get("remoteUrl")

    actor = _actor(commit.get("author"), actor_mode=actor_mode, privacy_hasher=privacy_hasher)
    actor.update(
        _commit_identity(
            author=author,
            committer=committer,
            include_raw_emails=include_raw_emails,
            privacy_hasher=privacy_hasher,
        )
    )
    return {
        "schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "event_id": (
            f"azure_devops.pull_request_commit:{repo_summary['repo_id']}:{pr_number}:{sha}"
        ),
        "event_type": "azure_devops.pull_request_commit",
        "semantic_type": "code_review.pull_request_commit",
        "source": _source_block(repo_summary),
        "occurred_at": str(committer.get("date") or author.get("date") or observed_at),
        "observed_at": observed_at,
        "actor": actor,
        "payload": _drop_none(payload),
        "privacy": {
            "contains_content": commit_message_mode == "full",
            "contains_paths": False,
            "contains_commit_messages": commit_message_mode != "none",
            "contains_full_commit_body": commit_message_mode == "full",
            "contains_raw_email": include_raw_emails,
            "contains_urls": include_urls,
        },
        "provenance": _provenance(),
    }


def _pr_file_artifact(
    change: Mapping[str, object],
    repo_summary: Mapping[str, object],
    *,
    pr_number: int,
    iteration_id: int | None,
    observed_at: str,
    include_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object] | None:
    item = change.get("item") if isinstance(change.get("item"), dict) else {}
    assert isinstance(item, dict)
    path = str(item.get("path") or change.get("originalPath") or "")
    if not path:
        return None
    payload: dict[str, object] = {
        "pull_request_number": pr_number,
        "iteration_id": iteration_id,
        "change_id": change.get("changeId"),
        "filename": path,
        "path": path,
        "path_hash": privacy_hasher.code_path(path),
        "status": change.get("changeType"),
        "previous_filename": change.get("originalPath"),
        "sha": item.get("objectId"),
    }
    if include_urls:
        payload["url"] = item.get("url") or change.get("url")
    return {
        "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
        "artifact_id": (
            f"azure_devops.pr_file:{repo_summary['repo_id']}:{pr_number}:"
            f"{privacy_hasher.code_path(path)}"
        ),
        "artifact_type": "azure_devops.pull_request_file",
        "semantic_type": "code_review.pull_request_file",
        "source": _source_block(repo_summary),
        "observed_at": observed_at,
        "payload": _drop_none(payload),
        "privacy": {
            "contains_content": False,
            "contains_paths": True,
            "contains_patches": False,
            "contains_urls": include_urls,
        },
        "provenance": _provenance(),
    }


def _comment_event(
    comment: Mapping[str, object],
    thread: Mapping[str, object],
    repo_summary: Mapping[str, object],
    *,
    pr_number: int,
    observed_at: str,
    comment_mode: CommentMode,
    actor_mode: ActorMode,
    include_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    comment_id = comment.get("id")
    thread_id = thread.get("id")
    context = thread.get("threadContext") if isinstance(thread.get("threadContext"), dict) else {}
    assert isinstance(context, dict)
    payload: dict[str, object] = {
        "pull_request_number": pr_number,
        "id": comment_id,
        "thread_id": thread_id,
        "parent_comment_id": comment.get("parentCommentId"),
        "comment_type": comment.get("commentType"),
        "created_at": comment.get("publishedDate"),
        "updated_at": comment.get("lastUpdatedDate"),
        "thread_status": thread.get("status"),
        "path": context.get("filePath"),
        "right_file_start": context.get("rightFileStart"),
        "right_file_end": context.get("rightFileEnd"),
    }
    if comment_mode == "full":
        payload["body"] = comment.get("content")
    if include_urls:
        payload["url"] = comment.get("url") or thread.get("url")
    return {
        "schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "event_id": (
            f"azure_devops.comment:{repo_summary['repo_id']}:{pr_number}:{thread_id}:{comment_id}"
        ),
        "event_type": "azure_devops.pull_request_comment",
        "semantic_type": "code_review.comment",
        "source": _source_block(repo_summary),
        "occurred_at": str(comment.get("publishedDate") or observed_at),
        "observed_at": observed_at,
        "actor": _actor(
            comment.get("author"), actor_mode=actor_mode, privacy_hasher=privacy_hasher
        ),
        "payload": _drop_none(payload),
        "privacy": {
            "contains_content": comment_mode == "full",
            "contains_paths": bool(context.get("filePath")),
            "contains_comment_body": comment_mode == "full",
            "contains_urls": include_urls,
        },
        "provenance": _provenance(),
    }


def _update_changed_path_stats(
    path_stats: dict[tuple[str, str], dict[str, object]],
    *,
    repo_id: str,
    pr: Mapping[str, object],
    change: Mapping[str, object],
    privacy_hasher: PrivacyHasher,
) -> None:
    item = change.get("item") if isinstance(change.get("item"), dict) else {}
    assert isinstance(item, dict)
    path = str(item.get("path") or change.get("originalPath") or "")
    if not path:
        return
    occurred_at = str(pr.get("closedDate") or pr.get("creationDate") or "")
    row = path_stats.setdefault(
        (repo_id, path),
        {
            "repo_id": repo_id,
            "path": path,
            "path_hash": privacy_hasher.code_path(path),
            "pull_request_count": 0,
            "statuses": defaultdict(int),
            "first_seen_at": occurred_at,
            "last_seen_at": occurred_at,
        },
    )
    row["pull_request_count"] = int(row["pull_request_count"]) + 1
    statuses = row["statuses"]
    assert isinstance(statuses, defaultdict)
    statuses[str(change.get("changeType") or "unknown")] += 1
    if occurred_at:
        row["first_seen_at"] = min(str(row["first_seen_at"]), occurred_at)
        row["last_seen_at"] = max(str(row["last_seen_at"]), occurred_at)


def _changed_path_artifacts(
    path_stats: Mapping[tuple[str, str], Mapping[str, object]],
    *,
    observed_at: str,
    privacy_hasher: PrivacyHasher,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for (repo_id, path), stats in sorted(path_stats.items()):
        statuses = stats.get("statuses")
        status_counts = dict(sorted(statuses.items())) if isinstance(statuses, dict) else {}
        records.append(
            {
                "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
                "artifact_id": (f"azure_devops.path:{repo_id}:{privacy_hasher.code_path(path)}"),
                "artifact_type": "azure_devops.changed_path",
                "semantic_type": "code_review.changed_path",
                "source": {
                    "kind": "azure_devops",
                    "provider": "azure_devops",
                    "repo_id": repo_id,
                    "repository_fingerprint": repo_id,
                },
                "observed_at": observed_at,
                "payload": {
                    "path": path,
                    "path_hash": stats["path_hash"],
                    "pull_request_count": stats["pull_request_count"],
                    "status_counts": status_counts,
                    "first_seen_at": stats["first_seen_at"],
                    "last_seen_at": stats["last_seen_at"],
                },
                "privacy": {"contains_content": False, "contains_paths": True},
                "provenance": _provenance(),
            }
        )
    return records


def _source_block(repo_summary: Mapping[str, object]) -> dict[str, object]:
    keys = [
        "kind",
        "provider",
        "repo_id",
        "repository_fingerprint",
        "organization",
        "project",
        "project_id",
        "repo",
        "repository_id",
        "repo_full_name",
    ]
    return {key: repo_summary[key] for key in keys if key in repo_summary}


def _actor(
    value: object,
    *,
    actor_mode: ActorMode,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    if actor_mode == "none" or not isinstance(value, dict):
        return {}
    display = value.get("displayName") or value.get("uniqueName") or value.get("id")
    if not isinstance(display, str) or not display:
        return {}
    if actor_mode == "hash":
        return {"login_hash": privacy_hasher.actor(display.casefold())}
    result = {"login": display, "type": "azure_devops_identity"}
    if value.get("id"):
        result["id"] = value.get("id")
    return result


def _reviewers(
    value: object,
    *,
    actor_mode: ActorMode,
    privacy_hasher: PrivacyHasher,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    rows: list[dict[str, object]] = []
    for reviewer in value:
        if not isinstance(reviewer, dict):
            continue
        rows.append(
            _drop_none(
                {
                    **_actor(
                        reviewer,
                        actor_mode=actor_mode,
                        privacy_hasher=privacy_hasher,
                    ),
                    "vote": reviewer.get("vote"),
                    "is_required": reviewer.get("isRequired"),
                    "has_declined": reviewer.get("hasDeclined"),
                }
            )
        )
    return rows


def _commit_identity(
    *,
    author: Mapping[str, object],
    committer: Mapping[str, object],
    include_raw_emails: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    identity: dict[str, object] = {}
    for prefix, block in [("author", author), ("committer", committer)]:
        name = block.get("name")
        email = block.get("email")
        if isinstance(name, str) and name:
            identity[f"{prefix}_name"] = name
        if isinstance(email, str) and email:
            identity[f"{prefix}_email_hash"] = privacy_hasher.email(email.casefold().strip())
            if include_raw_emails:
                identity[f"{prefix}_email"] = email
    return identity


def _thread_comments(thread: Mapping[str, object]) -> Iterable[dict[str, object]]:
    comments = thread.get("comments")
    if not isinstance(comments, list):
        return []
    return [
        comment
        for comment in comments
        if isinstance(comment, dict) and not comment.get("isDeleted")
    ]


def _commit_ref(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return _drop_none({"sha": value.get("commitId"), "url": value.get("url")})


def _labels(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [
        _drop_none({"id": row.get("id"), "name": row.get("name"), "active": row.get("active")})
        for row in value
        if isinstance(row, dict)
    ]


def _resource_refs(value: object, *, include_urls: bool = False) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [
        _drop_none({"id": row.get("id"), "url": row.get("url") if include_urls else None})
        for row in value
        if isinstance(row, dict)
    ]


def _completion_options(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return _drop_none(
        {
            "merge_strategy": value.get("mergeStrategy"),
            "squash_merge": value.get("squashMerge"),
            "delete_source_branch": value.get("deleteSourceBranch"),
            "bypass_policy": value.get("bypassPolicy"),
            "bypass_reason": value.get("bypassReason"),
            "triggered_by_auto_complete": value.get("triggeredByAutoComplete"),
        }
    )


def _filter_pulls(
    pulls: list[dict[str, object]], *, since: datetime | None, max_prs: int | None
) -> list[dict[str, object]]:
    filtered: list[dict[str, object]] = []
    for pull in pulls:
        if since is not None:
            timestamp = _parse_iso(str(pull.get("closedDate") or pull.get("creationDate") or ""))
            if timestamp is not None and timestamp < since:
                continue
        filtered.append(pull)
    filtered.sort(
        key=lambda row: str(row.get("closedDate") or row.get("creationDate") or ""),
        reverse=True,
    )
    return filtered[:max_prs] if max_prs is not None else filtered


def _value_list(payload: Mapping[str, object]) -> list[dict[str, object]]:
    value = payload.get("value")
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = _parse_iso(value)
    if parsed is None:
        raise ValueError(f"Unable to parse --since value {value!r}")
    return parsed


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(candidate[:10])
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _drop_none(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if item is not None}


def _int(value: object, *, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _provenance() -> dict[str, object]:
    return {"collector": "shevek_collect", "collector_version": __version__}


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _privacy_hasher(options: AzureDevOpsCollectOptions) -> PrivacyHasher:
    privacy_hasher = options.privacy_hasher
    assert privacy_hasher is not None
    return privacy_hasher
