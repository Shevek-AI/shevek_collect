from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Literal, Sequence

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
from .repo_identity import github_repository_identity

BodyMode = Literal["none", "title", "full"]
CommentMode = Literal["none", "metadata", "full"]
ActorMode = Literal["login", "hash", "none"]
CommitMessageMode = Literal["none", "subject", "full"]

SOURCE_EVENT_SCHEMA_VERSION = "shevek.source_event.v1"
SOURCE_ARTIFACT_SCHEMA_VERSION = "shevek.source_artifact.v1"
COLLECT_MANIFEST_SCHEMA_VERSION = "shevek.collect_manifest.v1"

GhRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class GitHubCollectOptions:
    repos: tuple[str, ...]
    out: Path
    overwrite: bool = False
    force_overwrite: bool = False
    hostname: str = "github.com"
    since: str | None = None
    max_prs: int | None = None
    body_mode: BodyMode = "title"
    comment_mode: CommentMode = "metadata"
    actor_mode: ActorMode = "login"
    commit_message_mode: CommitMessageMode = "subject"
    include_raw_emails: bool = False
    include_urls: bool = False
    include_file_patches: bool = False
    skip_auth_check: bool = False
    gh_runner: GhRunner | None = field(default=None, repr=False, compare=False)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    retry_sleep: Callable[[float], None] | None = field(default=None, repr=False, compare=False)
    retry_random: Callable[[], float] | None = field(default=None, repr=False, compare=False)
    privacy_hasher: PrivacyHasher | None = field(default=None, repr=False, compare=False)
    progress: ProgressCallback | None = field(default=None, repr=False, compare=False)


class GitHubCommandError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class GhClient:
    def __init__(
        self,
        *,
        hostname: str = "github.com",
        runner: GhRunner | None = None,
        retry_policy: RetryPolicy | None = None,
        retry_sleep: Callable[[float], None] | None = None,
        retry_random: Callable[[], float] | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.hostname = hostname
        self._runner = runner
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

    def check_available(self) -> None:
        if shutil.which("gh") is None and self._runner is None:
            raise RuntimeError("GitHub CLI 'gh' was not found on PATH")
        self._run(["--version"], retryable=False)

    def check_auth(self) -> None:
        self._run(["auth", "status", "--hostname", self.hostname], retryable=False)

    def api_jsonl(self, endpoint: str, *, paginate: bool) -> list[dict[str, object]]:
        args = ["api"]
        if paginate:
            args.append("--paginate")
        args.extend([endpoint, "--hostname", self.hostname, "--jq", ".[]"])
        output = self._run(args, retryable=True).stdout
        return _parse_jsonl(output)

    def api_json(self, endpoint: str) -> dict[str, object]:
        output = self._run(["api", endpoint, "--hostname", self.hostname], retryable=True).stdout
        if not output.strip():
            return {}
        parsed = json.loads(output)
        if not isinstance(parsed, dict):
            raise RuntimeError(
                f"Expected JSON object from gh api {endpoint}, got {type(parsed).__name__}"
            )
        return parsed

    def _run(
        self,
        args: Sequence[str],
        *,
        retryable: bool,
    ) -> subprocess.CompletedProcess[str]:
        if not retryable:
            return self._run_once(args)
        return self._retry.run(
            lambda: self._run_once(args),
            should_retry=_github_should_retry,
            retry_after=_github_retry_after,
            operation_name="GitHub API request",
        )

    def _run_once(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        cmd = ["gh", *args]
        if self._runner is not None:
            proc = self._runner(cmd)
        else:
            proc = subprocess.run(
                cmd,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        if proc.returncode != 0:
            message = proc.stderr.strip() or proc.stdout.strip() or "gh command failed"
            redacted_cmd = " ".join(cmd[:2] + ["..."] if len(cmd) > 2 else cmd)
            raise GitHubCommandError(
                f"{redacted_cmd} failed: {message}",
                status_code=_http_status(message),
            )
        return proc


def _github_should_retry(exc: Exception) -> bool:
    if isinstance(exc, GitHubCommandError):
        status = exc.status_code
        message = str(exc)
        if status in {408, 429}:
            return True
        if status is not None and 500 <= status <= 599:
            return True
        if status == 403:
            return rate_limit_message(message) or _github_retry_after(exc) is not None
        return status is None and transient_network_message(message)
    return isinstance(exc, (ConnectionError, TimeoutError, OSError)) and not isinstance(
        exc, FileNotFoundError
    )


def _github_retry_after(exc: Exception) -> float | None:
    return retry_after_seconds(message=str(exc))


def _http_status(message: str) -> int | None:
    patterns = (r"\bHTTP\s+([45]\d{2})\b", r"\(([45]\d{2})\)")
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def collect_github(options: GitHubCollectOptions) -> dict[str, object]:
    """Collect GitHub PR activity and atomically publish the bundle."""
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
        return _collect_github_into(options, out=stage, public_out=public_out)


def _collect_github_into(
    options: GitHubCollectOptions,
    *,
    out: Path,
    public_out: Path,
) -> dict[str, object]:
    observed_at = _now_iso()
    privacy_hasher = options.privacy_hasher
    assert privacy_hasher is not None
    client = GhClient(
        hostname=options.hostname,
        runner=options.gh_runner,
        retry_policy=options.retry_policy,
        retry_sleep=options.retry_sleep,
        retry_random=options.retry_random,
        progress=options.progress,
    )
    events: list[dict[str, object]] = []
    repo_artifacts: list[dict[str, object]] = []
    pr_file_artifacts: list[dict[str, object]] = []
    changed_path_stats: dict[tuple[str, str], dict[str, object]] = {}
    errors: list[str] = []
    collected_repos: list[dict[str, object]] = []
    repository_results: list[dict[str, object]] = []

    emit_progress(
        options.progress, f"Starting GitHub collection for {len(options.repos)} repositories"
    )
    try:
        client.check_available()
        if not options.skip_auth_check:
            client.check_auth()
    except Exception as exc:
        errors.append("github_setup: provider_setup_failed")
        emit_progress(options.progress, f"GitHub setup failed: {exc}")
        repository_results.extend(
            {
                "repo_id": _input_repo_id(
                    full_repo,
                    hostname=options.hostname,
                    privacy_hasher=privacy_hasher,
                ),
                "status": "failed",
                "error": "provider_setup_failed",
                "retry": RetrySnapshot().as_dict(),
            }
            for full_repo in options.repos
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
            artifacts=repo_artifacts + pr_file_artifacts,
            errors=errors,
        )

    since_dt = _parse_since(options.since)

    for repo_index, full_repo in enumerate(options.repos, start=1):
        emit_progress(
            options.progress,
            f"GitHub repository {repo_index}/{len(options.repos)}: {full_repo}",
        )
        retry_before = client.retry_snapshot()
        repo_events: list[dict[str, object]] = []
        repo_artifact_records: list[dict[str, object]] = []
        repo_file_artifacts: list[dict[str, object]] = []
        repo_path_stats: dict[tuple[str, str], dict[str, object]] = {}
        repo_id = _input_repo_id(
            full_repo,
            hostname=options.hostname,
            privacy_hasher=privacy_hasher,
        )
        repo_result: dict[str, object] = {
            "repo_id": repo_id,
            "status": "failed",
        }
        try:
            owner, repo_name = _parse_repo(full_repo)
            repo_summary = _repo_summary(
                owner=owner,
                repo=repo_name,
                hostname=options.hostname,
                privacy_hasher=privacy_hasher,
            )
            repo_id = str(repo_summary["repo_id"])
            repo_result.update(
                {
                    "repo_id": repo_id,
                    "repo_full_name": full_repo,
                }
            )
            pulls = client.api_jsonl(
                f"/repos/{owner}/{repo_name}/pulls?state=all&per_page=100",
                paginate=True,
            )
            pulls = _filter_pulls(pulls, since=since_dt, max_prs=options.max_prs)
            emit_progress(options.progress, f"  found {len(pulls)} pull requests")

            repo_artifact_records.append(
                _repo_artifact(
                    repo_summary,
                    observed_at=observed_at,
                    pull_request_count=len(pulls),
                )
            )

            repo_counts = {
                "pull_requests": 0,
                "pr_commits": 0,
                "pr_files": 0,
                "issue_comments": 0,
            }
            for pull_index, pull in enumerate(pulls, start=1):
                number = pull.get("number")
                if not isinstance(number, int):
                    continue
                pr = client.api_json(f"/repos/{owner}/{repo_name}/pulls/{number}")
                commits = client.api_jsonl(
                    f"/repos/{owner}/{repo_name}/pulls/{number}/commits?per_page=100",
                    paginate=True,
                )
                files = client.api_jsonl(
                    f"/repos/{owner}/{repo_name}/pulls/{number}/files?per_page=100",
                    paginate=True,
                )
                comments = client.api_jsonl(
                    f"/repos/{owner}/{repo_name}/issues/{number}/comments?per_page=100",
                    paginate=True,
                )

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
                repo_counts["pull_requests"] += 1

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
                    repo_counts["pr_commits"] += 1

                for file_record in files:
                    artifact = _pr_file_artifact(
                        file_record,
                        repo_summary,
                        pr_number=number,
                        observed_at=observed_at,
                        include_urls=options.include_urls,
                        include_file_patches=options.include_file_patches,
                        privacy_hasher=privacy_hasher,
                    )
                    repo_file_artifacts.append(artifact)
                    _update_changed_path_stats(
                        repo_path_stats,
                        repo_id=repo_id,
                        pr=pr,
                        file_record=file_record,
                        privacy_hasher=privacy_hasher,
                    )
                    repo_counts["pr_files"] += 1

                for comment in comments:
                    if options.comment_mode == "none":
                        continue
                    repo_events.append(
                        _issue_comment_event(
                            comment,
                            repo_summary,
                            pr_number=number,
                            observed_at=observed_at,
                            comment_mode=options.comment_mode,
                            actor_mode=options.actor_mode,
                            include_urls=options.include_urls,
                            privacy_hasher=privacy_hasher,
                        )
                    )
                    repo_counts["issue_comments"] += 1

                if progress_checkpoint(pull_index, len(pulls), every=25):
                    emit_progress(
                        options.progress,
                        f"  processed {pull_index}/{len(pulls)} pull requests",
                    )

            # Commit repository observations only after every request and transform succeeds.
            events.extend(repo_events)
            repo_artifacts.extend(repo_artifact_records)
            pr_file_artifacts.extend(repo_file_artifacts)
            changed_path_stats.update(repo_path_stats)
            collected_repos.append(
                {
                    "repo_id": repo_id,
                    "repo_full_name": f"{owner}/{repo_name}",
                    "hostname": options.hostname,
                    **repo_counts,
                }
            )
            repo_result.update(
                {
                    "status": "complete",
                    "counts": repo_counts,
                }
            )
            emit_progress(
                options.progress,
                f"  complete: {repo_counts['pull_requests']} pull requests",
            )
        except Exception as exc:  # keep one bad repo from hiding successful exports
            error_code = _bundle_safe_github_error(exc)
            repo_result.pop("repo_full_name", None)
            repo_result["error"] = error_code
            errors.append(f"{repo_id}: {error_code}")
            emit_progress(options.progress, f"  failed: {exc}")
        finally:
            repo_result["retry"] = (client.retry_snapshot() - retry_before).as_dict()
            repository_results.append(repo_result)

    artifacts = (
        repo_artifacts
        + pr_file_artifacts
        + _changed_path_artifacts(
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
    full_repo: str,
    *,
    hostname: str,
    privacy_hasher: PrivacyHasher,
) -> str:
    """Return the normal repository ID, or a keyed fallback for malformed input."""
    try:
        owner, repo = _parse_repo(full_repo)
        return github_repository_identity(
            hostname=hostname,
            owner=owner,
            repo=repo,
            privacy_hasher=privacy_hasher,
        ).fingerprint
    except Exception:
        return privacy_hasher.repository_fingerprint(
            f"github-input:{hostname.casefold()}:{full_repo.strip().casefold()}"
        )


def _bundle_safe_github_error(exc: Exception) -> str:
    """Return a stable bundle error code without provider text or repository names."""
    if isinstance(exc, FileNotFoundError):
        return "provider_cli_unavailable"
    if isinstance(exc, TimeoutError):
        return "provider_timeout"
    if isinstance(exc, json.JSONDecodeError):
        return "provider_response_parse_failed"
    if isinstance(exc, ValueError) and str(exc).startswith("Expected GitHub repository"):
        return "invalid_repository_reference"
    if isinstance(exc, GitHubCommandError):
        status = exc.status_code
        if status == 401:
            return "authentication_failed"
        if status == 403:
            if rate_limit_message(str(exc)) or _github_retry_after(exc) is not None:
                return "rate_limited"
            return "permission_denied"
        if status == 404:
            return "repository_not_found"
        if status == 408:
            return "provider_timeout"
        if status == 429:
            return "rate_limited"
        if status is not None and 500 <= status <= 599:
            return "provider_unavailable"
        return "provider_command_failed"
    return f"collector_error:{type(exc).__name__}"

def read_repo_file(path: Path) -> list[str]:
    repos: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        repos.append(line)
    return repos


def _write_outputs(
    *,
    out: Path,
    public_out: Path,
    observed_at: str,
    options: GitHubCollectOptions,
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
    privacy_report = _privacy_report(manifest, options=options)

    write_jsonl(out / outputs["source_events"], events)
    write_jsonl(out / outputs["source_artifacts"], artifacts)
    write_json(out / outputs["collect_manifest"], manifest)
    write_text(out / outputs["privacy_report"], privacy_report)

    status = collection_status(
        repos_requested=len(options.repos),
        repos_collected=len(collected_repos),
        errors=errors,
    )
    emit_progress(
        options.progress,
        f"GitHub collection {status}: {len(collected_repos)}/{len(options.repos)} repositories",
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
    options: GitHubCollectOptions,
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
        "command": "github scan",
        "source_kinds": ["github"],
        "collection_status": status,
        "complete": status == "complete",
        "settings": {
            "hostname": options.hostname,
            "since": options.since,
            "max_prs": options.max_prs,
            "body_mode": options.body_mode,
            "comment_mode": options.comment_mode,
            "actor_mode": options.actor_mode,
            "commit_message_mode": options.commit_message_mode,
            "include_raw_emails": options.include_raw_emails,
            "include_urls": options.include_urls,
            "include_file_patches": options.include_file_patches,
            "include_file_content": False,
            "include_patches": options.include_file_patches,
            "auth": "gh_cli_existing_auth"
            if not options.skip_auth_check
            else "gh_cli_auth_check_skipped",
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
            "contains_patches": options.include_file_patches,
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


def _privacy_report(manifest: dict[str, object], *, options: GitHubCollectOptions) -> str:
    counts = manifest.get("counts", {})
    assert isinstance(counts, dict)
    privacy = manifest.get("privacy", {})
    identity = manifest.get("identity", {})
    reliability = manifest.get("reliability", {})
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
        "## Included by this GitHub scan",
        "",
        "- Pull request metadata from the GitHub API.",
        "- Pull request commit metadata.",
        "- Pull request changed-file metadata and changed paths.",
        "- Pull request issue-comment metadata unless `--comment-mode none` was used.",
        "- Actor identities according to `--actor-mode`.",
    ]
    if options.body_mode == "none":
        lines.append("- Pull request titles and bodies were not included.")
    elif options.body_mode == "title":
        lines.append("- Pull request titles were included; pull request bodies were not included.")
    else:
        lines.append(
            "- Pull request titles and bodies were included because `--body-mode full` was used."
        )
    if options.comment_mode == "metadata":
        lines.append("- Comment bodies were not included; comment metadata was included.")
    elif options.comment_mode == "full":
        lines.append("- Comment bodies were included because `--comment-mode full` was used.")
    else:
        lines.append("- Comments were not included because `--comment-mode none` was used.")
    lines.extend(
        [
            "",
            "## Not included by default",
            "",
            "- Source file contents.",
            "- File patches/diff hunks unless `--include-file-patches` was used.",
            "- Raw commit author/committer emails unless `--include-raw-emails` was used.",
            "- URLs unless `--include-urls` was used.",
            "- Secret scanning results; no file content was collected for this pass.",
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
        for error in errors:
            lines.append(f"- {error}")
    return "\n".join(lines) + "\n"


def _repo_summary(
    *,
    owner: str,
    repo: str,
    hostname: str,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    full_name = f"{owner}/{repo}"
    identity = github_repository_identity(
        hostname=hostname,
        owner=owner,
        repo=repo,
        privacy_hasher=privacy_hasher,
    )
    return {
        "kind": "github",
        "provider": "github",
        "repo_id": identity.fingerprint,
        "repository_fingerprint": identity.fingerprint,
        "hostname": hostname,
        "owner": owner,
        "repo": repo,
        "repo_full_name": full_name,
    }


def _repo_artifact(
    repo_summary: dict[str, object],
    *,
    observed_at: str,
    pull_request_count: int,
) -> dict[str, object]:
    repo_id = str(repo_summary["repo_id"])
    return {
        "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
        "artifact_id": f"github.repo:{repo_id}",
        "artifact_type": "github.repository",
        "semantic_type": "code_host.repository",
        "source": _source_block(repo_summary),
        "observed_at": observed_at,
        "payload": {
            "repo_full_name": repo_summary["repo_full_name"],
            "hostname": repo_summary["hostname"],
            "pull_request_count": pull_request_count,
        },
        "privacy": {"contains_content": False, "contains_paths": False},
        "provenance": _provenance(),
    }


def _pull_request_event(
    pr: dict[str, object],
    repo_summary: dict[str, object],
    *,
    observed_at: str,
    body_mode: BodyMode,
    actor_mode: ActorMode,
    include_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    number = _int(pr.get("number"), default=0)
    repo_id = str(repo_summary["repo_id"])
    payload: dict[str, object] = {
        "number": number,
        "id": pr.get("id"),
        "node_id": pr.get("node_id"),
        "state": pr.get("state"),
        "draft": pr.get("draft"),
        "locked": pr.get("locked"),
        "created_at": pr.get("created_at"),
        "updated_at": pr.get("updated_at"),
        "closed_at": pr.get("closed_at"),
        "merged_at": pr.get("merged_at"),
        "merged": pr.get("merged"),
        "merge_commit_sha": pr.get("merge_commit_sha"),
        "additions": pr.get("additions"),
        "deletions": pr.get("deletions"),
        "changed_files": pr.get("changed_files"),
        "commits": pr.get("commits"),
        "labels": _labels(pr.get("labels")),
        "milestone": _milestone(pr.get("milestone")),
        "base": _branch_ref(
            pr.get("base"),
            hostname=str(repo_summary.get("hostname") or "github.com"),
            privacy_hasher=privacy_hasher,
            actor_mode=actor_mode,
        ),
        "head": _branch_ref(
            pr.get("head"),
            hostname=str(repo_summary.get("hostname") or "github.com"),
            privacy_hasher=privacy_hasher,
            actor_mode=actor_mode,
        ),
    }
    if body_mode in {"title", "full"}:
        payload["title"] = pr.get("title")
    if body_mode == "full":
        payload["body"] = pr.get("body")
    if include_urls:
        payload["url"] = pr.get("url")
        payload["html_url"] = pr.get("html_url")
        payload["diff_url"] = pr.get("diff_url")
        payload["patch_url"] = pr.get("patch_url")

    return {
        "schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "event_id": f"github.pull_request:{repo_id}:{number}",
        "event_type": "github.pull_request",
        "semantic_type": "code_review.pull_request",
        "source": _source_block(repo_summary),
        "occurred_at": str(pr.get("created_at") or pr.get("updated_at") or observed_at),
        "observed_at": observed_at,
        "actor": _actor(pr.get("user"), actor_mode=actor_mode, privacy_hasher=privacy_hasher),
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
    commit: dict[str, object],
    repo_summary: dict[str, object],
    *,
    pr_number: int,
    observed_at: str,
    actor_mode: ActorMode,
    commit_message_mode: CommitMessageMode,
    include_raw_emails: bool,
    include_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    repo_id = str(repo_summary["repo_id"])
    sha = str(commit.get("sha") or "")
    commit_block = commit.get("commit") if isinstance(commit.get("commit"), dict) else {}
    assert isinstance(commit_block, dict)
    author_block = (
        commit_block.get("author") if isinstance(commit_block.get("author"), dict) else {}
    )
    committer_block = (
        commit_block.get("committer") if isinstance(commit_block.get("committer"), dict) else {}
    )
    assert isinstance(author_block, dict)
    assert isinstance(committer_block, dict)
    message = str(commit_block.get("message") or "")
    payload: dict[str, object] = {
        "pull_request_number": pr_number,
        "sha": sha,
        "author_date": author_block.get("date"),
        "committer_date": committer_block.get("date"),
        "parents": [
            parent.get("sha") for parent in commit.get("parents", []) if isinstance(parent, dict)
        ],
    }
    if commit_message_mode == "subject":
        payload["subject"] = message.splitlines()[0] if message else ""
    elif commit_message_mode == "full":
        payload["message"] = message
    if include_urls:
        payload["url"] = commit.get("url")
        payload["html_url"] = commit.get("html_url")

    actor = _actor(commit.get("author"), actor_mode=actor_mode, privacy_hasher=privacy_hasher)
    actor.update(
        _commit_identity(
            author_block=author_block,
            committer_block=committer_block,
            include_raw_emails=include_raw_emails,
            privacy_hasher=privacy_hasher,
        )
    )
    return {
        "schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "event_id": f"github.pull_request_commit:{repo_id}:{pr_number}:{sha}",
        "event_type": "github.pull_request_commit",
        "semantic_type": "code_review.pull_request_commit",
        "source": _source_block(repo_summary),
        "occurred_at": str(committer_block.get("date") or author_block.get("date") or observed_at),
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
    file_record: dict[str, object],
    repo_summary: dict[str, object],
    *,
    pr_number: int,
    observed_at: str,
    include_urls: bool,
    include_file_patches: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    repo_id = str(repo_summary["repo_id"])
    filename = str(file_record.get("filename") or "")
    payload: dict[str, object] = {
        "pull_request_number": pr_number,
        "filename": filename,
        "path": filename,
        "path_hash": privacy_hasher.code_path(filename),
        "status": file_record.get("status"),
        "previous_filename": file_record.get("previous_filename"),
        "sha": file_record.get("sha"),
        "additions": file_record.get("additions"),
        "deletions": file_record.get("deletions"),
        "changes": file_record.get("changes"),
    }
    if include_urls:
        payload["blob_url"] = file_record.get("blob_url")
        payload["raw_url"] = file_record.get("raw_url")
        payload["contents_url"] = file_record.get("contents_url")
    if include_file_patches:
        payload["patch"] = file_record.get("patch")
    return {
        "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
        "artifact_id": (
            f"github.pr_file:{repo_id}:{pr_number}:{privacy_hasher.code_path(filename)}"
        ),
        "artifact_type": "github.pull_request_file",
        "semantic_type": "code_review.pull_request_file",
        "source": _source_block(repo_summary),
        "observed_at": observed_at,
        "payload": _drop_none(payload),
        "privacy": {
            "contains_content": include_file_patches,
            "contains_paths": True,
            "contains_patches": include_file_patches,
            "contains_urls": include_urls,
        },
        "provenance": _provenance(),
    }


def _issue_comment_event(
    comment: dict[str, object],
    repo_summary: dict[str, object],
    *,
    pr_number: int,
    observed_at: str,
    comment_mode: CommentMode,
    actor_mode: ActorMode,
    include_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    repo_id = str(repo_summary["repo_id"])
    comment_id = comment.get("id")
    payload: dict[str, object] = {
        "pull_request_number": pr_number,
        "id": comment_id,
        "node_id": comment.get("node_id"),
        "created_at": comment.get("created_at"),
        "updated_at": comment.get("updated_at"),
        "author_association": comment.get("author_association"),
    }
    if comment_mode == "full":
        payload["body"] = comment.get("body")
    if include_urls:
        payload["url"] = comment.get("url")
        payload["html_url"] = comment.get("html_url")
        payload["issue_url"] = comment.get("issue_url")
    return {
        "schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "event_id": f"github.issue_comment:{repo_id}:{pr_number}:{comment_id}",
        "event_type": "github.issue_comment",
        "semantic_type": "code_review.comment",
        "source": _source_block(repo_summary),
        "occurred_at": str(comment.get("created_at") or observed_at),
        "observed_at": observed_at,
        "actor": _actor(comment.get("user"), actor_mode=actor_mode, privacy_hasher=privacy_hasher),
        "payload": _drop_none(payload),
        "privacy": {
            "contains_content": comment_mode == "full",
            "contains_paths": False,
            "contains_comment_body": comment_mode == "full",
            "contains_urls": include_urls,
        },
        "provenance": _provenance(),
    }


def _update_changed_path_stats(
    path_stats: dict[tuple[str, str], dict[str, object]],
    *,
    repo_id: str,
    pr: dict[str, object],
    file_record: dict[str, object],
    privacy_hasher: PrivacyHasher,
) -> None:
    path = str(file_record.get("filename") or "")
    if not path:
        return
    occurred_at = str(pr.get("updated_at") or pr.get("created_at") or "")
    key = (repo_id, path)
    row = path_stats.setdefault(
        key,
        {
            "repo_id": repo_id,
            "path": path,
            "path_hash": privacy_hasher.code_path(path),
            "pull_request_count": 0,
            "statuses": defaultdict(int),
            "first_seen_at": occurred_at,
            "last_seen_at": occurred_at,
            "total_additions": 0,
            "total_deletions": 0,
            "total_changes": 0,
        },
    )
    row["pull_request_count"] = int(row["pull_request_count"]) + 1
    statuses = row["statuses"]
    assert isinstance(statuses, defaultdict)
    statuses[str(file_record.get("status") or "unknown")] += 1
    if occurred_at:
        row["first_seen_at"] = min(str(row["first_seen_at"]), occurred_at)
        row["last_seen_at"] = max(str(row["last_seen_at"]), occurred_at)
    for target, source in [
        ("total_additions", "additions"),
        ("total_deletions", "deletions"),
        ("total_changes", "changes"),
    ]:
        value = file_record.get(source)
        if isinstance(value, int):
            row[target] = int(row[target]) + value


def _changed_path_artifacts(
    path_stats: dict[tuple[str, str], dict[str, object]],
    *,
    observed_at: str,
    privacy_hasher: PrivacyHasher,
) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for (repo_id, path), stats in sorted(path_stats.items()):
        statuses = stats.get("statuses")
        if isinstance(statuses, defaultdict):
            status_counts = dict(sorted(statuses.items()))
        elif isinstance(statuses, dict):
            status_counts = dict(sorted(statuses.items()))
        else:
            status_counts = {}
        artifacts.append(
            {
                "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
                "artifact_id": (f"github.path:{repo_id}:{privacy_hasher.code_path(path)}"),
                "artifact_type": "github.changed_path",
                "semantic_type": "code_review.changed_path",
                "source": {"kind": "github", "repo_id": repo_id},
                "observed_at": observed_at,
                "payload": {
                    "path": path,
                    "path_hash": stats["path_hash"],
                    "pull_request_count": stats["pull_request_count"],
                    "status_counts": status_counts,
                    "first_seen_at": stats["first_seen_at"],
                    "last_seen_at": stats["last_seen_at"],
                    "total_additions": stats["total_additions"],
                    "total_deletions": stats["total_deletions"],
                    "total_changes": stats["total_changes"],
                },
                "privacy": {"contains_content": False, "contains_paths": True},
                "provenance": _provenance(),
            }
        )
    return artifacts


def _actor(
    value: object,
    *,
    actor_mode: ActorMode,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    if actor_mode == "none":
        return {}
    if not isinstance(value, dict):
        return {}
    login = value.get("login")
    if not isinstance(login, str) or not login:
        return {}
    if actor_mode == "hash":
        return {"login_hash": privacy_hasher.actor(login.casefold())}
    return {"login": login, "type": value.get("type")}


def _commit_identity(
    *,
    author_block: dict[str, object],
    committer_block: dict[str, object],
    include_raw_emails: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    identity: dict[str, object] = {}
    for prefix, block in [("author", author_block), ("committer", committer_block)]:
        name = block.get("name")
        email = block.get("email")
        if isinstance(name, str) and name:
            identity[f"{prefix}_name"] = name
        if isinstance(email, str) and email:
            identity[f"{prefix}_email_hash"] = privacy_hasher.email(email.casefold().strip())
            if include_raw_emails:
                identity[f"{prefix}_email"] = email
    return identity


def _branch_ref(
    value: object,
    *,
    hostname: str,
    privacy_hasher: PrivacyHasher,
    actor_mode: ActorMode = "login",
) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    repo = value.get("repo") if isinstance(value.get("repo"), dict) else {}
    assert isinstance(repo, dict)
    full_name = repo.get("full_name")
    fingerprint = None
    if isinstance(full_name, str) and "/" in full_name:
        owner, repo_name = full_name.split("/", 1)
        fingerprint = github_repository_identity(
            hostname=hostname,
            owner=owner,
            repo=repo_name,
            privacy_hasher=privacy_hasher,
        ).fingerprint
    return _drop_none(
        {
            "ref": value.get("ref"),
            "sha": value.get("sha"),
            "repo_full_name": full_name,
            "repository_fingerprint": fingerprint,
            "repo_private": repo.get("private"),
            "owner_login": _nested_login(repo.get("owner")) if actor_mode == "login" else None,
            "owner_login_hash": privacy_hasher.actor(str(_nested_login(repo.get("owner"))).casefold())
            if actor_mode == "hash" and _nested_login(repo.get("owner")) else None,
        }
    )


def _labels(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    labels: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            labels.append(_drop_none({"name": item.get("name"), "color": item.get("color")}))
    return labels


def _milestone(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return _drop_none(
        {
            "number": value.get("number"),
            "title": value.get("title"),
            "state": value.get("state"),
            "created_at": value.get("created_at"),
            "due_on": value.get("due_on"),
        }
    )


def _source_block(repo_summary: dict[str, object]) -> dict[str, object]:
    keys = [
        "kind",
        "provider",
        "repo_id",
        "repository_fingerprint",
        "hostname",
        "owner",
        "repo",
        "repo_full_name",
    ]
    return {key: repo_summary[key] for key in keys if key in repo_summary}


def _parse_jsonl(output: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parsed = json.loads(line)
        if not isinstance(parsed, dict):
            raise RuntimeError(
                f"Expected JSON object in gh JSONL output, got {type(parsed).__name__}"
            )
        records.append(parsed)
    return records


def _parse_repo(full_repo: str) -> tuple[str, str]:
    parts = full_repo.strip().split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Expected repo as owner/name, got {full_repo!r}")
    return parts[0], parts[1]


def _filter_pulls(
    pulls: list[dict[str, object]],
    *,
    since: datetime | None,
    max_prs: int | None,
) -> list[dict[str, object]]:
    filtered: list[dict[str, object]] = []
    for pull in pulls:
        if since is not None:
            updated = _parse_iso(str(pull.get("updated_at") or pull.get("created_at") or ""))
            if updated is not None and updated < since:
                continue
        filtered.append(pull)
        if max_prs is not None and len(filtered) >= max_prs:
            break
    return filtered


def _parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = _parse_iso(value)
    if parsed is None:
        raise ValueError("--since must be ISO-like, e.g. 2026-06-01 or 2026-06-01T00:00:00Z")
    return parsed


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if len(text) == 10 and text[4] == "-" and text[7] == "-":
        text = text + "T00:00:00+00:00"
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _nested_login(value: object) -> object:
    if isinstance(value, dict):
        return value.get("login")
    return None


def _int(value: object, *, default: int) -> int:
    return value if isinstance(value, int) else default


def _drop_none(mapping: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in mapping.items() if value is not None}


def _provenance() -> dict[str, object]:
    return {
        "collector": "shevek_collect",
        "collector_version": __version__,
    }


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _privacy_hasher(options: GitHubCollectOptions) -> PrivacyHasher:
    privacy_hasher = options.privacy_hasher
    assert privacy_hasher is not None
    return privacy_hasher
