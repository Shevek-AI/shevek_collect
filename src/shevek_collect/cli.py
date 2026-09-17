from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Sequence

from . import __version__
from .api_submit import (
    ANALYSIS_DEPTHS,
    ApiSubmissionError,
    DEFAULT_API_ENDPOINT_ENV,
    DEFAULT_API_URL,
    DEFAULT_TOKEN_ENV,
    jobs_from_bundle,
    submission_manifest_from_bundle,
    filter_unchanged_trace_jobs,
    load_submit_commit_state,
    load_submit_commit_state_store,
    merge_submitted_trace_commits,
    write_submit_commit_state,
    write_submit_commit_state_store,
    submit_alignment,
    submit_bundle,
    zip_bundle,
)
from .azure_devops_collect import (
    AzureDevOpsCollectOptions,
    collect_azure_devops,
    parse_azure_repo,
)
from .git_security import FETCH_TIMEOUT_SECONDS, safe_git_command
from .git_collect import GitCollectOptions, GitRepoSpec, collect_git, discover_git_repos
from .github_collect import GitHubCollectOptions, collect_github, read_repo_file
from .io_utils import validate_bundle
from .progress import ProgressReporter
from .privacy import (
    DEFAULT_PRIVACY_KEY_ENV,
    PrivacyHasher,
    load_privacy_hasher,
)
from .reliability import RetryPolicy
from .run_collect import (
    RunCollectOptions, collect_from_config, configured_git_repositories, load_config,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shevek-collect",
        description="Collect inspectable Git, GitHub and Azure DevOps evidence bundles locally.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    activity_parser = subparsers.add_parser(
        "activity",
        help="Collect repository activity and control evidence; no source snapshots",
    )
    activity_subparsers = activity_parser.add_subparsers(
        dest="activity_command", required=True
    )
    activity_git = activity_subparsers.add_parser(
        "git",
        help="Collect Git commit and repository-control topology activity; no source content",
    )
    _add_git_activity_args(activity_git)

    git_parser = subparsers.add_parser(
        "git",
        help="Deprecated compatibility commands; use `activity git`",
    )
    git_subparsers = git_parser.add_subparsers(dest="git_command", required=True)
    git_scan = git_subparsers.add_parser(
        "scan",
        help="Deprecated alias for `activity git`; captures activity/topology, not source",
    )
    _add_git_activity_args(git_scan)

    snapshot = subparsers.add_parser(
        "snapshot",
        help="Capture one committed Git repository snapshot",
        description=(
            "Capture the committed tree at a Git ref. This is the direct CLI shortcut for "
            "repository_snapshots in a config-driven collection."
        ),
    )
    snapshot.add_argument(
        "--repo",
        type=Path,
        required=True,
        help="Git repository whose committed tree will be captured",
    )
    snapshot.add_argument(
        "--ref",
        default="HEAD",
        help="Committed Git ref to capture; default HEAD",
    )
    snapshot.add_argument(
        "--name",
        default="target",
        help="Snapshot selector recorded in the bundle; default target",
    )
    snapshot.add_argument(
        "--content-mode",
        choices=["full", "structure"],
        default="full",
        help=(
            "Capture source blobs (`full`, the default) or syntax/structure only (`structure`)"
        ),
    )
    snapshot.add_argument(
        "--max-file-bytes",
        type=int,
        default=2 * 1024 * 1024,
        help="Maximum captured bytes per file; default 2 MiB",
    )
    snapshot.add_argument(
        "--max-total-bytes",
        type=int,
        default=256 * 1024 * 1024,
        help="Maximum captured source bytes for the snapshot; default 256 MiB",
    )
    snapshot.add_argument(
        "--include-glob",
        action="append",
        default=[],
        help="Only select matching tracked paths; may be passed multiple times",
    )
    snapshot.add_argument(
        "--exclude-glob",
        action="append",
        default=[],
        help="Exclude matching tracked paths in addition to defaults; may be passed multiple times",
    )
    snapshot.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Disable the standard secret, dependency, cache, build, and environment exclusions",
    )
    snapshot.add_argument("--out", type=Path, required=True, help="Output bundle directory")
    _add_output_replacement_args(snapshot)
    _add_privacy_key_args(snapshot)
    _add_progress_args(snapshot)
    snapshot.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the equivalent config-driven collection plan without writing a bundle",
    )
    snapshot.add_argument("--json", action="store_true", help="Print a JSON summary")

    github_parser = subparsers.add_parser("github", help="Collect GitHub activity using the gh CLI")
    github_subparsers = github_parser.add_subparsers(dest="github_command", required=True)

    github_scan = github_subparsers.add_parser("scan", help="Scan GitHub pull request activity")
    github_scan.add_argument(
        "--repo",
        action="append",
        default=[],
        help="GitHub repository as owner/name; may be passed multiple times",
    )
    github_scan.add_argument(
        "--repo-file",
        type=Path,
        action="append",
        default=[],
        help="Text file containing owner/name repositories, one per line; may be passed multiple times",
    )
    github_scan.add_argument("--out", type=Path, required=True, help="Output bundle directory")
    github_scan.add_argument(
        "--hostname",
        default="github.com",
        help="GitHub hostname for gh, e.g. github.com or a GitHub Enterprise host",
    )
    _add_output_replacement_args(github_scan)
    _add_privacy_key_args(github_scan)
    _add_retry_args(github_scan)
    _add_progress_args(github_scan)
    github_scan.add_argument(
        "--since",
        default=None,
        help="Client-side lower bound for PR updated_at, e.g. 2026-06-01 or 2026-06-01T00:00:00Z",
    )
    github_scan.add_argument(
        "--max-prs",
        type=int,
        default=None,
        help="Maximum pull requests per repository to collect after filtering",
    )
    github_scan.add_argument(
        "--body-mode",
        choices=["none", "title", "full"],
        default="title",
        help="Pull request text detail to include; default is title only",
    )
    github_scan.add_argument(
        "--comment-mode",
        choices=["none", "metadata", "full"],
        default="metadata",
        help="Issue comment detail to include; default is metadata only",
    )
    github_scan.add_argument(
        "--actor-mode",
        choices=["login", "hash", "none"],
        default="login",
        help="Actor identity detail to include; default is GitHub login",
    )
    github_scan.add_argument(
        "--commit-message-mode",
        choices=["none", "subject", "full"],
        default="subject",
        help="Pull request commit message detail to include; default is subject only",
    )
    github_scan.add_argument(
        "--include-raw-emails",
        action="store_true",
        help="Include raw commit author/committer emails instead of hashes only",
    )
    github_scan.add_argument(
        "--include-urls",
        action="store_true",
        help="Include GitHub API/HTML/blob/raw URLs",
    )
    github_scan.add_argument(
        "--include-file-patches",
        action="store_true",
        help="Include PR file patch/diff snippets returned by GitHub",
    )
    github_scan.add_argument(
        "--skip-auth-check",
        action="store_true",
        help="Skip gh auth status check and let gh api calls fail naturally if needed",
    )
    github_scan.add_argument("--json", action="store_true", help="Print a JSON summary")

    azure_parser = subparsers.add_parser(
        "azure-devops", help="Collect Azure DevOps pull request activity"
    )
    azure_subparsers = azure_parser.add_subparsers(dest="azure_command", required=True)
    azure_scan = azure_subparsers.add_parser("scan", help="Scan Azure DevOps pull request activity")
    azure_scan.add_argument("--organization", required=True, help="Azure DevOps organization")
    azure_scan.add_argument(
        "--repo",
        action="append",
        default=[],
        help="Azure DevOps repository as project/repo; may be passed multiple times",
    )
    azure_scan.add_argument("--out", type=Path, required=True, help="Output bundle directory")
    _add_output_replacement_args(azure_scan)
    _add_privacy_key_args(azure_scan)
    _add_retry_args(azure_scan)
    _add_progress_args(azure_scan)
    azure_scan.add_argument(
        "--since",
        default=None,
        help="Client-side lower bound for PR creation/close time",
    )
    azure_scan.add_argument("--max-prs", type=int, default=None)
    azure_scan.add_argument("--body-mode", choices=["none", "title", "full"], default="title")
    azure_scan.add_argument(
        "--comment-mode", choices=["none", "metadata", "full"], default="metadata"
    )
    azure_scan.add_argument("--actor-mode", choices=["login", "hash", "none"], default="login")
    azure_scan.add_argument(
        "--commit-message-mode",
        choices=["none", "subject", "full"],
        default="subject",
    )
    azure_scan.add_argument("--include-raw-emails", action="store_true")
    azure_scan.add_argument("--include-urls", action="store_true")
    azure_scan.add_argument(
        "--token-env",
        default="AZURE_DEVOPS_EXT_PAT",
        help="Environment variable containing an Azure DevOps PAT",
    )
    azure_scan.add_argument("--api-version", default="7.1")
    azure_scan.add_argument("--json", action="store_true", help="Print a JSON summary")

    run = subparsers.add_parser("run", help="Run a config-driven multi-source collection")
    run.add_argument(
        "--config",
        type=Path,
        required=True,
        help="YAML config describing activity sources and optional repository snapshots",
    )
    run.add_argument("--out", type=Path, required=True, help="Output merged bundle directory")
    _add_output_replacement_args(run)
    _add_privacy_key_args(run)
    _add_progress_args(run)
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the collection plan without contacting sources or writing a bundle",
    )
    run.add_argument("--json", action="store_true", help="Print a JSON summary")

    submit = subparsers.add_parser(
        "submit",
        help="Collect from config and upload to the Shevek service (requires credentials)",
    )
    submit.add_argument(
        "--config",
        type=Path,
        required=True,
        help="YAML config describing activity sources and repository snapshots",
    )
    submit.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output collect bundle directory; the zip is written alongside it",
    )
    _add_output_replacement_args(submit)
    _add_privacy_key_args(submit)
    _add_progress_args(submit)
    submit.add_argument(
        "--api-endpoint",
        "--api-url",
        dest="api_endpoint",
        default=None,
        help=(
            "Shevek API base URL or /jobs/bundle endpoint. Overrides "
            f"{DEFAULT_API_ENDPOINT_ENV}; default {DEFAULT_API_URL}"
        ),
    )
    submit.add_argument(
        "--token",
        default=None,
        help=f"Shevek API service token. Overrides environment variable {DEFAULT_TOKEN_ENV}",
    )
    submit.add_argument(
        "--token-env",
        default=DEFAULT_TOKEN_ENV,
        help=f"Environment variable containing the service token; default {DEFAULT_TOKEN_ENV}",
    )
    submit.add_argument(
        "--project-id",
        default=None,
        help=(
            "Persistent backend project identifier. Overrides submission.project_id "
            "from the collect config; omitted when neither is set"
        ),
    )
    submit.add_argument(
        "--priorities",
        type=Path,
        default=None,
        help=(
            "Priorities Markdown file for the Alignment job. Overrides "
            "submission.priorities; default is priorities.md beside the config"
        ),
    )
    submit.add_argument(
        "--analysis-depth",
        choices=ANALYSIS_DEPTHS,
        default=None,
        help=(
            "Analysis depth for submitted Trace jobs; omitted to preserve the backend default"
        ),
    )
    submit.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="HTTP submission timeout in seconds; default 120",
    )
    submit.add_argument(
        "--zip-out",
        type=Path,
        default=None,
        help="Optional zip path; default is <out>.zip",
    )
    submit.add_argument("--overwrite-zip", action="store_true",
                        help="Explicitly replace an existing ZIP archive")
    submit.add_argument(
        "--fetch",
        action="store_true",
        help=(
            "Run `git fetch origin` for each local Git repository in the config before "
            "collecting, without changing the working tree"
        ),
    )
    submit.add_argument(
        "--skip-unchanged",
        action="store_true",
        help=(
            "Keep a commit history in <out>/.shevek_submit_commits.json and omit Trace jobs "
            "whose collected commit hash has already been successfully submitted"
        ),
    )
    submit.add_argument("--json", action="store_true", help="Print a JSON submission summary")

    inspect = subparsers.add_parser("inspect", help="Inspect a collected evidence bundle")
    inspect.add_argument(
        "bundle", type=Path, help="Bundle directory containing collect_manifest.json"
    )
    inspect.add_argument("--json", action="store_true", help="Print the manifest JSON")

    pack = subparsers.add_parser(
        "pack", help="Package an existing bundle locally without collecting or uploading",
    )
    pack.add_argument("bundle", type=Path, help="Existing evidence bundle directory")
    pack.add_argument("--out", type=Path, required=True, help="ZIP path outside the bundle")
    pack.add_argument(
        "--overwrite", "--overwrite-zip", dest="overwrite_zip", action="store_true",
        help="Explicitly replace an existing ZIP archive",
    )
    pack.add_argument("--json", action="store_true", help="Print a JSON summary")

    return parser


def _configured_project_id(config_path: Path) -> str | None:
    """Return optional opaque backend project identity from submission.project_id."""
    config = load_config(config_path)
    submission = config.get("submission")
    if submission is None:
        return None
    if not isinstance(submission, dict):
        raise ValueError("Config submission section must be a mapping")
    project_id = submission.get("project_id")
    if project_id is None:
        return None
    if not isinstance(project_id, str) or not project_id.strip():
        raise ValueError("submission.project_id must be a non-empty string")
    return project_id.strip()


def _configured_priorities_path(config_path: Path) -> Path:
    """Return the Alignment priorities path for a project submission.

    submission.priorities is resolved relative to the config file. When it is
    omitted, use priorities.md beside the config, matching the backend curl
    contract while keeping the submit command concise.
    """
    config = load_config(config_path)
    submission = config.get("submission")
    configured: object = None
    if submission is not None:
        if not isinstance(submission, dict):
            raise ValueError("Config submission section must be a mapping")
        configured = submission.get("priorities")
    if configured is None:
        return config_path.expanduser().resolve().parent / "priorities.md"
    if not isinstance(configured, str) or not configured.strip():
        raise ValueError("submission.priorities must be a non-empty path string")
    path = Path(configured.strip()).expanduser()
    if not path.is_absolute():
        path = config_path.expanduser().resolve().parent / path
    return path.resolve()


def _fetch_configured_git_repositories(
    config_path: Path,
    *,
    log: Callable[[str], None] = print,
) -> None:
    """Fetch origin for every local Git repository referenced by a config."""
    # Use the collection planner so shorthand, defaults and discovery agree with run.
    # Validate the whole configuration before performing any network operations.
    for path in configured_git_repositories(config_path):
        log(f"Fetching Git remote: {path} (origin)")
        try:
            proc = subprocess.run(
                safe_git_command(path, ["fetch", "--no-recurse-submodules", "origin"]),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=FETCH_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ApiSubmissionError(f"Unable to run git fetch for {path}: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise ApiSubmissionError(
                f"git fetch origin failed for {path} with exit code {proc.returncode}"
                + (f": {detail}" if detail else "")
            )
        log(f"Fetched Git remote: {path}")


def _add_git_activity_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repo",
        type=Path,
        action="append",
        default=[],
        help="Git repository whose activity will be scanned; may be passed multiple times",
    )
    parser.add_argument(
        "--root",
        type=Path,
        action="append",
        default=[],
        help="Root directory to search when --discover-repos is set; may be passed multiple times",
    )
    parser.add_argument(
        "--discover-repos",
        action="store_true",
        help="Discover Git repositories beneath each --root",
    )
    parser.add_argument("--out", type=Path, required=True, help="Output bundle directory")
    _add_output_replacement_args(parser)
    _add_privacy_key_args(parser)
    _add_progress_args(parser)
    parser.add_argument(
        "--since",
        default=None,
        help="Pass through to git rev-list --since, e.g. '90 days ago' or '2026-01-01'",
    )
    parser.add_argument(
        "--max-count",
        type=int,
        default=None,
        help="Maximum commits per repository to collect",
    )
    parser.add_argument(
        "--message-mode",
        choices=["none", "subject", "full"],
        default="subject",
        help="Commit message detail to include; default is subject only",
    )
    parser.add_argument(
        "--include-raw-emails",
        action="store_true",
        help="Include raw author/committer emails instead of hashes only",
    )
    parser.add_argument(
        "--include-remote-urls",
        action="store_true",
        help="Include raw remote URLs instead of hashes only",
    )
    parser.add_argument(
        "--include-local-paths",
        action="store_true",
        help="Include absolute local repo paths instead of path hashes only",
    )
    parser.add_argument(
        "--topology-comparison-ref",
        action="append",
        default=[],
        help=(
            "Additional branch/ref to use as a deterministic comparison anchor for "
            "each repository; may be passed multiple times"
        ),
    )
    parser.add_argument(
        "--max-topology-commit-ids",
        type=int,
        default=500,
        help="Maximum head-only commit SHAs retained per branch relation; default 500",
    )
    parser.add_argument(
        "--skip-merge-viability",
        action="store_true",
        help="Skip conflict simulation while still collecting refs, tags, and divergence",
    )
    parser.add_argument("--json", action="store_true", help="Print a JSON summary")


def _add_progress_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress interactive progress messages on stderr",
    )


def _add_output_replacement_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--overwrite",
        action="store_true",
        help="Atomically replace an existing recognised Shevek collect bundle",
    )
    group.add_argument(
        "--force-overwrite",
        action="store_true",
        help="Atomically replace any existing directory, including unrelated content",
    )


def _add_privacy_key_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--privacy-key-env",
        default=DEFAULT_PRIVACY_KEY_ENV,
        help=("Environment variable containing the stable per-organisation HMAC key"),
    )
    group.add_argument(
        "--privacy-key-file",
        type=Path,
        help="File containing the stable per-organisation HMAC key",
    )


def _add_retry_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--retry-attempts",
        type=int,
        default=5,
        help="Maximum attempts for transient provider API requests; default 5",
    )
    parser.add_argument(
        "--retry-initial-delay",
        type=float,
        default=1.0,
        help="Initial exponential-backoff ceiling in seconds; default 1",
    )
    parser.add_argument(
        "--retry-max-delay",
        type=float,
        default=30.0,
        help="Maximum generated backoff delay in seconds; default 30",
    )
    parser.add_argument(
        "--retry-max-retry-after",
        type=float,
        default=300.0,
        help="Safety cap for provider Retry-After delays in seconds; default 300",
    )


def _retry_policy_from_args(args: argparse.Namespace) -> RetryPolicy:
    return RetryPolicy(
        max_attempts=args.retry_attempts,
        initial_delay_seconds=args.retry_initial_delay,
        max_delay_seconds=args.retry_max_delay,
        max_retry_after_seconds=args.retry_max_retry_after,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(parser, args)
    except (ValueError, OSError, ApiSubmissionError) as exc:
        parser.error(str(exc))
    return 2


def _dispatch(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    progress = None if getattr(args, "quiet", False) else ProgressReporter()

    is_activity_git = (
        args.command == "activity" and args.activity_command == "git"
    ) or (args.command == "git" and args.git_command == "scan")
    if is_activity_git:
        if args.command == "git":
            print(
                "Warning: `shevek-collect git scan` is deprecated; use "
                "`shevek-collect activity git`. This command captures Git activity and "
                "repository-control topology, not repository source snapshots.",
                file=sys.stderr,
            )
        if args.max_topology_commit_ids <= 0:
            parser.error("--max-topology-commit-ids must be a positive integer")
        repos = list(args.repo or [])
        if args.discover_repos:
            for root in args.root or []:
                repos.extend(discover_git_repos(root))
        if not repos:
            parser.error(
                "activity git requires at least one --repo, or --discover-repos with "
                "one or more --root"
            )
        comparison_refs = tuple(args.topology_comparison_ref)
        result = collect_git(
            GitCollectOptions(
                repos=tuple(
                    GitRepoSpec(path=repo, topology_comparison_refs=comparison_refs)
                    for repo in repos
                ),
                out=args.out,
                overwrite=args.overwrite,
                force_overwrite=args.force_overwrite,
                command_name=("activity git" if args.command == "activity" else "git scan"),
                since=args.since,
                max_count=args.max_count,
                message_mode=args.message_mode,
                include_raw_emails=args.include_raw_emails,
                include_remote_urls=args.include_remote_urls,
                include_local_paths=args.include_local_paths,
                max_topology_commit_ids=args.max_topology_commit_ids,
                include_merge_viability=not args.skip_merge_viability,
                privacy_hasher=_privacy_hasher_from_args(args),
                progress=progress,
            )
        )
        _print_source_scan(result, as_json=args.json)
        return 1 if result.get("errors") else 0

    if args.command == "snapshot":
        config_data = {
            "version": 1,
            "repository_snapshots": {
                "git": {
                    "repos": [
                        {
                            "path": args.repo.expanduser().resolve().as_posix(),
                            "snapshots": [{"name": args.name, "ref": args.ref}],
                        }
                    ],
                    "capture": {
                        "content_mode": args.content_mode,
                        "max_file_bytes": args.max_file_bytes,
                        "max_total_bytes": args.max_total_bytes,
                        "include_globs": list(args.include_glob or []),
                        "exclude_globs": list(args.exclude_glob or []),
                        "use_default_excludes": not args.no_default_excludes,
                    },
                }
            },
        }
        result = collect_from_config(
            RunCollectOptions(
                config=Path("shevek-collect-snapshot-cli.yaml"),
                config_data=config_data,
                config_dir=Path.cwd(),
                out=args.out,
                overwrite=args.overwrite,
                force_overwrite=args.force_overwrite,
                dry_run=args.dry_run,
                command_name="snapshot",
                privacy_hasher=(None if args.dry_run else _privacy_hasher_from_args(args)),
                progress=(None if args.dry_run else progress),
            )
        )
        if args.dry_run:
            _print_plan(result, as_json=args.json)
            return 0
        _print_source_scan(result, as_json=args.json)
        return 1 if result.get("errors") else 0

    if args.command == "submit":
        configured_project_id = _configured_project_id(args.config)
        project_id = args.project_id.strip() if isinstance(args.project_id, str) and args.project_id.strip() else configured_project_id
        priorities_path: Path | None = None
        if project_id is not None:
            priorities_path = (
                args.priorities.expanduser().resolve()
                if args.priorities is not None
                else _configured_priorities_path(args.config)
            )
            if not priorities_path.is_file():
                raise ApiSubmissionError(
                    "Alignment priorities file not found: "
                    f"{priorities_path}. Use --priorities or submission.priorities."
                )
        elif args.priorities is not None:
            raise ApiSubmissionError("--priorities requires a project_id for Alignment")
        previous_submit_commits: dict[str, set[str]] = {}
        previous_submit_store: dict[str, object] | None = None
        if args.skip_unchanged:
            previous_submit_store = load_submit_commit_state_store(args.out)
            previous_submit_commits = load_submit_commit_state(args.out, project_id=project_id)
        if args.fetch:
            _fetch_configured_git_repositories(args.config, log=lambda message: print(message, file=sys.stderr))
        result = collect_from_config(
            RunCollectOptions(
                config=args.config,
                out=args.out,
                overwrite=args.overwrite,
                force_overwrite=args.force_overwrite,
                command_name="submit",
                privacy_hasher=_privacy_hasher_from_args(args),
                progress=progress,
            )
        )
        bundle_dir = Path(str(result["out"]))
        if args.skip_unchanged and bundle_dir.is_dir() and previous_submit_store is not None:
            # Collection may atomically replace <out>; restore all project namespaces first.
            write_submit_commit_state_store(bundle_dir, previous_submit_store)
        if result.get("errors"):
            raise ApiSubmissionError("Collection completed with errors; bundle was not submitted")
        jobs = jobs_from_bundle(bundle_dir, analysis_depth=args.analysis_depth)
        submission_manifest = submission_manifest_from_bundle(bundle_dir)
        current_submit_commits: dict[str, set[str]] = {}
        skipped_trace_jobs: list[dict[str, object]] = []
        if args.skip_unchanged:
            jobs, current_submit_commits, skipped_trace_jobs = filter_unchanged_trace_jobs(
                bundle_dir, jobs, previous_submit_commits
            )
            for skipped in skipped_trace_jobs:
                print(
                    f"Skipping unchanged {skipped.get('display_name')}: "
                    f"{', '.join(skipped.get('commits', []))}",
                    file=sys.stderr,
                )
        zip_path = args.zip_out or Path(str(bundle_dir) + ".zip")
        response: dict[str, object] = {}
        alignment_response: dict[str, object] = {}
        if jobs:
            zip_path = zip_bundle(bundle_dir, zip_path, overwrite=args.overwrite_zip)
            response = submit_bundle(
                zip_path=zip_path,
                jobs=jobs,
                submission_manifest=submission_manifest,
                project_id=project_id,
                api_endpoint=args.api_endpoint,
                token=args.token,
                token_env=args.token_env,
                timeout_seconds=args.timeout,
                log=lambda message: print(message, file=sys.stderr),
            )
            if args.skip_unchanged:
                write_submit_commit_state(
                    bundle_dir,
                    merge_submitted_trace_commits(
                        previous_submit_commits, current_submit_commits, jobs
                    ),
                    project_id=project_id,
                )
            if project_id is not None and priorities_path is not None:
                alignment_response = submit_alignment(
                    project_id=project_id,
                    priorities_path=priorities_path,
                    api_endpoint=args.api_endpoint,
                    token=args.token,
                    token_env=args.token_env,
                    timeout_seconds=args.timeout,
                    log=lambda message: print(message, file=sys.stderr),
                )
        elif args.skip_unchanged:
            # Preserve selected namespace inside a freshly replaced bundle even when there is nothing to POST.
            write_submit_commit_state(bundle_dir, previous_submit_commits, project_id=project_id)
        effective_api = args.api_endpoint or os.environ.get(DEFAULT_API_ENDPOINT_ENV) or DEFAULT_API_URL
        effective_endpoint = effective_api.rstrip("/")
        if not effective_endpoint.endswith("/jobs/bundle"):
            effective_endpoint += "/jobs/bundle"
        summary = {
            "bundle": bundle_dir.as_posix(),
            "zip": zip_path.as_posix(),
            "jobs": jobs,
            "submission_manifest": submission_manifest,
            "project_id": project_id,
            "skipped_trace_jobs": skipped_trace_jobs,
            "api_url": effective_endpoint,
            "response": response,
            "alignment_priorities": priorities_path.as_posix() if priorities_path is not None else None,
            "alignment_response": alignment_response,
        }
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            if jobs:
                print(f"Submitted {len(jobs)} jobs from {zip_path}")
            else:
                print("No jobs to submit; all Trace commits were already submitted")
            if response:
                if project_id is not None:
                    print(f"Project: {project_id}")
                group_id = response.get("group_id")
                if group_id is None:
                    jobs_response = response.get("jobs")
                    if isinstance(jobs_response, list):
                        for item in jobs_response:
                            if isinstance(item, dict) and item.get("group_id"):
                                group_id = item["group_id"]
                                break
                if group_id is not None:
                    print(f"Group: {group_id}")
                print(json.dumps(response, indent=2, sort_keys=True))
            if alignment_response:
                print("Alignment:")
                print(json.dumps(alignment_response, indent=2, sort_keys=True))
        return 0

    if args.command == "github" and args.github_command == "scan":
        repos = list(args.repo or [])
        for repo_file in args.repo_file or []:
            repos.extend(read_repo_file(repo_file))
        if not repos:
            parser.error("github scan requires at least one --repo or --repo-file")
        result = collect_github(
            GitHubCollectOptions(
                repos=tuple(repos),
                out=args.out,
                overwrite=args.overwrite,
                force_overwrite=args.force_overwrite,
                hostname=args.hostname,
                since=args.since,
                max_prs=args.max_prs,
                body_mode=args.body_mode,
                comment_mode=args.comment_mode,
                actor_mode=args.actor_mode,
                commit_message_mode=args.commit_message_mode,
                include_raw_emails=args.include_raw_emails,
                include_urls=args.include_urls,
                include_file_patches=args.include_file_patches,
                skip_auth_check=args.skip_auth_check,
                retry_policy=_retry_policy_from_args(args),
                privacy_hasher=_privacy_hasher_from_args(args),
                progress=progress,
            )
        )
        _print_source_scan(result, as_json=args.json)
        return 1 if result.get("errors") else 0

    if args.command == "azure-devops" and args.azure_command == "scan":
        repos = tuple(parse_azure_repo(value) for value in args.repo or [])
        if not repos:
            parser.error("azure-devops scan requires at least one --repo project/repo")
        result = collect_azure_devops(
            AzureDevOpsCollectOptions(
                organization=args.organization,
                repos=repos,
                out=args.out,
                overwrite=args.overwrite,
                force_overwrite=args.force_overwrite,
                since=args.since,
                max_prs=args.max_prs,
                body_mode=args.body_mode,
                comment_mode=args.comment_mode,
                actor_mode=args.actor_mode,
                commit_message_mode=args.commit_message_mode,
                include_raw_emails=args.include_raw_emails,
                include_urls=args.include_urls,
                token_env=args.token_env,
                api_version=args.api_version,
                retry_policy=_retry_policy_from_args(args),
                privacy_hasher=_privacy_hasher_from_args(args),
                progress=progress,
            )
        )
        _print_source_scan(result, as_json=args.json)
        return 1 if result.get("errors") else 0

    if args.command == "run":
        result = collect_from_config(
            RunCollectOptions(
                config=args.config,
                out=args.out,
                overwrite=args.overwrite,
                force_overwrite=args.force_overwrite,
                dry_run=args.dry_run,
                privacy_hasher=(None if args.dry_run else _privacy_hasher_from_args(args)),
                progress=(None if args.dry_run else progress),
            )
        )
        if args.dry_run:
            _print_plan(result, as_json=args.json)
            return 0
        _print_source_scan(result, as_json=args.json)
        return 1 if result.get("errors") else 0

    if args.command == "inspect":
        manifest = validate_bundle(args.bundle.expanduser())
        _print_manifest(manifest, as_json=args.json)
        return 0

    if args.command == "pack":
        archive = zip_bundle(args.bundle, args.out, overwrite=args.overwrite_zip)
        if args.json:
            print(json.dumps({"zip": archive.as_posix()}, indent=2, sort_keys=True))
        else:
            print(f"Bundle ZIP: {archive}")
        return 0

    parser.error("unknown command")
    return 2


def _privacy_hasher_from_args(args: argparse.Namespace) -> PrivacyHasher:
    return load_privacy_hasher(
        env_name=str(args.privacy_key_env),
        key_file=args.privacy_key_file,
    )


def _print_source_scan(result: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"Collect bundle: {result['out']}")
    if result.get("collection_status"):
        print(f"Collection status: {result['collection_status']}")
    if result.get("source_runs"):
        print(f"Activity repositories requested: {result['repos_requested']}")
        print(f"Activity repositories collected: {result['repos_collected']}")
    if result.get("snapshot_repos_requested"):
        print(f"Snapshot repositories requested: {result.get('snapshot_repos_requested', 0)}")
        print(f"Snapshot repositories collected: {result.get('snapshot_repos_collected', 0)}")
    print(f"Source events: {result['events']}")
    print(f"Source artifacts: {result['artifacts']}")
    if result.get("snapshots_collected"):
        print(f"Repository snapshots: {result.get('snapshots_collected', 0)}")
        print(f"Repository files observed: {result.get('repository_files', 0)}")
    retry = result.get("retry") or {}
    if isinstance(retry, dict) and retry.get("retry_attempts"):
        print(
            "Retries: "
            f"{retry.get('retry_attempts', 0)} retry attempts across "
            f"{retry.get('requests_retried', 0)} requests"
        )
    outputs = result.get("outputs") or {}
    if isinstance(outputs, dict):
        print("Outputs:")
        for name, relative_path in outputs.items():
            print(f"  - {name}: {relative_path}")
    errors = result.get("errors") or []
    if errors:
        print("Errors:")
        for error in errors:
            print(f"  - {error}")


def _print_plan(result: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"Collect plan: {result['config']}")
    print(f"Output bundle: {result['out']}")
    print(f"Source runs: {result['source_runs']}")
    for source in result.get("sources", []):
        if not isinstance(source, dict):
            continue
        kind = source.get("source_kind")
        repo_count = source.get("repo_count")
        print(f"  - {kind}: {repo_count} repos")
        if kind == "git":
            print(f"    message_mode: {source.get('message_mode')}")
            print(f"    include_raw_emails: {source.get('include_raw_emails')}")
            print(f"    include_remote_urls: {source.get('include_remote_urls')}")
            print(f"    include_local_paths: {source.get('include_local_paths')}")
            topology = source.get("topology") or {}
            print(f"    topology: {topology}")
            for repo in source.get("repos", []):
                if not isinstance(repo, dict):
                    continue
                repo_topology = repo.get("topology") or {}
                comparison_refs = repo_topology.get("comparison_refs") or []
                if comparison_refs:
                    print(
                        f"    {repo.get('path')} comparison_refs: {comparison_refs}"
                    )
        elif kind == "github":
            print(f"    hostname: {source.get('hostname')}")
            print(f"    body_mode: {source.get('body_mode')}")
            print(f"    comment_mode: {source.get('comment_mode')}")
            print(f"    actor_mode: {source.get('actor_mode')}")
            print(f"    include_file_patches: {source.get('include_file_patches')}")
        elif kind == "azure_devops":
            print(f"    organization: {source.get('organization')}")
            print(f"    body_mode: {source.get('body_mode')}")
            print(f"    comment_mode: {source.get('comment_mode')}")
            print(f"    actor_mode: {source.get('actor_mode')}")
            print(f"    token_env: {source.get('token_env')}")
    snapshot_plan = result.get("repository_snapshots")
    if isinstance(snapshot_plan, dict):
        print(f"Repository snapshot repos: {snapshot_plan.get('repo_count', 0)}")
        print(f"Repository snapshots: {snapshot_plan.get('snapshot_count', 0)}")
        print(f"Snapshot content mode: {snapshot_plan.get('content_mode')}")
        print("  - tracked files only: true")
        print("  - Git history database: excluded")
        print("  - untracked files: excluded")
    print("Outputs:")
    outputs = result.get("outputs") or {}
    if isinstance(outputs, dict):
        for name, relative_path in outputs.items():
            print(f"  - {name}: {relative_path}")


def _print_manifest(manifest: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return
    counts = manifest.get("counts") or {}
    privacy = manifest.get("privacy") or {}
    print(f"Bundle: {manifest.get('out')}")
    print(f"Created: {manifest.get('created_at')}")
    if manifest.get("collection_status"):
        print(f"Collection status: {manifest.get('collection_status')}")
    if isinstance(counts, dict):
        print(f"Repositories collected: {counts.get('repos_collected', 0)}")
        if counts.get("repos_failed"):
            print(f"Repositories failed: {counts.get('repos_failed', 0)}")
        print(f"Source events: {counts.get('source_events', 0)}")
        print(f"Source artifacts: {counts.get('source_artifacts', 0)}")
        print(f"Repository snapshots: {counts.get('repository_snapshots', 0)}")
        print(f"Repository files observed: {counts.get('repository_files', 0)}")
    if isinstance(privacy, dict):
        print("Privacy:")
        for key, value in sorted(privacy.items()):
            print(f"  - {key}: {value}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
