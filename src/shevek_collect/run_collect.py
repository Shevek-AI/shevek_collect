from __future__ import annotations

import json
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Sequence

import yaml

from .safe_yaml import load_config_yaml, YamlLimitError

from . import __version__
from .azure_devops_collect import (
    AzdoRequester,
    AzureDevOpsCollectOptions,
    AzureRepoRef,
    collect_azure_devops,
    parse_azure_repo,
)
from .git_collect import GitCollectOptions, GitRepoSpec, collect_git, discover_git_repos
from .github_collect import GhRunner, GitHubCollectOptions, collect_github, read_repo_file
from .io_utils import atomic_bundle_directory, write_json, write_jsonl, write_text
from .privacy import PrivacyHasher, resolve_privacy_hasher
from .progress import ProgressCallback, emit_progress
from .reliability import RetryPolicy, collection_status
from .repository_snapshot import (
    DEFAULT_EXCLUDE_GLOBS,
    RepositorySnapshotOptions,
    SnapshotCapturePolicy,
    SnapshotRepoSpec,
    SnapshotSpec,
    collect_repository_snapshots,
)

COLLECT_MANIFEST_SCHEMA_VERSION = "shevek.collect_manifest.v1"


@dataclass(frozen=True)
class RunCollectOptions:
    config: Path
    out: Path
    overwrite: bool = False
    force_overwrite: bool = False
    dry_run: bool = False
    command_name: str = "run"
    config_data: Mapping[str, object] | None = field(default=None, repr=False, compare=False)
    config_dir: Path | None = field(default=None, repr=False, compare=False)
    gh_runner: GhRunner | None = field(default=None, repr=False, compare=False)
    azdo_requester: AzdoRequester | None = field(default=None, repr=False, compare=False)
    retry_sleep: Callable[[float], None] | None = field(default=None, repr=False, compare=False)
    retry_random: Callable[[], float] | None = field(default=None, repr=False, compare=False)
    privacy_hasher: PrivacyHasher | None = field(default=None, repr=False, compare=False)
    progress: ProgressCallback | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class PlannedSource:
    kind: Literal["git", "github", "azure_devops"]
    options: GitCollectOptions | GitHubCollectOptions | AzureDevOpsCollectOptions
    summary: dict[str, object]


@dataclass(frozen=True)
class CollectPlan:
    config: Path
    command_name: str
    out: Path
    sources: tuple[PlannedSource, ...]
    repository_snapshots: RepositorySnapshotOptions | None
    repository_snapshot_summary: dict[str, object] | None
    raw_config: dict[str, object]
    privacy_hasher: PrivacyHasher | None = field(default=None, repr=False, compare=False)


def load_config(path: Path) -> dict[str, object]:
    """Load and minimally validate a shevek_collect YAML config."""
    try:
        loaded = load_config_yaml(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, YamlLimitError) as exc:
        raise ValueError(f"Unable to parse YAML config: {type(exc).__name__}") from None
    return _validated_config(loaded)


def _validated_config(value: object) -> dict[str, object]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise ValueError(f"Config root must be a mapping, got {type(value).__name__}")
    loaded = dict(value)
    version = loaded.get("version", 1)
    if version != 1:
        raise ValueError(f"Unsupported config version {version!r}; expected 1")
    return loaded


def plan_collect(options: RunCollectOptions) -> dict[str, object]:
    """Return a public-facing plan without collecting or writing a bundle."""
    plan = _build_plan(options, privacy_hasher=options.privacy_hasher)
    return _plan_summary(plan)


def configured_git_repositories(config_path: Path) -> tuple[Path, ...]:
    """Resolve local repositories using the same validation and discovery as collection.

    Planning does not write output, read Git objects or contact providers, so the
    unused output path can be the current directory. No privacy key is needed.
    """
    plan = _build_plan(
        RunCollectOptions(config=config_path, out=Path(".")), privacy_hasher=None,
    )
    paths = [
        repo.path
        for source in plan.sources
        if isinstance(source.options, GitCollectOptions)
        for repo in source.options.repos
    ]
    if plan.repository_snapshots is not None:
        paths.extend(repo.path for repo in plan.repository_snapshots.repos)
    return tuple(path.resolve() for path in _dedupe_paths(paths))


def collect_from_config(options: RunCollectOptions) -> dict[str, object]:
    """Run configured collectors and atomically publish the merged bundle."""
    if options.dry_run:
        return plan_collect(options)
    privacy_hasher = resolve_privacy_hasher(options.privacy_hasher)
    plan = _build_plan(options, privacy_hasher=privacy_hasher)

    public_out = options.out.expanduser().resolve()
    with atomic_bundle_directory(
        options.out,
        overwrite=options.overwrite,
        force_overwrite=options.force_overwrite,
    ) as stage:
        return _collect_plan_into(
            options,
            plan=plan,
            out=stage,
            public_out=public_out,
        )


def _collect_plan_into(
    options: RunCollectOptions,
    *,
    plan: CollectPlan,
    out: Path,
    public_out: Path,
) -> dict[str, object]:
    observed_at = _now_iso()
    emit_progress(
        options.progress,
        f"Starting configured collection with {len(plan.sources)} activity sources",
    )
    all_events: list[dict[str, object]] = []
    all_artifacts: list[dict[str, object]] = []
    source_runs: list[dict[str, object]] = []
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="shevek_collect_run_") as raw_tmp:
        tmp = Path(raw_tmp)
        for index, source in enumerate(plan.sources, start=1):
            emit_progress(
                options.progress,
                f"Activity source {index}/{len(plan.sources)}: {source.kind}",
            )
            stage = tmp / f"{index:02d}_{source.kind}"
            if source.kind == "git":
                assert isinstance(source.options, GitCollectOptions)
                result = collect_git(_replace_git_out(source.options, out=stage))
            elif source.kind == "github":
                assert isinstance(source.options, GitHubCollectOptions)
                result = collect_github(_replace_github_out(source.options, out=stage))
            elif source.kind == "azure_devops":
                assert isinstance(source.options, AzureDevOpsCollectOptions)
                result = collect_azure_devops(_replace_azure_devops_out(source.options, out=stage))
            else:  # pragma: no cover - kept for future source types
                raise AssertionError(f"Unhandled source kind: {source.kind}")

            manifest = _read_json(stage / "collect_manifest.json")
            events = _read_jsonl(stage / "source_events.jsonl")
            artifacts = _read_jsonl(stage / "source_artifacts.jsonl")
            all_events.extend(events)
            all_artifacts.extend(artifacts)
            source_errors = list(result.get("errors") or [])
            errors.extend(f"{source.kind}: {error}" for error in source_errors)
            source_runs.append(
                {
                    "source_kind": source.kind,
                    "summary": _bundle_safe_source_summary(
                        source.kind,
                        source.summary,
                        privacy_hasher=_plan_privacy_hasher(plan),
                    ),
                    "result": _source_result_summary(result),
                    "manifest": _source_manifest_summary(manifest),
                }
            )

    snapshot_result: dict[str, object] | None = None
    if plan.repository_snapshots is not None:
        snapshot_result = collect_repository_snapshots(
            RepositorySnapshotOptions(
                repos=plan.repository_snapshots.repos,
                out=out,
                policy=plan.repository_snapshots.policy,
                privacy_hasher=plan.repository_snapshots.privacy_hasher,
                progress=options.progress,
            )
        )
        errors.extend(
            f"repository_snapshot: {error}" for error in snapshot_result.get("errors", [])
        )

    events, event_duplicate_count = _dedupe_by_id(all_events, id_key="event_id")
    artifacts, artifact_duplicate_count = _dedupe_by_id(all_artifacts, id_key="artifact_id")

    outputs = {
        "source_events": "source_events.jsonl",
        "source_artifacts": "source_artifacts.jsonl",
        "collect_manifest": "collect_manifest.json",
        "privacy_report": "privacy_report.md",
    }
    if snapshot_result is not None:
        snapshot_outputs = snapshot_result.get("outputs")
        if isinstance(snapshot_outputs, dict):
            outputs.update({str(key): str(value) for key, value in snapshot_outputs.items()})

    manifest = _merged_manifest(
        out=public_out,
        observed_at=observed_at,
        plan=plan,
        source_runs=source_runs,
        snapshot_result=snapshot_result,
        events=events,
        artifacts=artifacts,
        errors=errors,
        outputs=outputs,
        event_duplicate_count=event_duplicate_count,
        artifact_duplicate_count=artifact_duplicate_count,
    )
    write_jsonl(out / outputs["source_events"], events)
    write_jsonl(out / outputs["source_artifacts"], artifacts)
    write_json(out / outputs["collect_manifest"], manifest)
    write_text(out / outputs["privacy_report"], _privacy_report(manifest))

    counts = manifest["counts"]
    assert isinstance(counts, dict)
    emit_progress(
        options.progress,
        f"Configured collection {manifest['collection_status']}: "
        f"{counts['repos_collected']}/{counts['repos_requested']} activity repositories",
    )
    return {
        "out": public_out.as_posix(),
        "collection_status": manifest["collection_status"],
        "complete": manifest["complete"],
        "source_runs": len(source_runs),
        "source_kinds": manifest["source_kinds"],
        "repos_requested": counts["repos_requested"],
        "repos_collected": counts["repos_collected"],
        "events": len(events),
        "artifacts": len(artifacts),
        "snapshot_repos_requested": counts.get("snapshot_repos_requested", 0),
        "snapshot_repos_collected": counts.get("snapshot_repos_collected", 0),
        "snapshots_collected": counts.get("repository_snapshots", 0),
        "repository_files": counts.get("repository_files", 0),
        "repository_operational_records": counts.get(
            "repository_operational_records", 0
        ),
        "errors": errors,
        "outputs": outputs,
    }


def _build_plan(
    options: RunCollectOptions,
    *,
    privacy_hasher: PrivacyHasher | None,
) -> CollectPlan:
    config_path = options.config.expanduser().resolve()
    raw = (
        load_config(config_path)
        if options.config_data is None
        else _validated_config(options.config_data)
    )
    config_dir = (options.config_dir or config_path.parent).expanduser().resolve()
    defaults = _mapping(raw.get("defaults"), field_name="defaults")
    activity_sources = _mapping(raw.get("activity_sources"), field_name="activity_sources")
    planned: list[PlannedSource] = []

    if "git" in activity_sources and activity_sources["git"] is not None:
        git_config = _merged(
            defaults, _mapping(activity_sources["git"], field_name="activity_sources.git")
        )
        _reject_legacy_git_topology_keys(git_config)
        git_repos = _git_repo_specs_from_items(
            git_config.get("repos"),
            config_dir=config_dir,
            field_name="activity_sources.git.repos",
        )
        roots = _paths_from_items(
            git_config.get("roots"), config_dir=config_dir, keys=("path", "root")
        )
        discover = _boolean(git_config.get("discover_repos", bool(roots)), field_name="discover_repos")
        if discover:
            for root in roots:
                git_repos.extend(GitRepoSpec(path=path) for path in discover_git_repos(root))
        git_repos = _dedupe_git_repo_specs(git_repos)
        if not git_repos:
            raise ValueError(
                "activity_sources.git requires repos, or roots with discover_repos enabled"
            )
        topology_config = _mapping(
            git_config.get("topology"), field_name="activity_sources.git.topology"
        )
        git_options = GitCollectOptions(
            repos=tuple(git_repos),
            out=options.out,
            overwrite=False,
            force_overwrite=False,
            command_name="run:git",
            since=_optional_str(git_config.get("since")),
            max_count=_optional_int(git_config.get("max_count")),
            message_mode=_choice(
                git_config.get("message_mode", "subject"),
                {"none", "subject", "full"},
                "git.message_mode",
            ),
            include_raw_emails=_boolean(git_config.get("include_raw_emails", False), field_name="include_raw_emails"),
            include_remote_urls=_boolean(git_config.get("include_remote_urls", False), field_name="include_remote_urls"),
            include_local_paths=_boolean(git_config.get("include_local_paths", False), field_name="include_local_paths"),
            max_topology_commit_ids=_positive_int(
                topology_config.get("max_commit_ids", 500),
                field_name="activity_sources.git.topology.max_commit_ids",
            ),
            include_merge_viability=_boolean(
                topology_config.get("include_merge_viability", True), field_name="include_merge_viability"
            ),
            privacy_hasher=privacy_hasher,
            progress=options.progress,
        )
        planned.append(
            PlannedSource(
                kind="git",
                options=git_options,
                summary={
                    "repos": [
                        {
                            "path": spec.path.as_posix(),
                            "topology": {
                                "comparison_refs": list(spec.topology_comparison_refs)
                            },
                        }
                        for spec in git_repos
                    ],
                    "repo_count": len(git_repos),
                    "roots": [path.as_posix() for path in roots],
                    "discover_repos": discover,
                    "since": git_options.since,
                    "max_count": git_options.max_count,
                    "message_mode": git_options.message_mode,
                    "include_raw_emails": git_options.include_raw_emails,
                    "include_remote_urls": git_options.include_remote_urls,
                    "include_local_paths": git_options.include_local_paths,
                    "topology": {
                        "max_commit_ids": git_options.max_topology_commit_ids,
                        "include_merge_viability": git_options.include_merge_viability,
                    },
                    "include_file_content": False,
                    "include_patches": False,
                },
            )
        )

    if "github" in activity_sources and activity_sources["github"] is not None:
        github_config = _merged(
            defaults, _mapping(activity_sources["github"], field_name="activity_sources.github")
        )
        github_repos = _repos_from_items(
            github_config.get("repos"), keys=("repo", "full_name", "name")
        )
        for repo_file in _paths_from_items(
            github_config.get("repo_files", github_config.get("repo_file")),
            config_dir=config_dir,
            keys=("path", "repo_file", "file"),
        ):
            github_repos.extend(read_repo_file(repo_file))
        github_repos = _dedupe_strings(github_repos)
        if not github_repos:
            raise ValueError("activity_sources.github requires repos or repo_files")
        github_retry = _retry_policy(
            github_config.get("retry"), field_name="activity_sources.github.retry"
        )
        github_options = GitHubCollectOptions(
            repos=tuple(github_repos),
            out=options.out,
            overwrite=False,
            force_overwrite=False,
            hostname=str(github_config.get("hostname", "github.com")),
            since=_optional_str(github_config.get("since")),
            max_prs=_optional_int(github_config.get("max_prs")),
            body_mode=_choice(
                github_config.get("body_mode", "title"),
                {"none", "title", "full"},
                "github.body_mode",
            ),
            comment_mode=_choice(
                github_config.get("comment_mode", "metadata"),
                {"none", "metadata", "full"},
                "github.comment_mode",
            ),
            actor_mode=_choice(
                github_config.get("actor_mode", "login"),
                {"login", "hash", "none"},
                "github.actor_mode",
            ),
            commit_message_mode=_choice(
                github_config.get("commit_message_mode", "subject"),
                {"none", "subject", "full"},
                "github.commit_message_mode",
            ),
            include_raw_emails=_boolean(github_config.get("include_raw_emails", False), field_name="include_raw_emails"),
            include_urls=_boolean(github_config.get("include_urls", False), field_name="include_urls"),
            include_file_patches=_boolean(github_config.get("include_file_patches", False), field_name="include_file_patches"),
            skip_auth_check=_boolean(github_config.get("skip_auth_check", False), field_name="skip_auth_check"),
            gh_runner=options.gh_runner,
            retry_policy=github_retry,
            retry_sleep=options.retry_sleep,
            retry_random=options.retry_random,
            privacy_hasher=privacy_hasher,
            progress=options.progress,
        )
        planned.append(
            PlannedSource(
                kind="github",
                options=github_options,
                summary={
                    "repos": github_repos,
                    "repo_count": len(github_repos),
                    "hostname": github_options.hostname,
                    "since": github_options.since,
                    "max_prs": github_options.max_prs,
                    "body_mode": github_options.body_mode,
                    "comment_mode": github_options.comment_mode,
                    "actor_mode": github_options.actor_mode,
                    "commit_message_mode": github_options.commit_message_mode,
                    "include_raw_emails": github_options.include_raw_emails,
                    "include_urls": github_options.include_urls,
                    "include_file_patches": github_options.include_file_patches,
                    "include_file_content": False,
                    "retry": github_retry.manifest_metadata(),
                },
            )
        )

    if "azure_devops" in activity_sources and activity_sources["azure_devops"] is not None:
        azure_config = _merged(
            defaults,
            _mapping(
                activity_sources["azure_devops"],
                field_name="activity_sources.azure_devops",
            ),
        )
        organization = str(azure_config.get("organization") or "").strip()
        if not organization:
            raise ValueError("activity_sources.azure_devops requires organization")
        azure_repos = _azure_repos_from_items(azure_config.get("repos"))
        if not azure_repos:
            raise ValueError("activity_sources.azure_devops requires repos")
        azure_retry = _retry_policy(
            azure_config.get("retry"), field_name="activity_sources.azure_devops.retry"
        )
        azure_options = AzureDevOpsCollectOptions(
            organization=organization,
            repos=tuple(azure_repos),
            out=options.out,
            overwrite=False,
            force_overwrite=False,
            since=_optional_str(azure_config.get("since")),
            max_prs=_optional_int(azure_config.get("max_prs")),
            body_mode=_choice(
                azure_config.get("body_mode", "title"),
                {"none", "title", "full"},
                "azure_devops.body_mode",
            ),
            comment_mode=_choice(
                azure_config.get("comment_mode", "metadata"),
                {"none", "metadata", "full"},
                "azure_devops.comment_mode",
            ),
            actor_mode=_choice(
                azure_config.get("actor_mode", "login"),
                {"login", "hash", "none"},
                "azure_devops.actor_mode",
            ),
            commit_message_mode=_choice(
                azure_config.get("commit_message_mode", "subject"),
                {"none", "subject", "full"},
                "azure_devops.commit_message_mode",
            ),
            include_raw_emails=_boolean(azure_config.get("include_raw_emails", False), field_name="include_raw_emails"),
            include_urls=_boolean(azure_config.get("include_urls", False), field_name="include_urls"),
            token_env=str(azure_config.get("token_env", "AZURE_DEVOPS_EXT_PAT")),
            api_version=str(azure_config.get("api_version", "7.1")),
            requester=options.azdo_requester,
            retry_policy=azure_retry,
            retry_sleep=options.retry_sleep,
            retry_random=options.retry_random,
            privacy_hasher=privacy_hasher,
            progress=options.progress,
        )
        planned.append(
            PlannedSource(
                kind="azure_devops",
                options=azure_options,
                summary={
                    "organization": organization,
                    "repos": [repo.display_name for repo in azure_repos],
                    "repo_count": len(azure_repos),
                    "since": azure_options.since,
                    "max_prs": azure_options.max_prs,
                    "body_mode": azure_options.body_mode,
                    "comment_mode": azure_options.comment_mode,
                    "actor_mode": azure_options.actor_mode,
                    "commit_message_mode": azure_options.commit_message_mode,
                    "include_raw_emails": azure_options.include_raw_emails,
                    "include_urls": azure_options.include_urls,
                    "token_env": azure_options.token_env,
                    "api_version": azure_options.api_version,
                    "include_file_content": False,
                    "include_patches": False,
                    "retry": azure_retry.manifest_metadata(),
                },
            )
        )

    repository_snapshots, repository_snapshot_summary = _build_repository_snapshot_plan(
        raw.get("repository_snapshots"),
        config_dir=config_dir,
        out=options.out,
        privacy_hasher=privacy_hasher,
    )

    if not planned and repository_snapshots is None:
        raise ValueError(
            "Config must enable at least one activity source or repository snapshot capture"
        )

    return CollectPlan(
        config=config_path,
        command_name=options.command_name,
        out=options.out.resolve(),
        sources=tuple(planned),
        repository_snapshots=repository_snapshots,
        repository_snapshot_summary=repository_snapshot_summary,
        raw_config=raw,
        privacy_hasher=privacy_hasher,
    )


def _retry_policy(value: object, *, field_name: str) -> RetryPolicy:
    config = _mapping(value, field_name=field_name) if value is not None else {}
    return RetryPolicy(
        max_attempts=_positive_int(
            config.get("max_attempts", 5), field_name=f"{field_name}.max_attempts"
        ),
        initial_delay_seconds=_nonnegative_float(
            config.get("initial_delay_seconds", 1.0),
            field_name=f"{field_name}.initial_delay_seconds",
        ),
        max_delay_seconds=_nonnegative_float(
            config.get("max_delay_seconds", 30.0),
            field_name=f"{field_name}.max_delay_seconds",
        ),
        max_retry_after_seconds=_nonnegative_float(
            config.get("max_retry_after_seconds", 300.0),
            field_name=f"{field_name}.max_retry_after_seconds",
        ),
    )


def _build_repository_snapshot_plan(
    value: object,
    *,
    config_dir: Path,
    out: Path,
    privacy_hasher: PrivacyHasher | None,
) -> tuple[RepositorySnapshotOptions | None, dict[str, object] | None]:
    if value is None:
        return None, None
    root = _mapping(value, field_name="repository_snapshots")
    git_value = root.get("git", root)
    git_config = _mapping(git_value, field_name="repository_snapshots.git")
    repo_items = _list(git_config.get("repos"))
    if not repo_items:
        raise ValueError("repository_snapshots.git requires repos")

    default_snapshots = _snapshot_specs(
        git_config.get("snapshots"),
        field_name="repository_snapshots.git.snapshots",
    )
    if not default_snapshots:
        default_snapshots = [SnapshotSpec(name="target", ref="HEAD")]

    repos: list[SnapshotRepoSpec] = []
    for index, item in enumerate(repo_items):
        field_name = f"repository_snapshots.git.repos[{index}]"
        if isinstance(item, str):
            raw_path = item
            snapshots = default_snapshots
        elif isinstance(item, dict):
            raw_path = item.get("path") or item.get("repo")
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise ValueError(f"{field_name} requires path")
            snapshots = (
                _snapshot_specs(
                    item.get("snapshots", item.get("refs")),
                    field_name=f"{field_name}.snapshots",
                )
                or default_snapshots
            )
        else:
            raise ValueError(f"{field_name} must be a path string or mapping")
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = (config_dir / path).resolve()
        repos.append(SnapshotRepoSpec(path=path.resolve(), snapshots=tuple(snapshots)))

    capture = _mapping(
        git_config.get("capture"),
        field_name="repository_snapshots.git.capture",
    )
    content_mode = _choice(
        capture.get("content_mode", "full"),
        {"full", "structure"},
        "repository_snapshots.git.capture.content_mode",
    )
    max_file_bytes = _positive_int(
        capture.get("max_file_bytes", 2 * 1024 * 1024),
        field_name="repository_snapshots.git.capture.max_file_bytes",
    )
    max_total_bytes = _positive_int(
        capture.get("max_total_bytes", 256 * 1024 * 1024),
        field_name="repository_snapshots.git.capture.max_total_bytes",
    )
    include_globs = tuple(
        _string_list(
            capture.get("include_globs"),
            field_name="repository_snapshots.git.capture.include_globs",
        )
    )
    custom_excludes = _string_list(
        capture.get("exclude_globs"),
        field_name="repository_snapshots.git.capture.exclude_globs",
    )
    use_default_excludes = _boolean(capture.get("use_default_excludes", True), field_name="use_default_excludes")
    exclude_globs = _dedupe_strings(
        [*(DEFAULT_EXCLUDE_GLOBS if use_default_excludes else ()), *custom_excludes]
    )
    policy = SnapshotCapturePolicy(
        content_mode=content_mode,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        include_globs=include_globs,
        exclude_globs=tuple(exclude_globs),
        use_default_excludes=use_default_excludes,
    )
    options = RepositorySnapshotOptions(
        repos=tuple(repos),
        out=out,
        policy=policy,
        privacy_hasher=privacy_hasher,
    )
    summary = {
        "repo_count": len(repos),
        "repos": [
            {
                "path": repo.path.as_posix(),
                "snapshots": [
                    {"name": snapshot.name, "ref": snapshot.ref} for snapshot in repo.snapshots
                ],
            }
            for repo in repos
        ],
        "snapshot_count": sum(len(repo.snapshots) for repo in repos),
        "content_mode": policy.content_mode,
        "max_file_bytes": policy.max_file_bytes,
        "max_total_bytes": policy.max_total_bytes,
        "include_globs": list(policy.include_globs),
        "exclude_globs": list(policy.exclude_globs),
        "tracked_files_only": True,
        "include_git_history_database": False,
        "include_untracked_files": False,
    }
    return options, summary


def _snapshot_specs(value: object, *, field_name: str) -> list[SnapshotSpec]:
    specs: list[SnapshotSpec] = []
    for index, item in enumerate(_list(value)):
        item_field = f"{field_name}[{index}]"
        if isinstance(item, str):
            ref = item.strip()
            if not ref:
                raise ValueError(f"{item_field} must not be empty")
            name = "target" if ref == "HEAD" and not specs else _snapshot_name(ref)
        elif isinstance(item, dict):
            raw_ref = item.get("ref")
            if not isinstance(raw_ref, str) or not raw_ref.strip():
                raise ValueError(f"{item_field} requires ref")
            ref = raw_ref.strip()
            raw_name = item.get("name")
            name = str(raw_name).strip() if raw_name is not None else _snapshot_name(ref)
            if not name:
                raise ValueError(f"{item_field}.name must not be empty")
        else:
            raise ValueError(f"{item_field} must be a ref string or mapping")
        specs.append(SnapshotSpec(name=name, ref=ref))
    names = [spec.name for spec in specs]
    if len(names) != len(set(names)):
        raise ValueError(f"{field_name} snapshot names must be unique")
    return specs


def _snapshot_name(ref: str) -> str:
    cleaned = "".join(character if character.isalnum() else "_" for character in ref)
    return cleaned.strip("_").lower() or "snapshot"


def _string_list(value: object, *, field_name: str) -> list[str]:
    values: list[str] = []
    for item in _list(value):
        if not isinstance(item, str):
            raise ValueError(f"{field_name} entries must be strings")
        stripped = item.strip()
        if stripped:
            values.append(stripped)
    return values


def _nonnegative_float(value: object, *, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a non-negative number") from exc
    if parsed < 0:
        raise ValueError(f"{field_name} must be a non-negative number")
    return parsed


def _positive_int(value: object, *, field_name: str) -> int:
    parsed = _int(value, default=0)
    if parsed <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return parsed


def _plan_summary(plan: CollectPlan) -> dict[str, object]:
    outputs = {
        "source_events": "source_events.jsonl",
        "source_artifacts": "source_artifacts.jsonl",
        "collect_manifest": "collect_manifest.json",
        "privacy_report": "privacy_report.md",
    }
    if plan.repository_snapshots is not None:
        outputs.update(
            {
                "repository_snapshots": "code/snapshots.jsonl",
                "repository_files": "code/files.jsonl",
                "repository_operational_records": "code/operational_records.jsonl",
                "repository_extraction_manifest": "code/extraction_manifest.json",
            }
        )
    return {
        "dry_run": True,
        "command": plan.command_name,
        "config": plan.config.as_posix(),
        "out": plan.out.as_posix(),
        "source_runs": len(plan.sources),
        "source_kinds": [source.kind for source in plan.sources],
        "sources": [{"source_kind": source.kind, **source.summary} for source in plan.sources],
        "repository_snapshots": plan.repository_snapshot_summary,
        "outputs": outputs,
    }


def _replace_git_out(options: GitCollectOptions, *, out: Path) -> GitCollectOptions:
    return GitCollectOptions(
        repos=options.repos,
        out=out,
        overwrite=False,
        force_overwrite=False,
        command_name=options.command_name,
        since=options.since,
        max_count=options.max_count,
        message_mode=options.message_mode,
        include_raw_emails=options.include_raw_emails,
        include_remote_urls=options.include_remote_urls,
        include_local_paths=options.include_local_paths,
        max_topology_commit_ids=options.max_topology_commit_ids,
        include_merge_viability=options.include_merge_viability,
        privacy_hasher=options.privacy_hasher,
        progress=options.progress,
    )


def _replace_github_out(options: GitHubCollectOptions, *, out: Path) -> GitHubCollectOptions:
    return GitHubCollectOptions(
        repos=options.repos,
        out=out,
        overwrite=False,
        force_overwrite=False,
        hostname=options.hostname,
        since=options.since,
        max_prs=options.max_prs,
        body_mode=options.body_mode,
        comment_mode=options.comment_mode,
        actor_mode=options.actor_mode,
        commit_message_mode=options.commit_message_mode,
        include_raw_emails=options.include_raw_emails,
        include_urls=options.include_urls,
        include_file_patches=options.include_file_patches,
        skip_auth_check=options.skip_auth_check,
        gh_runner=options.gh_runner,
        retry_policy=options.retry_policy,
        retry_sleep=options.retry_sleep,
        retry_random=options.retry_random,
        privacy_hasher=options.privacy_hasher,
        progress=options.progress,
    )


def _replace_azure_devops_out(
    options: AzureDevOpsCollectOptions, *, out: Path
) -> AzureDevOpsCollectOptions:
    return AzureDevOpsCollectOptions(
        organization=options.organization,
        repos=options.repos,
        out=out,
        overwrite=False,
        force_overwrite=False,
        since=options.since,
        max_prs=options.max_prs,
        body_mode=options.body_mode,
        comment_mode=options.comment_mode,
        actor_mode=options.actor_mode,
        commit_message_mode=options.commit_message_mode,
        include_raw_emails=options.include_raw_emails,
        include_urls=options.include_urls,
        token_env=options.token_env,
        api_version=options.api_version,
        requester=options.requester,
        retry_policy=options.retry_policy,
        retry_sleep=options.retry_sleep,
        retry_random=options.retry_random,
        privacy_hasher=options.privacy_hasher,
        progress=options.progress,
    )


def _merged_manifest(
    *,
    out: Path,
    observed_at: str,
    plan: CollectPlan,
    source_runs: list[dict[str, object]],
    snapshot_result: dict[str, object] | None,
    events: list[dict[str, object]],
    artifacts: list[dict[str, object]],
    errors: list[str],
    outputs: dict[str, str],
    event_duplicate_count: int,
    artifact_duplicate_count: int,
) -> dict[str, object]:
    event_counts = Counter(str(event.get("event_type") or "unknown") for event in events)
    artifact_counts = Counter(
        str(artifact.get("artifact_type") or "unknown") for artifact in artifacts
    )
    source_kinds = sorted({source.kind for source in plan.sources})
    repos_requested = 0
    repos_collected = 0
    repository_results: list[dict[str, object]] = []
    privacy_inputs: list[dict[str, object]] = []
    for run in source_runs:
        manifest = run.get("manifest")
        if not isinstance(manifest, dict):
            continue
        counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
        privacy = manifest.get("privacy") if isinstance(manifest.get("privacy"), dict) else {}
        repos_requested += _int(counts.get("repos_requested"), default=0)
        repos_collected += _int(counts.get("repos_collected"), default=0)
        source_kind = str(run.get("source_kind") or "unknown")
        raw_results = manifest.get("repository_results")
        if isinstance(raw_results, list):
            for item in raw_results:
                if isinstance(item, dict):
                    repository_results.append({"source_kind": source_kind, **item})
        privacy_inputs.append(dict(privacy))

    snapshot_counts: dict[str, object] = {}
    snapshot_privacy: dict[str, object] = {}
    snapshot_manifest: dict[str, object] | None = None
    if snapshot_result is not None:
        raw_manifest = snapshot_result.get("manifest")
        if isinstance(raw_manifest, dict):
            snapshot_manifest = raw_manifest
            if isinstance(raw_manifest.get("counts"), dict):
                snapshot_counts = dict(raw_manifest["counts"])
            if isinstance(raw_manifest.get("privacy"), dict):
                snapshot_privacy = dict(raw_manifest["privacy"])
                privacy_inputs.append(snapshot_privacy)
            raw_repositories = raw_manifest.get("repositories")
            if isinstance(raw_repositories, list):
                for item in raw_repositories:
                    if not isinstance(item, dict):
                        continue
                    requested = _int(item.get("snapshots_requested"), default=0)
                    collected = _int(item.get("snapshots_collected"), default=0)
                    status = (
                        "complete"
                        if collected == requested and not item.get("error")
                        else "partial"
                        if collected > 0
                        else "failed"
                    )
                    repository_results.append(
                        {
                            "source_kind": "repository_snapshot",
                            "repo_id": item.get("repo_id"),
                            "repo_hint": item.get("repo_hint"),
                            "status": status,
                            "counts": {
                                "snapshots_requested": requested,
                                "snapshots_collected": collected,
                            },
                            **({"error": item.get("error")} if item.get("error") else {}),
                        }
                    )

    facets: dict[str, object] = {
        "activity": {
            "schema_version": "shevek.activity_bundle.v1",
            "enabled": bool(source_runs),
            "events": outputs["source_events"],
            "artifacts": outputs["source_artifacts"],
        }
    }
    if snapshot_result is not None:
        facets["repository_snapshots"] = {
            "schema_version": "shevek.repository_snapshot_bundle.v1",
            "enabled": True,
            "snapshots": outputs.get("repository_snapshots"),
            "files": outputs.get("repository_files"),
            "operational_records": outputs.get("repository_operational_records"),
            "extraction_manifest": outputs.get("repository_extraction_manifest"),
            "content_mode": snapshot_privacy.get("content_mode"),
        }

    settings: dict[str, object] = {
        "source_runs": [run.get("summary", {}) for run in source_runs if isinstance(run, dict)],
        "merge": "dedupe_by_event_id_and_artifact_id",
    }
    if plan.repository_snapshot_summary is not None:
        settings["repository_snapshots"] = _bundle_safe_snapshot_summary(
            plan.repository_snapshot_summary,
            privacy_hasher=_plan_privacy_hasher(plan),
        )

    total_repos_requested = repos_requested + _int(
        snapshot_counts.get("repos_requested"), default=0
    )
    total_repos_collected = repos_collected + _int(
        snapshot_counts.get("repos_collected"), default=0
    )
    status = collection_status(
        repos_requested=total_repos_requested,
        repos_collected=total_repos_collected,
        errors=errors,
    )

    return {
        "schema_version": COLLECT_MANIFEST_SCHEMA_VERSION,
        "collector": {"name": "shevek_collect", "version": __version__},
        "created_at": observed_at,
        "bundle_kind": "evidence_bundle" if snapshot_result is not None else "source_evidence",
        "bundle_version": "0.2" if snapshot_result is not None else "0.1",
        "out": out.name,
        "out_path_hash": _plan_privacy_hasher(plan).local_path(out.as_posix()),
        "command": plan.command_name,
        "config": plan.config.name,
        "config_path_hash": _plan_privacy_hasher(plan).local_path(plan.config.as_posix()),
        "source_kinds": source_kinds,
        "collection_status": status,
        "complete": status == "complete",
        "facets": facets,
        "settings": settings,
        "counts": {
            "source_runs": len(source_runs),
            "repos_requested": repos_requested,
            "repos_collected": repos_collected,
            "repos_failed": repos_requested - repos_collected,
            "events": len(events),
            "source_events": len(events),
            "source_artifacts": len(artifacts),
            "duplicate_events_dropped": event_duplicate_count,
            "duplicate_artifacts_dropped": artifact_duplicate_count,
            "snapshot_repos_requested": _int(snapshot_counts.get("repos_requested"), default=0),
            "snapshot_repos_collected": _int(snapshot_counts.get("repos_collected"), default=0),
            "snapshot_repos_failed": _int(snapshot_counts.get("repos_requested"), default=0)
            - _int(snapshot_counts.get("repos_collected"), default=0),
            "repository_snapshots": _int(snapshot_counts.get("snapshots_collected"), default=0),
            "repository_files": _int(snapshot_counts.get("tracked_entries"), default=0),
            "repository_files_captured": _int(snapshot_counts.get("captured_files"), default=0),
            "repository_files_omitted": _int(snapshot_counts.get("omitted_files"), default=0),
            "repository_files_parsed": _int(snapshot_counts.get("parsed_files"), default=0),
            "repository_operational_records": _int(
                snapshot_counts.get("operational_records"), default=0
            ),
            "repository_source_bytes": _int(
                snapshot_counts.get("source_bytes_included"), default=0
            ),
            **{f"event:{key}": value for key, value in sorted(event_counts.items())},
            **{f"artifact:{key}": value for key, value in sorted(artifact_counts.items())},
        },
        "repository_results": repository_results,
        "source_runs": source_runs,
        "repository_snapshot_run": snapshot_manifest,
        "outputs": outputs,
        "identity": _plan_privacy_hasher(plan).manifest_metadata(),
        "privacy": _merge_privacy(privacy_inputs),
        "errors": errors,
    }


def _privacy_report(manifest: dict[str, object]) -> str:
    counts = manifest.get("counts", {})
    privacy = manifest.get("privacy", {})
    identity = manifest.get("identity", {})
    source_runs = manifest.get("source_runs", [])
    snapshot_run = manifest.get("repository_snapshot_run")
    assert isinstance(counts, dict)
    assert isinstance(privacy, dict)
    assert isinstance(identity, dict)
    lines = [
        "# Shevek Collect Privacy Report",
        "",
        f"Created at: `{manifest.get('created_at')}`",
        f"Bundle: `{manifest.get('out')}`",
        f"Config: `{manifest.get('config')}`",
        f"Collection status: `{manifest.get('collection_status')}`",
        "",
        "## Summary",
        "",
        f"- Source runs: {counts.get('source_runs', 0)}",
        f"- Activity repositories requested: {counts.get('repos_requested', 0)}",
        f"- Activity repositories collected: {counts.get('repos_collected', 0)}",
        f"- Activity repositories failed: {counts.get('repos_failed', 0)}",
        f"- Snapshot repositories requested: {counts.get('snapshot_repos_requested', 0)}",
        f"- Snapshot repositories collected: {counts.get('snapshot_repos_collected', 0)}",
        f"- Snapshot repositories failed: {counts.get('snapshot_repos_failed', 0)}",
        f"- Source events: {counts.get('source_events', 0)}",
        f"- Source artifacts: {counts.get('source_artifacts', 0)}",
        f"- Repository snapshots: {counts.get('repository_snapshots', 0)}",
        f"- Repository files observed: {counts.get('repository_files', 0)}",
        f"- Repository files captured: {counts.get('repository_files_captured', 0)}",
        f"- Repository files omitted: {counts.get('repository_files_omitted', 0)}",
        f"- Operational records: {counts.get('repository_operational_records', 0)}",
        f"- Source bytes included: {counts.get('repository_source_bytes', 0)}",
        f"- Duplicate events dropped during merge: {counts.get('duplicate_events_dropped', 0)}",
        f"- Duplicate artifacts dropped during merge: {counts.get('duplicate_artifacts_dropped', 0)}",
        "",
        "## Pseudonymous identifiers",
        "",
        f"- Scheme: `{identity.get('schema')}`",
        f"- Algorithm: `{identity.get('algorithm')}` with domain separation.",
        f"- Pseudonymisation namespace (public ID): `{identity.get('key_id')}`",
        "- The secret key is not included in the bundle.",
        "",
        "## Source runs",
        "",
    ]
    if isinstance(source_runs, list):
        if not source_runs:
            lines.append("- None.")
        for run in source_runs:
            if not isinstance(run, dict):
                continue
            summary = run.get("summary") if isinstance(run.get("summary"), dict) else {}
            result = run.get("result") if isinstance(run.get("result"), dict) else {}
            lines.append(
                f"- `{run.get('source_kind')}` (`{result.get('collection_status', 'unknown')}`): "
                f"{summary.get('repo_count', result.get('repos_requested', 0))} repos requested, "
                f"{result.get('repos_collected', 0)} repos collected, "
                f"{result.get('events', 0)} events, {result.get('artifacts', 0)} artifacts."
            )
    if isinstance(snapshot_run, dict):
        snapshot_settings = snapshot_run.get("settings")
        snapshot_counts = snapshot_run.get("counts")
        if not isinstance(snapshot_settings, dict):
            snapshot_settings = {}
        if not isinstance(snapshot_counts, dict):
            snapshot_counts = {}
        lines.extend(
            [
                "",
                "## Repository snapshot boundary",
                "",
                f"- Content mode: `{snapshot_settings.get('content_mode')}`",
                f"- Snapshot kind: `{snapshot_settings.get('snapshot_kind')}`",
                f"- Tracked files only: `{snapshot_settings.get('tracked_files_only')}`",
                f"- Untracked files included: `{snapshot_settings.get('untracked_files_included')}`",
                "- Gitignore rules are not applied to committed files; capture globs control selection.",
                f"- Git history database included: `{snapshot_settings.get('git_history_database_included')}`",
                f"- Symlink targets followed: `{snapshot_settings.get('symlink_targets_followed')}`",
                f"- Submodule contents included: `{snapshot_settings.get('submodule_contents_included')}`",
                f"- Parsed files: {snapshot_counts.get('parsed_files', 0)}",
                f"- Operational records: {snapshot_counts.get('operational_records', 0)}",
                f"- Parse-error files: {snapshot_counts.get('parse_error_files', 0)}",
                f"- Omission reasons: `{snapshot_counts.get('omit_reason_counts', {})}`",
            ]
        )

    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "- This bundle contains mechanical source observations, optional local syntax extraction, "
            "and structured operational evidence from recognised build/configuration artefacts.",
            "- Activity records are deduplicated by event/artifact ID only.",
            "- Syntax records describe declarations, imports, calls, symbolic references, and styles; they do not infer purpose or intent.",
            "- Operational records describe commands, references, controls, and artefact structure; "
            "they do not decide whether a build is deterministic or a runtime is observable.",
            "- It does not infer workstreams, projects, ownership, mechanisms, or design claims.",
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


def _bundle_safe_source_summary(
    kind: str,
    summary: Mapping[str, object],
    *,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    safe = dict(summary)
    if kind == "git":
        raw_repos = safe.pop("repos", [])
        roots = safe.pop("roots", [])
        repos: list[dict[str, object]] = []
        if isinstance(raw_repos, list):
            for item in raw_repos:
                if not isinstance(item, dict):
                    continue
                path = item.get("path")
                repos.append(
                    {
                        "repo_hint": Path(str(path)).name if path else None,
                        "repo_path_hash": (
                            privacy_hasher.local_path(str(path)) if path else None
                        ),
                        "topology": item.get("topology", {}),
                    }
                )
        safe["repos"] = repos
        safe["root_path_hashes"] = [
            privacy_hasher.local_path(str(value)) for value in roots if isinstance(value, str)
        ]
    return safe


def _bundle_safe_snapshot_summary(
    summary: Mapping[str, object],
    *,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    safe = dict(summary)
    raw_repos = safe.pop("repos", [])
    repos: list[dict[str, object]] = []
    if isinstance(raw_repos, list):
        for item in raw_repos:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            repos.append(
                {
                    "repo_hint": Path(str(path)).name if path else None,
                    "repo_path_hash": (privacy_hasher.local_path(str(path)) if path else None),
                    "snapshots": item.get("snapshots", []),
                }
            )
    safe["repos"] = repos
    return safe


def _source_result_summary(result: Mapping[str, object]) -> dict[str, object]:
    return {
        key: result.get(key)
        for key in (
            "collection_status",
            "complete",
            "repos_requested",
            "repos_collected",
            "events",
            "artifacts",
            "repository_results",
            "retry",
            "errors",
            "outputs",
        )
        if key in result
    }


def _source_manifest_summary(manifest: Mapping[str, object]) -> dict[str, object]:
    return {
        "command": manifest.get("command"),
        "source_kinds": manifest.get("source_kinds", []),
        "collection_status": manifest.get("collection_status"),
        "complete": manifest.get("complete"),
        "settings": manifest.get("settings", {}),
        "counts": manifest.get("counts", {}),
        "privacy": manifest.get("privacy", {}),
        "identity": manifest.get("identity", {}),
        "repository_results": manifest.get("repository_results", []),
        "reliability": manifest.get("reliability", {}),
        "errors": manifest.get("errors", []),
    }


def _merge_privacy(privacy_inputs: list[dict[str, object]]) -> dict[str, object]:
    merged: dict[str, object] = {
        "contains_file_content": False,
        "contains_patches": False,
        "contains_paths": False,
    }
    for privacy in privacy_inputs:
        for key, value in privacy.items():
            if isinstance(value, bool):
                merged[key] = bool(merged.get(key, False)) or value
            elif key not in merged:
                merged[key] = value
            elif merged[key] == value:
                continue
            else:
                existing = merged[key]
                values = existing if isinstance(existing, list) else [existing]
                if value not in values:
                    values.append(value)
                merged[key] = values
    return merged


def _dedupe_by_id(
    records: list[dict[str, object]], *, id_key: str
) -> tuple[list[dict[str, object]], int]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    duplicates = 0
    for record in records:
        record_id = str(record.get(id_key) or "")
        if not record_id:
            deduped.append(record)
            continue
        if record_id in seen:
            duplicates += 1
            continue
        seen.add(record_id)
        deduped.append(record)
    return deduped, duplicates


def _read_json(path: Path) -> dict[str, object]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return parsed


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        parsed = json.loads(line)
        if not isinstance(parsed, dict):
            raise ValueError(f"Expected JSON object at {path}:{line_number}")
        rows.append(parsed)
    return rows


def _mapping(value: object, *, field_name: str) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a mapping, got {type(value).__name__}")
    return dict(value)


def _merged(
    defaults: Mapping[str, object], source_config: Mapping[str, object]
) -> dict[str, object]:
    merged = dict(defaults)
    merged.update(source_config)
    return merged


def _paths_from_items(value: object, *, config_dir: Path, keys: Sequence[str]) -> list[Path]:
    paths: list[Path] = []
    for item in _list(value):
        raw = _item_value(item, keys=keys)
        if raw is None:
            continue
        if not isinstance(raw, str):
            raise ValueError(f"Path entries must be strings, got {type(raw).__name__}")
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (config_dir / path).resolve()
        paths.append(path)
    return paths


def _reject_legacy_git_topology_keys(git_config: Mapping[str, object]) -> None:
    replacements = {
        "topology_base_refs": "repos[].topology.comparison_refs",
        "max_topology_commit_ids": "topology.max_commit_ids",
        "include_merge_viability": "topology.include_merge_viability",
    }
    for legacy, replacement in replacements.items():
        if legacy in git_config:
            raise ValueError(
                f"activity_sources.git.{legacy} has moved to "
                f"activity_sources.git.{replacement}"
            )


def _git_repo_specs_from_items(
    value: object,
    *,
    config_dir: Path,
    field_name: str,
) -> list[GitRepoSpec]:
    specs: list[GitRepoSpec] = []
    for index, item in enumerate(_list(value)):
        item_field = f"{field_name}[{index}]"
        if isinstance(item, str):
            raw_path = item
            comparison_refs: tuple[str, ...] = ()
        elif isinstance(item, dict):
            raw_path = _item_value(item, keys=("path", "repo"))
            topology = _mapping(item.get("topology"), field_name=f"{item_field}.topology")
            comparison_refs = tuple(
                _string_list(
                    topology.get("comparison_refs"),
                    field_name=f"{item_field}.topology.comparison_refs",
                )
            )
        else:
            raise ValueError(
                f"{item_field} must be a path string or mapping, got "
                f"{type(item).__name__}"
            )
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ValueError(f"{item_field}.path must be a non-empty string")
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = (config_dir / path).resolve()
        specs.append(
            GitRepoSpec(
                path=path,
                topology_comparison_refs=comparison_refs,
            )
        )
    return specs


def _dedupe_git_repo_specs(specs: Sequence[GitRepoSpec]) -> list[GitRepoSpec]:
    order: list[str] = []
    paths: dict[str, Path] = {}
    refs: dict[str, list[str]] = {}
    for spec in specs:
        resolved = spec.path.resolve()
        key = resolved.as_posix()
        if key not in paths:
            order.append(key)
            paths[key] = resolved
            refs[key] = []
        for ref in spec.topology_comparison_refs:
            if ref not in refs[key]:
                refs[key].append(ref)
    return [
        GitRepoSpec(path=paths[key], topology_comparison_refs=tuple(refs[key]))
        for key in order
    ]


def _azure_repos_from_items(value: object) -> list[AzureRepoRef]:
    repos: list[AzureRepoRef] = []
    for item in _list(value):
        if isinstance(item, str):
            repos.append(parse_azure_repo(item))
            continue
        if isinstance(item, dict):
            project = str(item.get("project") or "").strip()
            repo = str(item.get("repo") or item.get("name") or "").strip()
            if not project or not repo:
                raise ValueError("Azure DevOps repo mappings require both project and repo")
            repos.append(AzureRepoRef(project=project, repo=repo))
            continue
        raise ValueError(
            f"Azure DevOps repository entries must be strings or mappings, got {type(item).__name__}"
        )
    seen: set[tuple[str, str]] = set()
    deduped: list[AzureRepoRef] = []
    for repo in repos:
        key = (repo.project.casefold(), repo.repo.casefold())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(repo)
    return deduped


def _repos_from_items(value: object, *, keys: Sequence[str]) -> list[str]:
    repos: list[str] = []
    for item in _list(value):
        raw = _item_value(item, keys=keys)
        if raw is None:
            continue
        if not isinstance(raw, str):
            raise ValueError(f"Repository entries must be strings, got {type(raw).__name__}")
        repo = raw.strip()
        if repo:
            repos.append(repo)
    return repos


def _item_value(item: object, *, keys: Sequence[str]) -> object | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for key in keys:
            if key in item:
                return item[key]
        raise ValueError(f"List item mapping must contain one of: {', '.join(keys)}")
    raise ValueError(f"List entries must be strings or mappings, got {type(item).__name__}")


def _list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _dedupe_paths(paths: Sequence[Path]) -> list[Path]:
    seen: set[str] = set()
    deduped: list[Path] = []
    for path in paths:
        key = path.resolve().as_posix()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path.resolve())
    return deduped


def _dedupe_strings(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        key = value.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(key)
    return deduped


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return _int(value, default=0)


def _int(value: object, *, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        return int(value.strip())
    return default


def _choice(value: object, choices: set[str], field_name: str) -> Any:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{field_name} must be one of {sorted(choices)}, got {value!r}")
    return value


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _plan_privacy_hasher(plan: CollectPlan) -> PrivacyHasher:
    privacy_hasher = plan.privacy_hasher
    assert privacy_hasher is not None
    return privacy_hasher


def _boolean(value: object, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field_name} must be a YAML boolean (true or false), not a quoted string or other value")
    return value
