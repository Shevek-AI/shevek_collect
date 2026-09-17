from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Literal, Sequence

from . import __version__
from .git_topology import GitTopologySnapshot, observe_git_topology
from .io_utils import atomic_bundle_directory, write_json, write_jsonl, write_text
from .structure_privacy import strip_url_credentials
from .git_security import run_git
from .privacy import PrivacyHasher, resolve_privacy_hasher
from .progress import ProgressCallback, emit_progress, progress_checkpoint
from .reliability import collection_status
from .repo_identity import repository_identity

MessageMode = Literal["none", "subject", "full"]

SOURCE_EVENT_SCHEMA_VERSION = "shevek.source_event.v1"
SOURCE_ARTIFACT_SCHEMA_VERSION = "shevek.source_artifact.v1"
COLLECT_MANIFEST_SCHEMA_VERSION = "shevek.collect_manifest.v1"


@dataclass(frozen=True)
class GitRepoSpec:
    path: Path
    topology_comparison_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class GitCollectOptions:
    repos: tuple[Path | GitRepoSpec, ...]
    out: Path
    overwrite: bool = False
    force_overwrite: bool = False
    command_name: str = "git scan"
    since: str | None = None
    max_count: int | None = None
    message_mode: MessageMode = "subject"
    include_raw_emails: bool = False
    include_remote_urls: bool = False
    include_local_paths: bool = False
    max_topology_commit_ids: int = 500
    include_merge_viability: bool = True
    privacy_hasher: PrivacyHasher | None = field(default=None, repr=False, compare=False)
    progress: ProgressCallback | None = field(default=None, repr=False, compare=False)


def _normalise_repo_specs(
    repos: Sequence[Path | GitRepoSpec],
) -> tuple[GitRepoSpec, ...]:
    specs: list[GitRepoSpec] = []
    for item in repos:
        if isinstance(item, GitRepoSpec):
            specs.append(
                GitRepoSpec(
                    path=item.path,
                    topology_comparison_refs=tuple(item.topology_comparison_refs),
                )
            )
        else:
            specs.append(GitRepoSpec(path=item))
    return tuple(specs)


def collect_git(options: GitCollectOptions) -> dict[str, object]:
    """Collect local git repository activity and atomically publish the bundle."""
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
        return _collect_git_into(options, out=stage, public_out=public_out)


def _collect_git_into(
    options: GitCollectOptions,
    *,
    out: Path,
    public_out: Path,
) -> dict[str, object]:
    observed_at = _now_iso()
    privacy_hasher = options.privacy_hasher
    assert privacy_hasher is not None
    events: list[dict[str, object]] = []
    repo_artifacts: list[dict[str, object]] = []
    topology_artifacts: list[dict[str, object]] = []
    path_stats: dict[tuple[str, str], dict[str, object]] = {}
    errors: list[str] = []
    collected_repos: list[dict[str, object]] = []
    repository_results: list[dict[str, object]] = []
    repo_specs = _normalise_repo_specs(options.repos)

    emit_progress(
        options.progress, f"Starting Git collection for {len(repo_specs)} repositories"
    )
    for repo_index, repo_spec in enumerate(repo_specs, start=1):
        repo_arg = repo_spec.path
        emit_progress(
            options.progress,
            f"Git repository {repo_index}/{len(repo_specs)}: {repo_arg.name}",
        )
        # A repository can fail before Git establishes its canonical root or hosted
        # identity. Seed the persisted result with a keyed local identifier rather
        # than the user-supplied name/path; detailed diagnostics stay on stderr.
        repo_id = privacy_hasher.local_repository_id(repo_arg.expanduser().absolute().as_posix())
        repo_result: dict[str, object] = {
            "repo_id": repo_id,
            "status": "failed",
        }
        try:
            repo = repo_arg.resolve()
            if not repo.exists():
                raise FileNotFoundError(f"Repository path does not exist: {repo}")
            if _git(repo, ["rev-parse", "--is-inside-work-tree"]).strip() != "true":
                raise ValueError(f"Not a git work tree: {repo}")

            repo_root = Path(_git(repo, ["rev-parse", "--show-toplevel"]).strip()).resolve()
            repo_summary = _repo_summary(
                repo_root,
                observed_at=observed_at,
                include_remote_urls=options.include_remote_urls,
                include_local_paths=options.include_local_paths,
                privacy_hasher=privacy_hasher,
            )
            topology = observe_git_topology(
                repo_root,
                privacy_hasher=privacy_hasher,
                configured_comparison_refs=repo_spec.topology_comparison_refs,
                max_commit_ids_per_relation=options.max_topology_commit_ids,
                include_merge_viability=options.include_merge_viability,
                include_raw_emails=options.include_raw_emails,
            )
            repo_id = str(repo_summary["repo_id"])
            repo_result["repo_id"] = repo_id
            repo_result["repo_hint"] = repo_summary["repo_hint"]
            commits = _commit_ids(repo_root, since=options.since, max_count=options.max_count)
            repo_artifact = _repo_artifact(
                repo_summary,
                observed_at=observed_at,
                commit_count=len(commits),
                topology=topology,
            )
            emit_progress(options.progress, f"  found {len(commits)} commits")
            repo_events: list[dict[str, object]] = []
            for commit_index, commit in enumerate(commits, start=1):
                repo_events.append(
                    _commit_event(
                        repo_root,
                        repo_summary,
                        commit,
                        observed_at=observed_at,
                        message_mode=options.message_mode,
                        include_raw_emails=options.include_raw_emails,
                        privacy_hasher=privacy_hasher,
                    )
                )
                if progress_checkpoint(commit_index, len(commits), every=250):
                    emit_progress(
                        options.progress,
                        f"  processed {commit_index}/{len(commits)} commits",
                    )
            repo_path_stats: dict[tuple[str, str], dict[str, object]] = {}
            _update_path_stats(
                repo_path_stats,
                repo_id=repo_id,
                repo_events=repo_events,
                privacy_hasher=privacy_hasher,
            )

            # Commit repository observations only after every git read and transform succeeds.
            repo_topology_artifacts = _topology_artifacts(
                repo_summary,
                topology=topology,
                observed_at=observed_at,
                include_raw_emails=options.include_raw_emails,
            )
            repo_artifacts.append(repo_artifact)
            topology_artifacts.extend(repo_topology_artifacts)
            events.extend(repo_events)
            path_stats.update(repo_path_stats)
            collected_repos.append(
                {
                    "repo_id": repo_id,
                    "repo_hint": repo_summary["repo_hint"],
                    "commits": len(commits),
                    "head": repo_summary["head"],
                    "branch": repo_summary["branch"],
                    "dirty": repo_summary["dirty"],
                    "refs": len(topology.refs),
                    "tags": len(topology.tags),
                    "branch_relations": len(topology.branch_relations),
                }
            )
            repo_result.update(
                {
                    "status": "complete",
                    "counts": {
                        "commits": len(commits),
                        "refs": len(topology.refs),
                        "tags": len(topology.tags),
                        "branch_relations": len(topology.branch_relations),
                    },
                }
            )
            emit_progress(
                options.progress,
                "  complete: "
                f"{len(commits)} commits, {len(topology.refs)} refs, "
                f"{len(topology.tags)} tags, {len(topology.branch_relations)} branch relations",
            )
        except Exception as exc:  # keep one bad repo from hiding successful exports
            error_code = _bundle_safe_git_error(exc)
            # repo_hint is intentionally plaintext for successfully collected Git
            # evidence, but must not survive a failed repository result.
            repo_result.pop("repo_hint", None)
            repo_result["repo_id"] = repo_id
            repo_result["error"] = error_code
            errors.append(f"{repo_id}: {error_code}")
            emit_progress(options.progress, f"  failed: {exc}")
        finally:
            repository_results.append(repo_result)

    artifact_records = (
        repo_artifacts
        + topology_artifacts
        + _path_artifacts(
            path_stats,
            observed_at=observed_at,
            privacy_hasher=privacy_hasher,
        )
    )
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
        events=events,
        artifacts=artifact_records,
        errors=errors,
        outputs=outputs,
        privacy_hasher=privacy_hasher,
    )
    privacy_report = _privacy_report(manifest, options=options)

    write_jsonl(out / outputs["source_events"], events)
    write_jsonl(out / outputs["source_artifacts"], artifact_records)
    write_json(out / outputs["collect_manifest"], manifest)
    write_text(out / outputs["privacy_report"], privacy_report)

    status = collection_status(
        repos_requested=len(repo_specs),
        repos_collected=len(collected_repos),
        errors=errors,
    )
    emit_progress(
        options.progress,
        f"Git collection {status}: {len(collected_repos)}/{len(repo_specs)} repositories",
    )
    return {
        "out": public_out.as_posix(),
        "collection_status": status,
        "complete": status == "complete",
        "repos_requested": len(repo_specs),
        "repos_collected": len(collected_repos),
        "events": len(events),
        "artifacts": len(artifact_records),
        "repository_results": repository_results,
        "errors": errors,
        "outputs": outputs,
    }


def discover_git_repos(root: Path) -> list[Path]:
    """Find git working trees below a root without descending into .git directories."""
    root = root.expanduser().resolve()
    repos: list[Path] = []
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        if ".git" in dirs or ".git" in files:
            repos.append(current_path)
            dirs[:] = []
            continue
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in {".git", ".venv", "venv", "node_modules"}
        ]
    return sorted(repos)


def _manifest(
    *,
    out: Path,
    observed_at: str,
    options: GitCollectOptions,
    collected_repos: list[dict[str, object]],
    repository_results: list[dict[str, object]],
    events: list[dict[str, object]],
    artifacts: list[dict[str, object]],
    errors: list[str],
    outputs: dict[str, str],
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
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
        "out_path_hash": privacy_hasher.local_path(out.as_posix()),
        "command": options.command_name,
        "source_kinds": ["git"],
        "collection_status": status,
        "complete": status == "complete",
        "settings": {
            "message_mode": options.message_mode,
            "include_raw_emails": options.include_raw_emails,
            "include_remote_urls": options.include_remote_urls,
            "include_local_paths": options.include_local_paths,
            "topology": {
                "max_commit_ids": options.max_topology_commit_ids,
                "include_merge_viability": options.include_merge_viability,
            },
            "include_file_content": False,
            "include_patches": False,
            "since": options.since,
            "max_count": options.max_count,
        },
        "counts": {
            "repos_requested": len(options.repos),
            "repos_collected": len(collected_repos),
            "repos_failed": len(options.repos) - len(collected_repos),
            "events": len(events),
            "source_events": len(events),
            "source_artifacts": len(artifacts),
            "git_commit_events": sum(
                1 for event in events if event.get("event_type") == "git.commit"
            ),
            "git_ref_artifacts": sum(
                1 for artifact in artifacts if artifact.get("artifact_type") == "git.ref_snapshot"
            ),
            "git_tag_artifacts": sum(
                1 for artifact in artifacts if artifact.get("artifact_type") == "git.tag_snapshot"
            ),
            "git_branch_relation_artifacts": sum(
                1
                for artifact in artifacts
                if artifact.get("artifact_type") == "git.branch_relation"
            ),
        },
        "repos": collected_repos,
        "repository_results": repository_results,
        "reliability": {"repository_transaction": "all_or_nothing"},
        "outputs": outputs,
        "privacy": {
            "contains_file_content": False,
            "contains_patches": False,
            "contains_paths": True,
            "contains_commit_messages": options.message_mode != "none",
            "contains_full_commit_bodies": options.message_mode == "full",
            "contains_raw_emails": options.include_raw_emails,
            "contains_raw_remote_urls": options.include_remote_urls,
            "contains_raw_local_paths": options.include_local_paths,
            "contains_ref_names": True,
            "contains_tag_subjects": True,
            "secret_scanning": "not_performed",
        },
        "identity": privacy_hasher.manifest_metadata(),
        "errors": errors,
    }


def _privacy_report(manifest: dict[str, object], *, options: GitCollectOptions) -> str:
    counts = manifest.get("counts", {})
    assert isinstance(counts, dict)
    privacy = manifest.get("privacy", {})
    identity = manifest.get("identity", {})
    assert isinstance(privacy, dict)
    assert isinstance(identity, dict)
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
        "",
        "## Pseudonymous identifiers",
        "",
        f"- Scheme: `{identity.get('schema')}`",
        f"- Algorithm: `{identity.get('algorithm')}` with domain separation.",
        f"- Pseudonymisation namespace (public ID): `{identity.get('key_id')}`",
        "- The secret key is not included in the bundle.",
        "",
        "## Included by this git scan",
        "",
        "- Commit SHAs, parent SHAs, author/committer timestamps, and current branch/head metadata.",
        "- Local and remote branch refs, symbolic remote defaults, tag metadata, and exact observation timestamps.",
        "- Deterministic branch-to-anchor divergence, patch-equivalence, and merge-viability observations.",
        "- Ref and tag names are included because they are required to reconstruct promotion topology.",
        "- Changed paths, git name-status values, and diff line counts from `git show --numstat`.",
        "- Author and committer display names.",
        "- Keyed, domain-separated email pseudonyms, not raw emails, unless `--include-raw-emails` was used.",
    ]
    if options.message_mode == "none":
        lines.append("- Commit messages were not included.")
    elif options.message_mode == "subject":
        lines.append("- Commit subjects were included; full commit bodies were not included.")
    else:
        lines.append("- Full commit messages were included because `--message-mode full` was used.")
    lines.extend(
        [
            "",
            "## Not included by default",
            "",
            "- File contents.",
            "- Patches or diff hunks.",
            "- Secret scanning results; no content was collected for this pass.",
            "- Raw remote URLs unless `--include-remote-urls` was used.",
            "- Absolute local repository paths unless `--include-local-paths` was used.",
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
    repo: Path,
    *,
    observed_at: str,
    include_remote_urls: bool,
    include_local_paths: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    repo_root = Path(_git(repo, ["rev-parse", "--show-toplevel"]).strip()).resolve()
    git_dir = Path(_git(repo_root, ["rev-parse", "--git-dir"]).strip())
    head = _git_maybe(repo_root, ["rev-parse", "HEAD"]).strip()
    branch = _git_maybe(repo_root, ["branch", "--show-current"]).strip()
    status_short = _git(repo_root, ["status", "--short"]).splitlines()
    remotes = _remote_records(
        repo_root,
        include_remote_urls=include_remote_urls,
        privacy_hasher=privacy_hasher,
    )
    preferred_remote = _preferred_remote_identity(remotes)
    if preferred_remote is not None:
        repo_id = str(preferred_remote["repository_fingerprint"])
        identity_kind = "hosted_remote"
    else:
        # A repository with no recognisable hosted remote cannot be joined to a
        # code-host provider. Keep a stable local-only identifier instead.
        repo_id = privacy_hasher.local_repository_id(repo_root.as_posix())
        identity_kind = "local_path"
    repository_fingerprints = sorted(
        {
            str(remote["repository_fingerprint"])
            for remote in remotes
            if remote.get("repository_fingerprint")
        }
    )
    summary: dict[str, object] = {
        "kind": "git",
        "repo_id": repo_id,
        "repository_fingerprint": repo_id,
        "repository_fingerprints": repository_fingerprints or [repo_id],
        "repository_identity_kind": identity_kind,
        "repo_hint": repo_root.name,
        "repo_path_hash": privacy_hasher.local_path(repo_root.as_posix()),
        "git_dir_hint": git_dir.name,
        "head": head,
        "branch": branch,
        "dirty": bool(status_short),
        "status_count": len(status_short),
        "remotes": remotes,
        "observed_at": observed_at,
    }
    if include_local_paths:
        summary["local_path"] = repo_root.as_posix()
    return summary


def _repo_artifact(
    repo_summary: dict[str, object],
    *,
    observed_at: str,
    commit_count: int,
    topology: GitTopologySnapshot,
) -> dict[str, object]:
    repo_id = str(repo_summary["repo_id"])
    return {
        "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
        "artifact_id": f"git.repo:{repo_id}",
        "artifact_type": "git.repository",
        "semantic_type": "scm.repository",
        "source": _source_block(repo_summary),
        "observed_at": observed_at,
        "payload": {
            "repo_hint": repo_summary["repo_hint"],
            "head": repo_summary["head"],
            "branch": repo_summary["branch"],
            "dirty": repo_summary["dirty"],
            "status_count": repo_summary["status_count"],
            "remote_count": len(repo_summary.get("remotes", [])),
            "commit_count": commit_count,
            "ref_count": len(topology.refs),
            "tag_count": len(topology.tags),
            "branch_relation_count": len(topology.branch_relations),
            "repository_state": topology.repository_state,
        },
        "privacy": {
            "contains_content": False,
            "contains_paths": bool(repo_summary.get("local_path")),
            "contains_raw_remote_urls": any(
                "url" in remote for remote in repo_summary.get("remotes", [])
            ),
        },
        "provenance": _provenance(),
    }


def _topology_artifacts(
    repo_summary: dict[str, object],
    *,
    topology: GitTopologySnapshot,
    observed_at: str,
    include_raw_emails: bool,
) -> list[dict[str, object]]:
    repo_id = str(repo_summary["repo_id"])
    source = _source_block(repo_summary)
    artifacts: list[dict[str, object]] = []

    for ref in topology.refs:
        payload = dict(ref)
        artifact_id = _snapshot_artifact_id(
            "git.ref_snapshot",
            repo_id,
            str(payload["ref_hash"]),
            str(payload.get("tip_sha") or "unborn"),
            observed_at,
        )
        artifacts.append(
            {
                "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
                "artifact_id": artifact_id,
                "artifact_type": "git.ref_snapshot",
                "semantic_type": "scm.ref",
                "source": source,
                "observed_at": observed_at,
                "payload": payload,
                "privacy": {
                    "contains_content": False,
                    "contains_ref_names": True,
                },
                "provenance": _provenance(),
            }
        )

    for tag in topology.tags:
        payload = dict(tag)
        if not include_raw_emails:
            payload.pop("tagger_email", None)
        artifact_id = _snapshot_artifact_id(
            "git.tag_snapshot",
            repo_id,
            str(payload["ref_hash"]),
            str(payload.get("target_object_sha") or "missing"),
            observed_at,
        )
        artifacts.append(
            {
                "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
                "artifact_id": artifact_id,
                "artifact_type": "git.tag_snapshot",
                "semantic_type": "scm.tag",
                "source": source,
                "observed_at": observed_at,
                "payload": payload,
                "privacy": {
                    "contains_content": False,
                    "contains_ref_names": True,
                    "contains_tag_subject": bool(payload.get("subject")),
                    "contains_raw_email": include_raw_emails and bool(payload.get("tagger_email")),
                },
                "provenance": _provenance(),
            }
        )

    for relation in topology.branch_relations:
        payload = dict(relation)
        artifact_id = _snapshot_artifact_id(
            "git.branch_relation",
            repo_id,
            str(payload["relation_hash"]),
            str(payload["base_sha"]),
            str(payload["head_sha"]),
            observed_at,
        )
        artifacts.append(
            {
                "schema_version": SOURCE_ARTIFACT_SCHEMA_VERSION,
                "artifact_id": artifact_id,
                "artifact_type": "git.branch_relation",
                "semantic_type": "scm.branch_relation",
                "source": source,
                "observed_at": observed_at,
                "payload": payload,
                "privacy": {
                    "contains_content": False,
                    "contains_ref_names": True,
                    "contains_commit_shas": True,
                },
                "provenance": _provenance(),
            }
        )

    return artifacts


def _snapshot_artifact_id(prefix: str, *identity_parts: str) -> str:
    material = "\0".join(identity_parts).encode("utf-8", errors="replace")
    digest = hashlib.sha256(material).hexdigest()[:32]
    return f"{prefix}:{digest}"


def _commit_ids(repo: Path, *, since: str | None, max_count: int | None) -> list[str]:
    if _git_maybe(repo, ["rev-parse", "--verify", "HEAD"]).strip() == "":
        return []
    args = ["rev-list", "--all", "--date-order"]
    if since:
        args.append(f"--since={since}")
    if max_count is not None:
        args.append(f"--max-count={max_count}")
    return [line.strip() for line in _git(repo, args).splitlines() if line.strip()]


def _commit_event(
    repo: Path,
    repo_summary: dict[str, object],
    commit: str,
    *,
    observed_at: str,
    message_mode: MessageMode,
    include_raw_emails: bool,
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    raw_meta = _git(
        repo,
        [
            "show",
            "-s",
            "--date=iso-strict",
            "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s%x00%B",
            commit,
        ],
    )
    parts = raw_meta.split("\x00", 9)
    if len(parts) != 10:
        raise ValueError(f"Unable to parse commit metadata for {commit}")

    (
        sha,
        parents,
        author_name,
        author_email,
        author_date,
        committer_name,
        committer_email,
        committer_date,
        subject,
        body,
    ) = parts
    repo_id = str(repo_summary["repo_id"])
    changed_paths = _changed_paths(repo, commit, privacy_hasher=privacy_hasher)
    payload: dict[str, object] = {
        "sha": sha,
        "parents": parents.split() if parents else [],
        "author_date": author_date,
        "committer_date": committer_date,
        "changed_paths": changed_paths,
    }
    if message_mode in {"subject", "full"}:
        payload["subject"] = subject
    if message_mode == "full":
        payload["body"] = body.strip()

    actor: dict[str, object] = {
        "author_name": author_name,
        "author_email_hash": privacy_hasher.email(author_email.casefold().strip()),
        "committer_name": committer_name,
        "committer_email_hash": privacy_hasher.email(committer_email.casefold().strip()),
    }
    if include_raw_emails:
        actor["author_email"] = author_email
        actor["committer_email"] = committer_email

    return {
        "schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "event_id": f"git.commit:{repo_id}:{sha}",
        "event_type": "git.commit",
        "semantic_type": "scm.commit",
        "source": _source_block(repo_summary),
        "occurred_at": committer_date or author_date,
        "observed_at": observed_at,
        "actor": actor,
        "payload": payload,
        "privacy": {
            "contains_content": False,
            "contains_paths": True,
            "contains_commit_messages": message_mode != "none",
            "contains_full_commit_body": message_mode == "full",
            "contains_raw_email": include_raw_emails,
        },
        "provenance": _provenance(),
    }


def _changed_paths(
    repo: Path,
    commit: str,
    *,
    privacy_hasher: PrivacyHasher,
) -> list[dict[str, object]]:
    numstat_by_path = _numstat_by_path(repo, commit)
    rows: list[dict[str, object]] = []
    output = _git(repo, ["show", "--name-status", "--find-renames", "--format=", commit])
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        paths = parts[1:]
        new_path = paths[-1] if paths else ""
        row: dict[str, object] = {
            "status": status,
            "path": new_path,
            "path_hash": privacy_hasher.code_path(new_path),
            "additions": None,
            "deletions": None,
        }
        if len(paths) > 1:
            row["old_path"] = paths[0]
            row["old_path_hash"] = privacy_hasher.code_path(paths[0])
        if new_path in numstat_by_path:
            row.update(numstat_by_path[new_path])
        rows.append(row)
    return rows


def _numstat_by_path(repo: Path, commit: str) -> dict[str, dict[str, object]]:
    stats: dict[str, dict[str, object]] = {}
    output = _git(repo, ["show", "--numstat", "--find-renames", "--format=", commit])
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        added, deleted, *paths = parts
        path = paths[-1]
        stats[path] = {
            "additions": None if added == "-" else int(added),
            "deletions": None if deleted == "-" else int(deleted),
        }
    return stats


def _update_path_stats(
    path_stats: dict[tuple[str, str], dict[str, object]],
    *,
    repo_id: str,
    repo_events: Iterable[dict[str, object]],
    privacy_hasher: PrivacyHasher,
) -> None:
    for event in repo_events:
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            continue
        occurred_at = str(event.get("occurred_at") or "")
        changed_paths = payload.get("changed_paths") or []
        if not isinstance(changed_paths, list):
            continue
        for changed_path in changed_paths:
            if not isinstance(changed_path, dict):
                continue
            path = str(changed_path.get("path") or "")
            if not path:
                continue
            key = (repo_id, path)
            row = path_stats.setdefault(
                key,
                {
                    "repo_id": repo_id,
                    "path": path,
                    "path_hash": privacy_hasher.code_path(path),
                    "event_count": 0,
                    "statuses": defaultdict(int),
                    "first_seen_at": occurred_at,
                    "last_seen_at": occurred_at,
                    "total_additions": 0,
                    "total_deletions": 0,
                },
            )
            row["event_count"] = int(row["event_count"]) + 1
            statuses = row["statuses"]
            assert isinstance(statuses, defaultdict)
            statuses[str(changed_path.get("status") or "unknown")] += 1
            if occurred_at:
                row["first_seen_at"] = min(str(row["first_seen_at"]), occurred_at)
                row["last_seen_at"] = max(str(row["last_seen_at"]), occurred_at)
            additions = changed_path.get("additions")
            deletions = changed_path.get("deletions")
            if isinstance(additions, int):
                row["total_additions"] = int(row["total_additions"]) + additions
            if isinstance(deletions, int):
                row["total_deletions"] = int(row["total_deletions"]) + deletions


def _path_artifacts(
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
                "artifact_id": (f"git.path:{repo_id}:{privacy_hasher.code_path(path)}"),
                "artifact_type": "git.changed_path",
                "semantic_type": "scm.changed_path",
                "source": {"kind": "git", "repo_id": repo_id},
                "observed_at": observed_at,
                "payload": {
                    "path": path,
                    "path_hash": stats["path_hash"],
                    "event_count": stats["event_count"],
                    "status_counts": status_counts,
                    "first_seen_at": stats["first_seen_at"],
                    "last_seen_at": stats["last_seen_at"],
                    "total_additions": stats["total_additions"],
                    "total_deletions": stats["total_deletions"],
                },
                "privacy": {"contains_content": False, "contains_paths": True},
                "provenance": _provenance(),
            }
        )
    return artifacts


def _source_block(repo_summary: dict[str, object]) -> dict[str, object]:
    keys = [
        "kind",
        "repo_id",
        "repository_fingerprint",
        "repository_fingerprints",
        "repository_identity_kind",
        "repo_hint",
        "repo_path_hash",
        "head",
        "branch",
        "dirty",
        "remotes",
        "local_path",
    ]
    return {key: repo_summary[key] for key in keys if key in repo_summary}


def _remote_records(
    repo: Path,
    *,
    include_remote_urls: bool,
    privacy_hasher: PrivacyHasher,
) -> list[dict[str, object]]:
    output = _git_maybe(repo, ["remote", "-v"])
    by_key: dict[tuple[str, str], set[str]] = defaultdict(set)
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name, url, kind_raw = parts[0], parts[1], parts[2]
        kind = kind_raw.strip("()")
        by_key[(name, url)].add(kind)
    records: list[dict[str, object]] = []
    for (name, url), kinds in sorted(by_key.items()):
        row: dict[str, object] = {
            "name": name,
            "url_hash": privacy_hasher.remote_url(url),
            "kinds": sorted(kinds),
        }
        identity = repository_identity(url, privacy_hasher=privacy_hasher)
        if identity is not None:
            row.update(
                {
                    "repository_fingerprint": identity.fingerprint,
                    "repository_provider": identity.provider,
                    "repository_hostname": identity.hostname,
                }
            )
            if include_remote_urls:
                row["canonical_locator"] = identity.canonical_locator
        if include_remote_urls:
            row["url"] = strip_url_credentials(url) if "://" in url else url
        records.append(row)
    return records


def _preferred_remote_identity(remotes: Sequence[dict[str, object]]) -> dict[str, object] | None:
    candidates = [remote for remote in remotes if remote.get("repository_fingerprint")]
    if not candidates:
        return None

    def priority(remote: dict[str, object]) -> tuple[int, str, str]:
        name = str(remote.get("name") or "")
        kinds = set(remote.get("kinds") or [])
        if name == "origin" and "fetch" in kinds:
            rank = 0
        elif name == "origin":
            rank = 1
        elif "fetch" in kinds:
            rank = 2
        else:
            rank = 3
        return rank, name, str(remote.get("repository_fingerprint") or "")

    return min(candidates, key=priority)


def _provenance() -> dict[str, object]:
    return {
        "collector": "shevek_collect",
        "collector_version": __version__,
    }


def _bundle_safe_git_error(exc: Exception) -> str:
    """Return a stable failure code without serialising local names or paths."""
    message = str(exc)
    if isinstance(exc, FileNotFoundError):
        return "repository_not_found"
    if isinstance(exc, ValueError) and message.startswith("Not a git work tree:"):
        return "not_a_git_work_tree"
    if isinstance(exc, ValueError) and message.startswith("Unable to parse commit metadata"):
        return "commit_metadata_parse_failed"
    if isinstance(exc, RuntimeError):
        return "git_command_failed"
    return f"collector_error:{type(exc).__name__}"


def _git(repo: Path, args: Sequence[str]) -> str:
    proc = run_git(repo, args)
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "git command failed"
        raise RuntimeError(f"git {' '.join(args)} failed: {message}")
    return proc.stdout


def _git_maybe(repo: Path, args: Sequence[str]) -> str:
    proc = run_git(repo, args)
    return proc.stdout if proc.returncode == 0 else ""


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
