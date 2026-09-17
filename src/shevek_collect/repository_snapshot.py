from __future__ import annotations

import fnmatch
import hashlib
import importlib.metadata
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, Sequence

from . import __version__
from .git_security import run_git
from .git_collect import _repo_summary, _bundle_safe_git_error
from .structure_privacy import sanitize_operational_structure
from .privacy import PrivacyHasher, resolve_privacy_hasher
from .progress import ProgressCallback, emit_progress
from .io_utils import write_json, write_jsonl
from .parser_worker import run_parser, PARSER_TIMEOUT_SECONDS, PARSER_MEMORY_BYTES
from .diagnostics import error_code
from .operational_extract import (
    empty_operational_structure,
    operational_records_for_file,
)
from .parsing import language_for_path
from .syntax_contract import SYNTAX_OBSERVATIONS_SCHEMA_VERSION, empty_syntax
from .syntax_extract import (
    parse_failed_result,
    sanitize_syntax_for_structure_mode,
)

REPOSITORY_SNAPSHOT_SCHEMA_VERSION = "shevek.repository_snapshot.v1"
REPOSITORY_FILE_SCHEMA_VERSION = "shevek.repository_file.v1"
EXTRACTION_MANIFEST_SCHEMA_VERSION = "shevek.repository_extraction_manifest.v1"

ContentMode = Literal["full", "structure"]

DEFAULT_EXCLUDE_GLOBS: tuple[str, ...] = (
    ".git/**",
    "**/.git/**",
    "node_modules/**",
    "**/node_modules/**",
    ".venv/**",
    "**/.venv/**",
    "venv/**",
    "**/venv/**",
    "__pycache__/**",
    "**/__pycache__/**",
    ".pytest_cache/**",
    "**/.pytest_cache/**",
    ".mypy_cache/**",
    "**/.mypy_cache/**",
    ".ruff_cache/**",
    "**/.ruff_cache/**",
    "dist/**",
    "**/dist/**",
    "build/**",
    "**/build/**",
    ".next/**",
    "**/.next/**",
    "coverage/**",
    "**/coverage/**",
    ".env.*",
    "**/.env.*",
    ".npmrc",
    "**/.npmrc",
    ".pypirc",
    "**/.pypirc",
    "id_ecdsa",
    "**/id_ecdsa",
    "id_dsa",
    "**/id_dsa",
    "*.p12",
    "**/*.p12",
    "*.pfx",
    "**/*.pfx",
    ".env",
    "**/.env",
    ".env.local",
    "**/.env.local",
    ".env.development",
    "**/.env.development",
    ".env.test",
    "**/.env.test",
    ".env.staging",
    "**/.env.staging",
    ".env.production",
    "**/.env.production",
    ".env.*.local",
    "**/.env.*.local",
    "*.pem",
    "**/*.pem",
    "*.key",
    "**/*.key",
    "id_rsa",
    "**/id_rsa",
    "id_ed25519",
    "**/id_ed25519",
)


@dataclass(frozen=True)
class SnapshotSpec:
    name: str
    ref: str


@dataclass(frozen=True)
class SnapshotRepoSpec:
    path: Path
    snapshots: tuple[SnapshotSpec, ...] = (SnapshotSpec(name="target", ref="HEAD"),)


@dataclass(frozen=True)
class SnapshotCapturePolicy:
    content_mode: ContentMode = "full"
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    include_globs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = DEFAULT_EXCLUDE_GLOBS
    use_default_excludes: bool = True


@dataclass(frozen=True)
class RepositorySnapshotOptions:
    repos: tuple[SnapshotRepoSpec, ...]
    out: Path
    policy: SnapshotCapturePolicy = field(default_factory=SnapshotCapturePolicy)
    privacy_hasher: PrivacyHasher | None = field(default=None, repr=False, compare=False)
    progress: ProgressCallback | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_type: str
    object_id: str
    size: int | None
    path: str


def collect_repository_snapshots(options: RepositorySnapshotOptions) -> dict[str, object]:
    """Capture exact committed repository snapshots and local syntax observations."""
    options = replace(
        options,
        privacy_hasher=resolve_privacy_hasher(options.privacy_hasher),
    )
    privacy_hasher = options.privacy_hasher
    assert privacy_hasher is not None
    out = options.out.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    code_dir = out / "code"
    blob_root = code_dir / "blobs" / "sha256"
    if options.policy.content_mode == "full":
        blob_root.mkdir(parents=True, exist_ok=True)

    observed_at = _now_iso()
    snapshots: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    operational_records: list[dict[str, object]] = []
    errors: list[str] = []
    repo_results: list[dict[str, object]] = []
    blobs_written: set[str] = set()

    emit_progress(
        options.progress,
        f"Starting repository snapshots for {len(options.repos)} repositories",
    )
    for repo_index, repo_spec in enumerate(options.repos, start=1):
        emit_progress(
            options.progress,
            f"Snapshot repository {repo_index}/{len(options.repos)}: {repo_spec.path.name}",
        )
        try:
            repo = repo_spec.path.expanduser().resolve()
            _validate_git_repo(repo)
            repo_root = Path(_git_text(repo, ["rev-parse", "--show-toplevel"]).strip()).resolve()
            repo_summary = _repo_summary(
                repo_root,
                observed_at=observed_at,
                include_remote_urls=False,
                include_local_paths=False,
                privacy_hasher=privacy_hasher,
            )
            repo_id = str(repo_summary["repo_id"])
            snapshot_results: list[dict[str, object]] = []

            for snapshot_index, snapshot_spec in enumerate(repo_spec.snapshots, start=1):
                emit_progress(
                    options.progress,
                    f"  snapshot {snapshot_index}/{len(repo_spec.snapshots)}: "
                    f"{snapshot_spec.name}={snapshot_spec.ref}",
                )
                try:
                    result = _capture_snapshot(
                        repo_root=repo_root,
                        repo_summary=repo_summary,
                        snapshot_spec=snapshot_spec,
                        policy=options.policy,
                        blob_root=blob_root,
                        blobs_written=blobs_written,
                        observed_at=observed_at,
                    )
                    snapshots.append(result["snapshot"])
                    files.extend(result["files"])
                    operational_records.extend(result["operational_records"])
                    snapshot_results.append(result["summary"])
                    emit_progress(
                        options.progress,
                        f"    complete: {len(result['files'])} files",
                    )
                except Exception as exc:
                    message = (
                        f"{_repo_label(repo_root, privacy_hasher=privacy_hasher)} "
                        f"[{snapshot_spec.name}]: {_bundle_safe_git_error(exc)}"
                    )
                    errors.append(message)
                    emit_progress(options.progress, f"    failed: {exc}")
                    snapshot_results.append(
                        {
                            "name": snapshot_spec.name,
                            "requested_ref": snapshot_spec.ref,
                            "status": "error",
                            "error": _bundle_safe_git_error(exc),
                        }
                    )

            repo_results.append(
                {
                    "repo_id": repo_id,
                    "repo_hint": repo_summary.get("repo_hint"),
                    "repo_path_hash": repo_summary.get("repo_path_hash"),
                    "snapshots_requested": len(repo_spec.snapshots),
                    "snapshots_collected": sum(
                        1 for item in snapshot_results if item.get("status") == "collected"
                    ),
                    "snapshots": snapshot_results,
                }
            )
        except Exception as exc:
            errors.append(f"{_repo_label(repo_spec.path, privacy_hasher=privacy_hasher)}: {_bundle_safe_git_error(exc)}")
            emit_progress(options.progress, f"  failed: {exc}")
            repo_results.append(
                {
                    "repo_id": privacy_hasher.local_repository_id(repo_spec.path.expanduser().resolve().as_posix()),
                    "snapshots_requested": len(repo_spec.snapshots),
                    "snapshots_collected": 0,
                    "status": "error",
                    "error": _bundle_safe_git_error(exc),
                }
            )

    snapshots.sort(key=lambda row: (str(row.get("repo_id")), str(row.get("name"))))
    files.sort(
        key=lambda row: (
            str(row.get("repo_id")),
            str(row.get("snapshot_id")),
            str(row.get("path")),
        )
    )
    operational_records.sort(
        key=lambda row: (
            str(row.get("repo_id")),
            str(row.get("snapshot_id")),
            str(row.get("path")),
            str(row.get("record_id")),
        )
    )

    outputs = {
        "repository_snapshots": "code/snapshots.jsonl",
        "repository_files": "code/files.jsonl",
        "repository_operational_records": "code/operational_records.jsonl",
        "repository_extraction_manifest": "code/extraction_manifest.json",
    }
    extraction_manifest = _extraction_manifest(
        observed_at=observed_at,
        options=options,
        snapshots=snapshots,
        files=files,
        operational_records=operational_records,
        repo_results=repo_results,
        errors=errors,
        outputs=outputs,
        blobs_written=blobs_written,
        privacy_hasher=privacy_hasher,
    )
    write_jsonl(out / outputs["repository_snapshots"], snapshots)
    write_jsonl(out / outputs["repository_files"], files)
    write_jsonl(out / outputs["repository_operational_records"], operational_records)
    write_json(out / outputs["repository_extraction_manifest"], extraction_manifest)

    counts = extraction_manifest["counts"]
    assert isinstance(counts, dict)
    privacy = extraction_manifest["privacy"]
    assert isinstance(privacy, dict)
    return {
        "out": out.as_posix(),
        "repos_requested": len(options.repos),
        "repos_collected": sum(1 for item in repo_results if item.get("snapshots_collected", 0)),
        "snapshots_requested": sum(len(repo.snapshots) for repo in options.repos),
        "snapshots_collected": len(snapshots),
        "files": len(files),
        "operational_records": len(operational_records),
        "captured_files": counts.get("captured_files", 0),
        "omitted_files": counts.get("omitted_files", 0),
        "parsed_files": counts.get("parsed_files", 0),
        "errors": errors,
        "outputs": outputs,
        "privacy": privacy,
        "manifest": extraction_manifest,
    }


def _capture_snapshot(
    *,
    repo_root: Path,
    repo_summary: dict[str, object],
    snapshot_spec: SnapshotSpec,
    policy: SnapshotCapturePolicy,
    blob_root: Path,
    blobs_written: set[str],
    observed_at: str,
) -> dict[str, object]:
    commit = _git_text(
        repo_root, ["rev-parse", "--verify", "--end-of-options", f"{snapshot_spec.ref}^{{commit}}"]
    ).strip()
    tree_oid = _git_text(repo_root, ["rev-parse", f"{commit}^{{tree}}"]).strip()
    parents = [
        value
        for value in _git_text(repo_root, ["show", "-s", "--format=%P", commit]).strip().split()
        if value
    ]
    repo_id = str(repo_summary["repo_id"])
    snapshot_id = _snapshot_id(repo_id, commit, snapshot_spec.name)
    entries = _list_tree(repo_root, commit)
    captured_bytes = 0
    included_blob_bytes = 0
    file_records: list[dict[str, object]] = []
    operational_records: list[dict[str, object]] = []
    contents_by_path: dict[str, str] = {}

    for entry in entries:
        base = _base_file_record(
            repo_id=repo_id,
            snapshot_id=snapshot_id,
            entry=entry,
            observed_at=observed_at,
        )
        omit_reason = _pre_read_omit_reason(entry, policy)
        if omit_reason is not None:
            base.update(_omitted_fields(omit_reason, path=entry.path))
            file_records.append(base)
            continue

        raw = _git_bytes(repo_root, ["cat-file", "blob", entry.object_id])
        if len(raw) > policy.max_file_bytes:
            base.update(_omitted_fields("file_size_limit", path=entry.path))
            file_records.append(base)
            continue
        if captured_bytes + len(raw) > policy.max_total_bytes:
            base.update(_omitted_fields("snapshot_total_size_limit", path=entry.path))
            file_records.append(base)
            continue
        if not _is_probably_text(raw):
            base.update(_omitted_fields("binary_or_non_text", path=entry.path))
            file_records.append(base)
            continue

        captured_bytes += len(raw)
        digest = hashlib.sha256(raw).hexdigest()
        content_hash = f"sha256:{digest}"
        text, text_encoding = _decode_text(raw)
        contents_by_path[entry.path] = text
        language = language_for_path(entry.path)
        try:
            parsed = _extract_file(entry.path, text)
            extracted = parsed["extracted"]
            operational = parsed["operational"]
        except Exception as exc:
            extracted = parse_failed_result(language, exc)
            operational = empty_operational_structure(
                entry.path, status="parse_failed", error=error_code(exc)
            )

        if policy.content_mode == "structure":
            operational = sanitize_operational_structure(operational)

        blob_path: str | None = None
        source_content_included = policy.content_mode == "full"
        if source_content_included:
            blob_path = f"code/blobs/sha256/{digest}"
            if digest not in blobs_written:
                target = blob_root / digest
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                blobs_written.add(digest)
                included_blob_bytes += len(raw)

        base.update(
            {
                "capture_status": "captured",
                "omit_reason": None,
                "content_hash": content_hash,
                "blob_path": blob_path,
                "source_content_included": source_content_included,
                "text_encoding": text_encoding,
                "language": extracted.get("language"),
                "parse": extracted.get("parse"),
                "syntax": extracted.get("syntax"),
                "operational_structure": operational,
            }
        )
        file_records.append(base)
        operational_records.extend(operational_records_for_file(base))

    _compose_julia_bounded(file_records, contents_by_path)
    if policy.content_mode == "structure":
        for record in file_records:
            sanitize_syntax_for_structure_mode(record.get("syntax"))

    status_counts = Counter(str(record.get("capture_status")) for record in file_records)
    parse_counts = Counter(
        str((record.get("parse") or {}).get("status"))
        for record in file_records
        if isinstance(record.get("parse"), dict)
    )
    snapshot = {
        "schema_version": REPOSITORY_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "repo_id": repo_id,
        "repository_fingerprint": repo_id,
        "repo_hint": repo_summary.get("repo_hint"),
        "repo_path_hash": repo_summary.get("repo_path_hash"),
        "name": snapshot_spec.name,
        "requested_ref": snapshot_spec.ref,
        "resolved_commit": commit,
        "git_tree": tree_oid,
        "parent_commits": parents,
        "snapshot_kind": "committed_git_tree",
        "dirty_overlay": False,
        "worktree_dirty_at_collection": bool(repo_summary.get("dirty")),
        "tracked_entry_count": len(entries),
        "captured_file_count": status_counts.get("captured", 0),
        "omitted_file_count": status_counts.get("omitted", 0),
        "captured_bytes": captured_bytes,
        "source_blob_bytes_written": included_blob_bytes,
        "content_mode": policy.content_mode,
        "parser_limits": {"wall_seconds_per_operation": PARSER_TIMEOUT_SECONDS,
                          "posix_address_space_bytes": PARSER_MEMORY_BYTES},
        "observed_at": observed_at,
    }
    return {
        "snapshot": snapshot,
        "files": file_records,
        "operational_records": operational_records,
        "summary": {
            "name": snapshot_spec.name,
            "requested_ref": snapshot_spec.ref,
            "resolved_commit": commit,
            "snapshot_id": snapshot_id,
            "status": "collected",
            "tracked_entries": len(entries),
            "captured_files": status_counts.get("captured", 0),
            "omitted_files": status_counts.get("omitted", 0),
            "parse_status_counts": dict(sorted(parse_counts.items())),
        },
    }


def _base_file_record(
    *, repo_id: str, snapshot_id: str, entry: TreeEntry, observed_at: str
) -> dict[str, object]:
    return {
        "schema_version": REPOSITORY_FILE_SCHEMA_VERSION,
        "file_id": _file_id(snapshot_id, entry.path, entry.object_id),
        "repo_id": repo_id,
        "snapshot_id": snapshot_id,
        "path": entry.path,
        "git_mode": entry.mode,
        "git_object_type": entry.object_type,
        "git_blob_oid": entry.object_id if entry.object_type == "blob" else None,
        "size_bytes": entry.size,
        "observed_at": observed_at,
    }


def _omitted_fields(reason: str, *, path: str) -> dict[str, object]:
    return {
        "capture_status": "omitted",
        "omit_reason": reason,
        "content_hash": None,
        "blob_path": None,
        "source_content_included": False,
        "text_encoding": None,
        "language": language_for_path(path),
        "parse": {
            "status": "not_attempted",
            "has_error_nodes": False,
            "error_node_count": 0,
            "missing_node_count": 0,
        },
        "syntax": empty_syntax(),
        "operational_structure": empty_operational_structure(
            path,
            status="not_attempted",
            error=reason,
        ),
    }


def _pre_read_omit_reason(entry: TreeEntry, policy: SnapshotCapturePolicy) -> str | None:
    if entry.object_type == "commit" or entry.mode == "160000":
        return "submodule"
    if entry.object_type != "blob":
        return f"unsupported_git_object:{entry.object_type}"
    if entry.mode == "120000":
        return "symlink"
    if policy.include_globs and not _matches_any(entry.path, policy.include_globs):
        return "not_selected_by_include_glob"
    if policy.exclude_globs and _matches_any(entry.path, policy.exclude_globs):
        return "excluded_by_path_policy"
    if entry.size is not None and entry.size > policy.max_file_bytes:
        return "file_size_limit"
    return None


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    pure = PurePosixPath(path)
    return any(fnmatch.fnmatchcase(path, pattern) or pure.match(pattern) for pattern in patterns)


def _is_probably_text(raw: bytes) -> bool:
    if not raw:
        return True
    if b"\x00" in raw[:65536]:
        return False
    sample = raw[:65536]
    disallowed = sum(1 for value in sample if value < 32 and value not in {9, 10, 12, 13})
    return disallowed / max(1, len(sample)) < 0.02


def _decode_text(raw: bytes) -> tuple[str, str]:
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), "utf-8-replacement"


def _list_tree(repo: Path, commit: str) -> list[TreeEntry]:
    raw = _git_bytes(
        repo,
        ["ls-tree", "-r", "-z", "--long", "--full-tree", commit],
    )
    entries: list[TreeEntry] = []
    for record in raw.split(b"\x00"):
        if not record:
            continue
        header, separator, path_bytes = record.partition(b"\t")
        if not separator:
            raise ValueError("Unable to parse git ls-tree record")
        fields = header.decode("ascii", errors="replace").split()
        if len(fields) != 4:
            raise ValueError(f"Unexpected git ls-tree header: {header!r}")
        mode, object_type, object_id, size_text = fields
        size = None if size_text == "-" else int(size_text)
        path = path_bytes.decode("utf-8", errors="replace")
        entries.append(
            TreeEntry(
                mode=mode,
                object_type=object_type,
                object_id=object_id,
                size=size,
                path=path,
            )
        )
    return sorted(entries, key=lambda entry: entry.path)


def _extraction_manifest(
    *,
    observed_at: str,
    options: RepositorySnapshotOptions,
    snapshots: list[dict[str, object]],
    files: list[dict[str, object]],
    operational_records: list[dict[str, object]],
    repo_results: list[dict[str, object]],
    errors: list[str],
    outputs: dict[str, str],
    blobs_written: set[str],
    privacy_hasher: PrivacyHasher,
) -> dict[str, object]:
    capture_counts = Counter(str(record.get("capture_status")) for record in files)
    omit_counts = Counter(
        str(record.get("omit_reason"))
        for record in files
        if record.get("capture_status") == "omitted"
    )
    parse_counts = Counter(
        str(parse.get("status"))
        for record in files
        if isinstance((parse := record.get("parse")), dict)
    )
    languages = Counter(str(record.get("language")) for record in files if record.get("language"))
    reference_kinds: Counter[str] = Counter()
    files_with_references = 0
    reference_observations = 0
    for record in files:
        syntax = record.get("syntax")
        if not isinstance(syntax, dict):
            continue
        references = syntax.get("references")
        if not isinstance(references, list) or not references:
            continue
        files_with_references += 1
        for reference in references:
            if not isinstance(reference, dict):
                continue
            reference_observations += 1
            reference_kinds[str(reference.get("kind") or "unknown")] += 1
    operational_artifacts = Counter(
        str(structure.get("artifact_kind"))
        for record in files
        if isinstance((structure := record.get("operational_structure")), dict)
        and structure.get("artifact_kind")
    )
    operational_parse_counts = Counter(
        str(parse.get("status"))
        for record in files
        if isinstance((structure := record.get("operational_structure")), dict)
        and structure.get("artifact_kind")
        and isinstance((parse := structure.get("parse")), dict)
    )
    included_source_bytes = sum(
        int(record.get("size_bytes") or 0)
        for record in files
        if record.get("source_content_included") is True
    )
    return {
        "schema_version": EXTRACTION_MANIFEST_SCHEMA_VERSION,
        "collector": {"name": "shevek_collect", "version": __version__},
        "created_at": observed_at,
        "facet": "repository_snapshots",
        "settings": {
            "snapshot_kind": "committed_git_tree",
            "content_mode": options.policy.content_mode,
            "max_file_bytes": options.policy.max_file_bytes,
            "max_total_bytes": options.policy.max_total_bytes,
            "include_globs": list(options.policy.include_globs),
            "exclude_globs": list(options.policy.exclude_globs),
            "use_default_excludes": options.policy.use_default_excludes,
            "tracked_files_only": True,
            "untracked_files_included": False,
            # Committed entries can match .gitignore; ignore rules are not consulted.
            "ignored_files_included": None,
            "gitignore_applied": False,
            "git_history_database_included": False,
            "symlink_targets_followed": False,
            "submodule_contents_included": False,
            "operational_structure_extracted": True,
            "structure_export_policy": "allowlisted_fields_v1",
            "parser_wall_seconds_per_operation": PARSER_TIMEOUT_SECONDS,
            "parser_posix_address_space_bytes": PARSER_MEMORY_BYTES,
        },
        "syntax_observations_schema_version": SYNTAX_OBSERVATIONS_SCHEMA_VERSION,
        "parser": {
            "name": "tree-sitter",
            "version": _package_version("tree-sitter"),
            "grammars": {
                package: _package_version(package)
                for package in (
                    "tree-sitter-python",
                    "tree-sitter-javascript",
                    "tree-sitter-julia",
                    "tree-sitter-typescript",
                    "tree-sitter-java",
                    "tree-sitter-c-sharp",
                    "tree-sitter-cpp",
                    "tree-sitter-css",
                )
            },
        },
        "builtin_syntax_parsers": {
            "sql": "shevek_collect_sql_structure.v1",
        },
        "operational_parsers": {
            "dockerfile": "shevek_collect_builtin_v1",
            "bash": "shevek_collect_shlex_v1",
            "toml": "python.tomllib",
            "yaml": {
                "name": "PyYAML",
                "version": _package_version("PyYAML"),
            },
        },
        "counts": {
            "repos_requested": len(options.repos),
            "repos_collected": sum(
                1 for item in repo_results if item.get("snapshots_collected", 0)
            ),
            "snapshots_requested": sum(len(repo.snapshots) for repo in options.repos),
            "snapshots_collected": len(snapshots),
            "tracked_entries": len(files),
            "captured_files": capture_counts.get("captured", 0),
            "omitted_files": capture_counts.get("omitted", 0),
            "parsed_files": parse_counts.get("parsed", 0)
            + parse_counts.get("parsed_with_errors", 0),
            "parse_error_files": parse_counts.get("parsed_with_errors", 0)
            + parse_counts.get("parse_failed", 0),
            "parser_unavailable_files": parse_counts.get("parser_unavailable", 0),
            "unique_source_blobs": len(blobs_written),
            "source_bytes_included": included_source_bytes,
            "capture_status_counts": dict(sorted(capture_counts.items())),
            "omit_reason_counts": dict(sorted(omit_counts.items())),
            "parse_status_counts": dict(sorted(parse_counts.items())),
            "language_counts": dict(sorted(languages.items())),
            "files_with_references": files_with_references,
            "reference_observations": reference_observations,
            "reference_kind_counts": dict(sorted(reference_kinds.items())),
            "operational_records": len(operational_records),
            "operational_artifact_counts": dict(sorted(operational_artifacts.items())),
            "operational_parse_status_counts": dict(
                sorted(operational_parse_counts.items())
            ),
        },
        "repositories": repo_results,
        "outputs": outputs,
        "identity": privacy_hasher.manifest_metadata(),
        "privacy": {
            "contains_file_content": options.policy.content_mode == "full",
            "contains_source_structure": True,
            "contains_operational_structure": True,
            "contains_verbatim_signatures": options.policy.content_mode == "full",
            "contains_verbatim_parameter_text": options.policy.content_mode == "full",
            "contains_raw_import_text": options.policy.content_mode == "full",
            "operational_literal_values_omitted": options.policy.content_mode == "structure",
            "parser_error_source_excerpts_included": False,
            "contains_paths": True,
            "contains_git_history_database": False,
            "contains_historical_file_content": options.policy.content_mode == "full"
            and any(str(snapshot.get("requested_ref")) != "HEAD" for snapshot in snapshots),
            "contains_untracked_files": False,
            "contains_ignored_files": None,
            "gitignore_applied": False,
            "contains_symlink_targets": False,
            "contains_submodule_content": False,
            "content_mode": options.policy.content_mode,
            "secret_scanning": "not_performed",
            "encryption": "not_applied_to_local_directory_bundle",
        },
        "errors": errors,
    }


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _snapshot_id(repo_id: str, commit: str, name: str) -> str:
    digest = hashlib.sha256(
        f"shevek.repository_snapshot.v1\n{repo_id}\n{commit}\n{name}".encode("utf-8")
    ).hexdigest()
    return f"snapshot_{digest[:24]}"


def _file_id(snapshot_id: str, path: str, object_id: str) -> str:
    digest = hashlib.sha256(
        f"shevek.repository_file.v1\n{snapshot_id}\n{path}\n{object_id}".encode(
            "utf-8", errors="surrogateescape"
        )
    ).hexdigest()
    return f"file_{digest[:24]}"


def _repo_label(path: Path, *, privacy_hasher: PrivacyHasher) -> str:
    expanded = path.expanduser().resolve()
    return privacy_hasher.local_repository_id(expanded.as_posix())


def _validate_git_repo(repo: Path) -> None:
    if not repo.exists():
        raise FileNotFoundError(f"Repository path does not exist: {repo}")
    if _git_text(repo, ["rev-parse", "--is-inside-work-tree"]).strip() != "true":
        raise ValueError(f"Not a git work tree: {repo}")


def _git_text(repo: Path, args: Sequence[str]) -> str:
    raw = _git_bytes(repo, args)
    return raw.decode("utf-8", errors="replace")


def _git_bytes(repo: Path, args: Sequence[str]) -> bytes:
    proc = run_git(repo, args, text=False)
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", errors="replace").strip()
        if not message:
            message = proc.stdout.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {message or 'git command failed'}")
    return proc.stdout


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _extract_file(path: str, content: str) -> dict:
    return run_parser("file", {"path": path, "content": content})


def _compose_julia_bounded(records: list[dict[str, object]], contents: dict[str, str]) -> None:
    selected = [record for record in records
                if record.get("language") == "julia" or PurePosixPath(str(record.get("path"))).name == "Project.toml"]
    if not any(record.get("language") == "julia" for record in selected):
        return
    paths = {str(record.get("path")) for record in selected}
    try:
        result = run_parser("julia_composition", {
            "records": selected,
            "contents": {path: content for path, content in contents.items() if path in paths},
        })
        by_path = {record["path"]: record for record in result["records"]}
        for record in selected:
            record.update(by_path[record["path"]])
    except Exception as exc:
        for record in selected:
            if record.get("language") == "julia":
                parse = record.get("parse")
                if isinstance(parse, dict):
                    parse["composition_status"] = "failed"
                    parse["composition_error"] = error_code(exc)
