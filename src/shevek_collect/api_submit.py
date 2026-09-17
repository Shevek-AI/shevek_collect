from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request

from .filesystem import (
    FileSafetyError, destination_path, destination_lock, open_regular,
    path_state, publish_staged, regular_file_in,
)
from .http_security import (
    multipart_filename, read_response, secure_urlopen, validate_https_url,
)
from .io_utils import validate_bundle


DEFAULT_API_URL = "https://api.shevek.ai"
DEFAULT_API_ENDPOINT_ENV = "SHEVEK_API_ENDPOINT"
DEFAULT_TOKEN_ENV = "SHEVEK_SERVICE_TOKEN"
SUBMIT_COMMIT_STATE_FILENAME = ".shevek_submit_commits.json"
ANALYSIS_DEPTHS = ("smoke", "demo", "standard", "deep")


class ApiSubmissionError(RuntimeError):
    """Raised when a collect bundle cannot be prepared or submitted."""


def jobs_from_bundle(
    bundle_dir: Path, *, analysis_depth: str | None = None
) -> list[dict[str, str]]:
    """Derive backend jobs mechanically from the facets present in a collect bundle."""
    if analysis_depth is not None and analysis_depth not in ANALYSIS_DEPTHS:
        allowed = ", ".join(ANALYSIS_DEPTHS)
        raise ApiSubmissionError(
            f"Invalid analysis depth {analysis_depth!r}; expected one of: {allowed}"
        )
    manifest_path = bundle_dir / "collect_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ApiSubmissionError(f"Collect manifest not found: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise ApiSubmissionError(f"Invalid collect manifest JSON: {manifest_path}") from exc

    if not manifest.get("complete", False):
        raise ApiSubmissionError("Refusing to submit an incomplete collect bundle")

    jobs: list[dict[str, str]] = []
    seen_repo_ids: set[str] = set()
    repository_results = manifest.get("repository_results") or []
    if isinstance(repository_results, list):
        for item in repository_results:
            if not isinstance(item, Mapping) or item.get("source_kind") != "repository_snapshot":
                continue
            if item.get("status") != "complete":
                continue
            repo_id = item.get("repo_id")
            if not isinstance(repo_id, str) or not repo_id or repo_id in seen_repo_ids:
                continue
            repo_hint = item.get("repo_hint")
            display_hint = repo_hint if isinstance(repo_hint, str) and repo_hint else repo_id
            trace_job = {
                "job": "trace",
                "repo_id": repo_id,
                "display_name": f"Trace: {display_hint}",
            }
            if analysis_depth is not None:
                trace_job["analysis_depth"] = analysis_depth
            jobs.append(trace_job)
            seen_repo_ids.add(repo_id)

    facets = manifest.get("facets") or {}
    activity = facets.get("activity") if isinstance(facets, Mapping) else None
    if isinstance(activity, Mapping) and activity.get("enabled"):
        jobs.append({"job": "catalogue", "display_name": "Catalogue: Shevek activity"})

    if not jobs:
        raise ApiSubmissionError("No Trace or Catalogue jobs could be derived from the bundle")
    return jobs




def submission_manifest_from_bundle(bundle_dir: Path) -> dict[str, object]:
    """Build backend reconciliation metadata for every repository represented by the bundle.

    This is intentionally independent of the filtered jobs list: repositories skipped by
    --skip-unchanged remain present so the backend can reconcile them to prior Trace runs.
    """
    manifest_path = bundle_dir / "collect_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ApiSubmissionError(f"Collect manifest not found: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise ApiSubmissionError(f"Invalid collect manifest JSON: {manifest_path}") from exc

    if not manifest.get("complete", False):
        raise ApiSubmissionError("Refusing to derive submission manifest from an incomplete collect bundle")

    hints: dict[str, str] = {}
    repository_results = manifest.get("repository_results") or []
    if isinstance(repository_results, list):
        for item in repository_results:
            if not isinstance(item, Mapping) or item.get("source_kind") != "repository_snapshot":
                continue
            if item.get("status") != "complete":
                continue
            repo_id = item.get("repo_id")
            repo_hint = item.get("repo_hint")
            if isinstance(repo_id, str) and repo_id and isinstance(repo_hint, str) and repo_hint:
                hints.setdefault(repo_id, repo_hint)

    commits = _collected_snapshot_commits(bundle_dir, manifest)
    repo_ids = set(hints) | set(commits)
    repositories: list[dict[str, object]] = []
    for repo_id in sorted(repo_ids):
        row: dict[str, object] = {
            "repo_id": repo_id,
            "resolved_commits": sorted(commits.get(repo_id, set())),
        }
        if repo_id in hints:
            row["repo_hint"] = hints[repo_id]
        repositories.append(row)

    facets = manifest.get("facets") or {}
    activity = facets.get("activity") if isinstance(facets, Mapping) else None
    catalogue_included = bool(isinstance(activity, Mapping) and activity.get("enabled"))

    return {
        "version": 1,
        "repositories": repositories,
        "catalogue_included": catalogue_included,
    }

def load_submit_commit_state(
    bundle_dir: Path,
    project_id: str | None = None,
) -> dict[str, set[str]]:
    """Load Trace commit hashes for one project submission namespace.

    Version 1 state is treated as unprojected legacy history. It is deliberately
    not reused for a configured project because its project ownership is unknowable.
    """
    store = load_submit_commit_state_store(bundle_dir)
    repos: object
    if project_id is None:
        unprojected = store.get("unprojected", {})
        repos = unprojected.get("repos", {}) if isinstance(unprojected, Mapping) else {}
    else:
        projects = store.get("projects", {})
        project = projects.get(project_id, {}) if isinstance(projects, Mapping) else {}
        repos = project.get("repos", {}) if isinstance(project, Mapping) else {}
    return _decode_repo_commit_state(repos)


def load_submit_commit_state_store(bundle_dir: Path) -> dict[str, object]:
    """Load and normalize the complete local submission state to version 2."""
    path = bundle_dir.expanduser().resolve() / SUBMIT_COMMIT_STATE_FILENAME
    if not path.exists():
        return {"version": 2, "projects": {}, "unprojected": {"repos": {}}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApiSubmissionError(f"Invalid submit commit state: {path}") from exc
    if not isinstance(raw, Mapping):
        raise ApiSubmissionError(f"Invalid submit commit state: {path}")

    version = raw.get("version", 1)
    if version == 1:
        # Existing files predate project identity. Preserve them only in the
        # unprojected namespace; never guess which backend project they belong to.
        repos = raw.get("repos", {})
        normalized = _encode_repo_commit_state(_decode_repo_commit_state(repos))
        return {
            "version": 2,
            "projects": {},
            "unprojected": {"repos": normalized},
        }
    if version != 2:
        raise ApiSubmissionError(f"Unsupported submit commit state version {version!r}: {path}")

    projects_raw = raw.get("projects", {})
    unprojected_raw = raw.get("unprojected", {})
    if not isinstance(projects_raw, Mapping) or not isinstance(unprojected_raw, Mapping):
        raise ApiSubmissionError(f"Invalid submit commit state: {path}")

    projects: dict[str, object] = {}
    for project_id, project_state in projects_raw.items():
        if not isinstance(project_id, str) or not project_id or not isinstance(project_state, Mapping):
            continue
        projects[project_id] = {
            "repos": _encode_repo_commit_state(
                _decode_repo_commit_state(project_state.get("repos", {}))
            )
        }
    return {
        "version": 2,
        "projects": projects,
        "unprojected": {
            "repos": _encode_repo_commit_state(
                _decode_repo_commit_state(unprojected_raw.get("repos", {}))
            )
        },
    }


def write_submit_commit_state_store(bundle_dir: Path, store: Mapping[str, object]) -> Path:
    """Persist a complete normalized local submission state store."""
    path = bundle_dir.expanduser().resolve() / SUBMIT_COMMIT_STATE_FILENAME
    path.write_text(json.dumps(dict(store), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_submit_commit_state(
    bundle_dir: Path,
    state: Mapping[str, set[str]],
    project_id: str | None = None,
) -> Path:
    """Persist Trace commit history for one project namespace after a successful submission."""
    store = load_submit_commit_state_store(bundle_dir)
    encoded = _encode_repo_commit_state(state)
    if project_id is None:
        store["unprojected"] = {"repos": encoded}
    else:
        projects = store.setdefault("projects", {})
        assert isinstance(projects, dict)
        projects[project_id] = {"repos": encoded}
    return write_submit_commit_state_store(bundle_dir, store)


def _decode_repo_commit_state(repos: object) -> dict[str, set[str]]:
    if not isinstance(repos, Mapping):
        return {}
    state: dict[str, set[str]] = {}
    for repo_id, commits in repos.items():
        if not isinstance(repo_id, str):
            continue
        if isinstance(commits, list):
            values = {value for value in commits if isinstance(value, str) and value}
        elif isinstance(commits, Mapping):
            # Accept the single resolved_commit shape proposed for early v2 files.
            resolved = commits.get("resolved_commit")
            values = {resolved} if isinstance(resolved, str) and resolved else set()
        else:
            continue
        if values:
            state[repo_id] = values
    return state


def _encode_repo_commit_state(state: Mapping[str, set[str]]) -> dict[str, list[str]]:
    return {repo_id: sorted(commits) for repo_id, commits in sorted(state.items()) if commits}

def filter_unchanged_trace_jobs(
    bundle_dir: Path,
    jobs: list[dict[str, str]],
    submitted_commits: Mapping[str, set[str]],
) -> tuple[list[dict[str, str]], dict[str, set[str]], list[dict[str, object]]]:
    """Omit Trace jobs whose collected commit set has already been submitted."""
    manifest_path = bundle_dir / "collect_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApiSubmissionError(f"Could not read collect manifest for commit tracking: {manifest_path}") from exc

    current = _collected_snapshot_commits(bundle_dir, manifest)

    filtered: list[dict[str, str]] = []
    skipped: list[dict[str, object]] = []
    for job in jobs:
        if job.get("job") != "trace":
            filtered.append(job)
            continue
        repo_id = job.get("repo_id")
        commits = current.get(repo_id or "", set())
        previous = submitted_commits.get(repo_id or "", set())
        if commits and commits.issubset(previous):
            skipped.append({
                "repo_id": repo_id,
                "display_name": job.get("display_name"),
                "commits": sorted(commits),
            })
            continue
        filtered.append(job)
    return filtered, current, skipped



def _collected_snapshot_commits(
    bundle_dir: Path, manifest: Mapping[str, object]
) -> dict[str, set[str]]:
    """Read the exact repo/commit pairs captured in the repository snapshot facet."""
    facets = manifest.get("facets")
    snapshot_facet = (
        facets.get("repository_snapshots")
        if isinstance(facets, Mapping)
        else None
    )
    if not isinstance(snapshot_facet, Mapping) or not snapshot_facet.get("enabled"):
        return {}

    snapshots_rel = snapshot_facet.get("snapshots")
    if not isinstance(snapshots_rel, str) or not snapshots_rel:
        snapshots_rel = "code/snapshots.jsonl"
    snapshots_path = regular_file_in(bundle_dir, snapshots_rel)
    try:
        lines = snapshots_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ApiSubmissionError(
            f"Could not read repository snapshots for commit tracking: {snapshots_path}"
        ) from exc

    current: dict[str, set[str]] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            snapshot = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ApiSubmissionError(
                f"Invalid repository snapshot JSON at {snapshots_path}:{line_number}"
            ) from exc
        if not isinstance(snapshot, Mapping):
            continue
        repo_id = snapshot.get("repo_id")
        commit = snapshot.get("resolved_commit")
        if isinstance(repo_id, str) and repo_id and isinstance(commit, str) and commit:
            current.setdefault(repo_id, set()).add(commit)
    return current

def merge_submitted_trace_commits(
    previous: Mapping[str, set[str]],
    current: Mapping[str, set[str]],
    submitted_jobs: list[dict[str, str]],
) -> dict[str, set[str]]:
    """Return commit history updated only for Trace jobs that were successfully submitted."""
    merged = {repo_id: set(commits) for repo_id, commits in previous.items()}
    for job in submitted_jobs:
        if job.get("job") != "trace":
            continue
        repo_id = job.get("repo_id")
        if isinstance(repo_id, str) and repo_id in current:
            merged.setdefault(repo_id, set()).update(current[repo_id])
    return merged

def zip_bundle(bundle_dir: Path, zip_path: Path, *, overwrite: bool = False) -> Path:
    """Archive only declared records and referenced blobs, using private staging."""
    try:
        bundle_dir = destination_path(bundle_dir)
        zip_path = destination_path(zip_path)
        if zip_path == bundle_dir or bundle_dir in zip_path.parents:
            raise ApiSubmissionError("ZIP destination must be outside the bundle")
        manifest = validate_bundle(bundle_dir)
        outputs = manifest["outputs"]
        assert isinstance(outputs, dict)
        members = {"collect_manifest.json", *outputs.values()}
        members.discard(SUBMIT_COMMIT_STATE_FILENAME)
        # Undeclared files are never uploaded. Reject links/nonregular objects
        # anywhere in the supplied tree instead of silently accepting a trap.
        for candidate in bundle_dir.rglob("*"):
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ApiSubmissionError("Bundle contains a symlink or nonregular member")
        files_relative = outputs.get("repository_files")
        if files_relative:
            with open_regular(regular_file_in(bundle_dir, files_relative)) as records:
                for line in records:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ApiSubmissionError("Invalid repository file record")
                    blob = row.get("blob_path")
                    if blob is None:
                        continue
                    if not isinstance(blob, str):
                        raise ApiSubmissionError("Invalid blob path")
                    match = re.fullmatch(r"code/blobs/sha256/([0-9a-f]{64})", blob)
                    if not match or row.get("content_hash") != "sha256:" + match.group(1):
                        raise ApiSubmissionError("Invalid content-addressed blob reference")
                    members.add(blob)
        with destination_lock(zip_path):
            expected = path_state(zip_path)
            if expected is not None:
                if not zip_path.is_file() or zip_path.is_symlink():
                    raise ApiSubmissionError("ZIP destination must be a regular file")
                if not overwrite:
                    raise ApiSubmissionError("ZIP already exists; pass --overwrite-zip to replace it")
            descriptor, temporary = tempfile.mkstemp(prefix=f".{zip_path.name}.staging-", dir=zip_path.parent)
            stage = Path(temporary)
            try:
                with os.fdopen(descriptor, "w+b") as output:
                    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                        for relative in sorted(members):
                            path = regular_file_in(bundle_dir, relative)
                            with open_regular(path) as source, archive.open(relative, "w") as dest:
                                digest = hashlib.sha256()
                                while chunk := source.read(1024 * 1024):
                                    digest.update(chunk)
                                    dest.write(chunk)
                                if relative.startswith("code/blobs/sha256/") and digest.hexdigest() != path.name:
                                    raise ApiSubmissionError("Source blob failed its content hash check")
                    output.flush()
                    os.fsync(output.fileno())
                publish_staged(stage, zip_path, expected)
            finally:
                stage.unlink(missing_ok=True)
    except (FileSafetyError, OSError, ValueError) as exc:
        raise ApiSubmissionError(f"Could not create bundle ZIP safely: {type(exc).__name__}") from exc
    return zip_path


def submit_bundle(
    *,
    zip_path: Path,
    jobs: list[dict[str, str]],
    submission_manifest: Mapping[str, object] | None = None,
    project_id: str | None = None,
    api_endpoint: str | None = None,
    token: str | None = None,
    token_env: str = DEFAULT_TOKEN_ENV,
    endpoint_env: str = DEFAULT_API_ENDPOINT_ENV,
    timeout_seconds: float = 120.0,
    opener: Callable[..., object] = secure_urlopen,
    log: Callable[[str], None] | None = None,
) -> dict[str, object]:
    effective_token = token or os.environ.get(token_env)
    if not effective_token:
        raise ApiSubmissionError(
            f"No API token supplied; use --token or set environment variable {token_env}"
        )

    api_base = api_endpoint or os.environ.get(endpoint_env) or DEFAULT_API_URL
    endpoint = _jobs_endpoint(api_base)
    body, content_type = _multipart_body(
        zip_path=zip_path, jobs=jobs, submission_manifest=submission_manifest, project_id=project_id
    )
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {effective_token}",
            "Content-Type": content_type,
            "Accept": "application/json",
        },
    )
    if log is not None:
        log("POST request:")
        log(f"  endpoint: {endpoint}")
        log(f"  bundle: {zip_path}")
        log(f"  authorization: Bearer <redacted>")
        log(f"  jobs: {json.dumps(jobs, indent=2)}")
        if submission_manifest is not None:
            log(f"  submission_manifest: {json.dumps(submission_manifest, indent=2)}")
        if project_id is not None:
            log(f"  project_id: {project_id}")

    try:
        response = opener(request, timeout=timeout_seconds)
        try:
            raw = read_response(response)
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()
        status = getattr(response, "status", None)
        if status is None and hasattr(response, "getcode"):
            status = response.getcode()
        if log is not None:
            log("POST response:")
            log(f"  status: {status if status is not None else 'unknown'}")
            log(f"  body: <omitted; {len(raw)} bytes>")
    except HTTPError as exc:
        detail = "redirect_refused" if 300 <= exc.code < 400 else "backend_request_failed"
        exc.close()
        if log is not None:
            log("POST response:")
            log(f"  status: {exc.code}")
            log(f"  body: {detail or str(exc.reason)}")
        raise ApiSubmissionError(
            f"Backend returned HTTP {exc.code}: {detail or exc.reason}"
        ) from exc
    except URLError as exc:
        if log is not None:
            log("POST response:")
            log("  status: connection failed")
            log("  body: connection_failed")
        raise ApiSubmissionError("Could not reach Shevek API") from None

    if not raw:
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiSubmissionError("Backend returned a non-JSON response") from exc
    if isinstance(parsed, dict):
        return parsed
    return {"response": parsed}


def submit_alignment(
    *,
    project_id: str,
    priorities_path: Path,
    api_endpoint: str | None = None,
    token: str | None = None,
    token_env: str = DEFAULT_TOKEN_ENV,
    endpoint_env: str = DEFAULT_API_ENDPOINT_ENV,
    timeout_seconds: float = 120.0,
    opener: Callable[..., object] = secure_urlopen,
    log: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Launch Alignment after the bundle jobs have been requested.

    The backend binds Alignment to the project's most recent group, so this
    request intentionally sends only project_id and priorities and must be
    issued after the /jobs/bundle request has completed successfully.
    """
    effective_token = token or os.environ.get(token_env)
    if not effective_token:
        raise ApiSubmissionError(
            f"No API token supplied; use --token or set environment variable {token_env}"
        )

    normalized_project_id = project_id.strip()
    if not normalized_project_id:
        raise ApiSubmissionError("Alignment submission requires a non-empty project_id")

    priorities_path = priorities_path.expanduser().resolve()
    try:
        priorities = priorities_path.read_bytes()
    except OSError as exc:
        raise ApiSubmissionError(
            f"Could not read Alignment priorities file: {priorities_path}"
        ) from exc

    api_base = api_endpoint or os.environ.get(endpoint_env) or DEFAULT_API_URL
    endpoint = _alignment_endpoint(api_base)
    body, content_type = _alignment_multipart_body(
        project_id=normalized_project_id,
        priorities=priorities,
        priorities_filename=priorities_path.name,
    )
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {effective_token}",
            "Content-Type": content_type,
            "Accept": "application/json",
        },
    )
    if log is not None:
        log("Alignment POST request:")
        log(f"  endpoint: {endpoint}")
        log("  authorization: Bearer <redacted>")
        log(f"  project_id: {normalized_project_id}")
        log(f"  priorities: {priorities_path}")

    try:
        response = opener(request, timeout=timeout_seconds)
        try:
            raw = read_response(response)
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()
        status = getattr(response, "status", None)
        if status is None and hasattr(response, "getcode"):
            status = response.getcode()
        if log is not None:
            log("Alignment POST response:")
            log(f"  status: {status if status is not None else 'unknown'}")
            log(f"  body: <omitted; {len(raw)} bytes>")
    except HTTPError as exc:
        detail = "redirect_refused" if 300 <= exc.code < 400 else "backend_request_failed"
        exc.close()
        if log is not None:
            log("Alignment POST response:")
            log(f"  status: {exc.code}")
            log(f"  body: {detail or str(exc.reason)}")
        raise ApiSubmissionError(
            f"Alignment backend returned HTTP {exc.code}: {detail or exc.reason}"
        ) from exc
    except URLError as exc:
        if log is not None:
            log("Alignment POST response:")
            log("  status: connection failed")
            log("  body: connection_failed")
        raise ApiSubmissionError("Could not reach Shevek API for Alignment") from None

    if not raw:
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiSubmissionError("Alignment backend returned a non-JSON response") from exc
    if isinstance(parsed, dict):
        return parsed
    return {"response": parsed}


def _jobs_endpoint(api_endpoint: str) -> str:
    value = api_endpoint.strip().rstrip("/")
    try:
        validate_https_url(value, allow_query=False)
    except ValueError as exc:
        raise ApiSubmissionError(str(exc)) from None
    if not value:
        raise ApiSubmissionError("Shevek API endpoint is empty")
    if value.endswith("/jobs/bundle"):
        return value
    return value + "/jobs/bundle"


def _alignment_endpoint(api_endpoint: str) -> str:
    value = api_endpoint.strip().rstrip("/")
    try:
        validate_https_url(value, allow_query=False)
    except ValueError as exc:
        raise ApiSubmissionError(str(exc)) from None
    if not value:
        raise ApiSubmissionError("Shevek API endpoint is empty")
    if value.endswith("/jobs/alignment"):
        return value
    if value.endswith("/jobs/bundle"):
        value = value[: -len("/jobs/bundle")]
    return value + "/jobs/alignment"


def _multipart_body(
    *,
    zip_path: Path,
    jobs: list[dict[str, str]],
    submission_manifest: Mapping[str, object] | None = None,
    project_id: str | None = None,
) -> tuple[bytes, str]:
    boundary = f"----shevek-collect-{uuid.uuid4().hex}"
    chunks: list[bytes] = []

    def field(name: str, value: bytes, *, filename: str | None = None, content_type: str | None = None) -> None:
        chunks.append(f"--{boundary}\r\n".encode())
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{multipart_filename(filename)}"'
        chunks.append((disposition + "\r\n").encode())
        if content_type is not None:
            chunks.append(f"Content-Type: {content_type}\r\n".encode())
        chunks.append(b"\r\n")
        chunks.append(value)
        chunks.append(b"\r\n")

    field(
        "bundle",
        zip_path.read_bytes(),
        filename=zip_path.name,
        content_type="application/zip",
    )
    field("jobs", json.dumps(jobs, separators=(",", ":")).encode("utf-8"), content_type="application/json")
    if submission_manifest is not None:
        field(
            "submission_manifest",
            json.dumps(submission_manifest, separators=(",", ":")).encode("utf-8"),
            content_type="application/json",
        )
    if project_id is not None and project_id.strip():
        field("project_id", project_id.strip().encode("utf-8"))
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _alignment_multipart_body(
    *,
    project_id: str,
    priorities: bytes,
    priorities_filename: str,
) -> tuple[bytes, str]:
    boundary = f"----shevek-collect-{uuid.uuid4().hex}"
    chunks: list[bytes] = []

    def field(
        name: str,
        value: bytes,
        *,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> None:
        chunks.append(f"--{boundary}\r\n".encode())
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{multipart_filename(filename)}"'
        chunks.append((disposition + "\r\n").encode())
        if content_type is not None:
            chunks.append(f"Content-Type: {content_type}\r\n".encode())
        chunks.append(b"\r\n")
        chunks.append(value)
        chunks.append(b"\r\n")

    field("project_id", project_id.encode("utf-8"))
    field(
        "priorities",
        priorities,
        filename=priorities_filename,
        content_type="text/plain",
    )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"
