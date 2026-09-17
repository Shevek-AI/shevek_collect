from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from bundle_fixtures import seal_bundle

from shevek_collect.api_submit import ApiSubmissionError, jobs_from_bundle, zip_bundle


def test_jobs_from_bundle_derives_trace_jobs_and_catalogue(tmp_path: Path) -> None:
    (tmp_path / "collect_manifest.json").write_text(
        json.dumps(
            {
                "complete": True,
                "facets": {"activity": {"enabled": True}},
                "repository_results": [
                    {
                        "source_kind": "repository_snapshot",
                        "repo_id": "repo_v2_one",
                        "repo_hint": "example-app",
                        "status": "complete",
                    },
                    {
                        "source_kind": "repository_snapshot",
                        "repo_id": "repo_v2_two",
                        "repo_hint": "shevek_trace",
                        "status": "complete",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    assert jobs_from_bundle(tmp_path) == [
        {"job": "trace", "repo_id": "repo_v2_one", "display_name": "Trace: example-app"},
        {"job": "trace", "repo_id": "repo_v2_two", "display_name": "Trace: shevek_trace"},
        {"job": "catalogue", "display_name": "Catalogue: Shevek activity"},
    ]


def test_jobs_from_bundle_adds_analysis_depth_only_to_trace_jobs(tmp_path: Path) -> None:
    (tmp_path / "collect_manifest.json").write_text(
        json.dumps(
            {
                "complete": True,
                "facets": {"activity": {"enabled": True}},
                "repository_results": [
                    {
                        "source_kind": "repository_snapshot",
                        "repo_id": "repo_v2_one",
                        "repo_hint": "shevek_trace",
                        "status": "complete",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert jobs_from_bundle(tmp_path, analysis_depth="deep") == [
        {
            "job": "trace",
            "repo_id": "repo_v2_one",
            "display_name": "Trace: shevek_trace",
            "analysis_depth": "deep",
        },
        {"job": "catalogue", "display_name": "Catalogue: Shevek activity"},
    ]


def test_jobs_from_bundle_refuses_incomplete_bundle(tmp_path: Path) -> None:
    (tmp_path / "collect_manifest.json").write_text(
        json.dumps({"complete": False}), encoding="utf-8"
    )
    with pytest.raises(ApiSubmissionError, match="incomplete"):
        jobs_from_bundle(tmp_path)


def test_zip_bundle_places_bundle_contents_at_zip_root(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "code").mkdir(parents=True)
    (bundle / "collect_manifest.json").write_text("{}", encoding="utf-8")
    (bundle / "code" / "files.jsonl").write_text("", encoding="utf-8")

    seal_bundle(bundle)
    archive_path = zip_bundle(bundle, tmp_path / "bundle.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.namelist() == ["code/files.jsonl", "collect_manifest.json"]


def test_submit_bundle_uses_endpoint_env_and_logs_request_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shevek_collect.api_submit import submit_bundle

    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"zip")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "env-token")
    monkeypatch.setenv("SHEVEK_API_ENDPOINT", "https://example.test/api")
    messages: list[str] = []
    captured: dict[str, object] = {}

    class Response:
        status = 201

        def read(self, size: int = -1) -> bytes:
            return b'{"group_id":"group-1"}'

    def opener(request: object, timeout: float) -> Response:
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["authorization"] = request.headers["Authorization"]  # type: ignore[attr-defined]
        captured["timeout"] = timeout
        return Response()

    result = submit_bundle(
        zip_path=zip_path,
        jobs=[{"job": "catalogue", "display_name": "Catalogue: Shevek activity"}],
        opener=opener,
        log=messages.append,
    )

    assert captured["url"] == "https://example.test/api/jobs/bundle"
    assert captured["authorization"] == "Bearer env-token"
    assert result == {"group_id": "group-1"}
    log_text = "\n".join(messages)
    assert "POST request:" in log_text
    assert "https://example.test/api/jobs/bundle" in log_text
    assert "Bearer <redacted>" in log_text
    assert "env-token" not in log_text
    assert "POST response:" in log_text
    assert "status: 201" in log_text
    assert '{"group_id":"group-1"}' not in log_text
    assert "body: <omitted;" in log_text


def test_submit_bundle_cli_values_override_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shevek_collect.api_submit import submit_bundle

    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"zip")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "env-token")
    monkeypatch.setenv("SHEVEK_API_ENDPOINT", "https://env.example")
    captured: dict[str, object] = {}

    class Response:
        status = 200

        def read(self, size: int = -1) -> bytes:
            return b"{}"

    def opener(request: object, timeout: float) -> Response:
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["authorization"] = request.headers["Authorization"]  # type: ignore[attr-defined]
        return Response()

    submit_bundle(
        zip_path=zip_path,
        jobs=[{"job": "catalogue", "display_name": "Catalogue: Shevek activity"}],
        api_endpoint="https://cli.example/jobs/bundle",
        token="cli-token",
        opener=opener,
    )

    assert captured["url"] == "https://cli.example/jobs/bundle"
    assert captured["authorization"] == "Bearer cli-token"


def test_submit_alignment_posts_project_and_priorities_after_bundle_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shevek_collect.api_submit import submit_alignment

    priorities = tmp_path / "priorities.md"
    priorities.write_text("# Priorities\n\nShip architecture visibility.\n", encoding="utf-8")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "env-token")
    captured: dict[str, object] = {}

    class Response:
        status = 201

        def read(self, size: int = -1) -> bytes:
            return b'{"job_id":"align-1"}'

    def opener(request: object, timeout: float) -> Response:
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["authorization"] = request.headers["Authorization"]  # type: ignore[attr-defined]
        captured["body"] = request.data  # type: ignore[attr-defined]
        return Response()

    result = submit_alignment(
        project_id="project-1",
        priorities_path=priorities,
        api_endpoint="https://example.test/jobs/bundle",
        opener=opener,
    )

    assert captured["url"] == "https://example.test/jobs/alignment"
    assert captured["authorization"] == "Bearer env-token"
    body = captured["body"]
    assert isinstance(body, bytes)
    assert b'name="project_id"' in body
    assert b"project-1" in body
    assert b'name="priorities"; filename="priorities.md"' in body
    assert b"Content-Type: text/plain" in body
    assert b"Ship architecture visibility." in body
    assert b"group_id" not in body
    assert result == {"job_id": "align-1"}


def test_filter_unchanged_trace_jobs_uses_resolved_commit_history(tmp_path: Path) -> None:
    from shevek_collect.api_submit import filter_unchanged_trace_jobs

    (tmp_path / "code").mkdir()
    (tmp_path / "code" / "snapshots.jsonl").write_text(
        "\n".join(
            json.dumps(item)
            for item in [
                {"repo_id": "repo_v2_old", "resolved_commit": "abc123"},
                {"repo_id": "repo_v2_new", "resolved_commit": "def456"},
            ]
        ) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "collect_manifest.json").write_text(
        json.dumps(
            {
                "facets": {
                    "repository_snapshots": {
                        "enabled": True,
                        "snapshots": "code/snapshots.jsonl",
                    }
                },
                "repository_results": [
                    {
                        "source_kind": "repository_snapshot",
                        "repo_id": "repo_v2_old",
                        "status": "complete",
                    },
                    {
                        "source_kind": "repository_snapshot",
                        "repo_id": "repo_v2_new",
                        "status": "complete",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    jobs = [
        {"job": "trace", "repo_id": "repo_v2_old", "display_name": "Trace: old"},
        {"job": "trace", "repo_id": "repo_v2_new", "display_name": "Trace: new"},
        {"job": "catalogue", "display_name": "Catalogue: Shevek activity"},
    ]

    filtered, current, skipped = filter_unchanged_trace_jobs(
        tmp_path, jobs, {"repo_v2_old": {"abc123"}}
    )

    assert filtered == [jobs[1], jobs[2]]
    assert current == {"repo_v2_old": {"abc123"}, "repo_v2_new": {"def456"}}
    assert skipped == [
        {"repo_id": "repo_v2_old", "display_name": "Trace: old", "commits": ["abc123"]}
    ]


def test_submit_commit_state_round_trip_and_zip_excludes_it(tmp_path: Path) -> None:
    from shevek_collect.api_submit import (
        SUBMIT_COMMIT_STATE_FILENAME,
        load_submit_commit_state,
        write_submit_commit_state,
    )

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "collect_manifest.json").write_text("{}", encoding="utf-8")
    write_submit_commit_state(bundle, {"repo_v2_one": {"bbb", "aaa"}})

    assert load_submit_commit_state(bundle) == {"repo_v2_one": {"aaa", "bbb"}}
    seal_bundle(bundle)
    archive_path = zip_bundle(bundle, tmp_path / "bundle.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert SUBMIT_COMMIT_STATE_FILENAME not in archive.namelist()


def test_submission_manifest_contains_all_repositories_and_commits(tmp_path: Path) -> None:
    from shevek_collect.api_submit import submission_manifest_from_bundle

    (tmp_path / "code").mkdir()
    (tmp_path / "code" / "snapshots.jsonl").write_text(
        json.dumps({"repo_id": "repo_v2_one", "resolved_commit": "aaa"}) + "\n"
        + json.dumps({"repo_id": "repo_v2_two", "resolved_commit": "bbb"}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "collect_manifest.json").write_text(
        json.dumps({
            "complete": True,
            "facets": {
                "activity": {"enabled": True},
                "repository_snapshots": {"enabled": True, "snapshots": "code/snapshots.jsonl"},
            },
            "repository_results": [
                {"source_kind": "repository_snapshot", "repo_id": "repo_v2_one", "repo_hint": "one", "status": "complete"},
                {"source_kind": "repository_snapshot", "repo_id": "repo_v2_two", "repo_hint": "two", "status": "complete"},
            ],
        }),
        encoding="utf-8",
    )

    assert submission_manifest_from_bundle(tmp_path) == {
        "version": 1,
        "repositories": [
            {"repo_id": "repo_v2_one", "resolved_commits": ["aaa"], "repo_hint": "one"},
            {"repo_id": "repo_v2_two", "resolved_commits": ["bbb"], "repo_hint": "two"},
        ],
        "catalogue_included": True,
    }


def test_submit_bundle_includes_submission_manifest_form_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shevek_collect.api_submit import submit_bundle

    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"zip")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "token")
    captured: dict[str, object] = {}

    class Response:
        status = 200
        def read(self, size: int = -1) -> bytes:
            return b"{}"

    def opener(request: object, timeout: float) -> Response:
        captured["body"] = request.data  # type: ignore[attr-defined]
        return Response()

    submission_manifest = {
        "version": 1,
        "repositories": [{"repo_id": "repo_v2_one", "resolved_commits": ["aaa"]}],
        "catalogue_included": True,
    }
    submit_bundle(
        zip_path=zip_path,
        jobs=[{"job": "catalogue", "display_name": "Catalogue: Shevek activity"}],
        submission_manifest=submission_manifest,
        opener=opener,
    )

    body = captured["body"]
    assert isinstance(body, bytes)
    assert b'name="submission_manifest"' in body
    assert b'"repo_id":"repo_v2_one"' in body
    assert b'"resolved_commits":["aaa"]' in body


def test_submit_bundle_serializes_analysis_depth_in_jobs_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shevek_collect.api_submit import submit_bundle

    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"zip")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "token")
    captured: dict[str, bytes] = {}

    class Response:
        status = 200

        def read(self, size: int = -1) -> bytes:
            return b"{}"

    def opener(request: object, timeout: float) -> Response:
        captured["body"] = request.data  # type: ignore[attr-defined]
        return Response()

    submit_bundle(
        zip_path=zip_path,
        jobs=[
            {
                "job": "trace",
                "repo_id": "repo_v2_abc",
                "display_name": "Trace: shevek_trace",
                "analysis_depth": "deep",
            },
            {"job": "catalogue", "display_name": "Catalogue: Shevek activity"},
        ],
        opener=opener,
    )

    body = captured["body"]
    assert b'name="jobs"' in body
    assert b'"job":"trace"' in body
    assert b'"analysis_depth":"deep"' in body
    assert b'"job":"catalogue","display_name":"Catalogue: Shevek activity"' in body


def test_submit_bundle_includes_project_id_as_separate_form_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shevek_collect.api_submit import submit_bundle

    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"zip")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "token")
    captured: dict[str, bytes] = {}

    class Response:
        status = 200
        def read(self, size: int = -1) -> bytes:
            return b"{}"

    def opener(request: object, timeout: float) -> Response:
        captured["body"] = request.data  # type: ignore[attr-defined]
        return Response()

    manifest = {"version": 1, "repositories": [], "catalogue_included": True}
    submit_bundle(
        zip_path=zip_path,
        jobs=[{"job": "catalogue", "display_name": "Catalogue: Shevek activity"}],
        submission_manifest=manifest,
        project_id="project-uuid",
        opener=opener,
    )

    body = captured["body"]
    assert b'name="project_id"' in body
    assert b"project-uuid" in body
    # Project identity remains outside the repository-state JSON.
    manifest_part = json.dumps(manifest, separators=(",", ":")).encode()
    assert manifest_part in body
    assert b'"project_id"' not in manifest_part


def test_submit_bundle_omits_empty_project_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shevek_collect.api_submit import submit_bundle

    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"zip")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "token")
    captured: dict[str, bytes] = {}

    class Response:
        status = 200
        def read(self, size: int = -1) -> bytes:
            return b"{}"

    def opener(request: object, timeout: float) -> Response:
        captured["body"] = request.data  # type: ignore[attr-defined]
        return Response()

    submit_bundle(
        zip_path=zip_path,
        jobs=[{"job": "catalogue", "display_name": "Catalogue: Shevek activity"}],
        project_id="   ",
        opener=opener,
    )
    assert b'name="project_id"' not in captured["body"]


def test_submit_commit_state_is_isolated_by_project_and_migrates_v1(tmp_path: Path) -> None:
    from shevek_collect.api_submit import (
        SUBMIT_COMMIT_STATE_FILENAME,
        load_submit_commit_state,
        write_submit_commit_state,
    )

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / SUBMIT_COMMIT_STATE_FILENAME).write_text(
        json.dumps({"version": 1, "repos": {"repo_v2_old": ["legacy"]}}),
        encoding="utf-8",
    )

    assert load_submit_commit_state(bundle) == {"repo_v2_old": {"legacy"}}
    assert load_submit_commit_state(bundle, project_id="P1") == {}

    write_submit_commit_state(bundle, {"repo_v2_a": {"aaa"}}, project_id="P1")
    write_submit_commit_state(bundle, {"repo_v2_a": {"bbb"}}, project_id="P2")

    assert load_submit_commit_state(bundle, project_id="P1") == {"repo_v2_a": {"aaa"}}
    assert load_submit_commit_state(bundle, project_id="P2") == {"repo_v2_a": {"bbb"}}
    assert load_submit_commit_state(bundle) == {"repo_v2_old": {"legacy"}}

    raw = json.loads((bundle / SUBMIT_COMMIT_STATE_FILENAME).read_text(encoding="utf-8"))
    assert raw["version"] == 2
    assert set(raw["projects"]) == {"P1", "P2"}
