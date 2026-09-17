from __future__ import annotations

import json
from pathlib import Path

import pytest
from bundle_fixtures import seal_bundle

import shevek_collect.cli as cli
from shevek_collect.azure_devops_collect import AzureDevOpsCollectOptions
from shevek_collect.git_collect import GitCollectOptions
from shevek_collect.github_collect import GitHubCollectOptions
from shevek_collect.run_collect import RunCollectOptions


def _result(out: Path, *, errors: list[str] | None = None) -> dict[str, object]:
    return {
        "out": out.resolve().as_posix(),
        "repos_requested": 1,
        "repos_collected": 1,
        "events": 1,
        "artifacts": 1,
        "errors": errors or [],
        "outputs": {},
    }


def test_github_scan_cli_parses_repositories_and_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo_file = tmp_path / "repos.txt"
    repo_file.write_text("# comment\nacme/from-file\n\n", encoding="utf-8")
    captured: list[GitHubCollectOptions] = []

    def fake_collect(options: GitHubCollectOptions) -> dict[str, object]:
        captured.append(options)
        return _result(options.out)

    monkeypatch.setattr(cli, "collect_github", fake_collect)
    out = tmp_path / "bundle"

    exit_code = cli.main(
        [
            "github",
            "scan",
            "--repo",
            "acme/direct",
            "--repo-file",
            str(repo_file),
            "--out",
            str(out),
            "--hostname",
            "github.example.com",
            "--since",
            "2026-01-01",
            "--max-prs",
            "17",
            "--body-mode",
            "full",
            "--comment-mode",
            "none",
            "--actor-mode",
            "hash",
            "--commit-message-mode",
            "none",
            "--include-raw-emails",
            "--include-urls",
            "--include-file-patches",
            "--skip-auth-check",
            "--retry-attempts",
            "7",
            "--retry-initial-delay",
            "0.25",
            "--retry-max-delay",
            "9",
            "--retry-max-retry-after",
            "45",
            "--overwrite",
            "--json",
        ]
    )

    assert exit_code == 0
    assert len(captured) == 1
    options = captured[0]
    assert options.repos == ("acme/direct", "acme/from-file")
    assert options.out == out
    assert options.hostname == "github.example.com"
    assert options.since == "2026-01-01"
    assert options.max_prs == 17
    assert options.body_mode == "full"
    assert options.comment_mode == "none"
    assert options.actor_mode == "hash"
    assert options.commit_message_mode == "none"
    assert options.include_raw_emails is True
    assert options.include_urls is True
    assert options.include_file_patches is True
    assert options.skip_auth_check is True
    assert options.retry_policy.max_attempts == 7
    assert options.retry_policy.initial_delay_seconds == 0.25
    assert options.retry_policy.max_delay_seconds == 9
    assert options.retry_policy.max_retry_after_seconds == 45
    assert options.overwrite is True
    assert options.force_overwrite is False
    assert json.loads(capsys.readouterr().out)["out"] == out.resolve().as_posix()


def test_azure_devops_scan_cli_parses_repositories_and_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[AzureDevOpsCollectOptions] = []

    def fake_collect(options: AzureDevOpsCollectOptions) -> dict[str, object]:
        captured.append(options)
        return _result(options.out)

    monkeypatch.setattr(cli, "collect_azure_devops", fake_collect)
    out = tmp_path / "bundle"

    exit_code = cli.main(
        [
            "azure-devops",
            "scan",
            "--organization",
            "Acme Org",
            "--repo",
            "Platform/API",
            "--repo",
            "Data/Warehouse",
            "--out",
            str(out),
            "--since",
            "2026-02-03",
            "--max-prs",
            "12",
            "--body-mode",
            "none",
            "--comment-mode",
            "full",
            "--actor-mode",
            "none",
            "--commit-message-mode",
            "full",
            "--include-raw-emails",
            "--include-urls",
            "--token-env",
            "TEST_AZDO_PAT",
            "--api-version",
            "7.2-preview",
            "--retry-attempts",
            "3",
            "--retry-initial-delay",
            "0",
            "--retry-max-delay",
            "5",
            "--retry-max-retry-after",
            "20",
            "--force-overwrite",
            "--json",
        ]
    )

    assert exit_code == 0
    assert len(captured) == 1
    options = captured[0]
    assert options.organization == "Acme Org"
    assert [(repo.project, repo.repo) for repo in options.repos] == [
        ("Platform", "API"),
        ("Data", "Warehouse"),
    ]
    assert options.out == out
    assert options.since == "2026-02-03"
    assert options.max_prs == 12
    assert options.body_mode == "none"
    assert options.comment_mode == "full"
    assert options.actor_mode == "none"
    assert options.commit_message_mode == "full"
    assert options.include_raw_emails is True
    assert options.include_urls is True
    assert options.token_env == "TEST_AZDO_PAT"
    assert options.api_version == "7.2-preview"
    assert options.retry_policy.max_attempts == 3
    assert options.retry_policy.initial_delay_seconds == 0
    assert options.retry_policy.max_delay_seconds == 5
    assert options.retry_policy.max_retry_after_seconds == 20
    assert options.overwrite is False
    assert options.force_overwrite is True


def test_inspect_cli_reads_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    manifest = {
        "schema_version": "shevek.collect_manifest.v1",
        "bundle_kind": "source_evidence",
        "created_at": "2026-07-17T00:00:00Z",
        "out": bundle.as_posix(),
        "counts": {"repos_collected": 2, "source_events": 3, "source_artifacts": 4},
        "privacy": {"contains_file_content": False},
        "outputs": {},
    }
    (bundle / "collect_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    exit_code = cli.main(["inspect", str(bundle), "--json"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == manifest


def test_output_replacement_flags_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "github",
                "scan",
                "--repo",
                "acme/demo",
                "--out",
                str(tmp_path / "bundle"),
                "--overwrite",
                "--force-overwrite",
            ]
        )

    assert exc_info.value.code == 2


def test_cli_loads_privacy_key_from_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[GitHubCollectOptions] = []

    def fake_collect(options: GitHubCollectOptions) -> dict[str, object]:
        captured.append(options)
        return _result(options.out)

    monkeypatch.setattr(cli, "collect_github", fake_collect)
    key_file = tmp_path / "privacy.key"
    key_file.write_text("hex:" + "ab" * 32 + "\n", encoding="utf-8")

    exit_code = cli.main(
        [
            "github",
            "scan",
            "--repo",
            "acme/demo",
            "--out",
            str(tmp_path / "bundle"),
            "--privacy-key-file",
            str(key_file),
            "--json",
        ]
    )

    assert exit_code == 0
    assert captured[0].privacy_hasher is not None
    assert captured[0].privacy_hasher.key == bytes.fromhex("ab" * 32)


def test_cli_refuses_collection_without_privacy_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHEVEK_COLLECT_PRIVACY_KEY", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "github",
                "scan",
                "--repo",
                "acme/demo",
                "--out",
                str(tmp_path / "bundle"),
            ]
        )

    assert exc_info.value.code == 2


def test_activity_git_is_canonical_and_legacy_alias_warns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: list[GitCollectOptions] = []

    def fake_collect(options: GitCollectOptions) -> dict[str, object]:
        captured.append(options)
        return _result(options.out)

    monkeypatch.setattr(cli, "collect_git", fake_collect)

    canonical_out = tmp_path / "canonical"
    assert cli.main(["activity", "git", "--repo", ".", "--out", str(canonical_out)]) == 0
    canonical_streams = capsys.readouterr()
    assert "deprecated" not in canonical_streams.err.lower()

    legacy_out = tmp_path / "legacy"
    assert cli.main(["git", "scan", "--repo", ".", "--out", str(legacy_out)]) == 0
    legacy_streams = capsys.readouterr()
    assert "deprecated" in legacy_streams.err.lower()
    assert "activity git" in legacy_streams.err
    assert "not repository source snapshots" in legacy_streams.err

    assert [options.out for options in captured] == [canonical_out, legacy_out]
    assert [options.command_name for options in captured] == ["activity git", "git scan"]


def test_snapshot_cli_routes_through_config_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[RunCollectOptions] = []

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        captured.append(options)
        return {
            **_result(options.out),
            "source_runs": 0,
            "snapshot_repos_requested": 1,
            "snapshot_repos_collected": 1,
            "snapshots_collected": 1,
            "repository_files": 3,
        }

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    repo = tmp_path / "repo"
    out = tmp_path / "bundle"

    exit_code = cli.main(
        [
            "snapshot",
            "--repo",
            str(repo),
            "--ref",
            "HEAD~1",
            "--name",
            "base",
            "--content-mode",
            "structure",
            "--include-glob",
            "src/**",
            "--exclude-glob",
            "src/generated/**",
            "--max-file-bytes",
            "1234",
            "--max-total-bytes",
            "5678",
            "--no-default-excludes",
            "--out",
            str(out),
            "--overwrite",
        ]
    )

    assert exit_code == 0
    assert len(captured) == 1
    options = captured[0]
    assert options.out == out
    assert options.overwrite is True
    assert options.config_data is not None
    snapshots = options.config_data["repository_snapshots"]
    assert isinstance(snapshots, dict)
    git = snapshots["git"]
    assert isinstance(git, dict)
    assert git["repos"] == [
        {
            "path": repo.resolve().as_posix(),
            "snapshots": [{"name": "base", "ref": "HEAD~1"}],
        }
    ]
    assert git["capture"] == {
        "content_mode": "structure",
        "max_file_bytes": 1234,
        "max_total_bytes": 5678,
        "include_globs": ["src/**"],
        "exclude_globs": ["src/generated/**"],
        "use_default_excludes": False,
    }


def test_submit_cli_collects_zips_derives_jobs_and_posts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    captured: dict[str, object] = {}

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        bundle.mkdir()
        (bundle / "collect_manifest.json").write_text(
            json.dumps(
                {
                    "complete": True,
                    "facets": {
                        "activity": {"enabled": True},
                        "repository_snapshots": {
                            "enabled": True,
                            "snapshots": "code/snapshots.jsonl",
                        },
                    },
                    "repository_results": [
                        {
                            "source_kind": "repository_snapshot",
                            "repo_id": "repo_v2_abc",
                            "repo_hint": "shevek_trace",
                            "status": "complete",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (bundle / "code").mkdir()
        (bundle / "code" / "snapshots.jsonl").write_text(
            json.dumps({"repo_id": "repo_v2_abc", "resolved_commit": "abc123"}) + "\n",
            encoding="utf-8",
        )
        (bundle / "source_events.jsonl").write_text("", encoding="utf-8")
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    def fake_submit_bundle(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"group_id": "group-123"}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", fake_submit_bundle)
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    exit_code = cli.main(
        ["submit", "--config", str(config), "--out", str(bundle), "--json"]
    )

    assert exit_code == 0
    jobs = captured["jobs"]
    assert jobs == [
        {"job": "trace", "repo_id": "repo_v2_abc", "display_name": "Trace: shevek_trace"},
        {"job": "catalogue", "display_name": "Catalogue: Shevek activity"},
    ]
    zip_path = Path(str(captured["zip_path"]))
    assert zip_path == Path(str(bundle) + ".zip").resolve()
    assert zip_path.exists()
    output = json.loads(capsys.readouterr().out)
    assert output["response"]["group_id"] == "group-123"


def test_submit_fetches_configured_git_repositories_before_collect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = tmp_path / "activity.yaml"
    config.write_text(
        """version: 1
activity_sources:
  git:
    repos:
      - path: repo
repository_snapshots:
  git:
    repos:
      - path: repo
        snapshots:
          - name: target
            ref: refs/remotes/origin/main
""",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    commands: list[list[str]] = []

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(command: list[str], **kwargs: object) -> Proc:
        commands.append(command)
        return Proc()

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        assert len(commands) == 1
        assert commands[0][-5:] == ["-C", str(repo.resolve()), "fetch", "--no-recurse-submodules", "origin"]
        assert "core.fsmonitor=false" in commands[0]
        bundle.mkdir()
        (bundle / "collect_manifest.json").write_text(
            json.dumps({"complete": True, "facets": {"activity": {"enabled": True}}, "repository_results": []}),
            encoding="utf-8",
        )
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", lambda **kwargs: {})
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "token")

    assert cli.main([
        "submit", "--config", str(config), "--out", str(bundle), "--fetch"
    ]) == 0


def test_fetch_failure_stops_submit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = tmp_path / "activity.yaml"
    config.write_text(
        "version: 1\nrepository_snapshots:\n  git:\n    repos:\n      - path: repo\n",
        encoding="utf-8",
    )

    class Proc:
        returncode = 1
        stdout = ""
        stderr = "remote unavailable"

    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: Proc())
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    with pytest.raises(SystemExit) as exc:
        cli.main(["submit", "--config", str(config), "--out", str(tmp_path / "bundle"), "--fetch"])
    assert exc.value.code == 2


def test_submit_skip_unchanged_preserves_history_and_only_posts_changed_trace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shevek_collect.api_submit import load_submit_commit_state, write_submit_commit_state

    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    write_submit_commit_state(bundle, {"repo_v2_old": {"oldhash"}})
    captured: dict[str, object] = {}

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        # Simulate --overwrite replacing the run directory, including its state file.
        import shutil
        shutil.rmtree(bundle)
        bundle.mkdir()
        (bundle / "collect_manifest.json").write_text(
            json.dumps(
                {
                    "complete": True,
                    "facets": {
                        "activity": {"enabled": True},
                        "repository_snapshots": {
                            "enabled": True,
                            "snapshots": "code/snapshots.jsonl",
                        },
                    },
                    "repository_results": [
                        {
                            "source_kind": "repository_snapshot",
                            "repo_id": "repo_v2_old",
                            "repo_hint": "old",
                            "status": "complete",
                        },
                        {
                            "source_kind": "repository_snapshot",
                            "repo_id": "repo_v2_new",
                            "repo_hint": "new",
                            "status": "complete",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (bundle / "code").mkdir()
        (bundle / "code" / "snapshots.jsonl").write_text(
            json.dumps({"repo_id": "repo_v2_old", "resolved_commit": "oldhash"}) + "\n"
            + json.dumps({"repo_id": "repo_v2_new", "resolved_commit": "newhash"}) + "\n",
            encoding="utf-8",
        )
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    def fake_submit_bundle(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"group_id": "group-1"}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", fake_submit_bundle)
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "token")

    assert cli.main([
        "submit", "--config", str(config), "--out", str(bundle),
        "--overwrite", "--skip-unchanged",
    ]) == 0

    assert captured["jobs"] == [
        {"job": "trace", "repo_id": "repo_v2_new", "display_name": "Trace: new"},
        {"job": "catalogue", "display_name": "Catalogue: Shevek activity"},
    ]
    assert load_submit_commit_state(bundle) == {
        "repo_v2_old": {"oldhash"},
        "repo_v2_new": {"newhash"},
    }


def test_submit_skip_unchanged_does_not_record_new_commit_when_post_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shevek_collect.api_submit import ApiSubmissionError, load_submit_commit_state, write_submit_commit_state

    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    write_submit_commit_state(bundle, {"repo_v2_old": {"oldhash"}})

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        import shutil
        shutil.rmtree(bundle)
        bundle.mkdir()
        (bundle / "collect_manifest.json").write_text(
            json.dumps(
                {
                    "complete": True,
                    "facets": {
                        "activity": {"enabled": False},
                        "repository_snapshots": {
                            "enabled": True,
                            "snapshots": "code/snapshots.jsonl",
                        },
                    },
                    "repository_results": [
                        {
                            "source_kind": "repository_snapshot",
                            "repo_id": "repo_v2_new",
                            "repo_hint": "new",
                            "status": "complete",
                        }
                    ],
                }
            ), encoding="utf-8"
        )
        (bundle / "code").mkdir()
        (bundle / "code" / "snapshots.jsonl").write_text(
            json.dumps({"repo_id": "repo_v2_new", "resolved_commit": "newhash"}) + "\n",
            encoding="utf-8",
        )
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(
        cli,
        "submit_bundle",
        lambda **kwargs: (_ for _ in ()).throw(ApiSubmissionError("post failed")),
    )
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "token")

    with pytest.raises(SystemExit) as exc:
        cli.main([
            "submit", "--config", str(config), "--out", str(bundle),
            "--overwrite", "--skip-unchanged",
        ])
    assert exc.value.code == 2

    assert load_submit_commit_state(bundle) == {"repo_v2_old": {"oldhash"}}


def _write_minimal_submit_bundle(bundle: Path) -> None:
    bundle.mkdir()
    (bundle / "collect_manifest.json").write_text(
        json.dumps({
            "complete": True,
            "facets": {
                "activity": {"enabled": True},
                "repository_snapshots": {"enabled": True, "snapshots": "code/snapshots.jsonl"},
            },
            "repository_results": [
                {"source_kind": "repository_snapshot", "repo_id": "repo_v2_abc", "repo_hint": "hint-only", "status": "complete"}
            ],
        }),
        encoding="utf-8",
    )
    (bundle / "code").mkdir()
    (bundle / "code" / "snapshots.jsonl").write_text(
        json.dumps({"repo_id": "repo_v2_abc", "resolved_commit": "abc123"}) + "\n",
        encoding="utf-8",
    )


def test_submit_analysis_depth_is_added_to_trace_jobs_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    captured: dict[str, object] = {}

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        _write_minimal_submit_bundle(bundle)
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", lambda **kwargs: captured.update(kwargs) or {})
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    assert (
        cli.main(
            [
                "submit",
                "--config",
                str(config),
                "--out",
                str(bundle),
                "--analysis-depth",
                "deep",
            ]
        )
        == 0
    )
    assert captured["jobs"] == [
        {
            "job": "trace",
            "repo_id": "repo_v2_abc",
            "display_name": "Trace: hint-only",
            "analysis_depth": "deep",
        },
        {"job": "catalogue", "display_name": "Catalogue: Shevek activity"},
    ]


def test_submit_analysis_depth_rejects_invalid_value() -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(
            [
                "submit",
                "--config",
                "activity.yaml",
                "--out",
                "bundle",
                "--analysis-depth",
                "extreme",
            ]
        )
    assert exc.value.code == 2


def test_submit_uses_configured_project_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\nsubmission:\n  project_id: project-config\n", encoding="utf-8")
    (tmp_path / "priorities.md").write_text("# Priorities\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    captured: dict[str, object] = {}
    alignment_captured: dict[str, object] = {}
    request_order: list[str] = []

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        _write_minimal_submit_bundle(bundle)
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    def fake_submit_bundle(**kwargs: object) -> dict[str, object]:
        request_order.append("bundle")
        captured.update(kwargs)
        return {"group_id": "g1"}

    def fake_submit_alignment(**kwargs: object) -> dict[str, object]:
        request_order.append("alignment")
        alignment_captured.update(kwargs)
        return {"job_id": "a1"}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", fake_submit_bundle)
    monkeypatch.setattr(cli, "submit_alignment", fake_submit_alignment)
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    assert cli.main(["submit", "--config", str(config), "--out", str(bundle)]) == 0
    assert captured["project_id"] == "project-config"
    assert "project_id" not in captured["submission_manifest"]  # type: ignore[operator]
    assert alignment_captured["project_id"] == "project-config"
    assert alignment_captured["priorities_path"] == (tmp_path / "priorities.md").resolve()
    assert request_order == ["bundle", "alignment"]


def test_submit_cli_project_id_overrides_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\nsubmission:\n  project_id: project-config\n", encoding="utf-8")
    (tmp_path / "priorities.md").write_text("# Priorities\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    captured: dict[str, object] = {}

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        _write_minimal_submit_bundle(bundle)
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", lambda **kwargs: captured.update(kwargs) or {})
    monkeypatch.setattr(cli, "submit_alignment", lambda **kwargs: {})
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    assert cli.main(["submit", "--config", str(config), "--out", str(bundle), "--project-id", "project-cli"]) == 0
    assert captured["project_id"] == "project-cli"


def test_submit_without_project_preserves_unprojected_behavior(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    captured: dict[str, object] = {}

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        _write_minimal_submit_bundle(bundle)
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", lambda **kwargs: captured.update(kwargs) or {})
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    assert cli.main(["submit", "--config", str(config), "--out", str(bundle)]) == 0
    assert captured["project_id"] is None


def test_skip_unchanged_does_not_reuse_another_projects_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shevek_collect.api_submit import load_submit_commit_state, write_submit_commit_state

    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\nsubmission:\n  project_id: P2\n", encoding="utf-8")
    (tmp_path / "priorities.md").write_text("# Priorities\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    write_submit_commit_state(bundle, {"repo_v2_abc": {"abc123"}}, project_id="P1")
    captured: dict[str, object] = {}

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        import shutil
        shutil.rmtree(bundle)
        _write_minimal_submit_bundle(bundle)
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", lambda **kwargs: captured.update(kwargs) or {})
    monkeypatch.setattr(cli, "submit_alignment", lambda **kwargs: {})
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    assert cli.main(["submit", "--config", str(config), "--out", str(bundle), "--overwrite", "--skip-unchanged"]) == 0
    assert [job["job"] for job in captured["jobs"]] == ["trace", "catalogue"]  # type: ignore[index]
    assert load_submit_commit_state(bundle, project_id="P1") == {"repo_v2_abc": {"abc123"}}
    assert load_submit_commit_state(bundle, project_id="P2") == {"repo_v2_abc": {"abc123"}}


def test_project_id_is_not_inferred_from_repository_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    captured: dict[str, object] = {}

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        _write_minimal_submit_bundle(bundle)
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", lambda **kwargs: captured.update(kwargs) or {})
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    assert cli.main(["submit", "--config", str(config), "--out", str(bundle)]) == 0
    assert captured["project_id"] is None
    assert captured["jobs"][0]["repo_id"] == "repo_v2_abc"  # type: ignore[index]
    assert captured["jobs"][0]["display_name"] == "Trace: hint-only"  # type: ignore[index]


def test_backend_project_error_is_not_retried_without_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shevek_collect.api_submit import ApiSubmissionError

    config = tmp_path / "activity.yaml"
    config.write_text("version: 1\nsubmission:\n  project_id: P1\n", encoding="utf-8")
    (tmp_path / "priorities.md").write_text("# Priorities\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    calls: list[object] = []

    def fake_collect(options: RunCollectOptions) -> dict[str, object]:
        _write_minimal_submit_bundle(bundle)
        seal_bundle(bundle)
        return {"out": bundle.as_posix(), "errors": []}

    def fail_submit(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs.get("project_id"))
        raise ApiSubmissionError("Project does not belong to the submission domain")

    monkeypatch.setattr(cli, "collect_from_config", fake_collect)
    monkeypatch.setattr(cli, "submit_bundle", fail_submit)
    monkeypatch.setenv("SHEVEK_PRIVACY_KEY", "x" * 32)

    with pytest.raises(SystemExit) as exc:
        cli.main(["submit", "--config", str(config), "--out", str(bundle)])
    assert exc.value.code == 2
    assert calls == ["P1"]
