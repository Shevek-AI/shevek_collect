from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from shevek_collect.git_collect import GitCollectOptions, GitRepoSpec, collect_git
from shevek_collect.run_collect import RunCollectOptions, plan_collect


def test_collect_git_emits_ref_tag_and_clean_branch_relation_artifacts(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    _git(repo, "tag", "-a", "v1.0.0", "-m", "First release")

    _git(repo, "checkout", "-b", "feature/job-runner")
    (repo / "feature.txt").write_text("feature\n", encoding="utf-8")
    _git(repo, "add", "feature.txt")
    feature_sha = _git(repo, "commit", "-m", "add feature").strip()

    _git(repo, "checkout", "main")
    (repo / "main.txt").write_text("main\n", encoding="utf-8")
    _git(repo, "add", "main.txt")
    _git(repo, "commit", "-m", "advance main")

    objects_before = _object_files(repo)
    out = tmp_path / "bundle"
    result = collect_git(
        GitCollectOptions(
            repos=(
                GitRepoSpec(
                    path=repo,
                    topology_comparison_refs=("refs/heads/main",),
                ),
            ),
            out=out,
        )
    )
    objects_after = _object_files(repo)

    assert result["errors"] == []
    assert objects_after == objects_before

    artifacts = _read_jsonl(out / "source_artifacts.jsonl")
    refs = [row for row in artifacts if row["artifact_type"] == "git.ref_snapshot"]
    tags = [row for row in artifacts if row["artifact_type"] == "git.tag_snapshot"]
    relations = [row for row in artifacts if row["artifact_type"] == "git.branch_relation"]

    assert {row["payload"]["ref"] for row in refs} == {
        "refs/heads/feature/job-runner",
        "refs/heads/main",
    }
    assert len(tags) == 1
    assert tags[0]["payload"]["name"] == "v1.0.0"
    assert tags[0]["payload"]["tag_type"] == "annotated"
    assert tags[0]["payload"]["resolved_commit_sha"]
    assert tags[0]["payload"]["signature_status"] == "not_checked"

    relation = _relation(relations, head_ref="refs/heads/feature/job-runner")
    assert relation["base_ref"] == "refs/heads/main"
    assert relation["base_reasons"] == [
        "configured_comparison_ref",
        "conventional_branch_fallback",
    ]
    assert relation["ahead_count"] == 1
    assert relation["behind_count"] == 1
    assert relation["head_only_commit_shas"] == [feature_sha]
    assert relation["head_only_commit_shas_truncated"] is False
    assert relation["patch_equivalence"]["unique_patch_count"] == 1
    assert relation["patch_equivalence"]["equivalent_patch_count"] == 0
    assert relation["merge_viability"]["state"] == "clean"

    repository = next(row for row in artifacts if row["artifact_type"] == "git.repository")
    state = repository["payload"]["repository_state"]
    assert state["head_ref"] == "refs/heads/main"
    assert state["head_detached"] is False
    assert state["history_scope"] == "local_object_database_not_shallow"
    assert state["ref_observation_scope"] == "local_ref_database"

    manifest = json.loads((out / "collect_manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["git_ref_artifacts"] == 2
    assert manifest["counts"]["git_tag_artifacts"] == 1
    assert manifest["counts"]["git_branch_relation_artifacts"] == 1
    assert manifest["privacy"]["contains_ref_names"] is True


def test_collect_git_reports_conflicting_branch_relation(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")

    _git(repo, "checkout", "-b", "feature/conflict")
    (repo / "README.md").write_text("feature\n", encoding="utf-8")
    _git(repo, "commit", "-am", "feature edit")

    _git(repo, "checkout", "main")
    (repo / "README.md").write_text("main\n", encoding="utf-8")
    _git(repo, "commit", "-am", "main edit")

    out = tmp_path / "bundle"
    collect_git(GitCollectOptions(repos=(repo,), out=out))

    relations = [
        row["payload"]
        for row in _read_jsonl(out / "source_artifacts.jsonl")
        if row["artifact_type"] == "git.branch_relation"
    ]
    relation = _relation_payload(relations, head_ref="refs/heads/feature/conflict")
    assert relation["ahead_count"] == 1
    assert relation["behind_count"] == 1
    assert relation["merge_viability"]["state"] == "conflicting"


def test_collect_git_recognises_patch_equivalent_cherry_pick(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")

    _git(repo, "checkout", "-b", "feature/cherry")
    (repo / "feature.txt").write_text("same change\n", encoding="utf-8")
    _git(repo, "add", "feature.txt")
    feature_sha = _git(repo, "commit", "-m", "feature patch").strip()

    _git(repo, "checkout", "main")
    (repo / "main.txt").write_text("main advance\n", encoding="utf-8")
    _git(repo, "add", "main.txt")
    _git(repo, "commit", "-m", "advance main")
    _git(repo, "cherry-pick", feature_sha)

    out = tmp_path / "bundle"
    collect_git(GitCollectOptions(repos=(repo,), out=out))

    relations = [
        row["payload"]
        for row in _read_jsonl(out / "source_artifacts.jsonl")
        if row["artifact_type"] == "git.branch_relation"
    ]
    relation = _relation_payload(relations, head_ref="refs/heads/feature/cherry")
    assert relation["ahead_count"] == 1
    assert relation["patch_equivalence"]["unique_patch_count"] == 0
    assert relation["patch_equivalence"]["equivalent_patch_count"] == 1
    assert relation["patch_equivalence"]["equivalent_patch_commit_shas"] == [feature_sha]


def test_collect_git_marks_head_only_commit_list_truncated(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    _git(repo, "checkout", "-b", "feature/large")
    for index in range(3):
        (repo / f"feature_{index}.txt").write_text(f"{index}\n", encoding="utf-8")
        _git(repo, "add", f"feature_{index}.txt")
        _git(repo, "commit", "-m", f"feature {index}")
    _git(repo, "checkout", "main")

    out = tmp_path / "bundle"
    collect_git(
        GitCollectOptions(
            repos=(repo,),
            out=out,
            max_topology_commit_ids=2,
            include_merge_viability=False,
        )
    )

    relations = [
        row["payload"]
        for row in _read_jsonl(out / "source_artifacts.jsonl")
        if row["artifact_type"] == "git.branch_relation"
    ]
    relation = _relation_payload(relations, head_ref="refs/heads/feature/large")
    assert relation["ahead_count"] == 3
    assert len(relation["head_only_commit_shas"]) == 2
    assert relation["head_only_commit_shas_truncated"] is True
    assert relation["head_only_commit_sha_limit"] == 2
    assert relation["merge_viability"]["state"] == "not_checked"


def test_collect_git_preserves_shallow_history_uncertainty(tmp_path: Path) -> None:
    source = _init_repo(tmp_path / "source")
    (source / "second.txt").write_text("second\n", encoding="utf-8")
    _git(source, "add", "second.txt")
    _git(source, "commit", "-m", "second")

    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--depth", "1", source.as_uri(), str(shallow)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    out = tmp_path / "bundle"
    collect_git(GitCollectOptions(repos=(shallow,), out=out))

    repository = next(
        row
        for row in _read_jsonl(out / "source_artifacts.jsonl")
        if row["artifact_type"] == "git.repository"
    )
    state = repository["payload"]["repository_state"]
    assert state["is_shallow_repository"] is True
    assert state["history_scope"] == "incomplete_shallow"


def test_config_plan_exposes_git_topology_settings(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    config = tmp_path / "shevek_collect.yaml"
    config.write_text(
        f"""
version: 1
activity_sources:
  git:
    repos:
      - path: {repo.as_posix()}
        topology:
          comparison_refs:
            - refs/heads/main
            - refs/heads/release/2.x
    topology:
      max_commit_ids: 123
      include_merge_viability: false
""".lstrip(),
        encoding="utf-8",
    )

    plan = plan_collect(
        RunCollectOptions(
            config=config,
            out=tmp_path / "bundle",
            dry_run=True,
        )
    )

    git_source = plan["sources"][0]
    assert git_source["repos"] == [
        {
            "path": repo.resolve().as_posix(),
            "topology": {
                "comparison_refs": [
                    "refs/heads/main",
                    "refs/heads/release/2.x",
                ]
            },
        }
    ]
    assert git_source["topology"] == {
        "max_commit_ids": 123,
        "include_merge_viability": False,
    }




def test_config_rejects_legacy_global_topology_base_refs(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    config = tmp_path / "shevek_collect.yaml"
    config.write_text(
        f"""
version: 1
activity_sources:
  git:
    repos:
      - {repo.as_posix()}
    topology_base_refs:
      - refs/heads/main
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=r"repos\[\]\.topology\.comparison_refs",
    ):
        plan_collect(
            RunCollectOptions(
                config=config,
                out=tmp_path / "bundle",
                dry_run=True,
            )
        )

def test_collect_git_applies_comparison_refs_per_repository(tmp_path: Path) -> None:
    release_repo = _init_repo(tmp_path / "release-repo")
    _git(release_repo, "branch", "release/1.x")
    deploy_repo = _init_repo(tmp_path / "deploy-repo")
    _git(deploy_repo, "branch", "production")

    out = tmp_path / "bundle"
    collect_git(
        GitCollectOptions(
            repos=(
                GitRepoSpec(
                    path=release_repo,
                    topology_comparison_refs=("refs/heads/release/1.x",),
                ),
                GitRepoSpec(
                    path=deploy_repo,
                    topology_comparison_refs=("refs/heads/production",),
                ),
            ),
            out=out,
        )
    )

    repositories = {
        row["payload"]["repo_hint"]: row["payload"]["repository_state"]
        for row in _read_jsonl(out / "source_artifacts.jsonl")
        if row["artifact_type"] == "git.repository"
    }
    assert repositories["release-repo"]["configured_comparison_refs"] == [
        "refs/heads/release/1.x"
    ]
    assert repositories["release-repo"]["unresolved_configured_comparison_refs"] == []
    assert repositories["deploy-repo"]["configured_comparison_refs"] == [
        "refs/heads/production"
    ]
    assert repositories["deploy-repo"]["unresolved_configured_comparison_refs"] == []

def test_collect_git_uses_remote_symbolic_head_as_comparison_anchor(tmp_path: Path) -> None:
    source = _init_repo(tmp_path / "source")
    _git(source, "checkout", "-b", "feature/remote")
    (source / "remote.txt").write_text("remote feature\n", encoding="utf-8")
    _git(source, "add", "remote.txt")
    _git(source, "commit", "-m", "remote feature")
    _git(source, "checkout", "main")

    bare = tmp_path / "origin.git"
    subprocess.run(
        ["git", "clone", "--bare", str(source), str(bare)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", str(bare), str(clone)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    out = tmp_path / "bundle"
    collect_git(GitCollectOptions(repos=(clone,), out=out))

    artifacts = _read_jsonl(out / "source_artifacts.jsonl")
    origin_head = next(
        row["payload"]
        for row in artifacts
        if row["artifact_type"] == "git.ref_snapshot"
        and row["payload"]["ref"] == "refs/remotes/origin/HEAD"
    )
    assert origin_head["ref_kind"] == "remote_symbolic"
    assert origin_head["symbolic_target"] == "refs/remotes/origin/main"

    relation = next(
        row["payload"]
        for row in artifacts
        if row["artifact_type"] == "git.branch_relation"
        and row["payload"]["head_ref"] == "refs/remotes/origin/feature/remote"
        and row["payload"]["base_ref"] == "refs/remotes/origin/main"
    )
    assert relation["base_reasons"] == ["remote_symbolic_head", "same_remote_default"]
    assert relation["ahead_count"] == 1


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test User")
    (path / "README.md").write_text("base\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial")
    return path


def _git(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if args and args[0] == "commit":
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout
    return process.stdout


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _relation(
    artifacts: list[dict[str, object]],
    *,
    head_ref: str,
) -> dict[str, object]:
    return _relation_payload([row["payload"] for row in artifacts], head_ref=head_ref)


def _relation_payload(
    relations: list[dict[str, object]],
    *,
    head_ref: str,
) -> dict[str, object]:
    return next(row for row in relations if row["head_ref"] == head_ref)


def _object_files(repo: Path) -> set[str]:
    objects = repo / ".git" / "objects"
    return {path.relative_to(objects).as_posix() for path in objects.rglob("*") if path.is_file()}
