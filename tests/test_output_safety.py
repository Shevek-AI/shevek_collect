from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import shevek_collect.git_collect as git_collect
from shevek_collect.git_collect import GitCollectOptions, collect_git
from shevek_collect.io_utils import OutputDirectoryError


def test_nonempty_unrecognised_directory_is_preserved(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "repo")
    out = tmp_path / "important"
    out.mkdir()
    marker = out / "do-not-delete.txt"
    marker.write_text("important", encoding="utf-8")

    with pytest.raises(OutputDirectoryError, match="not a recognised"):
        collect_git(GitCollectOptions(repos=(repo,), out=out))

    assert marker.read_text(encoding="utf-8") == "important"
    assert sorted(path.name for path in out.iterdir()) == ["do-not-delete.txt"]


def test_force_overwrite_replaces_unrecognised_directory(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "repo")
    out = tmp_path / "old-content"
    out.mkdir()
    marker = out / "old.txt"
    marker.write_text("old", encoding="utf-8")

    collect_git(
        GitCollectOptions(
            repos=(repo,),
            out=out,
            force_overwrite=True,
        )
    )

    assert not marker.exists()
    assert (out / "collect_manifest.json").exists()


def test_existing_bundle_requires_overwrite_and_uses_public_path(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "repo")
    out = tmp_path / "bundle"
    collect_git(GitCollectOptions(repos=(repo,), out=out))
    marker = out / "stale.txt"
    marker.write_text("stale", encoding="utf-8")

    with pytest.raises(OutputDirectoryError, match="Pass --overwrite"):
        collect_git(GitCollectOptions(repos=(repo,), out=out))
    assert marker.exists()

    result = collect_git(
        GitCollectOptions(
            repos=(repo,),
            out=out,
            overwrite=True,
        )
    )

    assert not marker.exists()
    assert result["out"] == out.resolve().as_posix()
    manifest = json.loads((out / "collect_manifest.json").read_text(encoding="utf-8"))
    assert manifest["out"] == out.name
    assert manifest["out_path_hash"]
    assert ".staging-" not in json.dumps(manifest)


def test_failed_overwrite_preserves_previous_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _make_git_repo(tmp_path / "repo")
    out = tmp_path / "bundle"
    collect_git(GitCollectOptions(repos=(repo,), out=out))
    original_manifest = (out / "collect_manifest.json").read_bytes()
    marker = out / "previous-good-bundle.txt"
    marker.write_text("good", encoding="utf-8")

    def fail_write_json(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated write failure")

    monkeypatch.setattr(git_collect, "write_json", fail_write_json)

    with pytest.raises(RuntimeError, match="simulated write failure"):
        collect_git(
            GitCollectOptions(
                repos=(repo,),
                out=out,
                overwrite=True,
            )
        )

    assert marker.read_text(encoding="utf-8") == "good"
    assert (out / "collect_manifest.json").read_bytes() == original_manifest
    assert not list(tmp_path.glob(".bundle.staging-*"))


def test_existing_empty_directory_is_safe_without_flags(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "repo")
    out = tmp_path / "empty"
    out.mkdir()

    collect_git(GitCollectOptions(repos=(repo,), out=out))

    assert (out / "collect_manifest.json").exists()


def test_current_working_directory_is_always_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _make_git_repo(tmp_path / "repo")
    marker = tmp_path / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(OutputDirectoryError, match="protected high-level"):
        collect_git(
            GitCollectOptions(
                repos=(repo,),
                out=tmp_path,
                force_overwrite=True,
            )
        )

    assert marker.read_text(encoding="utf-8") == "keep"


def test_symlink_output_is_refused(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path / "repo")
    real_out = tmp_path / "real"
    real_out.mkdir()
    linked_out = tmp_path / "linked"
    linked_out.symlink_to(real_out, target_is_directory=True)

    with pytest.raises(OutputDirectoryError, match="symlink"):
        collect_git(
            GitCollectOptions(
                repos=(repo,),
                out=linked_out,
                force_overwrite=True,
            )
        )

    assert list(real_out.iterdir()) == []


def _make_git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test User")
    (path / "README.md").write_text("# Demo\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial")
    return path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
