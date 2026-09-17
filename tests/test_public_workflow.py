from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from bundle_fixtures import seal_bundle
from shevek_collect import cli
from shevek_collect.git_collect import discover_git_repos


def test_fetch_uses_the_collection_plan_for_paths_defaults_and_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    explicit = tmp_path / "explicit"
    alias = tmp_path / "alias"
    snapshot = tmp_path / "snapshot"
    discovered = tmp_path / "root" / "discovered"
    discovered.mkdir(parents=True)
    (discovered / ".git").mkdir()
    for path in (explicit, alias, snapshot):
        path.mkdir()
    config = tmp_path / "collect.yaml"
    config.write_text(
        "version: 1\n"
        "defaults:\n  repos: [explicit, {repo: alias}]\n"
        "activity_sources:\n  git:\n    roots: [root]\n"
        "repository_snapshots:\n  git:\n    repos: [snapshot, {path: explicit}]\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(command)
        assert kwargs["timeout"] == 120
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.delenv("SHEVEK_COLLECT_PRIVACY_KEY", raising=False)
    cli._fetch_configured_git_repositories(config, log=lambda _: None)
    assert [command[-4] for command in calls] == [
        str(path) for path in (explicit, alias, discovered, snapshot)
    ]
    assert all(command[-3:] == ["fetch", "--no-recurse-submodules", "origin"] for command in calls)


def test_invalid_configuration_is_rejected_before_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "collect.yaml"
    config.write_text(
        'version: 1\nactivity_sources:\n  git:\n    repos: [repo]\n'
        '    include_raw_emails: "false"\n', encoding="utf-8",
    )

    def unexpected_fetch(*args: object, **kwargs: object) -> None:
        pytest.fail("An invalid configuration must not trigger a fetch")

    monkeypatch.setattr(cli.subprocess, "run", unexpected_fetch)
    with pytest.raises(ValueError, match="boolean"):
        cli._fetch_configured_git_repositories(config, log=lambda _: None)


def test_discovery_includes_linked_worktrees(tmp_path: Path) -> None:
    original = tmp_path / "original"
    linked = tmp_path / "linked"
    subprocess.run(["git", "init", "--initial-branch=main", str(original)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(original), "-c", "user.name=Test", "-c",
         "user.email=test@example.invalid", "commit", "--allow-empty", "-m", "Initial"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(original), "worktree", "add", "-b", "linked", str(linked)],
        check=True, capture_output=True,
    )
    assert discover_git_repos(tmp_path) == sorted([original, linked])


@pytest.mark.parametrize("problem", ["missing_config", "bad_boolean", "bad_manifest", "missing_output"])
def test_expected_user_errors_have_no_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], problem: str,
) -> None:
    config = tmp_path / "collect.yaml"
    bundle = tmp_path / "bundle"
    if problem == "missing_config":
        args = ["run", "--config", str(config), "--out", str(bundle), "--dry-run"]
    elif problem == "bad_boolean":
        config.write_text(
            'activity_sources:\n  git:\n    repos: [repo]\n    include_raw_emails: "false"\n',
            encoding="utf-8",
        )
        args = ["run", "--config", str(config), "--out", str(bundle), "--dry-run"]
    else:
        bundle.mkdir()
        if problem == "bad_manifest":
            text = "[]"
        else:
            text = json.dumps({
                "schema_version": "shevek.collect_manifest.v1",
                "bundle_kind": "source_evidence", "outputs": {"events": "absent.jsonl"},
            })
        (bundle / "collect_manifest.json").write_text(text, encoding="utf-8")
        args = ["inspect", str(bundle)]
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2
    stderr = capsys.readouterr().err
    assert "error:" in stderr
    assert "Traceback" not in stderr


def test_pack_is_local_requires_no_credentials_and_excludes_undeclared_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "collect_manifest.json").write_text('{"complete": true}', encoding="utf-8")
    (bundle / "source_events.jsonl").write_text('{}\n', encoding="utf-8")
    seal_bundle(bundle)
    (bundle / "private-notes.txt").write_text("not part of the export", encoding="utf-8")
    (bundle / ".shevek_submit_commits.json").write_text("{}", encoding="utf-8")
    for env in ("SHEVEK_COLLECT_PRIVACY_KEY", "SHEVEK_SERVICE_TOKEN"):
        monkeypatch.delenv(env, raising=False)

    def unexpected_call(*args: object, **kwargs: object) -> None:
        pytest.fail("pack must not collect or submit")

    monkeypatch.setattr(cli, "collect_from_config", unexpected_call)
    monkeypatch.setattr(cli, "submit_bundle", unexpected_call)
    archive = tmp_path / "bundle.zip"
    args = ["pack", str(bundle), "--out", str(archive), "--json"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out) == {"zip": str(archive)}
    with zipfile.ZipFile(archive) as zipped:
        assert set(zipped.namelist()) == {"collect_manifest.json", "source_events.jsonl"}
    original_bytes = archive.read_bytes()
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2
    assert archive.read_bytes() == original_bytes
    assert cli.main([*args, "--overwrite"]) == 0


def test_pack_rejects_tampered_blob_without_replacing_archive(tmp_path: Path) -> None:
    import hashlib

    bundle = tmp_path / "bundle"
    code = bundle / "code"
    blob_dir = code / "blobs" / "sha256"
    blob_dir.mkdir(parents=True)
    digest = hashlib.sha256(b"original").hexdigest()
    blob = blob_dir / digest
    blob.write_bytes(b"tampered")
    manifest = {
        "schema_version": "shevek.collect_manifest.v1", "bundle_kind": "evidence_bundle",
        "outputs": {"repository_files": "code/files.jsonl"},
    }
    (bundle / "collect_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (code / "files.jsonl").write_text(json.dumps({
        "blob_path": f"code/blobs/sha256/{digest}", "content_hash": f"sha256:{digest}",
    }) + "\n", encoding="utf-8")
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(b"previous archive")
    with pytest.raises(SystemExit) as exc:
        cli.main(["pack", str(bundle), "--out", str(archive), "--overwrite"])
    assert exc.value.code == 2
    assert archive.read_bytes() == b"previous archive"
