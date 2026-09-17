from __future__ import annotations

import json
from pathlib import Path

import pytest

from shevek_collect.git_collect import GitCollectOptions, collect_git
from shevek_collect.privacy import PrivacyHasher, PrivacyKeyError
from shevek_collect.repo_identity import (
    github_repository_identity,
    repository_identity,
)


def test_hmac_is_stable_domain_separated_and_key_isolated() -> None:
    first = PrivacyHasher(b"a" * 32)
    second = PrivacyHasher(b"b" * 32)

    assert first.email("alice@example.com") == first.email("alice@example.com")
    assert first.email("alice@example.com") != first.actor("alice@example.com")
    assert first.email("alice@example.com") != second.email("alice@example.com")
    assert first.key_id != second.key_id


def test_short_privacy_key_is_rejected() -> None:
    with pytest.raises(PrivacyKeyError, match="at least 32 bytes"):
        PrivacyHasher(b"too-short")


def test_repository_identity_is_stable_within_key_and_changes_across_keys() -> None:
    first = PrivacyHasher(b"a" * 32)
    second = PrivacyHasher(b"b" * 32)
    remote = "git@github.com:Acme/Demo.git"

    local_identity = repository_identity(remote, privacy_hasher=first)
    hosted_identity = github_repository_identity(
        hostname="github.com",
        owner="acme",
        repo="demo",
        privacy_hasher=first,
    )
    other_org_identity = repository_identity(remote, privacy_hasher=second)

    assert local_identity is not None
    assert other_org_identity is not None
    assert local_identity.fingerprint == hosted_identity.fingerprint
    assert local_identity.fingerprint.startswith("repo_v2_")
    assert local_identity.fingerprint != other_org_identity.fingerprint


def test_manifest_contains_key_identifier_but_not_secret(
    tmp_path: Path,
    privacy_hasher: PrivacyHasher,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    import subprocess

    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "alice@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Alice"],
        check=True,
    )
    (repo / "README.md").write_text("# Demo\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "initial"], check=True)

    out = tmp_path / "bundle"
    collect_git(
        GitCollectOptions(
            repos=(repo,),
            out=out,
            privacy_hasher=privacy_hasher,
        )
    )

    manifest_text = (out / "collect_manifest.json").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    assert manifest["identity"] == privacy_hasher.manifest_metadata()
    assert privacy_hasher.key.decode("utf-8") not in manifest_text
    assert "alice@example.com" not in manifest_text
