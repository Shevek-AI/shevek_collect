"""Regression coverage for the pre-publication hardening findings.
All credentials, repositories and remote names in this file are synthetic.
"""
from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import zipfile
from pathlib import Path
from urllib.request import Request
from urllib.error import HTTPError
from shevek_collect.http_security import NoRedirects
from shevek_collect.api_submit import ApiSubmissionError
from shevek_collect.filesystem import FileSafetyError

import pytest

from shevek_collect.api_submit import submit_bundle, zip_bundle
from shevek_collect.git_collect import GitCollectOptions, collect_git
from shevek_collect.io_utils import atomic_bundle_directory
from shevek_collect.privacy import PrivacyHasher
from shevek_collect.run_collect import RunCollectOptions, collect_from_config


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    monkeypatch.setenv("SHEVEK_COLLECT_PRIVACY_KEY", "AUDIT_ONLY_KEY_" + "x" * 32)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        capture_output=True, text=True, timeout=15,
    ).stdout.strip()


def make_repo(parent: Path, files: dict[str, str] | None = None) -> Path:
    repo = parent / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Audit Person")
    git(repo, "config", "user.email", "audit-person@example.invalid")
    for name, value in (files or {"README.md": "Synthetic audit fixture\n"}).items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "Synthetic fixture")
    return repo


def snapshot(parent: Path, repo: Path, *, mode: str = "structure") -> Path:
    out = parent / "bundle"
    result = collect_from_config(RunCollectOptions(
        config=parent / "config.yaml", config_dir=parent,
        config_data={"version": 1, "repository_snapshots": {"git": {
            "repos": [{"path": str(repo)}],
            "capture": {"content_mode": mode},
        }}}, out=out,
    ))
    assert result["complete"] is True
    return out


@pytest.mark.parametrize("name,content,marker", [
    ("Dockerfile", 'FROM alpine\nRUN ["tool", "--password", "AUDIT_DOCKER_SECRET"]\n', "AUDIT_DOCKER_SECRET"),
    ("docker-compose.yml", "services:\n  app:\n    command: tool --password AUDIT_COMPOSE_SECRET\n", "AUDIT_COMPOSE_SECRET"),
    ("pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n  containers:\n  - name: app\n    command: [tool]\n    args: [--password, AUDIT_KUBE_SECRET]\n", "AUDIT_KUBE_SECRET"),
    ("run.sh", 'curl -H "Authorization: Bearer AUDIT_HEADER_SECRET" https://example.invalid\n', "AUDIT_HEADER_SECRET"),
    ("pyproject.toml", '[project]\nname="demo"\ndependencies=["internal @ https://user:AUDIT_DEPENDENCY_SECRET@example.invalid/package.whl"]\n', "AUDIT_DEPENDENCY_SECRET"),
])
def test_structure_bundle_omits_command_secrets(tmp_path, name, content, marker):
    out = snapshot(tmp_path, make_repo(tmp_path, {name: content}))
    assert marker not in (out / "code/files.jsonl").read_text()
    assert marker not in (out / "code/operational_records.jsonl").read_text()
    assert not (out / "code/blobs").exists()
    manifest = json.loads((out / "code/extraction_manifest.json").read_text())
    assert manifest["privacy"]["contains_file_content"] is False


def test_structure_bundle_omits_yaml_source_in_diagnostics(tmp_path):
    out = snapshot(tmp_path, make_repo(tmp_path, {
        "broken.yaml": "password: [AUDIT_YAML_SECRET\n"
    }))
    records = [json.loads(x) for x in (out / "code/files.jsonl").read_text().splitlines()]
    error = records[0]["operational_structure"]["parse"]
    assert error["status"] == "parse_failed"
    assert error["error"] == "ParserError"
    assert "AUDIT_YAML_SECRET" not in json.dumps(records)
    assert json.loads((out / "collect_manifest.json").read_text())["complete"] is True


@pytest.mark.parametrize("name,content,marker", [
    ("demo.cpp", 'void f(const char* password = "AUDIT_CPP_SECRET") {}\n', "AUDIT_CPP_SECRET"),
    ("demo.py", 'def f(x="first,AUDIT_DEFAULT_SECRET"):\n    pass\n', "AUDIT_DEFAULT_SECRET"),
    ("demo.js", 'function f(x="first,AUDIT_DEFAULT_SECRET") {}\n', "AUDIT_DEFAULT_SECRET"),
    ("demo.ts", 'function f(x="first,AUDIT_DEFAULT_SECRET") {}\n', "AUDIT_DEFAULT_SECRET"),
    ("chain.py", 'def f():\n    factory("AUDIT_RECEIVER_SECRET").run()\n', "AUDIT_RECEIVER_SECRET"),
    ("chain.js", 'function f() { factory("AUDIT_RECEIVER_SECRET").run(); }\n', "AUDIT_RECEIVER_SECRET"),
])
def test_structure_bundle_omits_literals_from_syntax_fields(tmp_path, name, content, marker):
    out = snapshot(tmp_path, make_repo(tmp_path, {name: content}))
    rows = [json.loads(x) for x in (out / "code/files.jsonl").read_text().splitlines()]
    assert marker not in json.dumps(rows[0]["syntax"])
    assert rows[0]["source_content_included"] is False
    assert all(symbol["parameters_text"] is None for symbol in rows[0]["syntax"]["symbols"])


def test_quoted_false_is_rejected(tmp_path):
    repo = make_repo(tmp_path)
    config = tmp_path / "config.yaml"
    config.write_text("version: 1\nactivity_sources:\n  git:\n    repos: [" + str(repo)
                      + ']\n    include_raw_emails: "false"\n')
    with pytest.raises(ValueError, match="include_raw_emails"):
        collect_from_config(RunCollectOptions(config=config, out=tmp_path / "bundle"))






def test_submit_refuses_cleartext_before_sending(tmp_path):
    archive = tmp_path / "fixture.zip"
    archive.write_bytes(b"SYNTHETIC BUNDLE")
    def never_send(*args, **kwargs):
        pytest.fail("Insecure request reached the network transport")
    with pytest.raises(ApiSubmissionError, match="HTTPS"):
        submit_bundle(zip_path=archive, jobs=[{"job": "catalogue"}],
                      token="AUDIT_SERVICE_TOKEN", api_endpoint="http://127.0.0.1:9",
                      opener=never_send)



@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("target", ["http://other.example.invalid/sink", "https://other.example.invalid/sink"])
def test_authenticated_redirects_are_refused(code, target):
    for authorization in ["Bearer AUDIT_SERVICE_TOKEN", "Basic QVVESVQ6T05MWQ=="]:
        request = Request("https://trusted.example.invalid/path", method="POST",
                          headers={"Authorization": authorization})
        with pytest.raises(HTTPError):
            NoRedirects().redirect_request(request, None, code, "Redirect", {}, target)



def minimal_bundle(stage: Path):
    (stage / "source_events.jsonl").write_text("")
    (stage / "collect_manifest.json").write_text(json.dumps({
        "schema_version": "shevek.collect_manifest.v1", "bundle_kind": "source_evidence",
        "outputs": {"source_events": "source_events.jsonl"},
    }))


def test_zip_rejects_destination_symlink(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    minimal_bundle(bundle)
    victim = tmp_path / "unrelated-important-file.txt"
    victim.write_text("SYNTHETIC IMPORTANT FILE")
    link = tmp_path / "bundle.zip"
    link.symlink_to(victim)
    with pytest.raises((ApiSubmissionError, FileSafetyError)):
        zip_bundle(bundle, link)
    assert victim.read_text() == "SYNTHETIC IMPORTANT FILE"



def test_zip_rejects_source_symlink(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    minimal_bundle(bundle)
    outside = tmp_path / "synthetic-secret.txt"
    outside.write_text("AUDIT_OUTSIDE_BUNDLE_SECRET")
    (bundle / "unlisted.txt").symlink_to(outside)
    with pytest.raises(ApiSubmissionError, match="symlink"):
        zip_bundle(bundle, tmp_path / "bundle.zip")
    assert not (tmp_path / "bundle.zip").exists()



def test_zip_preserves_private_permissions(tmp_path):
    old_umask = os.umask(0o022)
    try:
        bundle = tmp_path / "bundle"
        with atomic_bundle_directory(bundle) as stage:
            minimal_bundle(stage)
        archive = zip_bundle(bundle, tmp_path / "bundle.zip")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600


def test_output_created_during_collection_is_preserved(tmp_path):
    out = tmp_path / "bundle"
    with pytest.raises(FileSafetyError):
        with atomic_bundle_directory(out) as stage:
            minimal_bundle(stage)
            out.mkdir()
            (out / "unrelated.txt").write_text("SYNTHETIC IMPORTANT FILE")
    assert (out / "unrelated.txt").read_text() == "SYNTHETIC IMPORTANT FILE"



def test_git_status_disables_repository_fsmonitor_command(tmp_path):
    repo = make_repo(tmp_path)
    marker = tmp_path / "fsmonitor-executed.txt"
    hook = repo / ".git" / "audit-fsmonitor"
    hook.write_text("#!/bin/sh\nprintf 'audit executed\\n' > " + shlex.quote(str(marker)) + "\nprintf '\\0'\n")
    hook.chmod(0o700)
    git(repo, "config", "core.fsmonitor", str(hook))
    result = collect_git(GitCollectOptions(repos=(repo,), out=tmp_path / "bundle"))
    assert result["complete"] is True
    assert not marker.exists()


def test_snapshot_error_omits_absolute_repository_path(tmp_path):
    repo = tmp_path / "private-customer" / "missing-repository"
    out = tmp_path / "bundle"
    result = collect_from_config(RunCollectOptions(
        config=tmp_path / "config.yaml", config_data={
            "repository_snapshots": {"git": {"repos": [{"path": str(repo)}]}}
        }, out=out,
    ))
    assert result["complete"] is False
    assert str(repo) not in (out / "collect_manifest.json").read_text()
    assert str(repo) not in (out / "code/extraction_manifest.json").read_text()


def test_default_full_capture_excludes_common_secret_file_variants(tmp_path):
    out = snapshot(tmp_path, make_repo(tmp_path, {
        ".env.prod": "API_TOKEN=AUDIT_ENV_SECRET\n",
        "id_ecdsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nAUDIT_FAKE_KEY\n",
        ".npmrc": "//registry.example.invalid/:_authToken=AUDIT_NPM_SECRET\n",
    }), mode="full")
    records = [json.loads(x) for x in (out / "code/files.jsonl").read_text().splitlines()]
    assert len(records) == 3
    assert all(row["source_content_included"] is False for row in records)
    assert all(row["capture_status"] == "omitted" for row in records)


def test_azure_nested_work_item_url_respects_include_urls_false():
    from shevek_collect.azure_devops_collect import _pull_request_event
    url = "https://dev.azure.com/private-org/private-project/_apis/wit/workItems/1"
    event = _pull_request_event(
        {"pullRequestId": 1, "workItemRefs": [{"id": "1", "url": url}]},
        {"repo_id": "audit_repo"}, observed_at="2026-09-11T00:00:00Z",
        body_mode="none", actor_mode="none", include_urls=False,
        privacy_hasher=PrivacyHasher(b"x" * 32),
    )
    assert event["privacy"]["contains_urls"] is False
    assert "url" not in event["payload"]["work_item_refs"][0]


@pytest.mark.parametrize("mode", ["none", "hash"])
def test_github_nested_fork_owner_respects_actor_mode(mode):
    from shevek_collect.github_collect import _pull_request_event
    event = _pull_request_event(
        {"number": 1, "head": {"ref": "feature", "sha": "abc", "repo": {
            "full_name": "audit-person/repo", "owner": {"login": "audit-person"}
        }}}, {"repo_id": "audit_repo", "hostname": "github.com"},
        observed_at="2026-09-11T00:00:00Z", body_mode="none", actor_mode=mode,
        include_urls=False, privacy_hasher=PrivacyHasher(b"x" * 32),
    )
    assert "owner_login" not in event["payload"]["head"]
    if mode == "hash":
        assert event["payload"]["head"]["owner_login_hash"]
    else:
        assert "owner_login_hash" not in event["payload"]["head"]


def test_tiny_yaml_merge_graph_is_rejected_before_expansion():
    from shevek_collect.parser_worker import run_parser
    content = "a0: &a0 {x: 1}\n"
    for i in range(1, 31):
        content += f"a{i}: &a{i} {{<<: [*a{i-1}, *a{i-1}]}}\n"
    result = run_parser("file", {"path": "config.yaml", "content": content})
    assert result["operational"]["parse"]["status"] == "parse_failed"
    assert result["operational"]["parse"]["error"] == "YamlLimitError"



def test_direct_activity_manifest_omits_absolute_output_path(tmp_path):
    repo = make_repo(tmp_path)
    out = tmp_path / "private-client" / "bundle"
    collect_git(GitCollectOptions(repos=(repo,), out=out))
    manifest = json.loads((out / "collect_manifest.json").read_text())
    assert manifest["settings"]["include_local_paths"] is False
    assert manifest["out"] == out.name
    assert manifest["out_path_hash"]
    assert str(out.resolve()) not in json.dumps(manifest)


def test_archive_is_declared_only_and_requires_explicit_replacement(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    minimal_bundle(bundle)
    (bundle / "unrelated.txt").write_text("AUDIT_UNLISTED_SECRET")
    archive = zip_bundle(bundle, tmp_path / "bundle.zip")
    with zipfile.ZipFile(archive) as contents:
        assert set(contents.namelist()) == {"collect_manifest.json", "source_events.jsonl"}
    archive.write_bytes(b"PREVIOUS FILE")
    with pytest.raises(ApiSubmissionError, match="overwrite-zip"):
        zip_bundle(bundle, archive)
    assert archive.read_bytes() == b"PREVIOUS FILE"
    zip_bundle(bundle, archive, overwrite=True)
    assert zipfile.is_zipfile(archive)


def test_archive_cannot_be_written_inside_its_source(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    minimal_bundle(bundle)
    with pytest.raises(ApiSubmissionError, match="outside"):
        zip_bundle(bundle, bundle / "recursive.zip")


def test_full_snapshot_archive_checks_content_addressed_blobs(tmp_path):
    content = "def safe_function(argument):\n    return argument\n"
    bundle = snapshot(tmp_path, make_repo(tmp_path, {"main.py": content}), mode="full")
    row = json.loads((bundle / "code/files.jsonl").read_text().strip())
    archive = zip_bundle(bundle, tmp_path / "bundle.zip")
    with zipfile.ZipFile(archive) as zipped:
        assert zipped.read(row["blob_path"]).decode() == content
        assert "code/files.jsonl" in zipped.namelist()
    original = archive.read_bytes()
    (bundle / row["blob_path"]).write_text("TAMPERED")
    with pytest.raises(ApiSubmissionError, match="hash"):
        zip_bundle(bundle, archive, overwrite=True)
    assert archive.read_bytes() == original


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "C:\\private.txt", "code/../../outside"])
def test_archive_rejects_unsafe_declared_paths(tmp_path, path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    minimal_bundle(bundle)
    manifest_path = bundle / "collect_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["outputs"]["unsafe"] = path
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ApiSubmissionError):
        zip_bundle(bundle, tmp_path / "bundle.zip")


def test_changes_to_previous_output_are_preserved(tmp_path):
    out = tmp_path / "bundle"
    with atomic_bundle_directory(out) as stage:
        minimal_bundle(stage)
    with pytest.raises(FileSafetyError):
        with atomic_bundle_directory(out, overwrite=True) as stage:
            minimal_bundle(stage)
            (out / "concurrent.txt").write_text("CONCURRENT WORK")
    assert (out / "concurrent.txt").read_text() == "CONCURRENT WORK"


def test_simultaneous_collectors_cannot_share_destination(tmp_path):
    out = tmp_path / "bundle"
    with atomic_bundle_directory(out) as stage:
        with pytest.raises(FileSafetyError, match="Another collection"):
            with atomic_bundle_directory(out):
                pytest.fail("Second collector acquired the same output")
        minimal_bundle(stage)


def test_publication_race_preserves_interloper_and_recovery(tmp_path, monkeypatch):
    import shevek_collect.filesystem as filesystem
    out = tmp_path / "bundle"
    with atomic_bundle_directory(out) as stage:
        minimal_bundle(stage)
        (stage / "old.txt").write_text("PREVIOUS BUNDLE")
    rename = filesystem.rename_noreplace
    def inject_interloper(source, target):
        if target == out and ".staging-" in source.name:
            out.mkdir()
            (out / "new.txt").write_text("UNRELATED DATA")
        rename(source, target)
    monkeypatch.setattr(filesystem, "rename_noreplace", inject_interloper)
    with pytest.raises(FileSafetyError, match="recovery preserved"):
        with atomic_bundle_directory(out, overwrite=True) as stage:
            minimal_bundle(stage)
    assert (out / "new.txt").read_text() == "UNRELATED DATA"
    recoveries = list(tmp_path.glob(".bundle.recovery-*/previous/old.txt"))
    assert len(recoveries) == 1
    assert recoveries[0].read_text() == "PREVIOUS BUNDLE"


def test_custom_merge_driver_is_not_executed(tmp_path):
    from shevek_collect.git_topology import _merge_viability
    repo = make_repo(tmp_path, {"data.txt": "base\n", ".gitattributes": "data.txt merge=audit\n"})
    git(repo, "checkout", "-b", "feature")
    (repo / "data.txt").write_text("feature\n")
    git(repo, "commit", "-am", "feature")
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "main")
    (repo / "data.txt").write_text("main\n")
    git(repo, "commit", "-am", "main")
    base = git(repo, "rev-parse", "HEAD")
    marker = tmp_path / "merge-driver-executed"
    git(repo, "config", "merge.audit.driver", "touch " + shlex.quote(str(marker)))
    result = _merge_viability(repo, base_sha=base, head_sha=head)
    assert result == {"state": "not_checked", "error": "custom_merge_driver_disabled"}
    assert not marker.exists()


def test_git_does_not_inherit_provider_tokens_or_redirected_repository(tmp_path, monkeypatch):
    from shevek_collect.git_security import run_git, observation_environment
    repo = make_repo(tmp_path)
    monkeypatch.setenv("GIT_DIR", "/synthetic/wrong/repo")
    monkeypatch.setenv("SHEVEK_SERVICE_TOKEN", "AUDIT_TOKEN")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    env = observation_environment()
    assert "SHEVEK_SERVICE_TOKEN" not in env
    assert "GIT_DIR" not in env
    assert "GIT_CONFIG_COUNT" not in env
    assert env["GIT_ALLOW_PROTOCOL"] == ""
    assert env["GIT_NO_LAZY_FETCH"] == "1"
    assert run_git(repo, ["rev-parse", "--is-inside-work-tree"]).stdout.strip() == "true"


def test_git_timeout_is_finite_and_safe(tmp_path, monkeypatch):
    import shevek_collect.git_security as security
    def timed_out(command, **kwargs):
        assert 0 < kwargs["timeout"] <= 60
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr=b"AUDIT_TOKEN")
    monkeypatch.setattr(security.subprocess, "run", timed_out)
    with pytest.raises(RuntimeError) as error:
        security.run_git(tmp_path, ["status"])
    assert "AUDIT_TOKEN" not in str(error.value)


def test_parser_budget_terminates_child_and_returns_safe_diagnostic(monkeypatch):
    import shevek_collect.parser_worker as worker
    # Start the real parser process with a deliberately exhausted wall budget.
    monkeypatch.setattr(worker, "PARSER_TIMEOUT_SECONDS", 0.000001)
    with pytest.raises(worker.ParserBudgetExceeded):
        worker.run_parser("file", {"path": "main.py", "content": "x = 1\n"})


def test_yaml_normal_aliases_work_but_cycles_and_depth_are_rejected():
    from shevek_collect.safe_yaml import load_documents, YamlLimitError
    assert load_documents("defaults: &d {name: app}\nservice: {<<: *d, port: 8000}")[0]["service"] == {
        "name": "app", "port": 8000,
    }
    for content in ["x: &x {self: *x}", "[" * 100 + "0" + "]" * 100, "---\nx: 1\n" * 201]:
        with pytest.raises(YamlLimitError):
            load_documents(content)


def test_structure_selector_omits_quoted_and_unquoted_attribute_literals():
    from shevek_collect.structure_privacy import sanitize_syntax_fields
    syntax = {"styles": [{"selector": '[data-a=AUDIT_SECRET][data-b="AUDIT_SECRET]"]'}]}
    sanitize_syntax_fields(syntax)
    assert "AUDIT_SECRET" not in json.dumps(syntax)
    assert "data-a" in json.dumps(syntax)


@pytest.mark.parametrize("url", ["http://host.test", "https://u:p@host.test", "https://host.test/#token",
                                "https://host.test:invalid", "https://host.test/\r\nheader", "file:///private"])
def test_authenticated_endpoint_validation(url):
    from shevek_collect.http_security import validate_https_url
    with pytest.raises(ValueError):
        validate_https_url(url)


def test_response_size_and_multipart_header_bounds():
    import io
    from urllib.error import URLError
    from shevek_collect.http_security import read_response, multipart_filename
    with pytest.raises(URLError):
        read_response(io.BytesIO(b"oversized"), limit=3)
    assert read_response(io.BytesIO(b"ok"), limit=3) == b"ok"
    name = multipart_filename('unsafe"\r\nX-Secret: injected.zip')
    assert all(char not in name for char in '\r\n"')


def test_default_authenticated_transport_never_contacts_redirect_target(monkeypatch):
    import io
    from email.message import Message
    from urllib.request import HTTPSHandler, build_opener
    from urllib.response import addinfourl
    import shevek_collect.http_security as security
    visited = []
    class SyntheticHTTPS(HTTPSHandler):
        def https_open(self, request):
            visited.append(request.full_url)
            headers = Message()
            headers["Location"] = "https://other.example.invalid/steal"
            response = addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
            response.msg = "Found"
            return response
    monkeypatch.setattr(security, "build_opener",
                        lambda *handlers: build_opener(SyntheticHTTPS(), *handlers))
    request = Request("https://origin.example.invalid/api", method="POST", data=b"bundle",
                      headers={"Authorization": "Bearer AUDIT_TOKEN"})
    with pytest.raises(HTTPError) as error:
        security.secure_urlopen(request)
    error.value.close()
    assert visited == ["https://origin.example.invalid/api"]
