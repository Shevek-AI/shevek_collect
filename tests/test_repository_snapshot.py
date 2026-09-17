from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from shevek_collect.cli import main
from shevek_collect.run_collect import RunCollectOptions, collect_from_config, plan_collect


def test_repository_snapshot_full_captures_committed_source_and_syntax(tmp_path: Path) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    # Dirty and untracked working-tree state must not leak into the committed snapshot.
    (repo / "src" / "app.py").write_text("raise RuntimeError('dirty')\n", encoding="utf-8")
    (repo / "untracked-secret.txt").write_text("do not collect\n", encoding="utf-8")

    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
repository_snapshots:
  git:
    repos:
      - path: {repo.as_posix()}
        snapshots:
          - name: target
            ref: HEAD
    capture:
      content_mode: full
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    result = collect_from_config(RunCollectOptions(config=config, out=out))

    assert result["errors"] == []
    assert result["source_runs"] == 0
    assert result["snapshots_collected"] == 1
    assert (out / "source_events.jsonl").read_text(encoding="utf-8") == ""
    assert (out / "source_artifacts.jsonl").read_text(encoding="utf-8") == ""

    snapshots = _read_jsonl(out / "code" / "snapshots.jsonl")
    files = _read_jsonl(out / "code" / "files.jsonl")
    assert len(snapshots) == 1
    assert snapshots[0]["requested_ref"] == "HEAD"
    assert snapshots[0]["snapshot_kind"] == "committed_git_tree"
    assert snapshots[0]["dirty_overlay"] is False
    assert snapshots[0]["worktree_dirty_at_collection"] is True

    by_path = {record["path"]: record for record in files}
    assert "untracked-secret.txt" not in by_path
    assert by_path[".env"]["capture_status"] == "omitted"
    assert by_path[".env"]["omit_reason"] == "excluded_by_path_policy"
    assert by_path["image.bin"]["capture_status"] == "omitted"
    assert by_path["image.bin"]["omit_reason"] == "binary_or_non_text"

    app = by_path["src/app.py"]
    assert app["capture_status"] == "captured"
    assert app["parse"]["status"] == "parsed"
    assert app["source_content_included"] is True
    blob_path = out / app["blob_path"]
    committed = "import os\n\nclass Greeter:\n    def greet(self, name: str):\n        return os.path.join('hello', name)\n"
    assert blob_path.read_text(encoding="utf-8") == committed
    assert app["content_hash"] == f"sha256:{hashlib.sha256(committed.encode()).hexdigest()}"
    symbols = app["syntax"]["symbols"]
    assert {(symbol["kind"], symbol["qualname"]) for symbol in symbols} == {
        ("class", "Greeter"),
        ("method", "Greeter.greet"),
    }
    method = next(symbol for symbol in symbols if symbol["qualname"] == "Greeter.greet")
    assert method["inputs"] == ["self", "name"]
    assert {call["callee"] for call in method["raw_calls"]} == {"os.path.join"}

    script = by_path["web/view.ts"]
    assert script["syntax"]["style_imports"][0]["path"] == "./view.css"
    arrow = script["syntax"]["symbols"][0]
    assert arrow["name"] == "render"
    assert arrow["inputs"] == ["name"]

    style = by_path["web/view.css"]
    assert {item["kind"] for item in style["syntax"]["styles"]} >= {
        "css_rule",
        "css_variable",
        "media_query",
    }

    manifest_text = (out / "collect_manifest.json").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    assert repo.as_posix() not in manifest_text
    assert config.as_posix() not in manifest_text
    assert out.as_posix() not in manifest_text
    assert repo.as_posix() not in (out / "privacy_report.md").read_text(encoding="utf-8")
    assert manifest["bundle_version"] == "0.2"
    assert manifest["facets"]["activity"]["enabled"] is False
    assert manifest["facets"]["repository_snapshots"]["enabled"] is True
    assert manifest["privacy"]["contains_file_content"] is True
    assert manifest["privacy"]["contains_verbatim_signatures"] is True
    assert manifest["privacy"]["contains_verbatim_parameter_text"] is True
    assert manifest["privacy"]["contains_raw_import_text"] is True
    assert manifest["privacy"]["contains_git_history_database"] is False
    assert manifest["privacy"]["contains_untracked_files"] is False



def test_snapshot_cli_produces_trace_compatible_full_bundle(tmp_path: Path) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    out = tmp_path / "bundle"

    exit_code = main(
        [
            "snapshot",
            "--repo",
            str(repo),
            "--out",
            str(out),
            "--quiet",
        ]
    )

    assert exit_code == 0
    manifest = json.loads((out / "collect_manifest.json").read_text(encoding="utf-8"))
    assert manifest["command"] == "snapshot"
    facet = manifest["facets"]["repository_snapshots"]
    assert facet["enabled"] is True
    assert facet["content_mode"] == "full"
    assert facet["snapshots"] == "code/snapshots.jsonl"
    assert facet["files"] == "code/files.jsonl"
    snapshots = _read_jsonl(out / "code" / "snapshots.jsonl")
    assert [(item["name"], item["requested_ref"]) for item in snapshots] == [("target", "HEAD")]


def test_repository_snapshot_structure_mode_exports_no_source_blobs(tmp_path: Path) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
repository_snapshots:
  git:
    repos:
      - {repo.as_posix()}
    capture:
      content_mode: structure
      include_globs:
        - src/**
        - web/**
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    result = collect_from_config(RunCollectOptions(config=config, out=out))

    assert result["errors"] == []
    assert not (out / "code" / "blobs").exists()
    files = _read_jsonl(out / "code" / "files.jsonl")
    by_path = {record["path"]: record for record in files}
    app = by_path["src/app.py"]
    assert app["capture_status"] == "captured"
    assert app["content_hash"].startswith("sha256:")
    assert app["blob_path"] is None
    assert app["source_content_included"] is False
    assert app["syntax"]["symbols"]
    assert by_path["README.md"]["omit_reason"] == "not_selected_by_include_glob"

    extraction = json.loads((out / "code" / "extraction_manifest.json").read_text(encoding="utf-8"))
    assert extraction["privacy"]["contains_file_content"] is False
    assert extraction["privacy"]["contains_source_structure"] is True
    assert extraction["privacy"]["contains_verbatim_signatures"] is False
    assert extraction["privacy"]["contains_verbatim_parameter_text"] is False
    assert extraction["privacy"]["contains_raw_import_text"] is False
    assert extraction["counts"]["unique_source_blobs"] == 0


def test_repository_snapshot_structure_mode_removes_verbatim_signature_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    secret_default = "PRIVATE_SIGNATURE_LITERAL_7e39"
    internal_endpoint = "https://internal.example.invalid/private-api"
    (repo / "src" / "defaults.py").write_text(
        "from internal.secret_module import handler as renamed\n\n"
        f'def configure(token: str = "{secret_default}", *, '
        f'endpoint: str = "{internal_endpoint}"):\n'
        "    return renamed(token, endpoint)\n",
        encoding="utf-8",
    )
    _git(repo, "add", "src/defaults.py")
    _git(repo, "commit", "-m", "add signature privacy fixture")

    def fake_extract_syntax(path: str, content: str) -> dict[str, object]:
        if path != "src/defaults.py":
            return {
                "language": None,
                "parse": {"status": "unsupported_language"},
                "syntax": {
                    "schema_version": "shevek.syntax_observations.v2",
                    "symbols": [],
                    "imports": [],
                    "call_sites": [],
                    "references": [],
                    "scopes": [],
                    "exports": [],
                    "publics": [],
                    "includes": [],
                    "styles": [],
                    "style_imports": [],
                },
            }
        return {
            "language": "Python",
            "parse": {"status": "parsed"},
            "syntax": {
                "schema_version": "shevek.syntax_observations.v2",
                "symbols": [
                    {
                        "kind": "function",
                        "name": "configure",
                        "qualname": "configure",
                        "signature": (
                            f'function configure(token: str = "{secret_default}", '
                            f'*, endpoint: str = "{internal_endpoint}")'
                        ),
                        "parameters_text": (
                            f'(token: str = "{secret_default}", '
                            f'*, endpoint: str = "{internal_endpoint}")'
                        ),
                        "inputs": ["token", "endpoint"],
                        "imports": ["internal.secret_module"],
                        "raw_calls": [],
                    }
                ],
                "imports": [
                    {
                        "target": "internal.secret_module",
                        "raw_text": "from internal.secret_module import handler as renamed",
                    }
                ],
                "call_sites": [],
                "references": [],
                "scopes": [],
                "exports": [],
                "publics": [],
                "includes": [],
                "styles": [],
                "style_imports": [],
            },
        }

    monkeypatch.setattr(
        "shevek_collect.repository_snapshot._extract_file",
        lambda path, content: {"extracted": fake_extract_syntax(path, content),
                               "operational": {}}
    )

    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
repository_snapshots:
  git:
    repos:
      - {repo.as_posix()}
    capture:
      content_mode: structure
      include_globs:
        - src/**
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    result = collect_from_config(RunCollectOptions(config=config, out=out))

    assert result["errors"] == []
    files_text = (out / "code" / "files.jsonl").read_text(encoding="utf-8")
    assert secret_default not in files_text
    assert internal_endpoint not in files_text
    assert "from internal.secret_module import handler as renamed" not in files_text

    files = _read_jsonl(out / "code" / "files.jsonl")
    defaults = next(record for record in files if record["path"] == "src/defaults.py")
    symbol = next(
        item for item in defaults["syntax"]["symbols"] if item["name"] == "configure"
    )
    assert symbol["signature"] == "function configure(token, endpoint)"
    assert symbol["parameters_text"] is None
    assert symbol["signature_fidelity"] == "canonical_structure"
    assert all("raw_text" not in item for item in defaults["syntax"]["imports"])

    extraction = json.loads((out / "code" / "extraction_manifest.json").read_text())
    privacy = extraction["privacy"]
    assert privacy["contains_verbatim_signatures"] is False
    assert privacy["contains_verbatim_parameter_text"] is False
    assert privacy["contains_raw_import_text"] is False


def test_repository_snapshot_plan_is_explicit_about_privacy_boundary(tmp_path: Path) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
repository_snapshots:
  git:
    repos:
      - path: {repo.as_posix()}
        snapshots:
          - name: base
            ref: HEAD~0
          - name: target
            ref: HEAD
    capture:
      content_mode: structure
""".lstrip(),
        encoding="utf-8",
    )

    plan = plan_collect(RunCollectOptions(config=config, out=tmp_path / "bundle", dry_run=True))

    snapshot_plan = plan["repository_snapshots"]
    assert snapshot_plan["snapshot_count"] == 2
    assert snapshot_plan["content_mode"] == "structure"
    assert snapshot_plan["tracked_files_only"] is True
    assert snapshot_plan["include_git_history_database"] is False
    assert snapshot_plan["include_untracked_files"] is False


def test_repository_snapshots_deduplicate_blobs_across_refs(tmp_path: Path) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    base = _git_output(repo, "rev-parse", "HEAD")
    (repo / "src" / "second.py").write_text("def second():\n    return 2\n", encoding="utf-8")
    _git(repo, "add", "src/second.py")
    _git(repo, "commit", "-m", "second snapshot")

    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
repository_snapshots:
  git:
    repos:
      - path: {repo.as_posix()}
        snapshots:
          - name: base
            ref: {base}
          - name: target
            ref: HEAD
    capture:
      content_mode: full
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    result = collect_from_config(RunCollectOptions(config=config, out=out))

    assert result["errors"] == []
    snapshots = _read_jsonl(out / "code" / "snapshots.jsonl")
    assert len(snapshots) == 2
    assert len({snapshot["snapshot_id"] for snapshot in snapshots}) == 2
    files = _read_jsonl(out / "code" / "files.jsonl")
    readmes = [record for record in files if record["path"] == "README.md"]
    assert len(readmes) == 2
    assert readmes[0]["content_hash"] == readmes[1]["content_hash"]
    extraction = json.loads((out / "code" / "extraction_manifest.json").read_text(encoding="utf-8"))
    assert extraction["counts"]["unique_source_blobs"] < extraction["counts"]["captured_files"]
    assert extraction["privacy"]["contains_historical_file_content"] is True


def test_repository_snapshot_emits_operational_structures_and_flattened_records(
    tmp_path: Path,
) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "COPY pyproject.toml uv.lock ./\n"
        "RUN uv pip install --system .\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        "[project]\n"
        'name = "demo"\n'
        'version = "1.0.0"\n'
        'dependencies = ["tree-sitter>=0.22"]\n',
        encoding="utf-8",
    )
    (repo / "uv.lock").write_text(
        "version = 1\n"
        "revision = 2\n"
        "[[package]]\n"
        'name = "tree-sitter"\n'
        'version = "0.25.2"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    _git(repo, "add", "Dockerfile", "pyproject.toml", "uv.lock")
    _git(repo, "commit", "-m", "add operational fixtures")

    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
repository_snapshots:
  git:
    repos:
      - {repo.as_posix()}
    capture:
      content_mode: structure
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    result = collect_from_config(RunCollectOptions(config=config, out=out))

    assert result["errors"] == []
    files = _read_jsonl(out / "code" / "files.jsonl")
    by_path = {record["path"]: record for record in files}
    assert by_path["Dockerfile"]["operational_structure"]["artifact_kind"] == "container_build"
    assert by_path["pyproject.toml"]["operational_structure"]["artifact_kind"] == (
        "dependency_manifest"
    )
    assert by_path["uv.lock"]["operational_structure"]["artifact_kind"] == "dependency_lock"

    records = _read_jsonl(out / "code" / "operational_records.jsonl")
    docker_records = [record for record in records if record["path"] == "Dockerfile"]
    assert any(record["kind"] == "dependency_install" for record in docker_records)
    assert all(record["repo_id"] == by_path["Dockerfile"]["repo_id"] for record in records)

    extraction = json.loads((out / "code" / "extraction_manifest.json").read_text())
    assert extraction["counts"]["operational_records"] == len(records)
    artifact_counts = extraction["counts"]["operational_artifact_counts"]
    assert artifact_counts["container_build"] >= 1
    assert artifact_counts["dependency_lock"] >= 1
    assert artifact_counts["dependency_manifest"] >= 1
    manifest = json.loads((out / "collect_manifest.json").read_text())
    facet = manifest["facets"]["repository_snapshots"]
    assert facet["operational_records"] == "code/operational_records.jsonl"
    assert manifest["counts"]["repository_operational_records"] == len(records)


def test_repository_snapshot_captures_sql_structural_references(tmp_path: Path) -> None:
    repo = tmp_path / "sql-repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "database").mkdir()
    (repo / "database" / "order.sql").write_text(
        "CREATE OR ALTER PROCEDURE dbo.usp_Order AS\n"
        "BEGIN\n"
        "  SELECT * FROM dbo.OrderHeader;\n"
        "  UPDATE dbo.Customer SET ModifiedDate=GETDATE();\n"
        "END\nGO\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "sql fixture")

    config = tmp_path / "collect.yaml"
    config.write_text(
        f"""
version: 1
repository_snapshots:
  git:
    repos:
      - {repo.as_posix()}
    capture:
      content_mode: structure
""".lstrip(),
        encoding="utf-8",
    )
    out = tmp_path / "bundle"

    result = collect_from_config(RunCollectOptions(config=config, out=out))

    assert result["errors"] == []
    files = _read_jsonl(out / "code" / "files.jsonl")
    sql = next(record for record in files if record["path"] == "database/order.sql")
    assert sql["language"] == "sql"
    assert sql["parse"]["status"] == "parsed"
    assert sql["parse"]["validation_level"] == "structural_scan"
    assert sql["syntax"]["schema_version"] == "shevek.syntax_observations.v2"
    assert {(ref["kind"], ref["target"]) for ref in sql["syntax"]["references"]} >= {
        ("read", "dbo.OrderHeader"),
        ("write", "dbo.Customer"),
    }
    extraction = json.loads((out / "code" / "extraction_manifest.json").read_text())
    assert extraction["syntax_observations_schema_version"] == "shevek.syntax_observations.v2"
    assert extraction["counts"]["language_counts"]["sql"] == 1
    assert extraction["counts"]["files_with_references"] == 1
    assert extraction["counts"]["reference_observations"] == 2
    assert extraction["counts"]["reference_kind_counts"] == {"read": 1, "write": 1}
    assert extraction["builtin_syntax_parsers"]["sql"] == "shevek_collect_sql_structure.v1"


def _make_snapshot_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test User")

    (path / "src").mkdir()
    (path / "web").mkdir()
    (path / "README.md").write_text("# Demo\n", encoding="utf-8")
    (path / ".env").write_text("TOKEN=not-a-real-secret\n", encoding="utf-8")
    (path / "image.bin").write_bytes(b"\x00\x01\x02binary")
    (path / "src" / "app.py").write_text(
        "import os\n\nclass Greeter:\n    def greet(self, name: str):\n"
        "        return os.path.join('hello', name)\n",
        encoding="utf-8",
    )
    (path / "web" / "view.ts").write_text(
        "import './view.css';\nexport const render = (name: string) => greet(name);\n",
        encoding="utf-8",
    )
    (path / "web" / "view.css").write_text(
        ":root { --accent: red; color: var(--accent); }\n"
        "@media (max-width: 800px) { .title { display: none; } }\n",
        encoding="utf-8",
    )
    _git(path, "add", ".")
    _git(path, "commit", "-m", "snapshot fixture")
    return path


def _git_output(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout.strip()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_snapshot_does_not_claim_gitignore_filters_committed_files(tmp_path: Path) -> None:
    repo = _make_snapshot_repo(tmp_path / "repo")
    (repo / ".gitignore").write_text("src/app.py\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-m", "Ignore an already tracked path")
    out = tmp_path / "bundle"
    result = collect_from_config(RunCollectOptions(
        config=tmp_path / "collect.yaml", out=out,
        config_data={"version": 1, "repository_snapshots": {"git": {"repos": [str(repo)]}}},
    ))
    assert result["errors"] == []
    files = _read_jsonl(out / "code" / "files.jsonl")
    app = next(row for row in files if row["path"] == "src/app.py")
    assert app["source_content_included"] is True
    extraction = json.loads((out / "code" / "extraction_manifest.json").read_text())
    assert extraction["settings"]["ignored_files_included"] is None
    assert extraction["settings"]["gitignore_applied"] is False
    assert extraction["privacy"]["contains_ignored_files"] is None
    assert "Gitignore rules are not applied" in (out / "privacy_report.md").read_text()
