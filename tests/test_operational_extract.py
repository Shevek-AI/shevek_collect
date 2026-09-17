from __future__ import annotations

import importlib.util

import pytest

from shevek_collect.operational_extract import (
    classify_operational_artifact,
    extract_operational_structure,
    operational_records_for_file,
)


def test_classifies_operational_artifacts_by_role() -> None:
    assert classify_operational_artifact("Dockerfile").artifact_kind == "container_build"
    assert classify_operational_artifact("scripts/build.sh").artifact_kind == "shell_script"
    assert classify_operational_artifact("pyproject.toml").artifact_kind == "dependency_manifest"
    assert classify_operational_artifact("uv.lock").artifact_kind == "dependency_lock"
    assert (
        classify_operational_artifact(".github/workflows/test.yml").artifact_kind == "workflow"
    )
    assert (
        classify_operational_artifact("docker-compose.yaml").artifact_kind
        == "container_orchestration"
    )
    assert (
        classify_operational_artifact("script", "#!/usr/bin/env bash\necho ok\n").format
        == "bash"
    )


def test_dockerfile_extracts_stages_build_inputs_and_nested_dependency_install() -> None:
    result = extract_operational_structure(
        "Dockerfile",
        """
FROM --platform=linux/amd64 python:3.12-slim AS runtime
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \\
    uv pip install --system .
ENTRYPOINT ["python", "-m", "demo"]
""".lstrip(),
    )

    assert result["parse"]["status"] == "parsed"
    assert result["artifact_kind"] == "container_build"
    stage = next(item for item in result["entities"] if item["kind"] == "container_stage")
    assert stage["name"] == "runtime"
    assert stage["platform"] == "linux/amd64"

    base = next(item for item in result["references"] if item["kind"] == "base_image")
    assert base["value"] == "python:3.12-slim"
    assert base["digest_pinned"] is False

    transfer = next(
        item for item in result["operations"] if item["kind"] == "container_file_transfer"
    )
    assert transfer["sources"] == ["pyproject.toml", "uv.lock"]
    assert transfer["destination"] == "./"

    install = next(item for item in result["operations"] if item["kind"] == "dependency_install")
    assert install["manager"] == "uv"
    assert install["manifest_install"] is True
    assert install["lock_enforced"] is False

    entrypoint = next(
        item for item in result["operations"] if item["kind"] == "container_entrypoint"
    )
    assert entrypoint["form"] == "exec"
    assert entrypoint["argv"] == ["python", "-m", "demo"]


def test_locked_uv_sync_is_observed_without_interpreting_it() -> None:
    result = extract_operational_structure(
        "Dockerfile",
        "FROM python:3.12-slim\nRUN uv sync --locked --no-dev\n",
    )

    install = next(item for item in result["operations"] if item["kind"] == "dependency_install")
    assert install["manager"] == "uv"
    assert install["lock_enforced"] is True
    assert install["lock_enforcement_flags"] == ["--locked"]


def test_shell_extracts_controls_downloads_and_redacts_sensitive_assignments() -> None:
    result = extract_operational_structure(
        "scripts/bootstrap.sh",
        """#!/usr/bin/env bash
set -euo pipefail
API_TOKEN=do-not-export curl -fsSL https://example.invalid/install.sh | sh
uv sync --locked
""",
    )

    assert result["parse"]["status"] == "parsed"
    assignment = next(
        item for item in result["operations"] if item["kind"] == "environment_assignment"
    )
    assert assignment["name"] == "API_TOKEN"
    assert assignment["value"] == "<redacted-sensitive-literal>"
    assert "do-not-export" not in str(result)
    assert any(item["kind"] == "external_download" for item in result["references"])
    shell_control = next(
        item for item in result["controls"] if item["kind"] == "shell_error_handling"
    )
    assert shell_control["errexit"] is True
    assert shell_control["nounset"] is True
    assert shell_control["pipefail"] is True


def test_pyproject_and_uv_lock_emit_dependency_contract_evidence() -> None:
    project = extract_operational_structure(
        "pyproject.toml",
        """
[project]
name = "demo"
version = "1.0.0"
requires-python = ">=3.11"
dependencies = ["tree-sitter>=0.22", "requests==2.32.0"]

[project.scripts]
demo = "demo.cli:main"

[dependency-groups]
dev = ["pytest>=8"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
""".lstrip(),
    )

    declarations = [
        item for item in project["references"] if item["kind"] == "dependency_declaration"
    ]
    assert {(item["name"], item["constraint"]) for item in declarations} >= {
        ("tree-sitter", ">=0.22"),
        ("requests", "==2.32.0"),
        ("pytest", ">=8"),
    }
    assert any(item["kind"] == "package_entrypoint" for item in project["operations"])
    assert any(item["kind"] == "build_backend" for item in project["controls"])

    lock = extract_operational_structure(
        "uv.lock",
        """
version = 1
revision = 2
requires-python = ">=3.11"

[[package]]
name = "tree-sitter-python"
version = "0.25.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
  { url = "https://files.example/tree_sitter_python-0.25.0-cp39-abi3-manylinux.whl" },
]

[[package]]
name = "pure-package"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
  { url = "https://files.example/pure_package-1.0.0-py3-none-any.whl" },
]
""".lstrip(),
    )
    resolved = {
        item["name"]: item
        for item in lock["references"]
        if item["kind"] == "resolved_dependency"
    }
    assert resolved["tree-sitter-python"]["platform_specific_wheel"] is True
    assert resolved["pure-package"]["platform_specific_wheel"] is False


def test_yaml_adapters_extract_workflows_compose_and_kubernetes() -> None:
    workflow = extract_operational_structure(
        ".github/workflows/test.yml",
        """
name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: install
        run: uv sync --locked
""".lstrip(),
    )
    assert workflow["artifact_kind"] == "workflow"
    assert any(item["kind"] == "workflow_job" for item in workflow["entities"])
    action = next(item for item in workflow["references"] if item["kind"] == "workflow_action")
    assert action["immutable_revision"] is False
    install = next(item for item in workflow["operations"] if item["kind"] == "dependency_install")
    assert install["lock_enforced"] is True

    compose = extract_operational_structure(
        "compose.yaml",
        """
services:
  api:
    image: example/api:latest
    build:
      context: .
      dockerfile: Dockerfile
    depends_on: [db]
    restart: unless-stopped
  db:
    image: postgres@sha256:abc
""".lstrip(),
    )
    assert compose["artifact_kind"] == "container_orchestration"
    images = [item for item in compose["references"] if item["kind"] == "container_image"]
    assert {item["value"] for item in images} == {"example/api:latest", "postgres@sha256:abc"}
    assert next(item for item in images if item["value"] == "postgres@sha256:abc")[
        "digest_pinned"
    ] is True

    deployment = extract_operational_structure(
        "deploy/app.yaml",
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: api
          image: example/api:v1
          resources:
            limits:
              memory: 1Gi
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
""".lstrip(),
    )
    assert deployment["artifact_kind"] == "deployment_config"
    assert any(item["kind"] == "container_resource_policy" for item in deployment["controls"])
    assert any(item["kind"] == "container_health_probe" for item in deployment["controls"])


def test_flattened_operational_records_have_stable_ids_and_provenance() -> None:
    structure = extract_operational_structure(
        "Dockerfile",
        "FROM python:3.12-slim\nRUN uv sync --locked\n",
    )
    file_record = {
        "repo_id": "repo_1",
        "snapshot_id": "snapshot_1",
        "file_id": "file_1",
        "path": "Dockerfile",
        "operational_structure": structure,
    }

    first = operational_records_for_file(file_record)
    second = operational_records_for_file(file_record)

    assert first == second
    assert first
    assert all(record["file_id"] == "file_1" for record in first)
    assert all(record["record_id"].startswith("operational_") for record in first)


def test_operational_parse_failures_and_unsupported_files_are_explicit() -> None:
    malformed_toml = extract_operational_structure("pyproject.toml", "[project\n")
    assert malformed_toml["artifact_kind"] == "dependency_manifest"
    assert malformed_toml["parse"]["status"] == "parse_failed"

    malformed_yaml = extract_operational_structure("deploy.yaml", "services: [\n")
    assert malformed_yaml["artifact_kind"] == "generic_configuration"
    assert malformed_yaml["parse"]["status"] == "parse_failed"

    unsupported = extract_operational_structure("README.md", "# Demo\n")
    assert unsupported["artifact_kind"] is None
    assert unsupported["parse"]["status"] == "unsupported_artifact"


def test_flattened_operational_record_categories_are_singular_words() -> None:
    structure = extract_operational_structure(
        "Dockerfile",
        "FROM python:3.12-slim\nWORKDIR /app\nRUN uv sync --locked\n",
    )
    records = operational_records_for_file(
        {
            "repo_id": "repo_1",
            "snapshot_id": "snapshot_1",
            "file_id": "file_1",
            "path": "Dockerfile",
            "operational_structure": structure,
        }
    )

    assert {record["category"] for record in records} <= {
        "entity",
        "operation",
        "reference",
        "control",
    }
    assert all(record["category"] != "entitie" for record in records)


def test_shell_parser_ignores_array_members_and_heredoc_payload_as_commands() -> None:
    result = extract_operational_structure(
        "scripts/create_trace_job.sh",
        r'''#!/usr/bin/env bash
FORM_ARGS=(
  -F "repo_zip=@${REPO_ZIP}"
  -F "analysis_depth=${ANALYSIS_DEPTH}"
)
FORM_ARGS+=( -F "llm_backend=${LLM_BACKEND}" )

PAYLOAD=$(cat <<EOF
job_type: repo_current_state,
payload: {
  s3_repo_prefix: "${S3_REPO_PREFIX}",
  SHEVEK_OPENAI_API_KEY: ollama,
}
EOF
)

curl -fsS "${API_URL}" "${FORM_ARGS[@]}"
''',
    )

    commands = [
        item
        for item in result["operations"]
        if item.get("executable") is not None
    ]
    executables = {str(item["executable"]) for item in commands}

    assignments = {
        str(item.get("name")): item
        for item in result["operations"]
        if item.get("kind") == "environment_assignment"
    }
    assert assignments["FORM_ARGS"]["value"] == "<array-assignment>"
    assert assignments["PAYLOAD"]["value"] == "<command-substitution>"
    assert "job_type" not in str(assignments["PAYLOAD"])

    assert "curl" in executables
    assert executables.isdisjoint(
        {
            "-F",
            ")",
            "FORM_ARGS+=(",
            "job_type:",
            "payload:",
            "s3_repo_prefix:",
            "SHEVEK_OPENAI_API_KEY:",
        }
    )


def test_multiline_shell_command_is_one_operation() -> None:
    result = extract_operational_structure(
        "scripts/upload.sh",
        r'''#!/usr/bin/env bash
curl -fsS \
  -F "repo_zip=@${REPO_ZIP}" \
  -F "analysis_depth=${ANALYSIS_DEPTH}" \
  "${API_URL}"
''',
    )

    curl_commands = [
        item for item in result["operations"] if item.get("executable") == "curl"
    ]
    assert len(curl_commands) == 1
    assert "-F" in curl_commands[0]["argv"]
    assert curl_commands[0]["start_line"] == 2
    assert curl_commands[0]["end_line"] == 5


@pytest.mark.skipif(
    importlib.util.find_spec("tree_sitter") is None
    or importlib.util.find_spec("tree_sitter_bash") is None,
    reason="Tree-sitter Bash grammar is not installed",
)
def test_docker_nested_shell_preserves_physical_line_offsets() -> None:
    result = extract_operational_structure(
        "Dockerfile",
        "FROM python:3.12-slim\n"
        "RUN --mount=type=cache,target=/root/.cache/uv \\\n"
        "    uv sync --locked \\\n"
        "    && python -m compileall src\n",
    )

    install = next(
        item for item in result["operations"] if item["kind"] == "dependency_install"
    )
    compile_command = next(
        item
        for item in result["operations"]
        if item.get("executable") == "python"
    )
    assert install["start_line"] == 3
    assert compile_command["start_line"] == 4


def test_docker_buildkit_run_options_do_not_hide_dependency_install() -> None:
    result = extract_operational_structure(
        "Dockerfile",
        r'''FROM python:3.12-slim AS runtime
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=ssh \
    uv sync \
        --locked \
        --no-dev
''',
    )

    build = next(
        item
        for item in result["operations"]
        if item["kind"] == "container_build_command"
    )
    install = next(
        item for item in result["operations"] if item["kind"] == "dependency_install"
    )

    assert build["flags"] == [
        "--mount=type=cache,target=/root/.cache/uv",
        "--mount=type=ssh",
    ]
    assert build["command"] == "uv sync --locked --no-dev"
    assert install["executable"] == "uv"
    assert install["argv"] == ["sync", "--locked", "--no-dev"]
    assert install["lock_enforced"] is True
    assert install["start_line"] == 4
    assert not any(
        str(item.get("executable", "")).startswith("--")
        for item in result["operations"]
    )


def test_docker_buildkit_run_preserves_unlocked_manifest_install() -> None:
    result = extract_operational_structure(
        "Dockerfile",
        r'''FROM python:3.12-slim
RUN --mount=type=ssh \
    uv pip install --system .
''',
    )

    install = next(
        item for item in result["operations"] if item["kind"] == "dependency_install"
    )
    assert install["manager"] == "uv"
    assert install["lock_enforced"] is False
    assert install["manifest_install"] is True
    assert install["argv"] == ["pip", "install", "--system", "."]


def test_shell_line_continuations_do_not_leak_newlines_into_argv() -> None:
    result = extract_operational_structure(
        "Dockerfile",
        r'''FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y \
        ca-certificates \
        git
''',
    )

    commands = [
        item
        for item in result["operations"]
        if item.get("executable") == "apt-get"
    ]
    assert [item["argv"] for item in commands] == [
        ["update"],
        ["install", "-y", "ca-certificates", "git"],
    ]
    assert all(
        "\n" not in token
        for item in commands
        for token in item["argv"]
    )


def test_json_valued_assignment_redacts_nested_sensitive_keys() -> None:
    result = extract_operational_structure(
        "scripts/run.sh",
        r'''#!/usr/bin/env bash
LLM_ENV_JSON='{"provider":"ollama","SHEVEK_OPENAI_API_KEY":"sk-secret","nested":{"token":"abc"}}'
''',
    )

    assignment = next(
        item
        for item in result["operations"]
        if item.get("kind") == "environment_assignment"
        and item.get("name") == "LLM_ENV_JSON"
    )
    assert "sk-secret" not in str(assignment)
    assert '"provider":"ollama"' in assignment["value"]
    assert assignment["value"].count("<redacted-sensitive-literal>") == 2
