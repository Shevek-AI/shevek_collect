from __future__ import annotations

import hashlib
import json
import re
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable

from .safe_yaml import load_documents
from .diagnostics import error_code, parse_diagnostic

from .parsing.tree_sitter_parser import TreeSitterUnavailable, make_parser

OPERATIONAL_STRUCTURE_SCHEMA_VERSION = "shevek.operational_structure.v1"
OPERATIONAL_RECORD_SCHEMA_VERSION = "shevek.operational_record.v1"

MAX_OPERATIONAL_ITEMS = 5_000
MAX_SHELL_COMMANDS = 2_000
MAX_YAML_DOCUMENTS = 200
MAX_TOML_DEPENDENCIES = 5_000

_DOCKERFILE_NAMES = {"dockerfile", "containerfile"}
_SHELL_SUFFIXES = {".sh", ".bash"}
_TOML_LOCK_NAMES = {"uv.lock", "poetry.lock", "cargo.lock", "pdm.lock"}
_COMPOSE_NAMES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}

_SENSITIVE_NAME_RE = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)", re.I
)


@dataclass(frozen=True)
class OperationalArtifact:
    artifact_kind: str
    format: str


@dataclass(frozen=True)
class LogicalLine:
    text: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int


def classify_operational_artifact(path: str, content: str = "") -> OperationalArtifact | None:
    pure = PurePosixPath(path)
    name = pure.name
    lower_name = name.lower()
    suffix = pure.suffix.lower()
    parts = tuple(part.lower() for part in pure.parts)

    if (
        lower_name in _DOCKERFILE_NAMES
        or lower_name.startswith("dockerfile.")
        or lower_name.startswith("containerfile.")
        or lower_name.endswith(".dockerfile")
    ):
        return OperationalArtifact("container_build", "dockerfile")

    if suffix in _SHELL_SUFFIXES or _has_shell_shebang(content):
        return OperationalArtifact("shell_script", "bash")

    if suffix == ".toml" or lower_name in _TOML_LOCK_NAMES:
        if _is_dependency_lock_name(lower_name):
            kind = "dependency_lock"
        elif lower_name in {"pyproject.toml", "project.toml", "cargo.toml"}:
            kind = "dependency_manifest"
        else:
            kind = "generic_configuration"
        return OperationalArtifact(kind, "toml")

    if suffix in {".yaml", ".yml"}:
        if ".github" in parts and "workflows" in parts:
            kind = "workflow"
        elif lower_name in _COMPOSE_NAMES:
            kind = "container_orchestration"
        else:
            kind = "generic_configuration"
        return OperationalArtifact(kind, "yaml")

    return None


def extract_operational_structure(path: str, content: str) -> dict[str, object]:
    """Extract deterministic operational evidence without making audit judgements."""
    artifact = classify_operational_artifact(path, content)
    if artifact is None:
        return empty_operational_structure(path, status="unsupported_artifact")

    try:
        if artifact.format == "dockerfile":
            return _extract_dockerfile(path, content, artifact)
        if artifact.format == "bash":
            return _extract_shell(path, content, artifact)
        if artifact.format == "toml":
            return _extract_toml(path, content, artifact)
        if artifact.format == "yaml":
            return _extract_yaml(path, content, artifact)
    except Exception as exc:
        return _structure(
            artifact,
            status="parse_failed",
            error=error_code(exc),
            details=parse_diagnostic(exc),
        )
    return empty_operational_structure(path, status="unsupported_artifact")


def empty_operational_structure(
    path: str,
    *,
    status: str = "not_attempted",
    error: str | None = None,
) -> dict[str, object]:
    artifact = classify_operational_artifact(path)
    return _structure(
        artifact,
        status=status,
        error=error,
    )


def operational_records_for_file(file_record: dict[str, object]) -> list[dict[str, object]]:
    structure = file_record.get("operational_structure")
    if not isinstance(structure, dict):
        return []
    records: list[dict[str, object]] = []
    duplicate_counts: dict[str, int] = {}
    for category in ("entities", "operations", "references", "controls"):
        rows = structure.get(category)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            payload = dict(row)
            kind = str(payload.pop("kind", "unknown"))
            identity_payload = {
                "file_id": file_record.get("file_id"),
                "category": category,
                "kind": kind,
                "payload": payload,
            }
            canonical = json.dumps(
                identity_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            duplicate_index = duplicate_counts.get(canonical, 0)
            duplicate_counts[canonical] = duplicate_index + 1
            digest = hashlib.sha256(
                f"{canonical}\noccurrence={duplicate_index}".encode(
                    "utf-8", errors="replace"
                )
            ).hexdigest()
            records.append(
                {
                    "schema_version": OPERATIONAL_RECORD_SCHEMA_VERSION,
                    "record_id": f"operational_{digest[:24]}",
                    "repo_id": file_record.get("repo_id"),
                    "snapshot_id": file_record.get("snapshot_id"),
                    "file_id": file_record.get("file_id"),
                    "path": file_record.get("path"),
                    "artifact_kind": structure.get("artifact_kind"),
                    "format": structure.get("format"),
                    "category": {
                        "entities": "entity",
                        "operations": "operation",
                        "references": "reference",
                        "controls": "control",
                    }[category],
                    "kind": kind,
                    **payload,
                }
            )
    return records


def _structure(
    artifact: OperationalArtifact | None,
    *,
    status: str,
    entities: list[dict[str, object]] | None = None,
    operations: list[dict[str, object]] | None = None,
    references: list[dict[str, object]] | None = None,
    controls: list[dict[str, object]] | None = None,
    error: str | None = None,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    parse: dict[str, object] = {"status": status}
    if error:
        parse["error"] = error
    if details:
        parse.update(details)
    return {
        "schema_version": OPERATIONAL_STRUCTURE_SCHEMA_VERSION,
        "artifact_kind": artifact.artifact_kind if artifact else None,
        "format": artifact.format if artifact else None,
        "parse": parse,
        "entities": (entities or [])[:MAX_OPERATIONAL_ITEMS],
        "operations": (operations or [])[:MAX_OPERATIONAL_ITEMS],
        "references": (references or [])[:MAX_OPERATIONAL_ITEMS],
        "controls": (controls or [])[:MAX_OPERATIONAL_ITEMS],
    }


def _extract_dockerfile(
    path: str,
    content: str,
    artifact: OperationalArtifact,
) -> dict[str, object]:
    entities: list[dict[str, object]] = []
    operations: list[dict[str, object]] = []
    references: list[dict[str, object]] = []
    controls: list[dict[str, object]] = []
    current_stage: str | None = None
    instruction_count = 0
    unknown_instructions = 0

    for logical in _docker_logical_lines(content):
        stripped = logical.text.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z]+)\s*(.*)$", stripped, re.DOTALL)
        if not match:
            unknown_instructions += 1
            continue
        instruction = match.group(1).upper()
        argument = match.group(2).strip()
        instruction_count += 1
        location = _location(logical)

        if instruction == "FROM":
            tokens = _safe_shell_split(argument)
            flags, remainder = _leading_flags(tokens)
            image = remainder[0] if remainder else argument
            alias = None
            if len(remainder) >= 3 and remainder[-2].lower() == "as":
                alias = remainder[-1]
            current_stage = alias or f"stage_{len(entities)}"
            image_details = _image_reference_details(image)
            entities.append(
                {
                    "kind": "container_stage",
                    "name": current_stage,
                    "base_image": image,
                    "platform": _flag_value(flags, "--platform"),
                    **location,
                }
            )
            references.append(
                {
                    "kind": "base_image",
                    "value": image,
                    "stage": current_stage,
                    **image_details,
                    **location,
                }
            )
            continue

        if instruction in {"RUN", "CMD", "ENTRYPOINT"}:
            command_line_offset = 0
            if instruction == "RUN":
                flags, command_text, command_line_offset = _docker_run_command(argument)
            else:
                flags = []
                command_text = argument
            json_argv = _json_array(command_text)
            operation_kind = {
                "RUN": "container_build_command",
                "CMD": "container_default_command",
                "ENTRYPOINT": "container_entrypoint",
            }[instruction]
            operation: dict[str, object] = {
                "kind": operation_kind,
                "instruction": instruction,
                "stage": current_stage,
                "form": "exec" if json_argv is not None else "shell",
                "argv": json_argv or [],
                "command": _redacted_shell_command(command_text) if json_argv is None else None,
                "flags": flags,
                **location,
            }
            operations.append(operation)
            if json_argv is None:
                nested = _shell_operations(
                    command_text,
                    start_line=logical.start_line + command_line_offset,
                    source_context=f"dockerfile_{instruction.lower()}",
                    stage=current_stage,
                )
                operations.extend(nested)
                references.extend(_references_from_shell_operations(nested))
                controls.extend(_controls_from_shell_operations(nested))
            continue

        if instruction in {"COPY", "ADD"}:
            tokens = _safe_shell_split(argument)
            flags, remainder = _leading_flags(tokens)
            sources: list[str] = []
            destination: str | None = None
            json_values = _json_array(_strip_leading_flags_from_text(argument, flags))
            if json_values is not None:
                sources = json_values[:-1]
                destination = json_values[-1] if json_values else None
            elif remainder:
                sources = remainder[:-1]
                destination = remainder[-1]
            operations.append(
                {
                    "kind": "container_file_transfer",
                    "instruction": instruction,
                    "stage": current_stage,
                    "sources": sources,
                    "destination": destination,
                    "from_stage": _flag_value(flags, "--from"),
                    "flags": flags,
                    **location,
                }
            )
            for source in sources:
                references.append(
                    {
                        "kind": "build_input",
                        "value": source,
                        "stage": current_stage,
                        "instruction": instruction,
                        **location,
                    }
                )
            from_stage = _flag_value(flags, "--from")
            if from_stage:
                references.append(
                    {
                        "kind": "container_stage_reference",
                        "value": from_stage,
                        "stage": current_stage,
                        **location,
                    }
                )
            continue

        if instruction in {"ARG", "ENV"}:
            assignments = _docker_assignments(argument, instruction)
            for name, value in assignments:
                entities.append(
                    {
                        "kind": (
                            "build_argument"
                            if instruction == "ARG"
                            else "environment_variable"
                        ),
                        "name": name,
                        "value": _redact_if_sensitive(name, value),
                        "has_default": value is not None,
                        "stage": current_stage,
                        **location,
                    }
                )
            continue

        if instruction in {"WORKDIR", "USER", "SHELL", "EXPOSE", "VOLUME", "STOPSIGNAL"}:
            controls.append(
                {
                    "kind": f"container_{instruction.lower()}",
                    "value": argument,
                    "stage": current_stage,
                    **location,
                }
            )
            continue

        if instruction == "HEALTHCHECK":
            controls.append(
                {
                    "kind": "container_healthcheck",
                    "value": argument,
                    "stage": current_stage,
                    **location,
                }
            )
            continue

        operations.append(
            {
                "kind": "container_instruction",
                "instruction": instruction,
                "argument": argument,
                "stage": current_stage,
                **location,
            }
        )

    status = "parsed_with_errors" if unknown_instructions else "parsed"
    return _structure(
        artifact,
        status=status,
        entities=entities,
        operations=operations,
        references=references,
        controls=controls,
        details={
            "instruction_count": instruction_count,
            "unparsed_instruction_count": unknown_instructions,
        },
    )


def _extract_shell(
    path: str,
    content: str,
    artifact: OperationalArtifact,
) -> dict[str, object]:
    operations = _shell_operations(content, start_line=1, source_context="shell_script")
    references = _references_from_shell_operations(operations)
    controls = _controls_from_shell_operations(operations)
    entities: list[dict[str, object]] = []
    first_line = content.splitlines()[0] if content.splitlines() else ""
    if first_line.startswith("#!"):
        entities.append(
            {
                "kind": "interpreter",
                "value": first_line[2:].strip(),
                "start_line": 1,
                "end_line": 1,
            }
        )
    return _structure(
        artifact,
        status="parsed",
        entities=entities,
        operations=operations,
        references=references,
        controls=controls,
        details={"command_count": len(operations)},
    )


def _extract_toml(
    path: str,
    content: str,
    artifact: OperationalArtifact,
) -> dict[str, object]:
    parsed = tomllib.loads(content)
    pure = PurePosixPath(path)
    lower_name = pure.name.lower()
    entities: list[dict[str, object]] = []
    operations: list[dict[str, object]] = []
    references: list[dict[str, object]] = []
    controls: list[dict[str, object]] = []

    for table_path in _toml_table_paths(parsed):
        entities.append({"kind": "configuration_table", "name": table_path})

    if lower_name == "pyproject.toml":
        project = parsed.get("project") if isinstance(parsed.get("project"), dict) else {}
        if project:
            entities.append(
                {
                    "kind": "package",
                    "name": project.get("name"),
                    "version": project.get("version"),
                    "requires_runtime": project.get("requires-python"),
                }
            )
            references.extend(
                _dependency_references(
                    project.get("dependencies"),
                    group="runtime",
                    manager="python",
                )
            )
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict):
                for group, values in sorted(optional.items()):
                    references.extend(
                        _dependency_references(values, group=f"optional:{group}", manager="python")
                    )
            scripts = project.get("scripts")
            if isinstance(scripts, dict):
                for name, target in sorted(scripts.items()):
                    operations.append(
                        {"kind": "package_entrypoint", "name": str(name), "target": str(target)}
                    )
        groups = parsed.get("dependency-groups")
        if isinstance(groups, dict):
            for group, values in sorted(groups.items()):
                references.extend(
                    _dependency_references(values, group=f"development:{group}", manager="python")
                )
        build_system = parsed.get("build-system")
        if isinstance(build_system, dict):
            controls.append(
                {
                    "kind": "build_backend",
                    "backend": build_system.get("build-backend"),
                    "requires": _string_values(build_system.get("requires")),
                }
            )

    elif lower_name == "uv.lock":
        packages = parsed.get("package")
        if isinstance(packages, list):
            for package in packages[:MAX_TOML_DEPENDENCIES]:
                if not isinstance(package, dict):
                    continue
                name = package.get("name")
                version = package.get("version")
                source = package.get("source")
                source_kind = next(iter(source), None) if isinstance(source, dict) else None
                wheels = package.get("wheels") if isinstance(package.get("wheels"), list) else []
                references.append(
                    {
                        "kind": "resolved_dependency",
                        "manager": "uv",
                        "name": name,
                        "version": version,
                        "source_kind": source_kind,
                        "wheel_count": len(wheels),
                        "platform_specific_wheel": any(
                            _wheel_looks_platform_specific(wheel) for wheel in wheels
                        ),
                    }
                )
        controls.append(
            {
                "kind": "dependency_lock_metadata",
                "manager": "uv",
                "lock_revision": parsed.get("revision"),
                "lock_version": parsed.get("version"),
                "requires_python": parsed.get("requires-python"),
            }
        )

    elif lower_name in {"project.toml", "cargo.toml"}:
        package = parsed.get("package") if isinstance(parsed.get("package"), dict) else parsed
        entities.append(
            {
                "kind": "package",
                "name": package.get("name") if isinstance(package, dict) else None,
                "version": package.get("version") if isinstance(package, dict) else None,
                "uuid": package.get("uuid") if isinstance(package, dict) else None,
            }
        )
        for key in ("deps", "weakdeps", "extras", "dependencies", "dev-dependencies"):
            values = parsed.get(key)
            if isinstance(values, dict):
                for name, constraint in sorted(values.items()):
                    references.append(
                        {
                            "kind": "dependency_declaration",
                            "manager": "julia" if lower_name == "project.toml" else "cargo",
                            "group": key,
                            "name": str(name),
                            "constraint": _normalised_scalar(constraint),
                        }
                    )

    elif lower_name in _TOML_LOCK_NAMES or lower_name == "manifest.toml":
        controls.append(
            {
                "kind": "dependency_lock_metadata",
                "manager": _lock_manager(lower_name),
            }
        )

    return _structure(
        artifact,
        status="parsed",
        entities=entities,
        operations=operations,
        references=references,
        controls=controls,
        details={"top_level_keys": sorted(str(key) for key in parsed)},
    )


def _extract_yaml(
    path: str,
    content: str,
    artifact: OperationalArtifact,
) -> dict[str, object]:
    documents = load_documents(content, max_documents=MAX_YAML_DOCUMENTS)
    entities: list[dict[str, object]] = []
    operations: list[dict[str, object]] = []
    references: list[dict[str, object]] = []
    controls: list[dict[str, object]] = []
    detected_kind = artifact.artifact_kind

    pure = PurePosixPath(path)
    lower_name = pure.name.lower()
    for document_index, document in enumerate(documents):
        if not isinstance(document, dict):
            continue
        if lower_name in _COMPOSE_NAMES or "services" in document:
            detected_kind = "container_orchestration"
            _extract_compose_document(
                document,
                document_index=document_index,
                entities=entities,
                operations=operations,
                references=references,
                controls=controls,
            )
        elif ".github" in tuple(part.lower() for part in pure.parts) and "jobs" in document:
            detected_kind = "workflow"
            _extract_github_actions_document(
                document,
                document_index=document_index,
                entities=entities,
                operations=operations,
                references=references,
                controls=controls,
            )
        elif "apiVersion" in document and "kind" in document:
            detected_kind = "deployment_config"
            _extract_kubernetes_document(
                document,
                document_index=document_index,
                entities=entities,
                operations=operations,
                references=references,
                controls=controls,
            )
        else:
            entities.append(
                {
                    "kind": "configuration_document",
                    "document_index": document_index,
                    "top_level_keys": sorted(str(key) for key in document),
                }
            )

    actual_artifact = OperationalArtifact(detected_kind, artifact.format)
    return _structure(
        actual_artifact,
        status="parsed",
        entities=entities,
        operations=operations,
        references=references,
        controls=controls,
        details={"document_count": len(documents)},
    )


def _extract_compose_document(
    document: dict[str, Any],
    *,
    document_index: int,
    entities: list[dict[str, object]],
    operations: list[dict[str, object]],
    references: list[dict[str, object]],
    controls: list[dict[str, object]],
) -> None:
    services = document.get("services")
    if not isinstance(services, dict):
        return
    for service_name, raw_service in sorted(services.items()):
        if not isinstance(raw_service, dict):
            continue
        entities.append(
            {
                "kind": "container_service",
                "name": str(service_name),
                "document_index": document_index,
            }
        )
        image = raw_service.get("image")
        if isinstance(image, str):
            references.append(
                {
                    "kind": "container_image",
                    "value": image,
                    "service": str(service_name),
                    **_image_reference_details(image),
                }
            )
        build = raw_service.get("build")
        if build is not None:
            build_record: dict[str, object] = {
                "kind": "container_build_invocation",
                "service": str(service_name),
            }
            if isinstance(build, str):
                build_record["context"] = build
            elif isinstance(build, dict):
                build_record.update(
                    {
                        "context": build.get("context"),
                        "dockerfile": build.get("dockerfile"),
                        "target": build.get("target"),
                        "platforms": _string_values(build.get("platforms")),
                    }
                )
            operations.append(build_record)
        for field, kind in (
            ("command", "container_command"),
            ("entrypoint", "container_entrypoint"),
        ):
            value = raw_service.get(field)
            if value is None:
                continue
            operations.append(
                {
                    "kind": kind,
                    "service": str(service_name),
                    "argv": _string_values(value) if isinstance(value, list) else [],
                    "command": value if isinstance(value, str) else None,
                }
            )
        depends_on = raw_service.get("depends_on")
        if isinstance(depends_on, dict):
            dependency_names = sorted(str(key) for key in depends_on)
        else:
            dependency_names = _string_values(depends_on)
        for dependency in dependency_names:
            references.append(
                {
                    "kind": "service_dependency",
                    "service": str(service_name),
                    "value": dependency,
                }
            )
        deploy = raw_service.get("deploy")
        if isinstance(deploy, dict):
            resources = deploy.get("resources")
            if isinstance(resources, dict):
                controls.append(
                    {
                        "kind": "container_resource_policy",
                        "service": str(service_name),
                        "limits": resources.get("limits"),
                        "reservations": resources.get("reservations"),
                    }
                )
        restart = raw_service.get("restart")
        if restart is not None:
            controls.append(
                {
                    "kind": "container_restart_policy",
                    "service": str(service_name),
                    "value": str(restart),
                }
            )


def _extract_github_actions_document(
    document: dict[str, Any],
    *,
    document_index: int,
    entities: list[dict[str, object]],
    operations: list[dict[str, object]],
    references: list[dict[str, object]],
    controls: list[dict[str, object]],
) -> None:
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_name, raw_job in sorted(jobs.items()):
        if not isinstance(raw_job, dict):
            continue
        entities.append(
            {
                "kind": "workflow_job",
                "name": str(job_name),
                "document_index": document_index,
                "runs_on": raw_job.get("runs-on"),
            }
        )
        needs = raw_job.get("needs")
        for dependency in _string_values(needs):
            references.append(
                {"kind": "workflow_job_dependency", "job": str(job_name), "value": dependency}
            )
        permissions = raw_job.get("permissions")
        if permissions is not None:
            controls.append(
                {"kind": "workflow_permissions", "job": str(job_name), "value": permissions}
            )
        steps = raw_job.get("steps")
        if not isinstance(steps, list):
            continue
        for step_index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            step_name = str(step.get("name") or f"step_{step_index}")
            uses = step.get("uses")
            if isinstance(uses, str):
                references.append(
                    {
                        "kind": "workflow_action",
                        "job": str(job_name),
                        "step": step_name,
                        "value": uses,
                        "immutable_revision": _action_uses_immutable_revision(uses),
                    }
                )
            run = step.get("run")
            if isinstance(run, str):
                operations.append(
                    {
                        "kind": "workflow_shell_step",
                        "job": str(job_name),
                        "step": step_name,
                        "shell": step.get("shell"),
                        "command": _redacted_shell_command(run),
                    }
                )
                nested = _shell_operations(
                    run,
                    start_line=None,
                    source_context="workflow_run",
                    workflow_job=str(job_name),
                    workflow_step=step_name,
                )
                operations.extend(nested)
                references.extend(_references_from_shell_operations(nested))
                controls.extend(_controls_from_shell_operations(nested))


def _extract_kubernetes_document(
    document: dict[str, Any],
    *,
    document_index: int,
    entities: list[dict[str, object]],
    operations: list[dict[str, object]],
    references: list[dict[str, object]],
    controls: list[dict[str, object]],
) -> None:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    resource_kind = str(document.get("kind") or "unknown")
    resource_name = str(metadata.get("name") or f"document_{document_index}")
    entities.append(
        {
            "kind": "deployment_resource",
            "resource_kind": resource_kind,
            "name": resource_name,
            "api_version": document.get("apiVersion"),
            "document_index": document_index,
        }
    )
    pod_spec = _kubernetes_pod_spec(document)
    if not isinstance(pod_spec, dict):
        return
    for container_group in ("initContainers", "containers"):
        containers = pod_spec.get(container_group)
        if not isinstance(containers, list):
            continue
        for container in containers:
            if not isinstance(container, dict):
                continue
            container_name = str(container.get("name") or "unknown")
            image = container.get("image")
            if isinstance(image, str):
                references.append(
                    {
                        "kind": "container_image",
                        "resource": resource_name,
                        "container": container_name,
                        "value": image,
                        **_image_reference_details(image),
                    }
                )
            operations.append(
                {
                    "kind": "deployed_container",
                    "resource": resource_name,
                    "container": container_name,
                    "container_group": container_group,
                    "command": _string_values(container.get("command")),
                    "args": _string_values(container.get("args")),
                }
            )
            resources = container.get("resources")
            if isinstance(resources, dict):
                controls.append(
                    {
                        "kind": "container_resource_policy",
                        "resource": resource_name,
                        "container": container_name,
                        "limits": resources.get("limits"),
                        "requests": resources.get("requests"),
                    }
                )
            for probe_name in ("startupProbe", "livenessProbe", "readinessProbe"):
                if probe_name in container:
                    controls.append(
                        {
                            "kind": "container_health_probe",
                            "resource": resource_name,
                            "container": container_name,
                            "probe": probe_name,
                        }
                    )
    restart_policy = pod_spec.get("restartPolicy")
    if restart_policy is not None:
        controls.append(
            {
                "kind": "container_restart_policy",
                "resource": resource_name,
                "value": str(restart_policy),
            }
        )


def _shell_operations(
    content: str,
    *,
    start_line: int | None,
    source_context: str,
    **context: object,
) -> list[dict[str, object]]:
    """Extract executable shell commands and assignments from a Bash syntax tree.

    Tree-sitter is the primary parser. The conservative fallback exists only so
    Collect can still produce a partial bundle when the optional native grammar
    is unavailable; normal locked installations include tree-sitter-bash.
    """
    try:
        return _tree_sitter_shell_operations(
            content,
            start_line=start_line,
            source_context=source_context,
            **context,
        )
    except TreeSitterUnavailable:
        return _fallback_shell_operations(
            content,
            start_line=start_line,
            source_context=source_context,
            **context,
        )


def _tree_sitter_shell_operations(
    content: str,
    *,
    start_line: int | None,
    source_context: str,
    **context: object,
) -> list[dict[str, object]]:
    parser = make_parser("bash")
    content_bytes = content.encode("utf-8", errors="replace")
    tree = parser.parse(content_bytes)
    operations: list[dict[str, object]] = []
    assignment_spans: set[tuple[int, int]] = set()

    for node in _walk_tree_sitter_nodes(tree.root_node):
        node_type = str(getattr(node, "type", ""))
        if node_type == "variable_assignment":
            assignment = _tree_sitter_assignment_operation(
                node,
                content_bytes=content_bytes,
                start_line=start_line,
                source_context=source_context,
                context=context,
            )
            if assignment is not None:
                span = (int(getattr(node, "start_byte", 0)), int(getattr(node, "end_byte", 0)))
                if span not in assignment_spans:
                    assignment_spans.add(span)
                    operations.append(assignment)
            continue

        if node_type != "command":
            continue

        command_text = _tree_sitter_node_text(node, content_bytes).strip()
        tokens = _safe_shell_split(command_text)
        while tokens and _looks_like_assignment(tokens[0]):
            tokens.pop(0)
        if not tokens:
            continue

        executable = tokens[0]
        redacted_tokens = _redact_sensitive_argv(tokens)
        operation: dict[str, object] = {
            "kind": _shell_operation_kind(tokens),
            "executable": executable,
            "argv": redacted_tokens[1:],
            "command": shlex.join(redacted_tokens),
            "source_context": source_context,
            **context,
            **_tree_sitter_shell_location(
                node,
                start_line=start_line,
                source_context=source_context,
            ),
        }
        operation.update(_dependency_install_details(tokens))
        operations.append(operation)
        if len(operations) >= MAX_SHELL_COMMANDS:
            break

    operations.sort(
        key=lambda item: (
            int(item.get("start_line") or 0),
            int(item.get("start_byte") or 0),
            0 if item.get("kind") == "environment_assignment" else 1,
        )
    )
    return operations[:MAX_SHELL_COMMANDS]


def _tree_sitter_assignment_operation(
    node: Any,
    *,
    content_bytes: bytes,
    start_line: int | None,
    source_context: str,
    context: dict[str, object],
) -> dict[str, object] | None:
    raw = _tree_sitter_node_text(node, content_bytes).strip()
    match = re.match(
        r"^(?:declare\s+|export\s+|local\s+|readonly\s+)?"
        r"([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$",
        raw,
        re.DOTALL,
    )
    if not match:
        return None
    name = match.group(1)
    value = match.group(3).strip()
    return {
        "kind": "environment_assignment",
        "name": name,
        "value": _normalised_shell_assignment_value(name, value),
        "assignment_value_kind": _shell_assignment_value_kind(value),
        "assignment_operator": match.group(2),
        "source_context": source_context,
        **context,
        **_tree_sitter_shell_location(
            node,
            start_line=start_line,
            source_context=source_context,
        ),
    }


def _walk_tree_sitter_nodes(root: Any) -> Iterable[Any]:
    stack = [root]
    visited = 0
    while stack:
        visited += 1
        if visited > 250_000:
            raise ValueError("shell_node_limit")
        node = stack.pop()
        yield node
        children = list(getattr(node, "children", ()) or ())
        stack.extend(reversed(children))


def _tree_sitter_node_text(node: Any, content_bytes: bytes) -> str:
    start = int(getattr(node, "start_byte", 0))
    end = int(getattr(node, "end_byte", start))
    return content_bytes[start:end].decode("utf-8", errors="replace")


def _tree_sitter_shell_location(
    node: Any,
    *,
    start_line: int | None,
    source_context: str,
) -> dict[str, int]:
    if start_line is None:
        return {}
    start_point = getattr(node, "start_point", (0, 0))
    end_point = getattr(node, "end_point", start_point)
    start_row = int(start_point[0])
    end_row = int(end_point[0])
    end_column = int(end_point[1])
    first_line = start_line + start_row
    last_line = start_line + end_row
    if end_row > start_row and end_column == 0:
        last_line -= 1
    location: dict[str, int] = {
        "start_line": first_line,
        "end_line": max(first_line, last_line),
    }
    if source_context == "shell_script":
        location.update(
            {
                "start_byte": int(getattr(node, "start_byte", 0)),
                "end_byte": int(getattr(node, "end_byte", 0)),
            }
        )
    return location


def _fallback_shell_operations(
    content: str,
    *,
    start_line: int | None,
    source_context: str,
    **context: object,
) -> list[dict[str, object]]:
    operations: list[dict[str, object]] = []
    sanitised = _strip_shell_heredoc_bodies(content)
    array_depth = 0
    for logical in _shell_logical_lines(sanitised, start_line=start_line or 1):
        stripped = logical.text.strip()
        if array_depth:
            array_depth += stripped.count("(") - stripped.count(")")
            array_depth = max(0, array_depth)
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=\s*\(", stripped):
            array_depth = max(0, stripped.count("(") - stripped.count(")"))
            name, operator, value = _split_shell_assignment(stripped)
            if name is not None:
                operations.append(
                    {
                        "kind": "environment_assignment",
                        "name": name,
                        "value": _normalised_shell_assignment_value(name, value),
                        "assignment_value_kind": _shell_assignment_value_kind(value),
                        "assignment_operator": operator,
                        "source_context": source_context,
                        **context,
                        **_shell_location(
                            logical,
                            source_context=source_context,
                            include_lines=start_line is not None,
                        ),
                    }
                )
            continue
        if re.match(
            r"^[A-Za-z_][A-Za-z0-9_]*\+?=\s*\$\(",
            stripped,
        ):
            name, operator, value = _split_shell_assignment(stripped)
            if name is not None:
                operations.append(
                    {
                        "kind": "environment_assignment",
                        "name": name,
                        "value": _normalised_shell_assignment_value(name, value),
                        "assignment_value_kind": _shell_assignment_value_kind(value),
                        "assignment_operator": operator,
                        "source_context": source_context,
                        **context,
                        **_shell_location(
                            logical,
                            source_context=source_context,
                            include_lines=start_line is not None,
                        ),
                    }
                )
            continue
        assignment_match = re.match(
            r"^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$",
            stripped,
            re.DOTALL,
        )
        if assignment_match and _looks_like_complete_assignment_value(
            assignment_match.group(3)
        ):
            name = assignment_match.group(1)
            operations.append(
                {
                    "kind": "environment_assignment",
                    "name": name,
                    "value": _normalised_shell_assignment_value(
                        name, assignment_match.group(3).strip()
                    ),
                    "assignment_value_kind": _shell_assignment_value_kind(
                        assignment_match.group(3).strip()
                    ),
                    "assignment_operator": assignment_match.group(2),
                    "source_context": source_context,
                    **context,
                    **_shell_location(
                        logical,
                        source_context=source_context,
                        include_lines=start_line is not None,
                    ),
                }
            )
            continue
        for segment in _split_shell_segments(logical.text):
            tokens = _safe_shell_split(segment)
            if not tokens:
                continue
            while tokens and _looks_like_assignment(tokens[0]):
                assignment = tokens.pop(0)
                name, _, value = assignment.partition("=")
                operations.append(
                    {
                        "kind": "environment_assignment",
                        "name": name,
                        "value": _normalised_shell_assignment_value(name, value),
                        "assignment_value_kind": _shell_assignment_value_kind(value),
                        "assignment_operator": "=",
                        "source_context": source_context,
                        **context,
                        **_shell_location(
                            logical,
                            source_context=source_context,
                            include_lines=start_line is not None,
                        ),
                    }
                )
            if not tokens:
                continue
            executable = tokens[0]
            if executable in {
                "if", "then", "elif", "else", "fi", "for", "while", "until",
                "do", "done", "case", "esac", "function", "{", "}", ")",
            } or executable.startswith("-") or executable.endswith(":"):
                continue
            redacted_tokens = _redact_sensitive_argv(tokens)
            operation = {
                "kind": _shell_operation_kind(tokens),
                "executable": executable,
                "argv": redacted_tokens[1:],
                "command": shlex.join(redacted_tokens),
                "source_context": source_context,
                **context,
                **_shell_location(
                    logical,
                    source_context=source_context,
                    include_lines=start_line is not None,
                ),
            }
            operation.update(_dependency_install_details(tokens))
            operations.append(operation)
            if len(operations) >= MAX_SHELL_COMMANDS:
                return operations
    return operations


def _shell_assignment_value_kind(value: str | None) -> str:
    stripped = (value or "").strip()
    if stripped.startswith("("):
        return "array"
    if stripped.startswith("$(") or stripped.startswith("`"):
        return "command_substitution"
    if stripped.startswith("${"):
        return "parameter_expansion"
    return "literal_or_expansion"


def _normalised_shell_assignment_value(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if _SENSITIVE_NAME_RE.search(name):
        return "<redacted-sensitive-literal>"
    kind = _shell_assignment_value_kind(value)
    if kind == "array":
        return "<array-assignment>"
    if kind == "command_substitution":
        return "<command-substitution>"
    stripped = value.strip()
    redacted_json = _redact_sensitive_json_value(stripped)
    if redacted_json is not None:
        stripped = redacted_json
    if len(stripped) > 500:
        return f"{stripped[:500]}…"
    return stripped


def _looks_like_complete_assignment_value(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if stripped.startswith("${") and stripped.endswith("}"):
        return True
    if stripped[0:1] in {"\"", "'"} and stripped[-1:] == stripped[0:1]:
        return True
    return not bool(re.search(r"\s", stripped))


def _split_shell_assignment(value: str) -> tuple[str | None, str | None, str | None]:
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$", value, re.DOTALL)
    if not match:
        return None, None, None
    return match.group(1), match.group(2), match.group(3).strip()


def _strip_shell_heredoc_bodies(content: str) -> str:
    lines = content.splitlines(keepends=True)
    result: list[str] = []
    delimiter: str | None = None
    strip_tabs = False
    for raw in lines:
        text = raw.rstrip("\r\n")
        newline = raw[len(text):]
        if delimiter is not None:
            candidate = text.lstrip("\t") if strip_tabs else text
            result.append(newline or "\n")
            if candidate == delimiter:
                delimiter = None
                strip_tabs = False
            continue
        result.append(raw)
        match = re.search(r"<<(-)?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", text)
        if match:
            strip_tabs = bool(match.group(1))
            delimiter = match.group(2)
    return "".join(result)


def _references_from_shell_operations(
    operations: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    references: list[dict[str, object]] = []
    for operation in operations:
        executable = str(operation.get("executable") or "")
        argv = [str(value) for value in operation.get("argv", []) if value is not None]
        location = {
            key: operation.get(key)
            for key in (
                "start_line",
                "end_line",
                "start_byte",
                "end_byte",
                "source_context",
                "stage",
                "workflow_job",
                "workflow_step",
            )
            if operation.get(key) is not None
        }
        if executable in {"curl", "wget"}:
            for value in argv:
                if value.startswith(("http://", "https://")):
                    references.append(
                        {"kind": "external_download", "value": value, **location}
                    )
        if executable == "git" and argv[:1] in (["clone"], ["checkout"], ["switch"]):
            if len(argv) > 1:
                references.append(
                    {
                        "kind": "git_reference",
                        "operation": argv[0],
                        "value": argv[1],
                        **location,
                    }
                )
        if operation.get("kind") == "dependency_install":
            references.append(
                {
                    "kind": "dependency_install_input",
                    "manager": operation.get("manager"),
                    "lock_enforced": operation.get("lock_enforced"),
                    "manifest_install": operation.get("manifest_install"),
                    "arguments": argv,
                    **location,
                }
            )
    return references


def _controls_from_shell_operations(
    operations: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    controls: list[dict[str, object]] = []
    for operation in operations:
        executable = str(operation.get("executable") or "")
        argv = [str(value) for value in operation.get("argv", []) if value is not None]
        if executable != "set":
            continue
        flags = set(argv)
        controls.append(
            {
                "kind": "shell_error_handling",
                "errexit": any(flag in flags for flag in {"-e", "-eu", "-euo", "-eux", "-euxo"}),
                "nounset": any("u" in flag[1:] for flag in flags if flag.startswith("-")),
                "pipefail": "pipefail" in flags,
                "xtrace": any("x" in flag[1:] for flag in flags if flag.startswith("-")),
                "arguments": argv,
                **{
                    key: operation.get(key)
                    for key in ("start_line", "end_line", "source_context", "stage")
                    if operation.get(key) is not None
                },
            }
        )
    return controls


def _shell_operation_kind(tokens: list[str]) -> str:
    executable = tokens[0]
    argv = tokens[1:]
    if executable in {"pip", "pip3", "uv", "poetry", "pdm", "npm", "pnpm", "yarn", "cargo"}:
        details = _dependency_install_details(tokens)
        if details:
            return "dependency_install"
    if executable in {"curl", "wget"}:
        return "external_download_command"
    if executable == "docker" and argv[:1] in (["build"], ["buildx"]):
        return "container_build_invocation"
    if executable == "docker" and argv[:1] == ["run"]:
        return "container_run_invocation"
    if executable == "git":
        return "version_control_command"
    if executable == "trap":
        return "signal_handler"
    if executable == "set":
        return "shell_option"
    return "shell_command"


def _dependency_install_details(tokens: list[str]) -> dict[str, object]:
    if not tokens:
        return {}
    executable = tokens[0]
    argv = tokens[1:]
    manager: str | None = None
    install = False
    lock_flags: set[str] = set()
    manifest_install = False

    if executable == "uv":
        manager = "uv"
        install = argv[:1] == ["sync"] or argv[:2] == ["pip", "install"]
        lock_flags = {"--locked", "--frozen"}
        manifest_install = any(value in {".", "./"} for value in argv)
    elif executable in {"pip", "pip3"}:
        manager = "pip"
        install = argv[:1] == ["install"]
        lock_flags = {"--require-hashes"}
        manifest_install = any(value in {".", "./"} for value in argv)
    elif executable == "poetry":
        manager = "poetry"
        install = argv[:1] in (["install"], ["sync"])
        lock_flags = {"--sync"}
    elif executable == "pdm":
        manager = "pdm"
        install = argv[:1] in (["install"], ["sync"])
        lock_flags = {"--frozen-lockfile", "--check"}
    elif executable in {"npm", "pnpm", "yarn"}:
        manager = executable
        install = argv[:1] in (["install"], ["ci"], ["frozen-install"])
        lock_flags = {"ci", "--frozen-lockfile", "--immutable"}
    elif executable == "cargo":
        manager = "cargo"
        install = argv[:1] in (["build"], ["install"], ["fetch"])
        lock_flags = {"--locked", "--frozen"}

    if not install or manager is None:
        return {}
    observed = set(argv)
    return {
        "manager": manager,
        "lock_enforced": bool(observed & lock_flags),
        "lock_enforcement_flags": sorted(observed & lock_flags),
        "manifest_install": manifest_install,
    }


def _docker_logical_lines(content: str) -> list[LogicalLine]:
    escape = "\\"
    lines = content.splitlines(keepends=True)
    for raw in lines[:8]:
        stripped = raw.strip()
        match = re.match(r"^#\s*escape\s*=\s*([`\\])\s*$", stripped, re.I)
        if match:
            escape = match.group(1)
            break
    return _logical_lines(content, continuation=escape, preserve_newlines=True)


def _shell_logical_lines(content: str, *, start_line: int) -> list[LogicalLine]:
    lines = _logical_lines(content, continuation="\\")
    if start_line == 1:
        return lines
    return [
        LogicalLine(
            text=line.text,
            start_line=line.start_line + start_line - 1,
            end_line=line.end_line + start_line - 1,
            start_byte=line.start_byte,
            end_byte=line.end_byte,
        )
        for line in lines
    ]


def _shell_location(
    logical: LogicalLine,
    *,
    source_context: str,
    include_lines: bool,
) -> dict[str, int]:
    if not include_lines:
        return {}
    location = {
        "start_line": logical.start_line,
        "end_line": logical.end_line,
    }
    if source_context == "shell_script":
        location.update(
            {
                "start_byte": logical.start_byte,
                "end_byte": logical.end_byte,
            }
        )
    return location


def _logical_lines(
    content: str,
    *,
    continuation: str,
    preserve_newlines: bool = False,
) -> list[LogicalLine]:
    physical = content.splitlines(keepends=True)
    results: list[LogicalLine] = []
    buffer: list[str] = []
    start_line = 1
    start_byte = 0
    byte_offset = 0
    for index, raw in enumerate(physical, start=1):
        if not buffer:
            start_line = index
            start_byte = byte_offset
        text = raw.rstrip("\r\n")
        stripped = text.rstrip()
        continued = bool(stripped) and stripped.endswith(continuation)
        if continued:
            buffer.append(
                stripped
                if preserve_newlines
                else stripped[: -len(continuation)].rstrip()
            )
        else:
            buffer.append(text)
            if preserve_newlines:
                joined = "\n".join(part.strip() for part in buffer)
            else:
                joined = " ".join(part.strip() for part in buffer if part.strip())
            results.append(
                LogicalLine(
                    text=joined,
                    start_line=start_line,
                    end_line=index,
                    start_byte=start_byte,
                    end_byte=byte_offset + len(raw.encode("utf-8", errors="replace")),
                )
            )
            buffer = []
        byte_offset += len(raw.encode("utf-8", errors="replace"))
    if buffer:
        results.append(
            LogicalLine(
                text=(
                    "\n".join(part.strip() for part in buffer)
                    if preserve_newlines
                    else " ".join(part.strip() for part in buffer if part.strip())
                ),
                start_line=start_line,
                end_line=len(physical),
                start_byte=start_byte,
                end_byte=byte_offset,
            )
        )
    return results


def _split_shell_segments(command: str) -> list[str]:
    segments = re.split(r"(?:&&|\|\||\||;|\n)", command)
    return [
        segment.strip()
        for segment in segments
        if segment.strip() and not segment.lstrip().startswith("#")
    ]


def _remove_shell_line_continuations(value: str) -> str:
    """Apply the shell's backslash-newline removal before tokenisation."""
    return re.sub(r"\\\r?\n[ \t]*", " ", value)


def _docker_run_command(argument: str) -> tuple[list[str], str, int]:
    """Separate leading Docker BuildKit RUN options from the shell payload.

    Docker options are not shell argv. They can be split across physical lines,
    so retain the line offset of the actual command for nested evidence spans.
    """
    tokens = _safe_shell_split(argument)
    flags, _ = _leading_flags(tokens)
    if not flags:
        return [], argument, 0

    position = 0
    consumed: list[str] = []
    for flag in flags:
        position = _skip_docker_run_spacing(argument, position)
        if not argument.startswith(flag, position):
            # Be conservative if quoting or an unfamiliar syntax prevents exact
            # span recovery. The normalised token stream is still usable.
            remainder = tokens[len(flags) :]
            return flags, shlex.join(remainder), 0
        position += len(flag)
        consumed.append(flag)

    position = _skip_docker_run_spacing(argument, position)
    command_text = argument[position:]
    return consumed, command_text, argument[:position].count("\n")


def _skip_docker_run_spacing(value: str, position: int) -> int:
    length = len(value)
    while position < length:
        if value.startswith("\\\r\n", position):
            position += 3
            continue
        if value.startswith("\\\n", position):
            position += 2
            continue
        if value[position] in " \t\r\n":
            position += 1
            continue
        break
    return position


def _redact_sensitive_json_value(value: str) -> str | None:
    """Redact sensitive keys in a JSON-valued shell assignment when parseable."""
    candidates = [value]
    try:
        shell_values = shlex.split(value, comments=False, posix=True)
    except ValueError:
        shell_values = []
    if len(shell_values) == 1 and shell_values[0] != value:
        candidates.insert(0, shell_values[0])

    for candidate in candidates:
        stripped = candidate.strip()
        if not stripped.startswith(("{", "[")):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        redacted, changed = _redact_sensitive_json_tree(parsed)
        if changed:
            return json.dumps(
                redacted,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
    return None


def _redact_sensitive_json_tree(value: Any) -> tuple[Any, bool]:
    if isinstance(value, dict):
        changed = False
        result: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if _SENSITIVE_NAME_RE.search(key_text):
                result[key_text] = "<redacted-sensitive-literal>"
                changed = True
                continue
            redacted_child, child_changed = _redact_sensitive_json_tree(child)
            result[key_text] = redacted_child
            changed = changed or child_changed
        return result, changed
    if isinstance(value, list):
        result_list: list[Any] = []
        changed = False
        for child in value:
            redacted_child, child_changed = _redact_sensitive_json_tree(child)
            result_list.append(redacted_child)
            changed = changed or child_changed
        return result_list, changed
    return value, False


def _safe_shell_split(value: str) -> list[str]:
    normalised = _remove_shell_line_continuations(value)
    try:
        return shlex.split(normalised, comments=True, posix=True)
    except ValueError:
        try:
            return shlex.split(normalised, comments=False, posix=True)
        except ValueError:
            return [part for part in normalised.strip().split() if part]


def _leading_flags(tokens: list[str]) -> tuple[list[str], list[str]]:
    flags: list[str] = []
    index = 0
    while index < len(tokens) and tokens[index].startswith("--"):
        flags.append(tokens[index])
        index += 1
    return flags, tokens[index:]


def _strip_leading_flags_from_text(value: str, flags: list[str]) -> str:
    remainder = value.lstrip()
    for flag in flags:
        if remainder.startswith(flag):
            remainder = remainder[len(flag) :].lstrip()
    return remainder


def _flag_value(flags: list[str], name: str) -> str | None:
    for index, flag in enumerate(flags):
        if flag.startswith(f"{name}="):
            return flag.split("=", 1)[1]
        if flag == name and index + 1 < len(flags):
            return flags[index + 1]
    return None


def _json_array(value: str) -> list[str] | None:
    stripped = value.strip()
    if not stripped.startswith("["):
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        return None
    return list(parsed)


def _docker_assignments(argument: str, instruction: str) -> list[tuple[str, str | None]]:
    if instruction == "ARG":
        name, separator, value = argument.partition("=")
        return [(name.strip(), value if separator else None)] if name.strip() else []
    tokens = _safe_shell_split(argument)
    assignments: list[tuple[str, str | None]] = []
    if tokens and all("=" in token for token in tokens):
        for token in tokens:
            name, _, value = token.partition("=")
            assignments.append((name, value))
    elif tokens:
        assignments.append((tokens[0], " ".join(tokens[1:]) if len(tokens) > 1 else None))
    return assignments


def _image_reference_details(image: str) -> dict[str, object]:
    digest = None
    base = image
    if "@" in image:
        base, digest = image.rsplit("@", 1)
    last_component = base.rsplit("/", 1)[-1]
    tag = None
    if ":" in last_component:
        tag = last_component.rsplit(":", 1)[1]
    return {
        "tag": tag,
        "digest": digest,
        "digest_pinned": bool(digest),
        "tag_reference": bool(tag),
    }


def _dependency_references(
    values: object,
    *,
    group: str,
    manager: str,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for value in _string_values(values)[:MAX_TOML_DEPENDENCIES]:
        name, constraint = _split_dependency_spec(value)
        result.append(
            {
                "kind": "dependency_declaration",
                "manager": manager,
                "group": group,
                "name": name,
                "constraint": constraint,
                "raw": value,
            }
        )
    return result


def _split_dependency_spec(value: str) -> tuple[str, str | None]:
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", value.strip())
    if not match:
        return value.strip(), None
    return match.group(1), match.group(2).strip() or None


def _toml_table_paths(value: object, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if not isinstance(value, dict):
        return paths
    for key, child in sorted(value.items(), key=lambda item: str(item[0])):
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, dict):
            paths.append(path)
            paths.extend(_toml_table_paths(child, path))
    return paths[:MAX_OPERATIONAL_ITEMS]


def _wheel_looks_platform_specific(wheel: object) -> bool:
    if not isinstance(wheel, dict):
        return False
    url = str(wheel.get("url") or wheel.get("filename") or "")
    filename = url.rsplit("/", 1)[-1]
    return bool(filename.endswith(".whl") and "none-any.whl" not in filename)


def _is_dependency_lock_name(lower_name: str) -> bool:
    return lower_name in _TOML_LOCK_NAMES or lower_name == "manifest.toml"


def _lock_manager(lower_name: str) -> str | None:
    return {
        "uv.lock": "uv",
        "poetry.lock": "poetry",
        "pdm.lock": "pdm",
        "cargo.lock": "cargo",
        "manifest.toml": "julia",
    }.get(lower_name)


def _normalised_scalar(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_normalised_scalar(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalised_scalar(child) for key, child in sorted(value.items())}
    return str(value)


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return []


def _looks_like_assignment(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", value))


def _redact_if_sensitive(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    return "<redacted-sensitive-literal>" if _SENSITIVE_NAME_RE.search(name) else value


def _redact_sensitive_argv(tokens: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for token in tokens:
        if redact_next:
            redacted.append("<redacted-sensitive-literal>")
            redact_next = False
            continue
        if "=" in token:
            name, separator, value = token.partition("=")
            if _SENSITIVE_NAME_RE.search(name):
                redacted.append(f"{name}{separator}<redacted-sensitive-literal>")
                continue
        if token.startswith("-") and _SENSITIVE_NAME_RE.search(token.lstrip("-")):
            redacted.append(token)
            redact_next = True
            continue
        redacted.append(token)
    return redacted


def _redacted_shell_command(value: str) -> str:
    commands: list[str] = []
    normalised = _remove_shell_line_continuations(value)
    for segment in _split_shell_segments(normalised):
        tokens = _safe_shell_split(segment)
        if not tokens:
            continue
        commands.append(shlex.join(_redact_sensitive_argv(tokens)))
    return " ; ".join(commands)


def _has_shell_shebang(content: str) -> bool:
    first_line = content.splitlines()[0] if content.splitlines() else ""
    if not first_line.startswith("#!"):
        return False
    return bool(re.search(r"/(?:ba|da|k|z)?sh(?:\s|$)|\benv\s+(?:ba|da|k|z)?sh\b", first_line))


def _action_uses_immutable_revision(value: str) -> bool:
    if "@" not in value:
        return False
    revision = value.rsplit("@", 1)[1]
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", revision))


def _kubernetes_pod_spec(document: dict[str, Any]) -> dict[str, Any] | None:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        return None
    if isinstance(spec.get("template"), dict):
        template_spec = spec["template"].get("spec")
        return template_spec if isinstance(template_spec, dict) else None
    return spec


def _location(logical: LogicalLine) -> dict[str, int]:
    return {
        "start_line": logical.start_line,
        "end_line": logical.end_line,
        "start_byte": logical.start_byte,
        "end_byte": logical.end_byte,
    }
