from __future__ import annotations

import json
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from .filesystem import (
    FileSafetyError, destination_path, destination_lock, path_state,
    publish_staged, regular_file_in,
)

COLLECT_MANIFEST_NAME = "collect_manifest.json"
COLLECT_MANIFEST_SCHEMA_PREFIX = "shevek.collect_manifest."


OutputDirectoryError = FileSafetyError


@contextmanager
def atomic_bundle_directory(
    target: Path,
    *,
    overwrite: bool = False,
    force_overwrite: bool = False,
) -> Iterator[Path]:
    """Yield a sibling staging directory and atomically publish it as ``target``.

    Existing recognised Shevek bundles require ``overwrite``. Existing non-empty
    directories that are not recognised bundles require ``force_overwrite``.
    Symlinks and non-directory targets are always refused.
    """
    target = destination_path(target)
    _validate_output_target(target, overwrite=overwrite, force_overwrite=force_overwrite)
    with destination_lock(target):
        _validate_output_target(target, overwrite=overwrite, force_overwrite=force_overwrite)
        expected = path_state(target)
        stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=target.parent))
        try:
            yield stage
            validate_bundle(stage)
            publish_staged(stage, target, expected)
        finally:
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)


def is_collect_bundle(path: Path) -> bool:
    """Return true only when ``path`` contains a recognisable collect manifest."""
    if not path.is_dir():
        return False
    manifest_path = path / COLLECT_MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict):
        return False
    schema_version = manifest.get("schema_version")
    return (
        isinstance(schema_version, str)
        and schema_version.startswith(COLLECT_MANIFEST_SCHEMA_PREFIX)
        and manifest.get("bundle_kind") in {"source_evidence", "evidence_bundle"}
        and isinstance(manifest.get("outputs"), dict)
    )


def validate_bundle(path: Path) -> dict[str, object]:
    """Validate the staged bundle before publication and return its manifest."""
    manifest_path = path / COLLECT_MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise OutputDirectoryError(
            f"Generated bundle is missing {COLLECT_MANIFEST_NAME}: {path}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise OutputDirectoryError(
            f"Generated bundle has an invalid {COLLECT_MANIFEST_NAME}: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise OutputDirectoryError("Generated collect manifest must be a JSON object")
    schema_version = manifest.get("schema_version")
    if not (
        isinstance(schema_version, str)
        and schema_version.startswith(COLLECT_MANIFEST_SCHEMA_PREFIX)
        and manifest.get("bundle_kind") in {"source_evidence", "evidence_bundle"}
    ):
        raise OutputDirectoryError(
            "Generated directory does not contain a recognised Shevek collect bundle"
        )
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict):
        raise OutputDirectoryError("Generated collect manifest is missing an outputs mapping")
    missing: list[str] = []
    for value in outputs.values():
        if not isinstance(value, str) or not value.strip():
            raise OutputDirectoryError("Generated collect manifest contains an invalid output path")
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise OutputDirectoryError(
                f"Generated collect manifest contains an unsafe output path: {value!r}"
            )
        try:
            regular_file_in(path, value)
        except FileNotFoundError:
            missing.append(value)
    if missing:
        raise OutputDirectoryError(
            "Generated bundle is missing declared outputs: " + ", ".join(sorted(missing))
        )
    return manifest


def write_json(path: Path, data: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(record, sort_keys=True, ensure_ascii=False) for record in records]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalize_newlines(text), encoding="utf-8")


def normalize_newlines(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text if text.endswith("\n") else text + "\n"


def _validate_output_target(
    target: Path,
    *,
    overwrite: bool,
    force_overwrite: bool,
) -> None:
    cwd = Path.cwd().resolve()
    protected = {Path.home().resolve(), Path(target.anchor).resolve()}
    if target in protected or target == cwd or target in cwd.parents:
        raise OutputDirectoryError(
            f"Refusing to use a protected high-level output directory: {target}"
        )
    if not target.exists():
        return
    if not target.is_dir():
        raise OutputDirectoryError(f"Output path exists and is not a directory: {target}")
    try:
        next(target.iterdir())
    except StopIteration:
        return
    if is_collect_bundle(target):
        if overwrite or force_overwrite:
            return
        raise OutputDirectoryError(
            f"Output already contains a Shevek collect bundle: {target}. "
            "Pass --overwrite to replace it atomically."
        )
    if force_overwrite:
        return
    raise OutputDirectoryError(
        f"Output directory is non-empty and is not a recognised Shevek collect bundle: {target}. "
        "Refusing to delete unrelated content; pass --force-overwrite only after checking the path."
    )
