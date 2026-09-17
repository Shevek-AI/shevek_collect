"""Build valid manifests for tests that mock collection rather than its format."""
import json
from pathlib import Path


def seal_bundle(bundle: Path) -> None:
    path = bundle / "collect_manifest.json"
    manifest = json.loads(path.read_text())
    manifest.update({
        "schema_version": "shevek.collect_manifest.v1",
        "bundle_kind": "source_evidence",
        "outputs": {member.relative_to(bundle).as_posix(): member.relative_to(bundle).as_posix()
                    for member in bundle.rglob("*") if member.is_file()
                    and member.name not in {"collect_manifest.json", ".shevek_submit_commits.json"}},
    })
    path.write_text(json.dumps(manifest), encoding="utf-8")
