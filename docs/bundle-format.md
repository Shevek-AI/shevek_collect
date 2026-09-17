# Bundle format

A bundle is a directory of UTF-8 JSON and JSONL files. JSONL contains one object
per non-empty line. Consumers can read the files directly; no Shevek service is
required. Use `collect_manifest.json` as the entry point and resolve its `outputs`
paths relative to the bundle root.

## Files

| File | Contents |
| --- | --- |
| `collect_manifest.json` | Collector version, schema, settings, counts, privacy flags, identities, completeness and output paths |
| `source_events.jsonl` | Commits, PRs, PR commits and comments |
| `source_artifacts.jsonl` | Repositories, changed paths, refs, tags, branch relationships and PR files |
| `privacy_report.md` | Human-readable capture settings and disclosure summary |
| `code/snapshots.jsonl` | Snapshot IDs, requested refs, resolved commits and tree identities |
| `code/files.jsonl` | Tracked entries, inclusion/omission reasons, hashes, paths, syntax and operational structure |
| `code/operational_records.jsonl` | Flattened operational observations with source locations |
| `code/extraction_manifest.json` | Parser versions, policy, extraction counts and diagnostics |
| `code/blobs/sha256/<hash>` | Deduplicated captured source bytes, in full mode only |

The `code/` outputs appear only for snapshot collection. Activity JSONL files are
present but empty in snapshot-only bundles. Paths for omitted files are still
observations and may themselves be sensitive.

A captured file's `content_hash` has the form `sha256:<hex>`. Its `blob_path`, when
present, points to `code/blobs/sha256/<hex>`. Structure-mode records retain hashes
without including the blobs. Do not infer that a hash-only record is downloadable.

## Versions and records

| Envelope | Current schema |
| --- | --- |
| Collection manifest | `shevek.collect_manifest.v1` |
| Activity event | `shevek.source_event.v1` |
| Activity artifact | `shevek.source_artifact.v1` |
| Snapshot | `shevek.repository_snapshot.v1` |
| File | `shevek.repository_file.v1` |
| Extraction manifest | `shevek.repository_extraction_manifest.v1` |
| Embedded syntax | `shevek.syntax_observations.v2` |

Preserve `schema_version` and collector version when storing evidence. Accept
additional fields, but check schema compatibility before interpreting them.
`run` combines sources mechanically and deduplicates by `event_id` or
`artifact_id`; it does not infer semantic equivalence or ownership.

| Provider | Event types | Artifact types |
| --- | --- | --- |
| Git | `git.commit` | `git.repository`, `git.changed_path`, `git.ref_snapshot`, `git.tag_snapshot`, `git.branch_relation` |
| GitHub | `github.pull_request`, `github.pull_request_commit`, `github.issue_comment` | `github.repository`, `github.pull_request_file`, `github.changed_path` |
| Azure DevOps | `azure_devops.pull_request`, `azure_devops.pull_request_commit`, `azure_devops.pull_request_comment` | `azure_devops.repository`, `azure_devops.pull_request_file`, `azure_devops.changed_path` |

Use `semantic_type` for provider-independent routing and retain the original
`event_type`/`artifact_type` as provenance. Semantic types include `scm.commit`,
`scm.ref`, `scm.tag`, `scm.branch_relation`, `code_review.pull_request`,
`code_review.pull_request_commit`, `code_review.pull_request_file` and
`code_review.comment`.

Syntax observations contain declarations, calls, imports, non-call references and
scopes. Operational observations record build commands, dependencies, workflow
jobs, container/service relationships and configuration structure. These are
syntactic observations, not verified dependency graphs or security conclusions.

Snapshot privacy flags `contains_ignored_files` and `ignored_files_included` are
`null` (unknown): committed entries can match ignore patterns, and Collect does not
consult `.gitignore`. `gitignore_applied` is explicitly `false`. Use capture globs
to control selection. `secret_scanning: "not_performed"` means no scanner ran
inside Collect, even if an operator checked the export separately.

## Identity

The same hosted repository can share a `repo_id` across local Git and provider
records when common HTTPS, SSH and SCP-style locators normalise to the same host
and repository. The same organisation privacy key must be used throughout.
Repository fingerprints use the `repo_v2_` namespace. Unknown/unhosted remotes
fall back to local repository identity and are not guessed to match a provider.

Manifests expose `identity.schema` and `identity.key_id`. Compare these before
joining datasets. A useful cross-source join is `(repo_id, sha)` for local and
PR commits. A snapshot's `snapshot_id` binds its repository, resolved commit and
selector name; `file_id` identifies an entry within that snapshot.

## Completeness

`collection_status` is `complete`, `partial` or `failed`; `complete` is also
available as a boolean. Per-repository results carry status, counts and safe
error codes. Hosted provider manifests record retry policy and accounting.
Failed provider repositories do not contribute partial sets of events/artifacts.

Collection completeness is separate from **coverage**. A successful bounded run
can omit old commits, capped PRs, excluded/large/binary files and unsupported
syntax. File parsing failures do not necessarily fail collection. Inspect:

- The collection manifest's `complete`, `errors`, settings and repository results.
- The extraction manifest's omission counts, parse status counts and parser versions.
- Each file's `capture_status`, `omit_reason` and parse metadata.
- History/topology states that indicate shallow, partial or unavailable evidence.

For example, this checks collection status without interpreting source content:

```python
import json
from pathlib import Path

bundle = Path("runs/combined")
manifest = json.loads((bundle / "collect_manifest.json").read_text(encoding="utf-8"))
if manifest.get("complete") is not True:
    raise RuntimeError("Collection is incomplete; inspect repository_results")
```

Treat bundle paths as untrusted when writing your own reader. `inspect` validates
declared outputs; `pack` additionally rejects unsafe members and verifies
referenced blob hashes. Neither command certifies the content as non-sensitive.

## Local submission state

`submit --skip-unchanged` stores `.shevek_submit_commits.json` beside the bundle
outputs. It is local service bookkeeping and is excluded from packaged ZIPs.
It records accepted submissions, not proof of successful downstream analysis.
