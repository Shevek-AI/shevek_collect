# Usage and troubleshooting

Run examples from the Collect checkout after installation. Every collection
command requires a privacy key; see [setup](privacy.md#privacy-key). Use
`uv run shevek-collect COMMAND --help` for the full flag list.

## Local Git activity

```bash
uv run shevek-collect activity git \
  --repo ~/src/example-app --repo ~/src/example-library \
  --since '90 days ago' --max-count 500 \
  --out runs/activity
```

`--since` uses Git's date syntax; `--max-count` caps commits per repository.
Activity includes commit metadata and changed paths, not file contents or patches.
`--message-mode none|subject|full` controls message detail; `subject` is the default.

To discover repositories below a directory:

```bash
uv run shevek-collect activity git \
  --root ~/src --discover-repos --out runs/discovered
```

Discovery recognises working trees and linked Git worktrees. It stops descending
when it finds a repository and skips common dependency directories. Bare
repositories and nested repositories below an already discovered repository are
not discovered automatically.

Topology observations include local and remote-tracking refs, tags, repository
history state, comparison anchors, branch divergence, patch-equivalent commits
and merge viability. They describe the locally available objects and refs; remote
refs can be stale. Shallow or partial history limits what can be observed.

Add a comparison anchor with `--topology-comparison-ref refs/remotes/origin/develop`.
Use `--max-topology-commit-ids 500` to bound retained commit IDs or
`--skip-merge-viability` to omit conflict simulation. Merge checks use a private
object database and never invoke custom merge drivers. Unsupported checks remain
explicitly unavailable rather than being reported as successful.

Local observation never fetches implicitly. Fetch missing objects with your own
Git workflow first. The optional service command has an explicit
[`submit --fetch`](submission.md#fetching-and-repeat-submissions) flag.

## GitHub activity

Install `gh` and authenticate locally with `gh auth login`. Use credentials with
read access to the selected repositories and pull requests.

```bash
uv run shevek-collect github scan \
  --repo example-org/example-app \
  --since 2026-01-01 --max-prs 200 \
  --actor-mode hash \
  --out runs/github
```

Repeat `--repo`, or pass `--repo-file repositories.txt` with one `owner/name` per
line. Blank lines and lines beginning with `#` are ignored. GitHub Enterprise
uses `--hostname github.example.com` and that host's existing `gh` authentication.
`--since` filters PR update timestamps locally; it is not a cap on every request.

Defaults: PR titles, comment metadata, commit subjects, actor logins, changed paths
and file statistics. `--actor-mode hash` pseudonymises logins; `none` omits them.
Optional `--body-mode full`, `--comment-mode full`, `--commit-message-mode full`,
`--include-file-patches`, `--include-urls` and `--include-raw-emails` increase
what is disclosed. The `none` mode is also available for bodies/comments/messages.

## Azure DevOps activity

Supply a PAT through the `AZURE_DEVOPS_EXT_PAT` environment variable, or name a
different variable with `--token-env`. Scope credentials to read the relevant
repositories, PRs and associated work items. Collect does not need write access.

```bash
uv run shevek-collect azure-devops scan \
  --organization example-org \
  --repo Platform/example-app \
  --since 2026-01-01 --actor-mode hash \
  --out runs/azure
```

Repeat `--repo Project/Repository` for more repositories. The default API version
is `7.1`; override with `--api-version` where appropriate. Bodies, comments, commit
messages, actor identities, raw emails and URLs use the same privacy switches as
GitHub. Azure collection has no file-patch export option. The PAT is not included
in the bundle.

## Source snapshots

```bash
uv run shevek-collect snapshot \
  --repo ~/src/example-app --ref HEAD --name target \
  --content-mode structure --out runs/structure
```

Defaults are `HEAD`, snapshot name `target`, and content mode `full`.

| Mode | Exported content |
| --- | --- |
| `full` | Selected source blobs, hashes, paths and syntax/operational observations |
| `structure` | Hashes, paths and filtered syntax/operational observations; no source blobs |

Snapshots use exact committed trees without checking out a ref. They do not read
dirty working files, follow symlink targets, expand submodules or copy `.git`.
Tracked files remain eligible even if a current `.gitignore` pattern matches them;
selection is controlled by the snapshot capture policy.

Selection flags are `--include-glob`, `--exclude-glob`, `--max-file-bytes`
(default 2 MiB) and `--max-total-bytes` (default 256 MiB per snapshot). Repeat a
glob flag for several patterns. Exclusions take precedence over inclusions.
`--no-default-excludes` disables the built-in filename exclusions. See
[configuration](configuration.md#snapshots) before changing that policy.

Every tracked entry gets a record, including omitted entries. Git LFS objects are
not fetched: a committed pointer is observed as that pointer, not the large file.
Use configuration for multiple repositories or refs. A missing ref produces a
failed snapshot result and a non-zero collection exit status.

### Parsing coverage

Tree-sitter covers Python, JavaScript, TypeScript/TSX, Java, C#, C++, CSS and Julia.
C++ headers are treated as C++; plain `.c` files are not currently parsed.
Julia composition reads `Project.toml`, resolves literal include trees and records
module ownership, exports, method families, scopes and top-level workflows.
Dynamic references remain unresolved observations.

SQL uses a conservative structural scanner for declarations and named
relation/routine references. It is not a validating grammar for any SQL dialect.
Operational extraction covers Dockerfiles/Containerfiles, Bash/shell scripts,
TOML manifests/locks and YAML, including GitHub Actions, Compose and Kubernetes.
Unrecognised files can still be included as source blobs in full mode.

Parsing runs in disposable processes with a 10-second wall timeout and 32 MiB
request/result limits. POSIX workers also have a 768 MiB address-space limit and a
10-second CPU limit. Failures appear in file parse metadata without source
excerpts. These limits are not an operating-system sandbox.

## Output handling

Collection stages and validates a bundle before publishing it. A failed rerun
leaves the previous bundle intact. A recorded partial collection can still be
published for diagnosis; check the status before using it.

- A missing or empty output directory needs no replacement flag.
- `--overwrite` replaces a recognised Collect bundle.
- `--force-overwrite` permits replacing an unrelated non-empty directory.
- Symlinks, home directories, filesystem roots, and the current working directory
  or its ancestors are refused as output targets.

Keep the output parent directory private. POSIX output permissions are restricted;
Windows relies on the parent directory ACLs. Locks prevent competing Collect runs;
recovery directories preserve the prior bundle if another writer interferes with
publication. Do not delete a reported recovery directory until its contents are
recovered.

Package an existing bundle without collecting again or making network requests:

```bash
uv run shevek-collect pack runs/activity --out runs/activity.zip
# To replace a previous archive:
uv run shevek-collect pack runs/activity --out runs/activity.zip --overwrite
```

The ZIP must be outside the bundle. Only declared files and referenced,
SHA-256-verified source blobs are included. Links and nonregular members are
refused. Undeclared notes and local submission state are not included. A partial
bundle can be packaged for diagnosis; packing is not a completeness or secret check.

## Progress, errors and automation

Progress goes to stderr. `--quiet` suppresses collection progress; `--json` makes
the final stdout summary machine-readable. Dry-run plans and local diagnostics
may include local paths, so review them before attaching logs to an issue.

Collection returns `0` on success and `1` for recorded collection failures.
Invalid arguments, configuration, output or submission errors return `2`.
`inspect` validates the manifest and declared output files, then reports them;
its success does not mean collection or parsing was complete.

GitHub and Azure requests retry timeouts, 408/429/5xx responses and explicit
throttling errors. Defaults: five attempts, exponential jitter, a 30-second delay
ceiling and a 300-second `Retry-After` cap. Override with `--retry-attempts`,
`--retry-initial-delay`, `--retry-max-delay` and `--retry-max-retry-after`, or a
source-local YAML `retry` block. Auth/permission/not-found errors are not retried.
Failed provider repositories contribute no partially assembled records.

| Symptom | What to check |
| --- | --- |
| Privacy key missing or too short | Load the same stored key; decoded material must be at least 32 bytes |
| Existing output refused | Use a new path, or the appropriate replacement flag |
| No recent commits / old snapshot | Local refs may be stale; `HEAD` remains the checked-out commit after fetching |
| GitHub authentication failure | Run `gh auth status` for the configured hostname |
| Azure 401/403/404 | Check PAT, organisation, project, repo and read permissions |
| Some files missing | Inspect `code/files.jsonl` inclusion reasons, size limits and globs |
| Source looks out of date | Snapshots exclude working-tree edits; commit them or select the intended ref |
| Parse failures | Inspect file diagnostics and parser limits; collection completeness is separate |
| HTTPS redirect refused | Configure the final service endpoint directly |

`git scan` is retained as a deprecated alias for `activity git` for existing
scripts. New scripts should use `activity git`.
