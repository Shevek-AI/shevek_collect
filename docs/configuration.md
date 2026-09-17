# Configuration

Use `run --config shevek_collect.yaml --out runs/combined` for repeatable,
multi-source collection. Copy the [minimal example](../examples/shevek_collect.example.yaml)
or adapt the [multi-source example](../examples/multi-source.yaml).

Paths in YAML are relative to the config file, with `~` expansion. `--out` is
relative to the current working directory. Use actual YAML booleans (`true` and
`false`); strings such as `"false"`, numbers and nulls are rejected for flags.

## Minimal local activity

```yaml
version: 1
activity_sources:
  git:
    repos:
      - ~/src/example-app
    since: "90 days ago"
```

At least one activity source or snapshot section is required. Omit providers you
do not use. A source can also be disabled with `null`. `defaults` supplies shared
activity options; a source's own values override them. Provider dates should use
ISO-8601, for example `"2026-01-01"`; Git also accepts relative date expressions.

```bash
uv run shevek-collect run --config shevek_collect.yaml --out runs/combined --dry-run --json
```

Dry runs read config/repo-list files and perform requested local discovery. They
do not check remote access or resolve snapshot refs. Check the printed plan:
configuration is not a strict schema and unrecognised option names may be ignored.

## Local Git

```yaml
activity_sources:
  git:
    repos:
      - ~/src/example-app
      - path: ~/src/example-library
        topology:
          comparison_refs:
            - refs/remotes/origin/develop
    since: "90 days ago"
    max_count: 500
    message_mode: subject
    include_raw_emails: false
    include_remote_urls: false
    include_local_paths: false
    topology:
      max_commit_ids: 500
      include_merge_viability: true
```

Use `roots: [~/src]` with `discover_repos: true` instead of, or alongside, `repos`.
When roots are supplied, discovery defaults to enabled. Repositories are
deduplicated by resolved local path. Extra comparison refs belong to individual
repository entries. `message_mode` is `none`, `subject` (default) or `full`.

## GitHub and Azure DevOps

```yaml
activity_sources:
  github:
    hostname: github.com
    repos:
      - example-org/example-app
    # Optional files containing one owner/name per line:
    # repo_files: [repositories.txt]
    since: "2026-01-01"
    max_prs: 200
    body_mode: title
    comment_mode: metadata
    actor_mode: hash
    commit_message_mode: subject
    include_raw_emails: false
    include_file_patches: false
    include_urls: false
    retry:
      max_attempts: 5
      initial_delay_seconds: 1
      max_delay_seconds: 30
      max_retry_after_seconds: 300

  azure_devops:
    organization: example-org
    repos:
      - project: Platform
        repo: example-app
    token_env: AZURE_DEVOPS_EXT_PAT
    api_version: "7.1"
    actor_mode: hash
```

GitHub uses existing `gh` authentication. Azure uses the environment variable named
by `token_env`; never put a PAT value in YAML. The Azure repo shorthand is
`Platform/example-app`. Both providers support:

| Option | Values | Default |
| --- | --- | --- |
| `body_mode` | `none`, `title`, `full` | `title` |
| `comment_mode` | `none`, `metadata`, `full` | `metadata` |
| `actor_mode` | `none`, `login`, `hash` | `login` |
| `commit_message_mode` | `none`, `subject`, `full` | `subject` |
| `include_raw_emails` / `include_urls` | boolean | `false` |
| `since` / `max_prs` | date / integer | no explicit limit |
| `retry` | mapping shown above | values shown above |

Only GitHub supports `include_file_patches` (default `false`). Examples explicitly
use `actor_mode: hash`; omitting the option retains provider logins.

## Snapshots

Snapshot capture is separate from activity and is disabled unless configured.
A snapshot-only config is valid.

```yaml
version: 1
repository_snapshots:
  git:
    repos:
      - path: ~/src/example-app
        snapshots:
          - name: target
            ref: HEAD
          - name: base
            ref: HEAD~1
    capture:
      content_mode: full
      max_file_bytes: 2097152
      max_total_bytes: 268435456
      include_globs: []
      exclude_globs:
        - data/**
        - '**/data/**'
      use_default_excludes: true
```

Without `snapshots`, each repository captures `target` at `HEAD`. All requested
refs must exist locally. `defaults.since` affects activity, not which files appear
in a snapshot. Limits apply to each snapshot, including in structure mode.

Globs match if either Python `fnmatch.fnmatchcase` on the full repository-relative
POSIX path or `PurePosixPath.match` succeeds. These are not `.gitignore` rules:
`*` can cross `/` in the full-path match, while path matching also considers
trailing path components. Use explicit root and nested patterns as in the example
and check the resulting file records. An empty `include_globs` selects all otherwise eligible paths;
any exclusion wins over inclusion.

Defaults exclude generated/dependency directories and common credential filenames
such as `.env`, `.env.*`, `.npmrc`, `.pypirc`, private keys and certificate bundles.
This includes `.env.example`. The complete list is
[`DEFAULT_EXCLUDE_GLOBS`](../src/shevek_collect/repository_snapshot.py).
Custom excludes are added to those defaults. `use_default_excludes: false` removes
only the built-in list; explicitly configured excludes still apply.

## Optional submission settings

```yaml
submission:
  project_id: "your-project-id"
  priorities: priorities.md
```

These settings are only used by `submit`. They neither upload data nor enable
service access during `run`. See [service submission](submission.md).
