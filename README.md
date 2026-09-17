# Shevek Collect

Collect repository activity and committed source snapshots into inspectable local
bundles. It supports Git, GitHub and Azure DevOps, with JSON/JSONL output for your
own analysis tools or the [Shevek](https://shevek.com.au) service.

Collect runs in your environment. Local collection needs no account, backend or
LLM. It records observations: commits, pull requests, changed paths, repository
structure and optional source content. It does not summarise code or infer what
people are working on.

## Install

Requirements: Python 3.11 or later and a current Git installation. GitHub activity
also needs the [GitHub CLI](https://cli.github.com). Linux is the primary tested
platform; macOS and Windows have not yet been validated on native runners.

From a checkout or extracted source release, install with
[uv](https://docs.astral.sh/uv/getting-started/installation/):

```bash
uv sync --locked
uv run shevek-collect --version
```

Alternatively, install from source into your own virtual environment with
`python -m pip install .`, then use `shevek-collect` directly. The examples below
use `uv run` from the Collect checkout.

## Quick start

### 1. Set up a privacy key

Collect requires a reusable organisation key for HMAC pseudonyms. Generate it
**once**, store it in your secret manager, and load that same value for later
runs. Changing it changes the identifiers in your bundles.

```bash
# First-time setup only; save this value privately before ending the session.
export SHEVEK_COLLECT_PRIVACY_KEY="$(openssl rand -hex 32)"
```

The key is never written to a bundle. A mounted key file is also supported through
`--privacy-key-file /run/secrets/collect-key`. See [privacy](docs/privacy.md).

### 2. Collect local Git activity

```bash
uv run shevek-collect activity git \
  --repo ~/src/example-app \
  --since '90 days ago' \
  --out runs/activity
```

This captures commit subjects, changed paths, refs, tags and branch relationships.
It does not capture source files or patches.

### 3. Inspect and package

```bash
uv run shevek-collect inspect runs/activity
uv run shevek-collect inspect runs/activity --json
uv run shevek-collect pack runs/activity --out runs/activity.zip
```

Review `runs/activity/privacy_report.md` and the exported records before sharing.
`pack` creates a local ZIP; it makes no network requests. It validates declared
outputs and verifies the hashes of any included source blobs.

## Choose what to collect

| Goal | Command | Source code included? |
| --- | --- | --- |
| Local commits and repository topology | `activity git` | No |
| GitHub pull requests, commits and comments | `github scan` | Only patch text if explicitly enabled |
| Azure DevOps pull requests, commits and comments | `azure-devops scan` | No |
| One exact committed repository tree | `snapshot` | Yes by default; `--content-mode structure` omits blobs |
| Multiple repositories, providers or refs | `run --config collect.yaml` | Only if snapshots are configured |
| Review an existing bundle | `inspect BUNDLE` | Reads the manifest and validates declared outputs |
| Package an existing bundle locally | `pack BUNDLE --out bundle.zip` | Preserves the selected bundle content |
| Collect and send to Shevek | `submit --config collect.yaml` | Uploads the configured evidence |

For a source snapshot:

```bash
uv run shevek-collect snapshot \
  --repo ~/src/example-app \
  --ref HEAD \
  --content-mode full \
  --out runs/snapshot
```

Snapshots read committed Git objects. Uncommitted changes and untracked files are
not captured. Structure mode parses locally and retains engineering names and
relationships; it is not anonymous.

For repeatable collection, copy [the minimal config](examples/shevek_collect.example.yaml)
to `shevek_collect.yaml`, edit the repository path, then run:

```bash
uv run shevek-collect run --config shevek_collect.yaml --out runs/combined --dry-run
uv run shevek-collect run --config shevek_collect.yaml --out runs/combined
```

The dry run validates configuration and lists planned sources without contacting
providers or requiring a privacy key. It does not verify credentials or Git refs.

## Data handling

Default activity capture omits raw emails, remote URLs, PR bodies and comment
bodies. Names, repository names, changed paths, commit subjects and provider actor
logins can still identify people or systems. Snapshot `full` mode includes source
content; common credential filenames are excluded, but secrets in other files can
still be exported.

Collect does not run a secret-content scanner or encrypt stored bundles. An
[optional Gitleaks workflow](docs/privacy.md#optional-secret-scanning) checks the
finished export before packaging. Review sensitive bundles even after a clean scan.

Existing non-empty output directories are protected. Use `--overwrite` to replace
a previous Collect bundle. `--force-overwrite` can remove unrelated content and
should only be used after checking the destination. ZIP replacement is separately
opted into; see [output handling](docs/usage.md#output-handling).

## Documentation

- [Usage and troubleshooting](docs/usage.md): providers, snapshots, progress and failures.
- [Configuration](docs/configuration.md): YAML options and repeatable collection.
- [Privacy and secret scanning](docs/privacy.md): disclosure choices and review workflow.
- [Bundle format](docs/bundle-format.md): files, record types, identity and completeness.
- [Shevek service submission](docs/submission.md): optional authenticated integration.
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md).

Licensed under [Apache-2.0](LICENSE). Copyright 2026 Shevek Pty Ltd.
