# Shevek service submission

`submit` is the optional integration with the Shevek service. Local collection,
inspection and packaging need no service account. Submission requires access to
the service and a service token supplied by its operator.

**`submit` collects again and uploads immediately.** It is not an upload command
for a previously reviewed bundle, and it does not run a secret scanner. To inspect
and scan an exact export first, use `run`, then `inspect`, then `pack`, and share
that ZIP through your intended transfer process. See [privacy](privacy.md).

## Submit from configuration

Load your service token into `SHEVEK_SERVICE_TOKEN`, then:

```bash
uv run shevek-collect submit \
  --config shevek_collect.yaml --out runs/submission \
  --api-endpoint https://api.shevek.ai \
  --token-env SHEVEK_SERVICE_TOKEN
```

The endpoint defaults to `SHEVEK_API_ENDPOINT`, then `https://api.shevek.ai`.
`--api-endpoint` overrides both. It accepts a base URL or the final `/jobs/bundle`
endpoint; `--api-url` is a compatibility alias. `--token` is supported, but an
environment variable avoids exposing a token in command history/process arguments.

Authenticated endpoints must use HTTPS without URL credentials, query strings or
fragments. Redirects are refused. Submission logs omit tokens and response bodies;
`--json` returns the parsed service response, which should be treated as private.
Incomplete collections are not submitted.

The command derives Trace jobs for code snapshots and a Catalogue job for an
enabled activity facet. These are Shevek service job types; they are not required
by independent bundle consumers. `--analysis-depth smoke|demo|standard|deep`
sets depth for Trace jobs only. Omission keeps the service default.

The generated ZIP defaults to `<out>.zip`. Use `--zip-out` for another location.
A repeat run may require both `--overwrite` for the bundle and `--overwrite-zip`
for the archive. ZIPs contain only declared outputs and verified referenced blobs.
`--timeout` controls HTTP submission timeout (default 120 seconds).

## Projects and priorities

```yaml
submission:
  project_id: "your-project-id"
  priorities: priorities.md
```

`--project-id` overrides the config value. With a project ID, submission also
requests Alignment using a priorities Markdown file. File resolution is:

1. `--priorities PATH`, relative to the current working directory.
2. `submission.priorities`, relative to the config file.
3. `priorities.md` beside the config file.

The file must exist before collection starts. The request sequence is a
`POST /jobs/bundle`, followed by `POST /jobs/alignment` with the project ID and
priorities. Alignment uses the project's most recent group. Avoid simultaneous
submissions to the same project when this association matters.

The two requests are not atomic. An Alignment failure can occur after the bundle
was accepted; inspect the service state before retrying. Without a project ID,
only the bundle jobs are requested.

Each bundle request includes a `submission_manifest` field describing all
collected repository IDs and resolved commits, even if an unchanged Trace job is
omitted. This lets the service reconcile the complete submitted state.

## Fetching and repeat submissions

```bash
uv run shevek-collect submit \
  --config shevek_collect.yaml --out runs/submission \
  --overwrite --overwrite-zip --fetch --skip-unchanged
```

`--fetch` fetches `origin` once per resolved local repository from the collection
plan, including shorthand entries, discovered repositories and snapshot sources.
It validates the plan before fetching and disables recursive submodule fetches.
Fetching updates remote-tracking refs, not the current branch or working tree.
To capture the fetched branch, choose it explicitly:

```yaml
repository_snapshots:
  git:
    repos:
      - path: ~/src/example-app
        snapshots:
          - name: target
            ref: refs/remotes/origin/main
```

`--skip-unchanged` records accepted snapshot commit hashes in
`<out>/.shevek_submit_commits.json`. It omits Trace jobs whose commits have already
been submitted for the same repository/project. Catalogue jobs are unaffected.
State survives `--overwrite` and is excluded from the ZIP. Separate project
namespaces prevent reuse of another project's history.

This optimisation tracks **submission acceptance**, not downstream job success or
analysis settings. Omit it when retrying failed analysis or changing analysis
depth. If every Trace job is skipped and no Catalogue job exists, no bundle or
Alignment request is made.
