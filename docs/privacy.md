# Privacy and secret scanning

Collect writes an inspectable export. The capture settings determine what leaves
the repository; decide whether a bundle is suitable for its intended recipient
before sending it.

## Defaults and disclosure

| Evidence | Default disclosure |
| --- | --- |
| Local Git | Commit subjects, author names, changed paths, refs and topology; emails, remote URLs and local paths use keyed pseudonyms |
| GitHub / Azure DevOps | PR titles, comment metadata, commit subjects, actor identities and changed paths; no PR/comment bodies, raw emails or URLs |
| Full snapshot | Selected committed source blobs and extracted structure |
| Structure snapshot | Paths, hashes, engineering identifiers and filtered structural observations; no source blobs |

Provider logins are included by default. Set `actor_mode: hash` or
`--actor-mode hash` to pseudonymise them; use `none` to omit them. Pseudonymisation
does not scrub names or identities embedded in free text.

Structure mode removes raw signatures, default expressions, raw import text,
command argument values and unreviewed configuration fields after local parsing.
Selected reference URLs have credentials, queries and fragments removed. It
retains symbol names, imports, call targets, paths and selected configuration
identities. Those can still be confidential or contain secrets.

Full mode can include any secret present in an eligible source file. Filename
exclusions do not inspect content. Activity-only bundles can also disclose secrets
in messages, titles, paths and explicitly enabled bodies or patches.

## Privacy key

Reuse one key across providers, repositories and repeated runs for the same
organisation. HMAC-SHA256 uses domain separation, and manifests contain only a
non-secret `key_id`, algorithm and scheme version. Rotating the key deliberately
changes pseudonyms and prevents direct joins with earlier bundles.

Provide the stored key through `SHEVEK_COLLECT_PRIVACY_KEY`, use
`--privacy-key-env ANOTHER_VARIABLE`, or use a mounted file:

```bash
uv run shevek-collect activity git \
  --repo ~/src/example-app --out runs/activity \
  --privacy-key-file /run/secrets/collect-key
```

Key material can be raw text, `hex:...` or `base64:...`; it must decode to at least
32 bytes. A supplied key file takes precedence over the environment variable.
Keep keys out of config, repository files and process arguments.

The key is used for pseudonyms, not bundle encryption. Source content, selected
metadata and content hashes are not encrypted.

## Optional secret scanning

Install [Gitleaks](https://github.com/gitleaks/gitleaks#installing) separately.
Collect has no scanner dependency. Use the current `dir` command on the **finished
bundle directory**, so it covers exported JSON/JSONL and included source blobs:

```bash
uv run shevek-collect run --config shevek_collect.yaml --out runs/review
uv run shevek-collect inspect runs/review

gitleaks dir runs/review --redact=100 --no-banner --ignore-gitleaks-allow && \
  uv run shevek-collect pack runs/review --out runs/review.zip
```

The `&&` prevents packaging if the scanner returns non-zero. Resolve findings or
scanner errors before sharing. Redaction limits secret exposure in scanner output;
keep logs private. Do not write scanner reports into the bundle.

This is an operator-run check: Collect's `secret_scanning` metadata remains
`not_performed`. Neither `pack` nor `submit` automatically runs Gitleaks.
`submit` recollects before uploading, so it does not send the exact bundle reviewed
above. When that distinction matters, share the already reviewed ZIP using your
chosen transfer process.

A clean scan is not proof of safety. Content-addressed blobs have hash filenames,
so filename-dependent rules can miss findings. Metadata is serialised and may be
escaped; custom credentials and sensitive business information may not match any
rule. Scanner configuration and allowlists also affect coverage. To map a blob
finding back to source, match its `blob_path` in `code/files.jsonl` to `path` and
`snapshot_id`.

## Storage and execution boundary

- Bundles and ZIPs are unencrypted. Use private output directories and an
  appropriate transfer channel for the contents.
- POSIX staging/archives restrict access to the owner. Windows uses directory ACLs.
- Collect does not execute repository source. Git observation disables hooks,
  fsmonitor, external diffs/text conversion, optional writes and implicit fetching.
- Explicit fetching uses the operator's Git transport and authentication setup.
- Python, native parsers, Git/gh executables and local configuration are trusted.
  Parser limits contain resource use; they are not an exploit sandbox.
- Service and Azure authenticated HTTP requires HTTPS and refuses redirects.
  Transport encryption does not encrypt a saved bundle.

See [SECURITY.md](../SECURITY.md) for reporting and
[bundle completeness](bundle-format.md#completeness) for extraction limitations.
