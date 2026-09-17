# Contributing

Collect turns source evidence into local bundles. Contributions should preserve
that boundary: interpretation and analysis belong in consumers of the format.

## Development

Use Python 3.11 or later and a current Git installation:

```bash
uv sync --locked --group dev
uv run --locked pytest -q
uv build
```

The tests use temporary repositories, synthetic evidence and mocked provider
requests. They do not require provider credentials or contact the Shevek service.
CI runs the suite on Linux with Python 3.11–3.14 and builds source/wheel packages.
Native macOS and Windows validation is still needed before claiming support there.

Useful boundaries in `src/shevek_collect/`:

| Area | Modules |
| --- | --- |
| CLI and configuration | `cli.py`, `run_collect.py` |
| Activity providers | `git_collect.py`, `github_collect.py`, `azure_devops_collect.py` |
| Snapshots and parsing | `repository_snapshot.py`, `syntax_extract.py`, `operational_extract.py`, `parsing/` |
| Privacy and safety | `privacy.py`, `structure_privacy.py`, `filesystem.py`, `git_security.py`, `http_security.py` |
| Optional service integration | `api_submit.py` |

## Changes and reviews

Open an issue or pull request with the problem, expected behaviour and a small
reproduction. Use synthetic repositories and credentials. For fixes affecting
collection, privacy or publication, add a regression test at the relevant boundary.
Document new options and any bundle-format change alongside the implementation.

Preserve these properties:

- Observation does not execute repository code or fetch implicitly.
- Structure exports allow only reviewed fields; new parser fields do not become
  exported automatically.
- Persisted errors do not include source excerpts, tokens or raw provider responses.
- Repository failures remain visible and do not produce misleading partial records.
- Packaging validates declared members and source blob hashes before publishing.
- Output replacement is explicit and preserves the previous bundle on failure.

Follow existing Python style and keep changes focused. Parser fixes should use
small fixtures for the language construct at issue. Never add customer exports,
real tokens or a blanket secret-scanner exemption for the test directory.

## Preparing a release

1. Update the version in `pyproject.toml` and `src/shevek_collect/__init__.py`, run
   `uv lock`, and write user-facing notes in `CHANGELOG.md`.
2. Run the tests and build. Inspect the wheel and source archive for unintended files.
3. Scan the public source and its Git history with your chosen secret scanner.
   A source ZIP does not include history; a fresh repository starts a new history.
   For Gitleaks 8.25+ source checks, pass `--config .gitleaks.toml --redact=100`.
   The config extends default rules and exempts only two exact synthetic test
   values in their specific fixture files. It does not exempt the test directory.
4. Configure the repository host's private vulnerability reporting and dependency
   alerts. CI builds packages; it does not publish them automatically.

Contributions are made under the project's [Apache-2.0 licence](LICENSE).
Report sensitive vulnerabilities using [SECURITY.md](SECURITY.md).
