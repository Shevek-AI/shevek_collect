# Changelog

## 0.3.0

- Prepare the public source distribution under Apache-2.0.
- Replace internal onboarding and audit notes with task-oriented documentation,
  standalone local usage, neutral examples and a separate service integration guide.
- Add `pack` to archive an existing bundle without collecting or uploading.
- Add `--version`; report common configuration and filesystem errors as CLI errors.
- Validate declared bundle outputs when using `inspect`.
- Make `submit --fetch` use the collection planner, including shorthand repository
  paths, defaults, discovery and snapshot sources; reject invalid plans before fetching.
- Discover linked Git worktrees alongside ordinary working trees.
- Report unperformed secret scanning consistently as `not_performed`; document
  optional Gitleaks checks on completed exports. Source-scanning configuration
  narrowly exempts two synthetic regression-test values.
- Correct snapshot privacy metadata: committed files can match `.gitignore`, so
  ignored-file inclusion is unknown and `gitignore_applied` is explicitly false.
- Add Linux test/build CI, contribution guidance, package metadata and ignore rules
  for local config, credentials and generated outputs.

Record schemas and capture defaults are unchanged from 0.2.1. Existing
`git scan` and `--api-url` aliases remain available. Consumers comparing the old
verbose `secret_scanning` strings should accept the simplified `not_performed` value.
Snapshot `ignored_files_included` and `contains_ignored_files` now use `null` for
unknown rather than incorrectly claiming `false`.
