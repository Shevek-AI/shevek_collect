# Security

## Reporting a vulnerability

Use this repository's private vulnerability-reporting feature when available.
Do not post credentials, private source or sensitive reproductions in a public
issue. If private reporting is unavailable, request a private contact route without
disclosing the vulnerability. No response-time commitment is currently made.

Include the Collect version, platform, affected command, relevant configuration
with secrets removed, and a synthetic reproduction where possible.

## Trust boundary

Collect reads repositories and provider activity, writes local evidence bundles,
and optionally submits them to the Shevek service. The installed Python
environment, Git/gh binaries, native parsers and operator configuration are trusted.
Repository code is not executed by collection. Resource limits are not an
operating-system sandbox or a guarantee against native parser vulnerabilities.

Git observation disables hooks, fsmonitor, external diff/text conversion, ambient
Git overrides and implicit network fetching. Explicit `submit --fetch` uses the
operator's Git transport and authentication setup. Use a current Git installation.

`full` snapshots can contain secrets. `structure` omits blobs and filters extracted
fields, but names, paths and other retained engineering metadata remain sensitive.
Filename exclusions and keyed pseudonyms are not general redaction or anonymity.
Collect does not perform content secret scanning or encrypt bundles at rest.
See [privacy and optional scanning](docs/privacy.md).

Keep the output parent directory private and trusted. POSIX permissions, locks and
atomic publication protect against accidental exposure and competing Collect runs;
they cannot isolate a hostile process with the same account privileges. Windows
access restrictions depend on parent directory ACLs.

Authenticated service/Azure requests use HTTPS without redirects. TLS protects
transport, not stored exports. Do not treat `inspect`, `pack`, a clean scanner
result or collection status as a security certification.

## Maintenance

Use the latest released Collect version and review dependency updates before
processing untrusted inputs. Tests cover local synthetic scenarios and mocked
providers; a passing suite does not establish that every live provider account,
backend or operating system has been exercised.
