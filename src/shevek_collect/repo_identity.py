from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .privacy import PrivacyHasher, resolve_privacy_hasher


@dataclass(frozen=True)
class RepositoryIdentity:
    """Provider-neutral identity derived from a canonical hosted repository locator."""

    canonical_locator: str
    fingerprint: str
    provider: str
    hostname: str


def repository_identity(
    value: str,
    *,
    privacy_hasher: PrivacyHasher | None = None,
) -> RepositoryIdentity | None:
    privacy_hasher = resolve_privacy_hasher(privacy_hasher)
    canonical = canonical_repository_locator(value)
    if canonical is None:
        return None
    hostname = canonical.split("/", 1)[0]
    return RepositoryIdentity(
        canonical_locator=canonical,
        fingerprint=repository_fingerprint(
            canonical,
            privacy_hasher=privacy_hasher,
        ),
        provider=_provider_for_hostname(hostname),
        hostname=hostname,
    )


def github_repository_identity(
    *,
    hostname: str,
    owner: str,
    repo: str,
    privacy_hasher: PrivacyHasher | None = None,
) -> RepositoryIdentity:
    identity = repository_identity(
        f"https://{hostname}/{owner}/{repo}",
        privacy_hasher=privacy_hasher,
    )
    if identity is None:  # pragma: no cover - guarded by explicit components
        raise ValueError("Unable to construct GitHub repository identity")
    return identity


def azure_devops_repository_identity(
    *,
    organization: str,
    project: str,
    repo: str,
    privacy_hasher: PrivacyHasher | None = None,
) -> RepositoryIdentity:
    identity = repository_identity(
        f"https://dev.azure.com/{organization}/{project}/_git/{repo}",
        privacy_hasher=privacy_hasher,
    )
    if identity is None:  # pragma: no cover - guarded by explicit components
        raise ValueError("Unable to construct Azure DevOps repository identity")
    return identity


def repository_fingerprint(
    canonical_locator: str,
    *,
    privacy_hasher: PrivacyHasher | None = None,
) -> str:
    """Return a compact keyed identifier with an explicit v2 repository namespace."""
    return resolve_privacy_hasher(privacy_hasher).repository_fingerprint(canonical_locator)


def canonical_repository_locator(value: str) -> str | None:
    """Normalise common GitHub, GitHub Enterprise, and Azure DevOps remote forms.

    Examples which deliberately collapse to one identity:

    * ``git@github.com:org/repo.git`` and ``https://github.com/org/repo``
    * Azure HTTPS ``.../{project}/_git/{repo}`` and SSH ``.../v3/{org}/{project}/{repo}``
    """
    raw = unicodedata.normalize("NFKC", value.strip())
    if not raw:
        return None

    host, path = _split_remote(raw)
    if not host or not path:
        return None
    host = host.casefold().rstrip(".")
    segments = [_normalise_segment(part) for part in unquote(path).split("/") if part]
    if segments and segments[-1].casefold().endswith(".git"):
        segments[-1] = segments[-1][:-4]
    segments = [segment for segment in segments if segment]
    if not segments:
        return None

    azure = _canonical_azure(host, segments)
    if azure is not None:
        return azure

    # Generic Git hosting, including GitHub Enterprise: owner/repository is the
    # stable repository address. Extra URL suffixes are intentionally ignored.
    if len(segments) < 2:
        return None
    owner, repo = segments[0], segments[1]
    return f"{host}/{owner.casefold()}/{repo.casefold()}"


def _split_remote(value: str) -> tuple[str, str]:
    if "://" in value:
        parsed = urlsplit(value)
        return parsed.hostname or "", parsed.path

    # SCP-style Git remotes: git@host:path. Avoid treating Windows drive paths
    # as remotes.
    match = re.match(r"^(?:[^@/:]+@)?([^/:]+):(.+)$", value)
    if match and not re.match(r"^[A-Za-z]:[\\/]", value):
        return match.group(1), match.group(2)

    return "", ""


def _canonical_azure(host: str, segments: list[str]) -> str | None:
    if host in {"ssh.dev.azure.com", "vs-ssh.visualstudio.com"}:
        if segments and segments[0].casefold() == "v3":
            segments = segments[1:]
        if len(segments) < 3:
            return None
        organization, project, repo = segments[0], segments[1], segments[2]
        return _azure_locator(organization, project, repo)

    if host == "dev.azure.com":
        try:
            git_index = next(
                index for index, segment in enumerate(segments) if segment.casefold() == "_git"
            )
        except StopIteration:
            return None
        if git_index < 2 or git_index + 1 >= len(segments):
            return None
        organization = segments[0]
        project = segments[git_index - 1]
        repo = segments[git_index + 1]
        return _azure_locator(organization, project, repo)

    if host.endswith(".visualstudio.com"):
        organization = host[: -len(".visualstudio.com")]
        try:
            git_index = next(
                index for index, segment in enumerate(segments) if segment.casefold() == "_git"
            )
        except StopIteration:
            return None
        if not organization or git_index < 1 or git_index + 1 >= len(segments):
            return None
        project = segments[git_index - 1]
        repo = segments[git_index + 1]
        return _azure_locator(organization, project, repo)

    return None


def _azure_locator(organization: str, project: str, repo: str) -> str:
    return "/".join(
        [
            "dev.azure.com",
            organization.casefold(),
            project.casefold(),
            repo.casefold(),
        ]
    )


def _normalise_segment(value: str) -> str:
    return unicodedata.normalize("NFKC", value.strip())


def _provider_for_hostname(hostname: str) -> str:
    if hostname == "dev.azure.com":
        return "azure_devops"
    if hostname == "github.com" or hostname.endswith(".github.com"):
        return "github"
    return "git_host"
