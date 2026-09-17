from shevek_collect.repo_identity import (
    azure_devops_repository_identity,
    canonical_repository_locator,
    github_repository_identity,
    repository_identity,
)


def test_github_remote_forms_share_identity() -> None:
    values = [
        "git@github.com:Shevek-AI/shevek_collect.git",
        "https://github.com/shevek-ai/shevek_collect.git",
        "ssh://git@github.com/Shevek-AI/shevek_collect.git",
    ]
    identities = [repository_identity(value) for value in values]
    assert all(identity is not None for identity in identities)
    assert {identity.canonical_locator for identity in identities if identity} == {
        "github.com/shevek-ai/shevek_collect"
    }
    assert len({identity.fingerprint for identity in identities if identity}) == 1
    hosted = github_repository_identity(hostname="github.com", owner="Shevek-AI", repo="shevek_collect")
    assert hosted.fingerprint == identities[0].fingerprint


def test_azure_remote_forms_share_identity() -> None:
    values = [
        "https://dev.azure.com/Acme/Platform/_git/Backend",
        "https://acme@dev.azure.com/Acme/Platform/_git/Backend",
        "git@ssh.dev.azure.com:v3/Acme/Platform/Backend",
        "ssh://git@ssh.dev.azure.com/v3/Acme/Platform/Backend",
        "https://Acme.visualstudio.com/Platform/_git/Backend",
    ]
    identities = [repository_identity(value) for value in values]
    assert all(identity is not None for identity in identities)
    assert {identity.canonical_locator for identity in identities if identity} == {
        "dev.azure.com/acme/platform/backend"
    }
    assert len({identity.fingerprint for identity in identities if identity}) == 1
    hosted = azure_devops_repository_identity(organization="Acme", project="Platform", repo="Backend")
    assert hosted.fingerprint == identities[0].fingerprint


def test_unknown_local_path_is_not_treated_as_hosted_repo() -> None:
    assert canonical_repository_locator("/home/developer/src/demo") is None
