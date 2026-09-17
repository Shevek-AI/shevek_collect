from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .git_security import run_git
from .privacy import PrivacyHasher


@dataclass(frozen=True)
class GitTopologySnapshot:
    repository_state: dict[str, object]
    refs: tuple[dict[str, object], ...]
    tags: tuple[dict[str, object], ...]
    branch_relations: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class _Anchor:
    ref: str
    sha: str
    reasons: tuple[str, ...]


CONVENTIONAL_BRANCH_NAMES = ("main", "master", "trunk", "develop")


def observe_git_topology(
    repo: Path,
    *,
    privacy_hasher: PrivacyHasher,
    configured_comparison_refs: Sequence[str] = (),
    max_commit_ids_per_relation: int = 500,
    include_merge_viability: bool = True,
    include_raw_emails: bool = False,
) -> GitTopologySnapshot:
    """Observe local refs and deterministic branch relationships without interpreting intent."""
    if max_commit_ids_per_relation <= 0:
        raise ValueError("max_commit_ids_per_relation must be positive")

    refs = _ref_observations(repo, privacy_hasher=privacy_hasher)
    tags = _tag_observations(
        repo,
        privacy_hasher=privacy_hasher,
        include_raw_emails=include_raw_emails,
    )
    repository_state = _repository_state(repo, refs=refs)
    anchors, unresolved_configured_refs = _comparison_anchors(
        repo,
        refs=refs,
        configured_comparison_refs=configured_comparison_refs,
    )
    repository_state["comparison_anchors"] = [
        {"ref": anchor.ref, "sha": anchor.sha, "reasons": list(anchor.reasons)}
        for anchor in anchors
    ]
    repository_state["configured_comparison_refs"] = list(configured_comparison_refs)
    repository_state["unresolved_configured_comparison_refs"] = unresolved_configured_refs

    relations = _branch_relations(
        repo,
        refs=refs,
        anchors=anchors,
        privacy_hasher=privacy_hasher,
        max_commit_ids_per_relation=max_commit_ids_per_relation,
        include_merge_viability=include_merge_viability,
    )
    return GitTopologySnapshot(
        repository_state=repository_state,
        refs=tuple(refs),
        tags=tuple(tags),
        branch_relations=tuple(relations),
    )


def _ref_observations(
    repo: Path,
    *,
    privacy_hasher: PrivacyHasher,
) -> list[dict[str, object]]:
    format_string = (
        "%(refname)%00%(objectname)%00%(upstream)%00%(committerdate:iso-strict)"
        "%00%(HEAD)%00%(symref)"
    )
    output = _git(
        repo,
        ["for-each-ref", f"--format={format_string}", "refs/heads", "refs/remotes"],
    )
    observations: list[dict[str, object]] = []
    for line in output.splitlines():
        fields = line.split("\x00")
        if len(fields) != 6:
            raise ValueError("Unable to parse git ref metadata")
        ref, tip_sha, upstream_ref, tip_committed_at, head_marker, symbolic_target = fields
        ref_kind, short_name, remote_name = _ref_kind(ref, symbolic_target=symbolic_target)
        row: dict[str, object] = {
            "ref": ref,
            "ref_hash": privacy_hasher.hash(ref, domain="git_ref"),
            "ref_kind": ref_kind,
            "short_name": short_name,
            "tip_sha": tip_sha,
            "tip_committed_at": tip_committed_at or None,
            "upstream_ref": upstream_ref or None,
            "symbolic_target": symbolic_target or None,
            "is_current_head": head_marker == "*",
        }
        if remote_name is not None:
            row["remote_name"] = remote_name
        observations.append(row)
    return sorted(observations, key=lambda row: str(row["ref"]))


def _tag_observations(
    repo: Path,
    *,
    privacy_hasher: PrivacyHasher,
    include_raw_emails: bool,
) -> list[dict[str, object]]:
    format_string = (
        "%(refname)%00%(objecttype)%00%(objectname)%00%(*objectname)"
        "%00%(creatordate:iso-strict)%00%(taggername)%00%(taggeremail)%00%(subject)"
    )
    output = _git(repo, ["for-each-ref", f"--format={format_string}", "refs/tags"])
    observations: list[dict[str, object]] = []
    for line in output.splitlines():
        fields = line.split("\x00")
        if len(fields) != 8:
            raise ValueError("Unable to parse git tag metadata")
        (
            ref,
            object_type,
            target_object_sha,
            peeled_object_sha,
            created_at,
            tagger_name,
            tagger_email,
            subject,
        ) = fields
        resolved_commit_sha = _git_maybe(repo, ["rev-parse", f"{ref}^{{commit}}"]).strip()
        payload: dict[str, object] = {
            "ref": ref,
            "ref_hash": privacy_hasher.hash(ref, domain="git_ref"),
            "name": ref.removeprefix("refs/tags/"),
            "tag_type": "annotated" if object_type == "tag" else "lightweight",
            "target_object_type": object_type,
            "target_object_sha": target_object_sha,
            "peeled_object_sha": peeled_object_sha or None,
            "resolved_commit_sha": resolved_commit_sha or None,
            "created_at": created_at or None,
            "subject": subject or None,
            "signature_status": "not_checked",
        }
        if tagger_name:
            payload["tagger_name"] = tagger_name
        if tagger_email:
            normalised_email = tagger_email.strip("<>").casefold().strip()
            payload["tagger_email_hash"] = privacy_hasher.email(normalised_email)
            if include_raw_emails:
                payload["tagger_email"] = normalised_email
        observations.append(payload)
    return sorted(observations, key=lambda row: str(row["ref"]))


def _repository_state(
    repo: Path,
    *,
    refs: Sequence[dict[str, object]],
) -> dict[str, object]:
    head_ref = _git_maybe(repo, ["symbolic-ref", "-q", "HEAD"]).strip()
    shallow_raw = _git_maybe(repo, ["rev-parse", "--is-shallow-repository"]).strip()
    is_shallow = shallow_raw == "true"
    partial_clone_remotes = _partial_clone_remotes(repo)
    remote_default_refs = [
        {
            "symbolic_ref": str(row["ref"]),
            "target_ref": str(row["symbolic_target"]),
            "remote_name": row.get("remote_name"),
        }
        for row in refs
        if row.get("ref_kind") == "remote_symbolic" and row.get("symbolic_target")
    ]
    if is_shallow:
        history_scope = "incomplete_shallow"
    elif partial_clone_remotes:
        history_scope = "partial_clone_local_objects_may_be_lazy"
    else:
        history_scope = "local_object_database_not_shallow"
    return {
        "head_ref": head_ref or None,
        "head_detached": not bool(head_ref),
        "is_shallow_repository": is_shallow,
        "partial_clone_remotes": partial_clone_remotes,
        "history_scope": history_scope,
        "ref_observation_scope": "local_ref_database",
        "remote_default_refs": remote_default_refs,
    }


def _partial_clone_remotes(repo: Path) -> list[dict[str, object]]:
    output = _git_maybe(
        repo, ["config", "--get-regexp", r"^remote\..*\.(promisor|partialclonefilter)$"]
    )
    records: dict[str, dict[str, object]] = {}
    for line in output.splitlines():
        if not line.strip() or " " not in line:
            continue
        key, value = line.split(None, 1)
        match = re.match(r"^remote\.(.+)\.(promisor|partialclonefilter)$", key)
        if match is None:
            continue
        remote_name, field = match.groups()
        record = records.setdefault(remote_name, {"remote_name": remote_name})
        if field == "promisor":
            record["promisor"] = value.strip().casefold() == "true"
        elif field == "partialclonefilter":
            record["filter"] = value.strip()
    return [records[name] for name in sorted(records)]


def _comparison_anchors(
    repo: Path,
    *,
    refs: Sequence[dict[str, object]],
    configured_comparison_refs: Sequence[str],
) -> tuple[list[_Anchor], list[str]]:
    anchor_order: list[tuple[str, str]] = []
    anchor_reasons: dict[tuple[str, str], set[str]] = {}
    unresolved: list[str] = []

    def add_ref(ref_value: str, reason: str) -> bool:
        resolved = _resolve_commit_ref(repo, ref_value)
        if resolved is None:
            return False
        full_ref, sha = resolved
        key = (full_ref, sha)
        if key not in anchor_reasons:
            anchor_order.append(key)
            anchor_reasons[key] = set()
        anchor_reasons[key].add(reason)
        return True

    for configured in configured_comparison_refs:
        if not add_ref(configured, "configured_comparison_ref"):
            unresolved.append(configured)

    remote_defaults = [
        str(row["symbolic_target"])
        for row in refs
        if row.get("ref_kind") == "remote_symbolic" and row.get("symbolic_target")
    ]
    for ref in remote_defaults:
        add_ref(ref, "remote_symbolic_head")

    if not remote_defaults:
        ref_names = {str(row["ref"]) for row in refs if row.get("ref_kind") != "remote_symbolic"}
        conventional_candidates: list[str] = []
        for branch_name in CONVENTIONAL_BRANCH_NAMES:
            conventional_candidates.extend(
                sorted(ref for ref in ref_names if ref == f"refs/remotes/origin/{branch_name}")
            )
        for branch_name in CONVENTIONAL_BRANCH_NAMES:
            conventional_candidates.extend(
                sorted(
                    ref
                    for ref in ref_names
                    if ref.startswith("refs/remotes/") and ref.endswith(f"/{branch_name}")
                )
            )
        for branch_name in CONVENTIONAL_BRANCH_NAMES:
            if f"refs/heads/{branch_name}" in ref_names:
                conventional_candidates.append(f"refs/heads/{branch_name}")
        for candidate in conventional_candidates:
            if add_ref(candidate, "conventional_branch_fallback"):
                break

    if not anchor_order:
        head_ref = _git_maybe(repo, ["symbolic-ref", "-q", "HEAD"]).strip()
        if head_ref:
            add_ref(head_ref, "current_head_fallback")

    anchors = [
        _Anchor(ref=ref, sha=sha, reasons=tuple(sorted(anchor_reasons[(ref, sha)])))
        for ref, sha in anchor_order
    ]
    return anchors, unresolved


def _branch_relations(
    repo: Path,
    *,
    refs: Sequence[dict[str, object]],
    anchors: Sequence[_Anchor],
    privacy_hasher: PrivacyHasher,
    max_commit_ids_per_relation: int,
    include_merge_viability: bool,
) -> list[dict[str, object]]:
    branch_rows = [row for row in refs if row.get("ref_kind") in {"local_branch", "remote_branch"}]
    relations: list[dict[str, object]] = []
    seen_pairs: set[tuple[str, str]] = set()

    default_by_remote = {
        str(row.get("remote_name")): str(row["symbolic_target"])
        for row in refs
        if row.get("ref_kind") == "remote_symbolic"
        and row.get("remote_name")
        and row.get("symbolic_target")
    }

    for head in branch_rows:
        head_ref = str(head["ref"])
        head_sha = str(head["tip_sha"])
        candidate_bases: list[_Anchor] = list(anchors)

        upstream_ref = head.get("upstream_ref")
        if isinstance(upstream_ref, str) and upstream_ref:
            resolved = _resolve_commit_ref(repo, upstream_ref)
            if resolved is not None:
                full_ref, sha = resolved
                candidate_bases.append(
                    _Anchor(ref=full_ref, sha=sha, reasons=("configured_upstream",))
                )

        remote_name = head.get("remote_name")
        if isinstance(remote_name, str) and remote_name in default_by_remote:
            resolved = _resolve_commit_ref(repo, default_by_remote[remote_name])
            if resolved is not None:
                full_ref, sha = resolved
                candidate_bases.append(
                    _Anchor(ref=full_ref, sha=sha, reasons=("same_remote_default",))
                )

        pair_reasons: dict[tuple[str, str], set[str]] = {}
        pair_anchors: dict[tuple[str, str], _Anchor] = {}
        for base in candidate_bases:
            if base.ref == head_ref and base.sha == head_sha:
                continue
            pair = (base.ref, head_ref)
            pair_anchors[pair] = base
            pair_reasons.setdefault(pair, set()).update(base.reasons)

        for pair, base in pair_anchors.items():
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            base = _Anchor(
                ref=base.ref,
                sha=base.sha,
                reasons=tuple(sorted(pair_reasons[pair])),
            )
            relation = _branch_relation(
                repo,
                base=base,
                head_ref=head_ref,
                head_sha=head_sha,
                privacy_hasher=privacy_hasher,
                max_commit_ids=max_commit_ids_per_relation,
                include_merge_viability=include_merge_viability,
            )
            relations.append(relation)

    return sorted(relations, key=lambda row: (str(row["base_ref"]), str(row["head_ref"])))


def _branch_relation(
    repo: Path,
    *,
    base: _Anchor,
    head_ref: str,
    head_sha: str,
    privacy_hasher: PrivacyHasher,
    max_commit_ids: int,
    include_merge_viability: bool,
) -> dict[str, object]:
    counts_output = _git(repo, ["rev-list", "--left-right", "--count", f"{base.sha}...{head_sha}"])
    parts = counts_output.strip().split()
    if len(parts) != 2:
        raise ValueError(f"Unable to parse branch divergence for {head_ref}")
    behind_count, ahead_count = (int(parts[0]), int(parts[1]))
    merge_base_sha = _git_maybe(repo, ["merge-base", base.sha, head_sha]).strip() or None
    base_is_ancestor = _is_ancestor(repo, base.sha, head_sha)
    head_is_ancestor = _is_ancestor(repo, head_sha, base.sha)

    head_only = _git(
        repo,
        [
            "rev-list",
            "--topo-order",
            f"--max-count={max_commit_ids + 1}",
            head_sha,
            f"^{base.sha}",
        ],
    ).splitlines()
    head_only = [sha.strip() for sha in head_only if sha.strip()]
    head_only_truncated = len(head_only) > max_commit_ids
    if head_only_truncated:
        head_only = head_only[:max_commit_ids]

    patch_equivalence = _patch_equivalence(
        repo,
        base_sha=base.sha,
        head_sha=head_sha,
        max_commit_ids=max_commit_ids,
    )
    if not include_merge_viability:
        merge_viability = {"state": "not_checked"}
    elif ahead_count == 0:
        merge_viability = {"state": "already_reachable"}
    elif merge_base_sha is None:
        merge_viability = {"state": "disconnected"}
    else:
        merge_viability = _merge_viability(repo, base_sha=base.sha, head_sha=head_sha)

    relation_key = f"{base.ref}\n{head_ref}"
    return {
        "relation_hash": privacy_hasher.hash(relation_key, domain="git_branch_relation"),
        "base_ref": base.ref,
        "base_ref_hash": privacy_hasher.hash(base.ref, domain="git_ref"),
        "base_sha": base.sha,
        "base_reasons": list(base.reasons),
        "head_ref": head_ref,
        "head_ref_hash": privacy_hasher.hash(head_ref, domain="git_ref"),
        "head_sha": head_sha,
        "merge_base_sha": merge_base_sha,
        "ahead_count": ahead_count,
        "behind_count": behind_count,
        "base_is_ancestor_of_head": base_is_ancestor,
        "head_is_ancestor_of_base": head_is_ancestor,
        "head_only_commit_shas": head_only,
        "head_only_commit_shas_truncated": head_only_truncated,
        "head_only_commit_sha_limit": max_commit_ids,
        "patch_equivalence": patch_equivalence,
        "merge_viability": merge_viability,
    }


def _patch_equivalence(
    repo: Path,
    *,
    base_sha: str,
    head_sha: str,
    max_commit_ids: int,
) -> dict[str, object]:
    process = _git_process(repo, ["cherry", base_sha, head_sha])
    if process.returncode != 0:
        return {
            "state": "unknown",
            "scope": "non_merge_commits_only",
            "unique_patch_count": None,
            "equivalent_patch_count": None,
        }
    unique_shas: list[str] = []
    equivalent_shas: list[str] = []
    for line in process.stdout.splitlines():
        marker, _, sha = line.partition(" ")
        sha = sha.strip()
        if marker == "+" and sha:
            unique_shas.append(sha)
        elif marker == "-" and sha:
            equivalent_shas.append(sha)
    return {
        "state": "checked",
        "scope": "non_merge_commits_only",
        "unique_patch_count": len(unique_shas),
        "equivalent_patch_count": len(equivalent_shas),
        "unique_patch_commit_shas": unique_shas[:max_commit_ids],
        "equivalent_patch_commit_shas": equivalent_shas[:max_commit_ids],
        "commit_shas_truncated": (
            len(unique_shas) > max_commit_ids or len(equivalent_shas) > max_commit_ids
        ),
        "commit_sha_limit_per_state": max_commit_ids,
    }


def _merge_viability(repo: Path, *, base_sha: str, head_sha: str) -> dict[str, object]:
    drivers = _git_process(repo, ["config", "--get-regexp", r"^merge\..*\.driver$"])
    if drivers.returncode == 0:
        return {"state": "not_checked", "error": "custom_merge_driver_disabled"}
    if drivers.returncode != 1:
        return {"state": "unknown", "error": "merge_configuration_unavailable"}
    object_format = _git(repo, ["rev-parse", "--show-object-format"]).strip()
    if object_format not in {"sha1", "sha256"}:
        return {"state": "unknown", "error": "unsupported_object_format"}
    object_path_raw = _git(repo, ["rev-parse", "--git-path", "objects"]).strip()
    object_path = Path(object_path_raw)
    if not object_path.is_absolute():
        object_path = (repo / object_path).resolve()

    with tempfile.TemporaryDirectory(prefix="shevek-collect-merge-tree-") as temporary:
        temporary_repo = Path(temporary)
        # A private bare repository prevents merge-tree from consulting changing
        # source-repository config, attributes in the worktree, or custom drivers.
        _git(temporary_repo, ["init", "--bare", "--template=", f"--object-format={object_format}"])
        temporary_objects = temporary_repo / "objects"
        env = {}
        env["GIT_OBJECT_DIRECTORY"] = temporary_objects.as_posix()
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = object_path.as_posix()
        process = _git_process(
            temporary_repo,
            ["merge-tree", "--write-tree", base_sha, head_sha],
            env=env,
        )
    if process.returncode == 0:
        return {"state": "clean"}
    if process.returncode == 1:
        return {"state": "conflicting"}
    return {"state": "unknown", "error": "git_merge_tree_failed"}


def _resolve_commit_ref(repo: Path, value: str) -> tuple[str, str] | None:
    sha = _git_maybe(repo, ["rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}"]).strip()
    if not sha:
        return None
    full_ref = _git_maybe(repo, ["rev-parse", "--verify", "--symbolic-full-name", "--end-of-options", value]).strip()
    return (full_ref or value, sha)


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    process = _git_process(repo, ["merge-base", "--is-ancestor", ancestor, descendant])
    if process.returncode == 0:
        return True
    if process.returncode == 1:
        return False
    raise RuntimeError("git merge-base --is-ancestor failed")


def _ref_kind(ref: str, *, symbolic_target: str) -> tuple[str, str, str | None]:
    if ref.startswith("refs/heads/"):
        return "local_branch", ref.removeprefix("refs/heads/"), None
    if ref.startswith("refs/remotes/"):
        short_name = ref.removeprefix("refs/remotes/")
        remote_name = short_name.split("/", 1)[0] if "/" in short_name else short_name
        if symbolic_target:
            return "remote_symbolic", short_name, remote_name
        return "remote_branch", short_name, remote_name
    return "other", ref, None


def _git(repo: Path, args: Sequence[str]) -> str:
    process = _git_process(repo, args)
    if process.returncode != 0:
        stderr = process.stderr.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")
    return process.stdout


def _git_maybe(repo: Path, args: Sequence[str]) -> str:
    process = _git_process(repo, args)
    return process.stdout if process.returncode == 0 else ""


def _git_process(
    repo: Path,
    args: Iterable[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return run_git(repo, list(args), env=env)
