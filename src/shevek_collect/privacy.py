from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PRIVACY_KEY_ENV = "SHEVEK_COLLECT_PRIVACY_KEY"
MINIMUM_PRIVACY_KEY_BYTES = 32
IDENTIFIER_SCHEME = "shevek.pseudonymous_identifier.v2"


class PrivacyKeyError(ValueError):
    """Raised when keyed pseudonymisation cannot be configured safely."""


@dataclass(frozen=True)
class PrivacyHasher:
    """Domain-separated HMAC-SHA256 pseudonymisation for bundle identifiers.

    The key is deliberately excluded from repr/equality output and is never
    serialised into a collection bundle. Callers should reuse one stable key
    across all collectors for an organisation so Git, GitHub, and Azure DevOps
    records remain joinable.
    """

    key: bytes = field(repr=False, compare=False)
    key_id: str = field(init=False)

    def __post_init__(self) -> None:
        if len(self.key) < MINIMUM_PRIVACY_KEY_BYTES:
            raise PrivacyKeyError(
                "Privacy key must contain at least "
                f"{MINIMUM_PRIVACY_KEY_BYTES} bytes of key material"
            )
        digest = hashlib.sha256(b"shevek.privacy_key_id.v1\0" + self.key).hexdigest()
        object.__setattr__(self, "key_id", f"key_{digest[:16]}")

    @classmethod
    def from_env(cls, env_name: str = DEFAULT_PRIVACY_KEY_ENV) -> "PrivacyHasher":
        raw = os.environ.get(env_name)
        if raw is None:
            raise PrivacyKeyError(
                f"Privacy key environment variable {env_name!r} is not set. "
                "Generate a stable per-organisation key, for example with "
                "`openssl rand -hex 32`, and keep it in a secret manager."
            )
        return cls(_decode_key_material(raw, source=f"environment variable {env_name!r}"))

    @classmethod
    def from_file(cls, path: Path) -> "PrivacyHasher":
        expanded = path.expanduser().resolve()
        try:
            raw = expanded.read_text(encoding="utf-8")
        except OSError as exc:
            raise PrivacyKeyError(f"Unable to read privacy key file {expanded}: {exc}") from exc
        return cls(_decode_key_material(raw, source=f"privacy key file {expanded}"))

    def hash(self, value: str, *, domain: str) -> str:
        """Return a versioned HMAC identifier for a normalised caller value."""
        digest = self.digest_hex(value, domain=domain)
        return f"hmac-sha256:v1:{digest}"

    def digest_hex(self, value: str, *, domain: str) -> str:
        if not domain or any(character.isspace() for character in domain):
            raise ValueError("Privacy hash domain must be a non-empty token")
        material = f"shevek.{domain}.v1\0".encode("utf-8") + value.encode("utf-8", errors="replace")
        return hmac.new(self.key, material, hashlib.sha256).hexdigest()

    def email(self, value: str) -> str:
        return self.hash(value, domain="email")

    def actor(self, value: str) -> str:
        return self.hash(value, domain="actor")

    def local_path(self, value: str) -> str:
        return self.hash(value, domain="local_path")

    def remote_url(self, value: str) -> str:
        return self.hash(value, domain="remote_url")

    def code_path(self, value: str) -> str:
        return self.hash(value, domain="code_path")

    def repository_fingerprint(self, canonical_locator: str) -> str:
        digest = self.digest_hex(canonical_locator, domain="repository_locator")
        return f"repo_v2_{digest[:24]}"

    def local_repository_id(self, absolute_path: str) -> str:
        digest = self.digest_hex(absolute_path, domain="local_repository")
        return f"local_repo_v2_{digest[:24]}"

    def manifest_metadata(self) -> dict[str, object]:
        return {
            "schema": IDENTIFIER_SCHEME,
            "algorithm": "HMAC-SHA256",
            "version": 1,
            "key_id": self.key_id,
            "domain_separation": True,
        }


def resolve_privacy_hasher(
    hasher: PrivacyHasher | None,
    *,
    env_name: str = DEFAULT_PRIVACY_KEY_ENV,
) -> PrivacyHasher:
    return hasher if hasher is not None else PrivacyHasher.from_env(env_name)


def load_privacy_hasher(
    *,
    env_name: str = DEFAULT_PRIVACY_KEY_ENV,
    key_file: Path | None = None,
) -> PrivacyHasher:
    if key_file is not None:
        return PrivacyHasher.from_file(key_file)
    return PrivacyHasher.from_env(env_name)


def _decode_key_material(raw: str, *, source: str) -> bytes:
    value = raw.strip()
    if not value:
        raise PrivacyKeyError(f"{source} is empty")

    if value.startswith("hex:"):
        try:
            return bytes.fromhex(value[4:])
        except ValueError as exc:
            raise PrivacyKeyError(f"{source} contains invalid hex key material") from exc

    if value.startswith("base64:"):
        try:
            return base64.b64decode(value[7:], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise PrivacyKeyError(f"{source} contains invalid base64 key material") from exc

    return value.encode("utf-8")
