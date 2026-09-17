from __future__ import annotations

import pytest

from shevek_collect.privacy import DEFAULT_PRIVACY_KEY_ENV, PrivacyHasher

TEST_PRIVACY_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def configure_test_privacy_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DEFAULT_PRIVACY_KEY_ENV, TEST_PRIVACY_KEY)


@pytest.fixture
def privacy_hasher() -> PrivacyHasher:
    return PrivacyHasher(TEST_PRIVACY_KEY.encode("utf-8"))
