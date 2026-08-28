import asyncio
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptionMethod
from tests.factories import User, UserFactory
from tests.kms import (
    DATA_KEY,
    FakeAsyncKMSClient,
    FakeSyncKMSClient,
    configure_kms_settings,
    reset_adapter_state,
)


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Seed encryption + blind-index config for every test so individual tests can opt out."""

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.FERNET)

    if settings.ENCRYPTION_KEY is None:
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
        FernetAdapter._clients.clear()

    if settings.BLIND_INDEX_SECRET_KEY is None:
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "test-blind-index-secret-key")


@pytest.fixture
def fernet_key() -> str:
    """Generate a Fernet root key for tests that exercise that backend directly."""

    return Fernet.generate_key().decode()


@pytest.fixture
def fake_sync_kms(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSyncKMSClient]:
    """Install a fake sync KMS client and seed AWS settings for the test process."""

    reset_adapter_state()

    configure_kms_settings(monkeypatch)

    client = FakeSyncKMSClient(plaintext_data_key=DATA_KEY)
    AWSAdapter._sync_client = client

    yield client

    reset_adapter_state()


@pytest_asyncio.fixture
async def fake_async_kms(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[FakeAsyncKMSClient]:
    """Install a fake async KMS client and seed AWS settings for the test process."""

    reset_adapter_state()

    configure_kms_settings(monkeypatch)

    client = FakeAsyncKMSClient(plaintext_data_key=DATA_KEY)
    AWSAdapter._async_client = client
    AWSAdapter._async_loop = asyncio.get_running_loop()

    yield client

    reset_adapter_state()


@pytest.fixture
def user() -> User:
    """Generate a User instance with encrypted address and hashed password."""
    return UserFactory.build()


@pytest.fixture
def users_batch() -> list[User]:
    """Generate a batch of User instances."""
    return UserFactory.batch(5)
