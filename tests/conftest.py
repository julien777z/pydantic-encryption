from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptionMethod
from tests.factories import User, UserFactory
from tests.kms import FakeSyncKMSClient, configure_kms_settings, reset_adapter_state


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Set encryption and blind-index config for every test so individual tests can opt out."""

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.FERNET)

    if settings.ENCRYPTION_KEY is None:
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())

    if settings.BLIND_INDEX_SECRET_KEY is None:
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "test-blind-index-secret-key")


@pytest.fixture
def fernet_key() -> str:
    """Generate a Fernet root key for tests that exercise that backend directly."""

    return Fernet.generate_key().decode()


@pytest.fixture
def fake_sync_kms(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSyncKMSClient]:
    """Install a fake KMS client and set AWS settings for the test process."""

    reset_adapter_state()

    configure_kms_settings(monkeypatch)

    client = FakeSyncKMSClient()
    AWSAdapter._sync_client = client

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
