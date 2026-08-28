import pytest

from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptionMethod
from tests.factories import User, UserFactory
from tests.kms import install_fake_kms, reset_adapter_state


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Point every test at the AWS backend over fake KMS clients so ciphertexts bind a context."""

    reset_adapter_state()

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.AWS)
    install_fake_kms(monkeypatch)

    if settings.BLIND_INDEX_SECRET_KEY is None:
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "test-blind-index-secret-key")

    yield

    reset_adapter_state()


@pytest.fixture
def user() -> User:
    """Generate a User instance with encrypted address and hashed password."""
    return UserFactory.build()


@pytest.fixture
def users_batch() -> list[User]:
    """Generate a batch of User instances."""
    return UserFactory.batch(5)
