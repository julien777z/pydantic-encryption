import pytest

from pydantic_secure.config import settings
from pydantic_secure.types import EncryptionMethod
from tests.factories import UserFactory
from tests.models import User


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Set ENCRYPTION_METHOD to FERNET for all tests (no longer a global default)."""

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.FERNET)

    # Also ensure ENCRYPTION_KEY is set for Fernet tests if not already provided
    if settings.ENCRYPTION_KEY is None:
        from cryptography.fernet import Fernet

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
        # Reset cached Fernet client so it picks up new key
        from pydantic_secure.adapters.encryption.fernet import FernetAdapter

        FernetAdapter._client = None


@pytest.fixture
def user() -> User:
    """Generate a User instance with encrypted address and hashed password."""
    return UserFactory.build()


@pytest.fixture
def users_batch() -> list[User]:
    """Generate a batch of User instances."""
    return UserFactory.batch(5)
