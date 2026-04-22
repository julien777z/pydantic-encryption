import pytest
import pytest_asyncio

from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptionMethod
from tests.factories import UserFactory
from tests.models import User


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Set ENCRYPTION_METHOD to FERNET for all tests (no longer a global default)."""

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.FERNET)

    if settings.ENCRYPTION_KEY is None:
        from cryptography.fernet import Fernet

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
        from pydantic_encryption.adapters.encryption.fernet import FernetAdapter

        FernetAdapter._clients.clear()


@pytest_asyncio.fixture
async def user() -> User:
    """Generate an encrypted User instance with hashed password."""

    instance = UserFactory.build()
    await instance.post_init()

    return instance


@pytest_asyncio.fixture
async def users_batch() -> list[User]:
    """Generate a batch of encrypted User instances."""

    instances = UserFactory.batch(5)
    for instance in instances:
        await instance.post_init()

    return instances
