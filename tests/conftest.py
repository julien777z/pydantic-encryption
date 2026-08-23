from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet

from pydantic_encryption.adapters import registry
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import BlindIndexMethod, EncryptionMethod
from tests.factories import User, UserFactory


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Set encryption + blind-index config for every test so individual tests can opt out."""

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.FERNET)

    if settings.ENCRYPTION_KEY is None:
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
        FernetAdapter._clients.clear()

    if settings.BLIND_INDEX_SECRET_KEY is None:
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "test-blind-index-secret-key")


@pytest.fixture
def user() -> User:
    """Generate a User instance with encrypted address and hashed password."""
    return UserFactory.build()


@pytest.fixture
def users_batch() -> list[User]:
    """Generate a batch of User instances."""
    return UserFactory.batch(5)


@pytest.fixture
def unregistered_method() -> Iterator[EncryptionMethod]:
    """Lend a real encryption method with its registry entries cleared, restoring them afterwards."""

    method = EncryptionMethod.AWS
    backend = registry.encryption_backends.pop(method, None)
    factory = registry.encryption_factories.pop(method, None)

    try:
        yield method
    finally:
        registry.encryption_backends.pop(method, None)
        registry.encryption_factories.pop(method, None)

        if backend is not None:
            registry.encryption_backends[method] = backend

        if factory is not None:
            registry.encryption_factories[method] = factory


@pytest.fixture
def unregistered_blind_index_method() -> Iterator[BlindIndexMethod]:
    """Lend a real blind index method with its registry entry cleared, restoring it afterwards."""

    method = BlindIndexMethod.ARGON2
    backend = registry.blind_index_backends.pop(method, None)

    try:
        yield method
    finally:
        registry.blind_index_backends.pop(method, None)

        if backend is not None:
            registry.blind_index_backends[method] = backend
