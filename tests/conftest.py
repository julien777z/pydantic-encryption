import pytest

from tests.factories import UserFactory, UserDecryptFactory, UserDisabledFactory
from tests.models import User, UserDecrypt, UserDisabledEncryption


@pytest.fixture
def user() -> User:
    """Generate a User instance with encrypted address and hashed password."""
    return UserFactory.build()


@pytest.fixture
def user_decrypt() -> UserDecrypt:
    """Generate a UserDecrypt instance."""
    return UserDecryptFactory.build()


@pytest.fixture
def user_disabled() -> UserDisabledEncryption:
    """Generate a User instance with encryption disabled."""
    return UserDisabledFactory.build()


@pytest.fixture
def users_batch() -> list[User]:
    """Generate a batch of User instances."""
    return UserFactory.batch(5)
