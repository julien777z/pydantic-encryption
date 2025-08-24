from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Decrypt, Encrypt, Hash

__all__ = [
    "User",
    "UserDecrypt",
    "mock_basic_user",
    "mock_user_disabled_encryption",
]


# Basic User Models
class User(BaseModel):
    """Basic user model with encrypted address and hashed password."""

    username: str
    address: Annotated[bytes, Encrypt]
    password: Annotated[str, Hash] = None


class UserDecrypt(BaseModel):
    """Basic user model with decrypted address."""

    username: str
    address: Annotated[bytes, Decrypt]
    password: Annotated[str, Hash] = None


# Disabled Encryption Models
class UserDisabledEncryption(BaseModel, disable=True):
    """User model with disabled encryption and hashing."""

    username: str
    address: Annotated[bytes, Encrypt]
    password: Annotated[str, Hash] = None


@pytest.fixture()
def mock_basic_user():
    """Basic user model with encrypted address and hashed password."""

    return User(username="user1", address="pass123", password="pass123")


@pytest.fixture()
def mock_user_disabled_encryption():
    """User model with disabled encryption and hashing."""

    return UserDisabledEncryption(
        username="user1", address="pass123", password="pass123"
    )
