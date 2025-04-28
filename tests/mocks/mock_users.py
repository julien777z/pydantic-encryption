from typing import Annotated
import pytest
from pydantic_encryption import Encrypt, Decrypt, Hash, BaseModel


# Basic User Models
class User(BaseModel):
    """Basic user model with encrypted address and hashed password."""

    username: str
    address: Annotated[str, Encrypt]
    password: Annotated[str, Hash] = None


class UserDecrypt(BaseModel):
    """Basic user model with decrypted address."""

    username: str
    address: Annotated[str, Decrypt]
    password: Annotated[str, Hash] = None


# Disabled Encryption Models
class UserDisabledEncryption(BaseModel, disable=True):
    """User model with disabled encryption and hashing."""

    username: str
    address: Annotated[str, Encrypt]
    password: Annotated[str, Hash] = None


# Default Models
class UserDefaultModel(BaseModel):
    """Basic user model using the default model."""

    username: str
    address: Annotated[str, Encrypt]
    password: Annotated[str, Hash] = None


@pytest.fixture()
def mock_basic_user():
    return User(username="user1", address="pass123", password="pass123")


@pytest.fixture()
def mock_user_disabled_encryption():
    return UserDisabledEncryption(
        username="user1", address="pass123", password="pass123"
    )
