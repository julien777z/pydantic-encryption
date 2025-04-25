from typing import Annotated
import pytest
from pydantic_encryption import Encrypt, Decrypt, Hash
from tests.mocks.mock_secure_model import (
    MockBaseModel,
)


# Basic User Models
class User(MockBaseModel):
    """Basic user model with encrypted address and hashed password."""

    username: str
    address: Annotated[str, Encrypt]
    password: Annotated[str, Hash] = None


class UserDecrypt(MockBaseModel):
    """Basic user model with decrypted address."""

    username: str
    address: Annotated[str, Decrypt]
    password: Annotated[str, Hash] = None


# Optional Fields Models
class UserWithOptionalFields(MockBaseModel):
    """User model with optional encrypted fields."""

    username: str
    address: Annotated[str, Encrypt] | None = None
    password: Annotated[str, Hash] | None = None


# Union Type Models
class UserWithUnionTypes(MockBaseModel):
    """User model with union type encrypted fields."""

    username: str
    address: Annotated[str, Encrypt] | None
    password: Annotated[str, Hash] | None = None


# Disabled Encryption Models
class UserDisabledEncryption(MockBaseModel, disable=True):
    """User model with disabled encryption and hashing."""

    username: str
    address: Annotated[str, Encrypt]
    password: Annotated[str, Hash] = None


@pytest.fixture()
def mock_basic_user():
    return User(username="user1", address="pass123", password="pass123")


@pytest.fixture()
def mock_user_with_optional_fields():
    return UserWithOptionalFields(username="user1", address="pass123")


@pytest.fixture()
def mock_user_with_union_types():
    return UserWithUnionTypes(username="user1", address="pass123", password="pass123")


@pytest.fixture()
def mock_user_with_union_types_no_address():
    return UserWithUnionTypes(username="user1", address=None, password="pass123")


@pytest.fixture()
def mock_user_disabled_encryption():
    return UserDisabledEncryption(
        username="user1", address="pass123", password="pass123"
    )
