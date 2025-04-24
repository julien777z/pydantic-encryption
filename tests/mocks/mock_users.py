"""
Mock user models for pydantic-encryption tests.
"""

import pytest
from pydantic_encryption import EncryptField, DecryptField
from tests.mocks.mock_encryption import (
    MockBaseModel,
)


# Basic User Models
class User(MockBaseModel):
    """Basic user model with encrypted address."""

    username: str
    address: EncryptField


class UserDecrypt(MockBaseModel):
    """Basic user model with decrypted address."""

    username: str
    address: DecryptField


# Optional Fields Models
class UserWithOptionalFields(MockBaseModel):
    """User model with optional encrypted fields."""

    username: str
    address: EncryptField | None = None


# Union Type Models
class UserWithUnionTypes(MockBaseModel):
    """User model with union type encrypted fields."""

    username: str
    address: EncryptField | None
    token: str | EncryptField | None = None


# Disabled Encryption Models
class UserDisabledEncryption(MockBaseModel, disable=True):
    """User model with union type encrypted fields."""

    username: str
    address: EncryptField
    token: str | EncryptField | None = None


@pytest.fixture()
def mock_basic_user():
    return User(username="user1", address="pass123")


@pytest.fixture()
def mock_user_with_optional_fields():
    return UserWithOptionalFields(username="user1", address="pass123")


@pytest.fixture()
def mock_user_with_union_types():
    return UserWithUnionTypes(username="user1", address="pass123", token="token123")


@pytest.fixture()
def mock_user_with_union_types_no_address():
    return UserWithUnionTypes(username="user1", address=None, token="token123")


@pytest.fixture()
def mock_user_disabled_encryption():
    return UserDisabledEncryption(username="user1", address="pass123", token="token123")
