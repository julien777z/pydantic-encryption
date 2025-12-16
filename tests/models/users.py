from typing import Annotated

from pydantic_encryption import BaseModel, Decrypt, Encrypt, Hash

__all__ = [
    "User",
    "UserDecrypt",
    "UserDisabledEncryption",
]


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


class UserDisabledEncryption(BaseModel, disable=True):
    """User model with disabled encryption and hashing."""

    username: str
    address: Annotated[bytes, Encrypt]
    password: Annotated[str, Hash] = None
