from typing import Annotated

from pydantic_encryption import BaseModel, Encrypted, Hashed

__all__ = [
    "User",
    "UserNameFixture",
]


class User(BaseModel):
    """Basic user model with encrypted address and hashed password."""

    username: str
    address: Annotated[bytes, Encrypted]
    password: Annotated[str, Hashed] = None


class UserNameFixture(BaseModel):
    """Fixture-backed user with name parts + a bytes payload for SA test rows."""

    id: int
    first_name: str
    last_name: str
    payload: bytes
