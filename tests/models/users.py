from typing import Annotated

from pydantic_encryption import BaseModel, Encrypted, Hashed

__all__ = [
    "User",
]


class User(BaseModel):
    """Basic user model with encrypted address and hashed password."""

    username: str
    address: Annotated[bytes, Encrypted]
    password: Annotated[str, Hashed] = None
