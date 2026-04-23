from typing import Annotated

from polyfactory.factories.pydantic_factory import ModelFactory

from pydantic_encryption import BaseModel, Encrypted, Hashed

__all__ = ["User", "UserFactory"]


class User(BaseModel):
    """Faker-backed test user covering encryption, hashing, and SA row fields."""

    id: int
    username: str
    first_name: str
    last_name: str
    payload: bytes
    address: Annotated[bytes, Encrypted]
    password: Annotated[str, Hashed] = None


class UserFactory(ModelFactory[User]):
    """Factory for User with faker-backed values for every field."""

    __model__ = User

    @classmethod
    def first_name(cls) -> str:
        return cls.__faker__.first_name()

    @classmethod
    def last_name(cls) -> str:
        return cls.__faker__.last_name()

    @classmethod
    def payload(cls) -> bytes:
        return cls.__faker__.binary(length=16)

    @classmethod
    def address(cls) -> str:
        return cls.__faker__.address()

    @classmethod
    def password(cls) -> str:
        return cls.__faker__.password()
