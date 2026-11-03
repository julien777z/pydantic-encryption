from typing import Annotated

from polyfactory.factories.pydantic_factory import ModelFactory

from pydantic_encryption import BaseModel, Encrypted, Hashed

__all__ = ["SampleRecord", "SampleRecordFactory"]


class SampleRecord(BaseModel):
    """Faker-backed test sample covering encryption, hashing, and SA row fields."""

    id: int
    name: str
    label: str
    caption: str
    payload: bytes
    secret: Annotated[str | bytes, Encrypted]
    password: Annotated[str | bytes, Hashed]


class SampleRecordFactory(ModelFactory[SampleRecord]):
    """Factory for SampleRecord with faker-backed values for every field."""

    __model__ = SampleRecord

    @classmethod
    def label(cls) -> str:
        return cls.__faker__.word()

    @classmethod
    def caption(cls) -> str:
        return cls.__faker__.sentence(nb_words=3)

    @classmethod
    def payload(cls) -> bytes:
        return cls.__faker__.binary(length=16)

    @classmethod
    def secret(cls) -> str:
        return cls.__faker__.sentence()

    @classmethod
    def password(cls) -> str:
        return cls.__faker__.password()
