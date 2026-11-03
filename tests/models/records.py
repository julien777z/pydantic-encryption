from typing import Annotated, Generic, TypeVar

from pydantic import Field

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod, Encrypted, Hashed

ExtraT = TypeVar("ExtraT")


class PlainRecord(BaseModel):
    """Model holding no field to encrypt, hash or index."""

    name: str


class EncryptedRecord(BaseModel):
    """Model holding one encrypted text field."""

    secret: Annotated[str, Encrypted]


class AnyEncryptedRecord(BaseModel):
    """Model holding one encrypted field of any type an encrypted value can hold."""

    data: Annotated[object, Encrypted]


class OptionalRecord(BaseModel):
    """Model whose encrypted and hashed fields may be left empty."""

    secret: Annotated[str, Encrypted] | None = None
    password: Annotated[str, Hashed] | None = None


class HashedRecord(BaseModel):
    """Model holding one hashed field."""

    password: Annotated[str, Hashed]


class IndexedRecord(BaseModel):
    """Model holding one HMAC-SHA256 blind-indexed field."""

    email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]


class OptionalIndexedRecord(BaseModel):
    """Model whose blind-indexed field may be left empty."""

    email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)] | None = None


class MixedRecord(BaseModel):
    """Model holding a plain, an encrypted, a hashed and a blind-indexed field."""

    name: str
    secret: Annotated[str, Encrypted]
    password: Annotated[str, Hashed]
    email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]


class NestedRecord(BaseModel):
    """Model holding encrypted models directly and inside every container shape."""

    secret: Annotated[str, Encrypted]
    child: EncryptedRecord
    children: list[EncryptedRecord] = Field(default_factory=list)
    groups: list[list[EncryptedRecord]] = Field(default_factory=list)
    by_name: dict[str, EncryptedRecord] = Field(default_factory=dict)
    groups_by_name: dict[str, list[EncryptedRecord]] = Field(default_factory=dict)


class SharedSecretRecord(BaseModel):
    """Model declaring an encrypted field its subclasses inherit."""

    secret: Annotated[object, Encrypted]


class LeftSecretRecord(SharedSecretRecord):
    """Subclass inheriting the shared encrypted field."""


class RightSecretRecord(SharedSecretRecord):
    """Sibling subclass inheriting the same shared encrypted field."""


class GenericSecretRecord(BaseModel, Generic[ExtraT]):
    """Generic model declaring an encrypted field beside a field of its type parameter."""

    secret: Annotated[object, Encrypted]
    extra: ExtraT | None = None
