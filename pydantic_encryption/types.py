from enum import Enum
from typing import Self

from pydantic import GetCoreSchemaHandler, SerializerFunctionWrapHandler
from pydantic_core.core_schema import CoreSchema, wrap_serializer_function_ser_schema

from pydantic_encryption.normalization import NormalizationFlags, validate_normalization_flags


class EncryptionMethod(Enum):
    """Supported encryption methods."""

    FERNET = "fernet"
    AWS = "aws"


class BlindIndexMethod(Enum):
    """Supported blind index hashing methods."""

    HMAC_SHA256 = "hmac-sha256"
    ARGON2 = "argon2"


class EncryptedValueAccessError(RuntimeError):
    """Raised when an encrypted ciphertext is coerced to str before decryption."""


class TaggedBytes(bytes):
    """Bytes subclass that UTF-8-encodes ``str`` inputs."""

    def __new__(cls, value: str | bytes) -> Self:
        if isinstance(value, str):
            value = value.encode("utf-8")

        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: {len(self)} bytes>"


def serialize_processed_value(value: object, handler: SerializerFunctionWrapHandler) -> object:
    """Serialize a processed value as the bytes it holds, and any other value as its field declares."""

    if isinstance(value, TaggedBytes):
        return value

    return handler(value)


class FieldMarker:
    """Annotation marking a field whose model replaces its value with processed bytes."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: object, handler: GetCoreSchemaHandler) -> CoreSchema:
        """Return the schema of the field's declared type, serializing a processed value as its bytes."""

        schema = handler(source_type)
        schema["serialization"] = wrap_serializer_function_ser_schema(serialize_processed_value)

        return schema


class Encrypted(FieldMarker):
    """Annotation to mark fields for encryption."""


class Hashed(FieldMarker):
    """Annotation to mark fields for hashing."""


class EncryptedValue(TaggedBytes):
    """Bytes subclass representing an encrypted ciphertext; ``str()`` raises to flag accidental coercion."""

    def __str__(self) -> str:
        raise EncryptedValueAccessError(
            "Encrypted value coerced to str before decryption. Read the attribute via the ORM "
            "instance to trigger on-access decrypt, or call "
            "`await decrypt_pending_fields(session)` to materialize loaded rows. "
            "Use `bytes(value)` if you explicitly need the raw ciphertext."
        )


class HashedValue(TaggedBytes):
    """Bytes subclass representing a hashed value."""


class BlindIndexValue(TaggedBytes):
    """Bytes subclass representing a blind index value."""


class BlindIndex(FieldMarker):
    """Annotation to mark fields for blind indexing."""

    def __init__(
        self,
        method: BlindIndexMethod,
        *,
        strip_whitespace: bool = False,
        strip_non_characters: bool = False,
        strip_non_digits: bool = False,
        strip_trailing_punctuation: bool = False,
        normalize_to_lowercase: bool = False,
        normalize_to_uppercase: bool = False,
    ):
        self.method = method
        self.strip_whitespace = strip_whitespace
        self.strip_non_characters = strip_non_characters
        self.strip_non_digits = strip_non_digits
        self.strip_trailing_punctuation = strip_trailing_punctuation
        self.normalize_to_lowercase = normalize_to_lowercase
        self.normalize_to_uppercase = normalize_to_uppercase

        validate_normalization_flags(self.normalization_flags)

    @property
    def normalization_flags(self) -> NormalizationFlags:
        """Return this annotation's normalization flags as a grouped object."""

        return NormalizationFlags(
            strip_whitespace=self.strip_whitespace,
            strip_non_characters=self.strip_non_characters,
            strip_non_digits=self.strip_non_digits,
            strip_trailing_punctuation=self.strip_trailing_punctuation,
            normalize_to_lowercase=self.normalize_to_lowercase,
            normalize_to_uppercase=self.normalize_to_uppercase,
        )


def is_encrypted(value: object) -> bool:
    """Return True if the value is a still-encrypted ciphertext wrapper."""

    return isinstance(value, EncryptedValue)


__all__ = [
    "Encrypted",
    "Hashed",
    "EncryptionMethod",
    "EncryptedValue",
    "EncryptedValueAccessError",
    "HashedValue",
    "BlindIndex",
    "BlindIndexMethod",
    "BlindIndexValue",
    "is_encrypted",
]
