from enum import Enum
from types import MethodType
from typing import ClassVar, Self, TypedDict, cast

from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema

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


class _SchemaSerialization(TypedDict):
    """Describe the serializer slot of a Pydantic core schema."""

    serialization: core_schema.SerSchema | core_schema.IncExDictSerSchema | core_schema.IncExSeqSerSchema


class ProcessedField:
    """Serialize processed bytes and delegate unprocessed values to the field's serializer."""

    processed_type: ClassVar[type[TaggedBytes]]

    @classmethod
    def serialize_value(
        cls, value: object, serialize_field: core_schema.SerializerFunctionWrapHandler
    ) -> object:
        """Keep the processed value without applying the plaintext schema to it."""

        if isinstance(value, cls.processed_type):
            return value

        return serialize_field(value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: object, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Attach serialization without changing the field's validation schema."""

        field_schema = handler(source_type)
        schema = field_schema.copy()
        schema["serialization"] = core_schema.wrap_serializer_function_ser_schema(
            cls.serialize_value, schema=field_schema
        )

        return schema

    @classmethod
    def __get_pydantic_json_schema__(
        cls, schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        """Describe the plaintext serializer's declared output."""

        if handler.mode == "serialization":
            schema = cls.plaintext_serialization_schema(schema)

        return handler(schema)

    @staticmethod
    def plaintext_serialization_schema(schema: core_schema.CoreSchema) -> core_schema.CoreSchema:
        serialization = schema.get("serialization")

        if serialization is None:
            if (
                schema["type"] == "function-before"
                or schema["type"] == "function-after"
                or schema["type"] == "function-wrap"
            ):
                plaintext_schema = ProcessedField.plaintext_serialization_schema(schema["schema"])

                if plaintext_schema is not schema["schema"]:
                    schema = schema.copy()
                    schema["schema"] = plaintext_schema

            return schema

        if serialization["type"] != "function-wrap":
            return schema

        serializer = serialization["function"]
        field_schema = serialization.get("schema")

        if (
            field_schema is None
            or not isinstance(serializer, MethodType)
            or serializer.__func__ is not ProcessedField.serialize_value.__func__
        ):
            return schema

        field_serialization = field_schema.get("serialization")

        if field_serialization is None:
            return schema

        schema = schema.copy()

        # Pydantic types serializer slots per variant. The captured schema has the same variant.
        schema_serialization = cast(_SchemaSerialization, schema)
        schema_serialization["serialization"] = field_serialization

        return schema


class Encrypted(ProcessedField):
    """Annotation to mark fields for encryption."""

    processed_type = EncryptedValue


class Hashed(ProcessedField):
    """Annotation to mark fields for hashing."""

    processed_type = HashedValue


class BlindIndexValue(TaggedBytes):
    """Bytes subclass representing a blind index value."""


class BlindIndex:
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
