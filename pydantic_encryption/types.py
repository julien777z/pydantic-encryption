from enum import Enum

from pydantic_encryption.normalization import validate_normalization_flags


class Encrypted:
    """Annotation to mark fields for encryption."""


class Hashed:
    """Annotation to mark fields for hashing."""


class EncryptionMethod(Enum):
    """Supported encryption methods."""

    FERNET = "fernet"
    AWS = "aws"


class BlindIndexMethod(Enum):
    """Supported blind index hashing methods."""

    HMAC_SHA256 = "hmac-sha256"
    ARGON2 = "argon2"


class _TaggedBytes(bytes):
    """Bytes subclass that UTF-8-encodes ``str`` inputs."""

    def __new__(cls, value: str | bytes):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return super().__new__(cls, value)


class EncryptedValue(_TaggedBytes):
    """Bytes subclass representing an encrypted value."""

    encrypted: bool = True


class HashedValue(_TaggedBytes):
    """Bytes subclass representing a hashed value."""

    hashed: bool = True


class BlindIndexValue(_TaggedBytes):
    """Bytes subclass representing a blind index value."""

    blind_indexed: bool = True


class BlindIndex:
    """Annotation to mark fields for blind indexing."""

    def __init__(
        self,
        method: BlindIndexMethod,
        *,
        strip_whitespace: bool = False,
        strip_non_characters: bool = False,
        strip_non_digits: bool = False,
        normalize_to_lowercase: bool = False,
        normalize_to_uppercase: bool = False,
    ):
        validate_normalization_flags(
            strip_non_characters=strip_non_characters,
            strip_non_digits=strip_non_digits,
            normalize_to_lowercase=normalize_to_lowercase,
            normalize_to_uppercase=normalize_to_uppercase,
        )

        self.method = method
        self.strip_whitespace = strip_whitespace
        self.strip_non_characters = strip_non_characters
        self.strip_non_digits = strip_non_digits
        self.normalize_to_lowercase = normalize_to_lowercase
        self.normalize_to_uppercase = normalize_to_uppercase


__all__ = [
    "Encrypted",
    "Hashed",
    "EncryptionMethod",
    "EncryptedValue",
    "HashedValue",
    "BlindIndex",
    "BlindIndexMethod",
    "BlindIndexValue",
]
