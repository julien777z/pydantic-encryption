from enum import Enum


class Encrypted:
    """Annotation to mark fields for encryption."""


class Hashed:
    """Annotation to mark fields for hashing."""


class EncryptionMethod(Enum):
    """Enum for encryption methods."""

    FERNET = "fernet"
    AWS = "aws"


class BlindIndexMethod(Enum):
    """Enum for blind index hashing methods."""

    HMAC_SHA256 = "hmac-sha256"
    ARGON2 = "argon2"


class EncryptedValue(bytes):
    """Bytes subclass representing an encrypted value."""

    encrypted: bool = True

    def __new__(cls, value: str | bytes):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return super().__new__(cls, value)


class HashedValue(bytes):
    """Bytes subclass representing a hashed value."""

    hashed: bool = True

    def __new__(cls, value: str | bytes):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return super().__new__(cls, value)


class BlindIndexValue(bytes):
    """Bytes subclass representing a blind index value."""

    blind_indexed: bool = True

    def __new__(cls, value: str | bytes):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return super().__new__(cls, value)


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
        if strip_non_characters and strip_non_digits:
            raise ValueError("strip_non_characters and strip_non_digits cannot both be True.")

        if normalize_to_lowercase and normalize_to_uppercase:
            raise ValueError("normalize_to_lowercase and normalize_to_uppercase cannot both be True.")

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
