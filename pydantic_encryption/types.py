from enum import Enum
from typing import Annotated

from pydantic import BeforeValidator


class Encrypt:
    """Annotation to mark fields for encryption."""


class Hash:
    """Annotation to mark fields for hashing."""


class EncryptionMethod(Enum):
    """Enum for encryption methods."""

    FERNET = "fernet"
    AWS = "aws"


class BlindIndexMethod(Enum):
    """Enum for blind index hashing methods."""

    HMAC_SHA256 = "hmac-sha256"
    ARGON2 = "argon2"


def _decrypt_bytes_to_str(v: bytes | str) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8")

    return v


Decrypt = Annotated[str, BeforeValidator(_decrypt_bytes_to_str)]


class NormalizeToBytes(bytes):
    """Normalize a value to bytes."""

    def __new__(cls, value: str | bytes):
        if isinstance(value, str):
            value = value.encode("utf-8")

        return super().__new__(cls, value)


class NormalizeToString(str):
    """Normalize a value to string."""

    def __new__(cls, value: str | bytes):
        if isinstance(value, bytes):
            value = value.decode("utf-8")

        return super().__new__(cls, value)


class EncryptedValue(NormalizeToBytes):
    encrypted: bool = True


class DecryptedValue(NormalizeToString):
    encrypted: bool = False


class HashedValue(NormalizeToBytes):
    hashed: bool = True


class BlindIndexValue(NormalizeToBytes):
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
    "Encrypt",
    "Decrypt",
    "Hash",
    "EncryptionMethod",
    "EncryptedValue",
    "DecryptedValue",
    "HashedValue",
    "BlindIndex",
    "BlindIndexMethod",
    "BlindIndexValue",
    "NormalizeToBytes",
    "NormalizeToString",
]
