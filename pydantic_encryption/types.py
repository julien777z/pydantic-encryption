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
    EVERVAULT = "evervault"
    AWS = "aws"


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


__all__ = [
    "Encrypt",
    "Decrypt",
    "Hash",
    "EncryptionMethod",
    "EncryptedValue",
    "DecryptedValue",
    "HashedValue",
    "NormalizeToBytes",
    "NormalizeToString",
]
